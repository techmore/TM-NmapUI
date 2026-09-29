#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$BASE_DIR"
LOG_DIR="${NMAPUI_EVAL_LOG_DIR:-$ROOT_DIR/docs/notes/eval-logs}"
MODE="${1:---dry-run}"
if [[ -z "${PYTHON_BIN:-}" && -x "$BASE_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$BASE_DIR/.venv/bin/python"
elif [[ -z "${PYTHON_BIN:-}" && -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi
PYTEST_BIN="${PYTEST_BIN:-$PYTHON_BIN -m pytest}"
SAFE_TARGET="${NMAPUI_EVAL_TARGET:-127.0.0.1}"

timestamp() {
  "$PYTHON_BIN" - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat())
PY
}

git_revision() {
  git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf '%s' unknown
}

log_file_for() {
  local suffix="$1"
  printf '%s/nightly-product-eval%s.log' "$LOG_DIR" "$suffix"
}

server_log() {
  printf '%s/nightly-product-eval-server.log' "$LOG_DIR"
}

run_log() {
  printf '%s/nightly-product-eval.log' "$LOG_DIR"
}

json_log() {
  printf '%s/nightly-product-eval.json' "$LOG_DIR"
}

write_json_report() {
  local path="$1"
  local mode="$2"
  local scenarios_json="$3"
  local artifacts_json="$4"
  mkdir -p "$LOG_DIR"
  "$PYTHON_BIN" - "$path" "$mode" "$(git_revision)" "$ROOT_DIR" "$scenarios_json" "$artifacts_json" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
revision = sys.argv[3]
root_dir = sys.argv[4]
scenarios = json.loads(sys.argv[5])
artifacts = json.loads(sys.argv[6])
payload = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "mode": mode,
    "revision": revision,
    "environment": pathlib.Path(root_dir).name,
    "scenarios": scenarios,
    "artifacts": artifacts,
}
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

run_pytest_slice() {
  local tests="$1"
  local output_file="$2"
  mkdir -p "$LOG_DIR"
  eval "$PYTEST_BIN -q $tests" >"$output_file" 2>&1
}

probe_liveness() {
  curl -fsS "http://127.0.0.1:9000/api/health/live"
}

probe_identity() {
  # Flask exposes /api/health (with app_version); /api/app-identity only ever
  # existed in the legacy Node runtime.
  curl -fsS "http://127.0.0.1:9000/api/health"
}

probe_root() {
  curl -fsS "http://127.0.0.1:9000/"
}

probe_static_asset() {
  curl -fsS "http://127.0.0.1:9000/static/techmore.png" >/dev/null
}

port_in_use() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.settimeout(1)
    raise SystemExit(0 if sock.connect_ex(("127.0.0.1", 9000)) == 0 else 1)
PY
}

wait_for_port() {
  python3 - <<'PY'
import socket
import time

deadline = time.time() + 120
while time.time() < deadline:
    with socket.socket() as sock:
        sock.settimeout(1)
        if sock.connect_ex(("127.0.0.1", 9000)) == 0:
            raise SystemExit(0)
    time.sleep(1)
raise SystemExit(1)
PY
}

start_server() {
  # Boot the authoritative Flask runtime with the project virtualenv.
  # The legacy `npm start` path was never the product and does not exist on
  # launchd's minimal PATH, which left this evaluation blocked for weeks.
  (
    cd "$ROOT_DIR" || exit 1
    # exec so $! is the Flask process itself and teardown is reliable.
    exec env NMAPUI_PORT=9000 \
      NMAPUI_ALLOW_UNSAFE_WERKZEUG=true \
      "$PYTHON_BIN" "$ROOT_DIR/app.py" --quick
  ) >"$(server_log)" 2>&1 &
  echo $!
}

stop_server() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return
  fi
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

print_dry_run() {
  cat <<EOF2
NmapUI nightly product evaluation loop
Mode: dry-run
Root: $ROOT_DIR
Target: $SAFE_TARGET
Log dir: $LOG_DIR

Planned scenarios:
1. Boot the Flask app with .venv/bin/python app.py --quick
2. Probe /api/health/live
3. Probe /api/health (app identity)
4. Probe /
5. Probe /static/techmore.png
6. Record the result
EOF2
}

main() {
  local server_pid=""
  case "$MODE" in
    --dry-run)
      print_dry_run
      ;;
    --run)
      mkdir -p "$LOG_DIR"
      local runtime_log
      runtime_log="$(run_log)"

      if port_in_use; then
        printf 'Port 9000 already in use; blocked evaluation run.\n' >"$runtime_log"
        write_json_report "$(json_log)" "run" '[
          {"name": "app_start", "status": "blocked", "reason": "port already in use"},
          {"name": "identity_probe", "status": "blocked", "reason": "port already in use"},
          {"name": "root_probe", "status": "blocked", "reason": "port already in use"},
          {"name": "static_asset_probe", "status": "blocked", "reason": "port already in use"}
        ]' "$(printf '%s' "[\"$runtime_log\", \"$(server_log)\"]")"
        printf '%s nightly-product-eval blocked: port 9000 already in use\n' "$(timestamp)"
        exit 1
      fi

      server_pid="$(start_server)"
      if ! wait_for_port; then
        printf 'Server did not start on port 9000.\n' >"$runtime_log"
        write_json_report "$(json_log)" "run" '[
          {"name": "app_start", "status": "blocked", "reason": "server did not start"},
          {"name": "identity_probe", "status": "blocked", "reason": "server did not start"},
          {"name": "root_probe", "status": "blocked", "reason": "server did not start"},
          {"name": "static_asset_probe", "status": "blocked", "reason": "server did not start"}
        ]' "$(printf '%s' "[\"$runtime_log\", \"$(server_log)\"]")"
        printf '%s nightly-product-eval blocked: server did not start on port 9000\n' "$(timestamp)"
        stop_server "${server_pid:-}"
        printf '%s\n' '--- server log (tail) ---'
        tail -n 40 "$(server_log)" 2>/dev/null || true
        exit 1
      fi

      liveness_json="$(probe_liveness)"
      identity_json="$(probe_identity)"
      root_html="$(probe_root)"
      probe_static_asset
      printf '%s\n' "$liveness_json"
      printf '%s\n' "$identity_json"
      printf '%s\n' "$root_html" | sed -n '1,5p'
      {
        printf '%s\n' "$(timestamp)"
        printf 'liveness=%s\n' "$liveness_json"
        printf 'identity=%s\n' "$identity_json"
        printf 'root=%s\n' "$(printf '%s' "$root_html" | tr '\n' ' ' | cut -c1-200)"
        printf 'static_asset=ok\n'
      } >"$runtime_log"
      write_json_report "$(json_log)" "run" '[
        {"name": "app_start", "status": "pass"},
        {"name": "identity_probe", "status": "pass"},
        {"name": "root_probe", "status": "pass"},
        {"name": "static_asset_probe", "status": "pass"}
      ]' "$(printf '%s' "[\"$runtime_log\", \"$(server_log)\"]")"
      stop_server "${server_pid:-}"
      printf '%s nightly-product-eval completed successfully\n' "$(timestamp)"
      ;;
    --record)
      mkdir -p "$LOG_DIR"
      local record_log
      record_log="${LOG_DIR}/nightly-product-eval.record.log"
      {
        printf '%s nightly-product-eval record mode\n' "$(timestamp)"
        printf 'root=%s\n' "$ROOT_DIR"
        printf 'target=%s\n' "$SAFE_TARGET"
      } >"$record_log"
      printf 'Wrote %s\n' "$record_log"
      ;;
    *)
      echo "Usage: $0 [--dry-run|--record|--run]" >&2
      exit 1
      ;;
  esac
}

main "$@"
