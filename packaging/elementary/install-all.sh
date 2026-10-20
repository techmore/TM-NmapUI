#!/usr/bin/env bash
# One-shot elementary OS install for the current user:
#   system packages -> Python venv -> Chromium for PDFs -> user service ->
#   native window + dock pin -> Wingpanel scan-summary indicator.
#   packaging/elementary/install-all.sh [--no-indicator] [--no-service]
# The Wingpanel module loads at next login; Wingpanel is not restarted here.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
app=$(cd "$here/../.." && pwd)
indicator=1; service=1
for arg in "$@"; do
  case "$arg" in
    --no-indicator) indicator=0 ;;
    --no-service) service=0 ;;
    *) echo "Usage: install-all.sh [--no-indicator] [--no-service]" >&2; exit 2 ;;
  esac
done

echo "== 1/5 System packages"; bash "$here/install-deps.sh"

echo "== 2/5 Python environment"
if ! "$app/.venv/bin/python" -c "import flask, flask_socketio, netifaces, playwright" 2>/dev/null; then
  rm -rf "$app/.venv"
  python3 -m venv "$app/.venv"
  "$app/.venv/bin/pip" install -q --upgrade pip
  "$app/.venv/bin/pip" install -q -r "$app/requirements.txt"
fi
echo "venv ok: $("$app/.venv/bin/python" --version)"

echo "== 3/5 Chromium for PDF reports"
"$app/.venv/bin/python" -m playwright install chromium
sudo "$app/.venv/bin/python" -m playwright install-deps chromium >/dev/null 2>&1 \
  || echo "note: could not install Chromium system libraries; PDF export may fail"

if ((service)); then
  echo "== 4/5 User service"
  unit="$HOME/.config/systemd/user/nmapui.service"
  mkdir -p "$(dirname "$unit")"
  sed "s|@APP_DIR@|$app|g" "$here/nmapui.service" > "$unit"
  # Migrate the earlier development unit, if present.
  if systemctl --user cat nmapui-dev.service >/dev/null 2>&1; then
    systemctl --user disable --now nmapui-dev.service 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/nmapui-dev.service"
  fi
  systemctl --user daemon-reload
  systemctl --user enable --now nmapui.service
  for _ in $(seq 1 20); do
    curl -fsS http://127.0.0.1:9000/api/health/live >/dev/null 2>&1 && break; sleep 1
  done
  curl -fsS http://127.0.0.1:9000/api/health/live >/dev/null && echo "scanner service is up on 127.0.0.1:9000"
else
  echo "== 4/5 User service (skipped)"
fi

echo "== 5/5 Native window, dock pin$([[ $indicator == 1 ]] && echo ' and panel indicator')"
bash "$here/install.sh"
if ((indicator)); then bash "$here/install-wingpanel.sh"; fi
echo "Done. Open 'Network Scanner' from the dock."
