#!/bin/bash
#
# Install NmapUI as a system LaunchDaemon.
#
# This is what makes the appliance requirement work:
#   * the server starts at boot and after a crash (RunAtLoad + KeepAlive),
#   * it runs with no user logged in,
#   * it never asks for a password after this one-time install,
#   * scans are privileged because the daemon runs as root.
#
# Usage:
#   sudo packaging/macos/install-daemon.sh              # install + start
#   sudo packaging/macos/install-daemon.sh --uninstall  # stop + remove
#        packaging/macos/install-daemon.sh --dry-run    # validate only, no root
#
# Options:
#   --user <name>   Run the daemon as <name> instead of root. Requires the
#                   sudoers rule this script also installs.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

LABEL="com.techmore.nmapui"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
SUDOERS_PATH="/etc/sudoers.d/nmapui"
WRAPPER_PATH="/usr/local/bin/nmapui-run"
DATA_DIR="/Library/Application Support/NmapUI"
LOG_DIR="/Library/Logs/NmapUI"
CREDENTIALS_FILE="$DATA_DIR/credentials.env"

PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
APP_PATH="$ROOT_DIR/app.py"

MODE="install"
RUN_USER="root"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --user) RUN_USER="${2:?--user needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[nmapui-daemon] %s\n' "$*"; }
die() { printf '[nmapui-daemon] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    die "must run as root. Re-run with: sudo $0 $*"
  fi
}

resolve_tool() {
  command -v "$1" 2>/dev/null || true
}

NMAP_PATH="$(resolve_tool nmap)"
ARP_SCAN_PATH="$(resolve_tool arp-scan)"

build_plist() {
  local target="$1"
  "$PYTHON_BIN" - "$target" "$LABEL" "$WRAPPER_PATH" "$RUN_USER" "$ROOT_DIR" "$LOG_DIR" <<'PYTHON'
import plistlib
import sys

path, label, wrapper, user, root, logs = sys.argv[1:]
with open(path, "wb") as stream:
    plistlib.dump({
        "Label": label,
        "ProgramArguments": [wrapper],
        "UserName": user,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "WorkingDirectory": root,
        "StandardOutPath": logs + "/server.out.log",
        "StandardErrorPath": logs + "/server.err.log",
        "EnvironmentVariables": {
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
    }, stream)
PYTHON
}

build_wrapper() {
  local target="$1"
  {
    printf '%s\n' '#!/bin/bash' 'set -euo pipefail'
    printf 'credentials_file=%q\n' "$CREDENTIALS_FILE"
    printf 'app_root=%q\n' "$ROOT_DIR"
    printf 'python_bin=%q\n' "$PYTHON_BIN"
    printf 'app_path=%q\n' "$APP_PATH"
    cat <<'WRAPPER'
# This file contains literal KEY=value records, not shell code. Preserve spaces,
# equals signs and metacharacters without evaluating credentials as commands.
if [[ ! -r "$credentials_file" ]]; then
  echo "NmapUI credentials file is not readable: $credentials_file" >&2
  exit 1
fi
while IFS='=' read -r name value || [[ -n "$name" ]]; do
  case "$name" in
    NMAPUI_DATA_DIR|NMAPUI_LOG_DIR|NMAPUI_HOST|NMAPUI_PORT|NMAPUI_ALLOW_UNSAFE_WERKZEUG|NMAPUI_USERNAME|NMAPUI_PASSWORD)
      export "$name=$value" ;;
    ''|'#'*) ;;
    *) echo "Unsupported setting in NmapUI credentials file: $name" >&2; exit 1 ;;
  esac
done < "$credentials_file"
cd "$app_root"
exec "$python_bin" "$app_path"
WRAPPER
  } > "$target"
  chmod 0755 "$target"
}

build_sudoers() {
  local target="$1"
  {
    echo "# NmapUI: allow the app user to run scans without a password prompt."
    echo "# One-time install; the appliance must never prompt for a password."
    if [[ -n "$NMAP_PATH" ]]; then
      echo "${RUN_USER} ALL=(root) NOPASSWD: ${NMAP_PATH}"
    fi
    if [[ -n "$ARP_SCAN_PATH" ]]; then
      echo "${RUN_USER} ALL=(root) NOPASSWD: ${ARP_SCAN_PATH}"
    fi
  } > "$target"
}

validate_plist() {
  plutil -lint "$1" >/dev/null || die "generated plist is invalid: $1"
}

validate_sudoers() {
  if command -v visudo >/dev/null 2>&1; then
    visudo -cf "$1" >/dev/null || die "generated sudoers file is invalid: $1"
  else
    die "visudo is required to validate sudoers before installation"
  fi
}

dry_run() {
  local stage
  stage="$(mktemp -d)"
  log "dry run: staging artifacts in $stage"

  [[ -x "$PYTHON_BIN" ]] || die "virtualenv python not found: $PYTHON_BIN (run ./install.sh or build.sh first)"
  [[ -f "$APP_PATH" ]] || die "app.py not found: $APP_PATH"

  build_plist "$stage/$LABEL.plist"
  build_wrapper "$stage/nmapui-run"
  build_sudoers "$stage/nmapui.sudoers"

  validate_plist "$stage/$LABEL.plist"
  validate_sudoers "$stage/nmapui.sudoers"
  bash -n "$stage/nmapui-run"

  log "plist:    OK ($stage/$LABEL.plist)"
  log "sudoers:  OK ($stage/nmapui.sudoers)"
  log "wrapper:  OK ($stage/nmapui-run)"
  log "python:   $PYTHON_BIN"
  log "nmap:     ${NMAP_PATH:-<not found>}"
  log "arp-scan: ${ARP_SCAN_PATH:-<not found>}"
  log "daemon user: $RUN_USER"
  log "dry run complete; nothing was installed"
  rm -rf "$stage"
}

uninstall() {
  require_root --uninstall
  log "stopping and removing ${LABEL}"
  launchctl bootout "system/${LABEL}" 2>/dev/null || true
  rm -f "$PLIST_PATH" "$SUDOERS_PATH" "$WRAPPER_PATH"
  log "removed plist, sudoers rule and wrapper"
  log "data and logs left in place: $DATA_DIR, $LOG_DIR"
}

set_runtime_permissions() {
  # --user must be able to read credentials and write persistent state/logs.
  # Do not recursively change ownership through links into other directories.
  chown "$RUN_USER" "$DATA_DIR" "$CREDENTIALS_FILE" "$DATA_DIR/data" "$LOG_DIR"
  find "$DATA_DIR/data" "$LOG_DIR" -type f -exec chown "$RUN_USER" {} +
  find "$DATA_DIR/data" "$LOG_DIR" -type d -exec chown "$RUN_USER" {} +
  chmod 0700 "$LOG_DIR"
  chmod 0600 "$CREDENTIALS_FILE"
}

install_daemon() {
  [[ "$(id -u)" == "0" ]] || die "must run as root. Re-run with: sudo $0"
  [[ -x "$PYTHON_BIN" ]] || die "virtualenv python not found: $PYTHON_BIN (run ./install.sh or build.sh first)"
  [[ -f "$APP_PATH" ]] || die "app.py not found: $APP_PATH"

  if [[ -z "$NMAP_PATH" ]]; then
    log "WARNING: nmap not found on PATH; scans will fail until it is installed"
  fi

  id "$RUN_USER" >/dev/null 2>&1 || die "unknown daemon user: $RUN_USER"
  log "creating data and log directories"
  mkdir -p "$DATA_DIR" "$LOG_DIR" /usr/local/bin
  chmod 0700 "$DATA_DIR"

  if [[ ! -f "$CREDENTIALS_FILE" ]]; then
    local password
    if command -v openssl >/dev/null 2>&1; then
      password="$(openssl rand -hex 16)"
    else
      password="$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_hex(16))')"
    fi
    umask 077
    {
      echo "NMAPUI_DATA_DIR=${DATA_DIR}/data"
      echo "NMAPUI_LOG_DIR=${LOG_DIR}"
      echo "NMAPUI_HOST=127.0.0.1"
      echo "NMAPUI_PORT=9000"
      echo "NMAPUI_ALLOW_UNSAFE_WERKZEUG=true"
      echo "NMAPUI_USERNAME=admin"
      echo "NMAPUI_PASSWORD=${password}"
    } > "$CREDENTIALS_FILE"
    chmod 0600 "$CREDENTIALS_FILE"
    log "generated credentials at $CREDENTIALS_FILE (username: admin)"
    log "read the password with: sudo cat '$CREDENTIALS_FILE'"
  else
    log "reusing existing credentials at $CREDENTIALS_FILE"
  fi
  mkdir -p "$DATA_DIR/data"
  chmod 0700 "$DATA_DIR/data"
  set_runtime_permissions

  log "installing wrapper $WRAPPER_PATH"
  build_wrapper "$WRAPPER_PATH"

  log "installing sudoers rule $SUDOERS_PATH"
  local staged_sudoers
  staged_sudoers="$(mktemp)"
  build_sudoers "$staged_sudoers"
  validate_sudoers "$staged_sudoers"
  install -m 0440 -o root -g wheel "$staged_sudoers" "$SUDOERS_PATH"
  rm -f "$staged_sudoers"

  log "installing LaunchDaemon $PLIST_PATH"
  local staged_plist
  staged_plist="$(mktemp)"
  build_plist "$staged_plist"
  validate_plist "$staged_plist"
  install -m 0644 -o root -g wheel "$staged_plist" "$PLIST_PATH"
  rm -f "$staged_plist"

  log "bootstrapping the daemon"
  launchctl bootout "system/${LABEL}" 2>/dev/null || true
  launchctl bootstrap system "$PLIST_PATH"
  launchctl enable "system/${LABEL}"
  launchctl kickstart -k "system/${LABEL}"

  log "waiting for readiness..."
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if curl --max-time 5 -fsS "http://127.0.0.1:9000/api/health/ready" >/dev/null 2>&1; then
      log "NmapUI is up: http://127.0.0.1:9000 (sign in at /login)"
      return 0
    fi
    sleep 2
  done
  log "WARNING: server did not report ready within 120s; check $LOG_DIR/server.err.log"
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
case "$MODE" in
  dry-run) dry_run ;;
  uninstall) uninstall ;;
  install) install_daemon ;;
esac
fi
