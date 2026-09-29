#!/bin/bash
#
# Install NmapUI as a system LaunchDaemon.
#
# This is what makes the appliance requirement work:
#   * the server starts at boot and after a crash (RunAtLoad + KeepAlive),
#   * it runs with no user logged in,
#   * it never asks for a password after this one-time install,
#   * scans are privileged, with no privilege prompts at any point.
#
# The appliance runs as root by default. That is the simplest configuration that
# actually works: no sudoers dependency, full SYN/OS/ARP capability, and nothing
# to go wrong. `--user <name>` opts into the least-privilege path instead, where
# sudoers grants NOPASSWD for packaging/macos/nmapui-privileged-scanner only
# (never nmap itself) and that helper re-validates every flag, path and target.
# In both modes root-owned copies of vulners.nse and the stylesheets are staged
# so a writable checkout cannot inject Lua into a root-run nmap.
#
# Usage:
#   sudo packaging/macos/install-daemon.sh                 # install + start
#   sudo packaging/macos/install-daemon.sh --rollback      # restore prior release
#   sudo packaging/macos/install-daemon.sh --uninstall     # stop + remove
#        packaging/macos/install-daemon.sh --dry-run       # validate, no root
#
# Options:
#   --user <name>   Run the web backend as <name> instead of root (least
#                   privilege; uses the validating scanner helper).
#   --allow-root    Deprecated no-op: root is already the default.
#
set -euo pipefail

# Never execute installer utilities from a user-writable Homebrew directory.
# The service may also use /usr/local/bin after each required tool is checked.
INSTALLER_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
SERVICE_PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"
export PATH="$INSTALLER_PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_ROOT="/usr/local/lib/nmapui"
RELEASES_DIR="$INSTALL_ROOT/releases"
ROOT_DIR="$INSTALL_ROOT/current"
PREVIOUS_LINK="$INSTALL_ROOT/previous"
SOURCE_PYTHON_BIN="$SOURCE_ROOT_DIR/.venv/bin/python"
STAGER_PATH="$SOURCE_ROOT_DIR/packaging/stage_runtime.py"
READY_CHECK_PATH="$SOURCE_ROOT_DIR/packaging/check_release_ready.py"
SERVICE_ENV_CHECK_PATH="$SOURCE_ROOT_DIR/packaging/validate_service_env.py"

LABEL="com.techmore.nmapui"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
SUDOERS_PATH="/etc/sudoers.d/nmapui"
WRAPPER_PATH="/usr/local/bin/nmapui-run"
HELPER_PATH="/usr/local/libexec/nmapui-privileged-scanner"
HELPER_SOURCE="$SCRIPT_DIR/nmapui-privileged-scanner"
ASSET_DIR="/usr/local/share/nmapui"
BROWSER_DIR="$ASSET_DIR/playwright-browsers"
DATA_DIR="/Library/Application Support/NmapUI"
LOG_DIR="/Library/Logs/NmapUI"
CREDENTIALS_FILE="$DATA_DIR/credentials.env"

PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
APP_PATH="$ROOT_DIR/app.py"

MODE="install"
RUN_USER=""
ALLOW_ROOT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run"; shift ;;
    --rollback) MODE="rollback"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --user) RUN_USER="${2:?--user needs a value}"; shift 2 ;;
    --allow-root) ALLOW_ROOT=1; shift ;;
    -h|--help) sed -n '2,29p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[nmapui-daemon] %s\n' "$*"; }
die() { printf '[nmapui-daemon] ERROR: %s\n' "$*" >&2; exit 1; }

ensure_privacy_safe_egress_defaults() {
  local setting
  for setting in NMAPUI_ENABLE_NETWORK_FINGERPRINT NMAPUI_ENABLE_UPDATE_CHECK NMAPUI_ENABLE_VULNERS; do
    if ! grep -q "^$setting=" "$CREDENTIALS_FILE"; then
      printf '%s=false\n' "$setting" >> "$CREDENTIALS_FILE"
    fi
  done
}

resolve_run_user() {
  # This appliance platform runs as root deliberately: it is the simplest thing
  # that actually works, needs no sudoers entry, and gives the scanner full
  # SYN/OS/ARP capability with no privilege plumbing. Root is therefore the
  # default, and installing requires no extra decision.
  #
  # `--user <name>` opts into the non-root path instead, which uses the
  # validating helper (packaging/macos/nmapui-privileged-scanner) that this
  # installer also stages. Called only by install/dry-run so the script stays
  # sourceable for tests.
  [[ -n "${RUN_USER:-}" ]] && return 0
  RUN_USER="root"
}

require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    die "must run as root. Re-run with: sudo $0 $*"
  fi
}

resolve_tool() {
  PATH="$SERVICE_PATH" command -v "$1" 2>/dev/null || true
}

NMAP_PATH="$(resolve_tool nmap)"
ARP_SCAN_PATH="$(resolve_tool arp-scan)"
NMAP_DATA_DIR=""

build_plist() {
  local target="$1"
  "$SOURCE_PYTHON_BIN" - "$target" "$LABEL" "$WRAPPER_PATH" "$RUN_USER" "$ROOT_DIR" "$LOG_DIR" "$SERVICE_PATH" <<'PYTHON'
import plistlib
import sys

path, label, wrapper, user, root, logs, service_path = sys.argv[1:]
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
            "PATH": service_path,
        },
    }, stream)
PYTHON
}

build_wrapper() {
  local target="$1"
  local runner="${2:-gunicorn}"
  [[ "$runner" == "gunicorn" || "$runner" == "direct" ]] || die "invalid wrapper runner: $runner"
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
    NMAPUI_DATA_DIR|NMAPUI_LOG_DIR|NMAPUI_HOST|NMAPUI_PORT|NMAPUI_ALLOWED_ORIGINS|NMAPUI_TRUST_LOCAL_UI|NMAPUI_COOKIE_SECURE|NMAPUI_MAX_CONCURRENT_JOBS|NMAPUI_RUNTIME_LOGS_KEEP_LATEST|NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST|NMAPUI_FINISHED_JOBS_KEEP_LATEST|NMAPUI_ALLOW_UNSAFE_WERKZEUG|NMAPUI_STARTUP_TRACEROUTE|NMAPUI_ENABLE_NETWORK_FINGERPRINT|NMAPUI_ENABLE_UPDATE_CHECK|NMAPUI_ENABLE_VULNERS|NMAPUI_USERNAME|NMAPUI_PASSWORD|NMAPUI_PRIVILEGED_ASSETS|PLAYWRIGHT_BROWSERS_PATH)
      export "$name=$value" ;;
    ''|'#'*) ;;
    *) echo "Unsupported setting in NmapUI credentials file: $name" >&2; exit 1 ;;
  esac
done < "$credentials_file"
if [[ -d "$app_root/privileged-assets" ]]; then
  export NMAPUI_PRIVILEGED_ASSETS="$app_root/privileged-assets"
fi
cd "$app_root"
WRAPPER
    if [[ -n "$NMAP_DATA_DIR" ]]; then
      printf 'export NMAPDIR=%q\n' "$NMAP_DATA_DIR"
    fi
    if [[ "$runner" == "direct" ]]; then
      printf '%s\n' 'exec "$python_bin" "$app_path"'
    else
      cat <<'GUNICORN'
port="${NMAPUI_PORT:-9000}"
if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
  echo "Invalid NMAPUI_PORT: $port" >&2
  exit 1
fi
bind_host="${NMAPUI_HOST:-127.0.0.1}"
if [[ "$bind_host" == *:* && "$bind_host" != \[*\] ]]; then
  bind_host="[$bind_host]"
fi
exec "$python_bin" -m gunicorn \
  --bind "$bind_host:$port" \
  --workers 1 --threads 100 --timeout 180 --graceful-timeout 30 \
  nmapui.wsgi:application
GUNICORN
    fi
  } > "$target"
  chmod 0755 "$target"
}

build_sudoers() {
  local target="$1"
  {
    if [[ "$RUN_USER" == "root" ]]; then
      # Running the backend as root needs no privilege escalation at all.
      echo "# NmapUI: backend runs as root (default), so no sudoers grant is needed."
      echo "# The validating helper is still installed for the --user mode."
    else
      echo "# NmapUI: allow the service user to request privileged scans without a"
      echo "# password prompt. Only the validating helper is granted — never nmap or"
      echo "# arp-scan directly — so the backend cannot ask root to run anything else."
      echo "${RUN_USER} ALL=(root) NOPASSWD: ${HELPER_PATH}"
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
  resolve_run_user
  local stage
  [[ -x "$SOURCE_PYTHON_BIN" ]] || die "virtualenv python not found: $SOURCE_PYTHON_BIN (run ./install.sh or build.sh first)"
  [[ -f "$SOURCE_ROOT_DIR/app.py" ]] || die "app.py not found: $SOURCE_ROOT_DIR/app.py"
  [[ -f "$STAGER_PATH" ]] || die "runtime stager not found: $STAGER_PATH"
  [[ -f "$READY_CHECK_PATH" ]] || die "release readiness checker not found: $READY_CHECK_PATH"
  [[ -f "$SERVICE_ENV_CHECK_PATH" ]] || die "service env validator not found: $SERVICE_ENV_CHECK_PATH"
  [[ -f "$HELPER_SOURCE" ]] || die "helper source not found: $HELPER_SOURCE"
  "$SOURCE_PYTHON_BIN" -m py_compile "$HELPER_SOURCE" || die "helper failed to compile"
  "$SOURCE_PYTHON_BIN" -c 'import flask, flask_socketio, gunicorn, playwright, simple_websocket' \
    || die "install pinned requirements before installing the daemon"
  if [[ "$RUN_USER" == "root" ]] && ! "$SOURCE_PYTHON_BIN" "$STAGER_PATH" \
    --source "$SOURCE_ROOT_DIR" --verify-root-interpreter >/dev/null 2>&1; then
    log "WARNING: root install will require a root-owned Python interpreter (use --user or install a trusted Python)"
  fi
  verify_service_toolchain

  if [[ -f "$CREDENTIALS_FILE" && -r "$CREDENTIALS_FILE" ]]; then
    "$SOURCE_PYTHON_BIN" "$SERVICE_ENV_CHECK_PATH" --file "$CREDENTIALS_FILE" \
      --data "$DATA_DIR/data" --log "$LOG_DIR" --browser "$BROWSER_DIR" \
      || die "existing service credentials do not match installer paths"
  fi

  stage="$(mktemp -d)"
  log "dry run: staging artifacts in $stage"
  build_plist "$stage/$LABEL.plist"
  build_wrapper "$stage/nmapui-run"
  build_sudoers "$stage/nmapui.sudoers"

  validate_plist "$stage/$LABEL.plist"
  validate_sudoers "$stage/nmapui.sudoers"
  bash -n "$stage/nmapui-run"

  if [[ "$RUN_USER" != "root" ]]; then
    grep -q "NOPASSWD: ${HELPER_PATH}" "$stage/nmapui.sudoers" \
      || die "sudoers rule does not grant the helper"
    if grep -qE "NOPASSWD:.*(bin/nmap|bin/arp-scan)" "$stage/nmapui.sudoers"; then
      die "sudoers rule must not grant nmap or arp-scan directly"
    fi
  fi

  log "plist:    OK ($stage/$LABEL.plist)"
  if [[ "$RUN_USER" == "root" ]]; then
    log "sudoers:  OK ($stage/nmapui.sudoers, no grant needed in root mode)"
  else
    log "sudoers:  OK ($stage/nmapui.sudoers, helper only)"
  fi
  log "wrapper:  OK ($stage/nmapui-run)"
  log "helper:   OK ($HELPER_SOURCE)"
  log "source python: $SOURCE_PYTHON_BIN"
  log "service release: $ROOT_DIR (staged at install time)"
  log "nmap:     ${NMAP_PATH:-<not found>}"
  log "arp-scan: ${ARP_SCAN_PATH:-<not found>}"
  log "daemon user: $RUN_USER"
  log "dry run complete; nothing was installed"
  rm -rf "$stage"
}

uninstall() {
  require_root --uninstall
  [[ ! -e "$ROOT_DIR" || -L "$ROOT_DIR" ]] || die "refusing non-symlink current release: $ROOT_DIR"
  [[ ! -e "$PREVIOUS_LINK" || -L "$PREVIOUS_LINK" ]] \
    || die "refusing non-symlink previous release: $PREVIOUS_LINK"
  if [[ ! -L "$ROOT_DIR" && ! -L "$PREVIOUS_LINK" && ! -e "$PLIST_PATH" && ! -L "$PLIST_PATH" && \
        ! -e "$SUDOERS_PATH" && ! -L "$SUDOERS_PATH" && \
        ! -e "$WRAPPER_PATH" && ! -L "$WRAPPER_PATH" && \
        ! -e "$HELPER_PATH" && ! -L "$HELPER_PATH" ]]; then
    if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
      die "launchd reports an unmanaged NmapUI daemon"
    fi
    log "NmapUI daemon is already absent; preserved data and release archives"
    return 0
  fi
  [[ -L "$ROOT_DIR" ]] || die "cannot uninstall service files without a managed current release"
  validate_managed_release "$(readlink "$ROOT_DIR")"
  if [[ -L "$PREVIOUS_LINK" ]]; then
    validate_managed_release "$(readlink "$PREVIOUS_LINK")"
  fi
  verify_installed_artifacts
  log "stopping and removing ${LABEL}"
  if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    launchctl bootout "system/${LABEL}" || die "could not stop daemon; no files removed"
  fi
  rm -f "$PLIST_PATH" "$SUDOERS_PATH" "$WRAPPER_PATH" "$HELPER_PATH"
  rm -f "$ROOT_DIR" "$PREVIOUS_LINK"
  log "removed plist, sudoers rule, wrapper and helper"
  log "data, logs, legacy scan assets and rollback releases left in place: $DATA_DIR, $LOG_DIR, $ASSET_DIR, $RELEASES_DIR"
}

stage_release() {
  local version release_path
  version="$(tr -d '\r\n' < "$SOURCE_ROOT_DIR/VERSION")"
  [[ "$version" =~ ^[A-Za-z0-9._-]+$ ]] || die "VERSION contains invalid release-path characters"
  install -d -m 0755 -o root -g wheel "$INSTALL_ROOT" "$RELEASES_DIR"
  chmod 0755 "$INSTALL_ROOT" "$RELEASES_DIR"
  release_path="$RELEASES_DIR/${version}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" \
    --source "$SOURCE_ROOT_DIR" --destination "$release_path"
  "$release_path/.venv/bin/python" -m compileall -q \
    "$release_path/app.py" "$release_path/nmapui" \
    || die "staged runtime failed syntax validation: $release_path"
  "$release_path/.venv/bin/python" -c 'import flask, flask_socketio, gunicorn, playwright, simple_websocket' \
    || die "staged runtime dependencies are unavailable: $release_path"
  printf '%s\n' "$release_path"
}

switch_managed_link() {
  local link="$1" release_path="$2" next_link
  next_link="$INSTALL_ROOT/.$(basename "$link").next.$$"
  if [[ -e "$link" && ! -L "$link" ]]; then
    die "refusing to replace a non-symlink runtime path: $link"
  fi
  ln -s "$release_path" "$next_link"
  # BSD mv follows a destination symlink to a directory unless -h is given.
  # Without -h, the new link lands *inside* the old release instead of
  # atomically replacing current.
  mv -fh "$next_link" "$link"
}

switch_release() {
  switch_managed_link "$ROOT_DIR" "$1"
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

migrate_legacy_file() {
  local source="$1" destination="$2"
  [[ ! -L "$destination" ]] || die "refusing symlinked runtime file: $destination"
  if [[ ! -e "$destination" && -f "$source" ]]; then
    install -m 0600 "$source" "$destination"
    log "preserved legacy runtime file at $destination"
  fi
}

read_service_port() {
  local port=""
  if [[ -f "$CREDENTIALS_FILE" ]]; then
    port="$(sed -n 's/^NMAPUI_PORT=//p' "$CREDENTIALS_FILE" | tail -n 1)"
  fi
  port="${port:-9000}"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) \
    || die "invalid NMAPUI_PORT in $CREDENTIALS_FILE"
  printf '%s\n' "$port"
}

read_service_host() {
  local host=""
  if [[ -f "$CREDENTIALS_FILE" ]]; then
    host="$(sed -n 's/^NMAPUI_HOST=//p' "$CREDENTIALS_FILE" | tail -n 1)"
  fi
  printf '%s\n' "${host:-127.0.0.1}"
}

check_port_conflict() {
  local port
  command -v lsof >/dev/null || die "lsof is required to check the configured port"
  port="$(read_service_port)"
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1 && \
    ! launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    die "port $port is already occupied by an unmanaged process; stop it or choose another NMAPUI_PORT"
  fi
}

check_state_paths() {
  local state_path
  for state_path in "$DATA_DIR" "$DATA_DIR/data" "$LOG_DIR" "$CREDENTIALS_FILE"; do
    [[ ! -L "$state_path" ]] || die "refusing symlinked service state path: $state_path"
  done
}

verify_service_toolchain() {
  local tool path
  for path in /bin/bash /usr/bin/python3; do
    [[ -x "$path" ]] || die "required protected script interpreter is missing: $path"
    "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
      --verify-root-executable "$path" \
      || die "script interpreter is not protected: $path"
  done
  for tool in nmap arp-scan xsltproc traceroute; do
    path="$(resolve_tool "$tool")"
    [[ -n "$path" ]] || die "$tool is required in the protected service PATH: $SERVICE_PATH"
    "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
      --verify-root-executable "$path" \
      || die "$tool is not safe to execute as root: $path"
    if [[ "$tool" == nmap ]]; then
      NMAP_DATA_DIR="$("$SOURCE_PYTHON_BIN" -c \
        'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve().parents[1] / "share/nmap")' "$path")"
      "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
        --verify-root-nmap-data-dir "$NMAP_DATA_DIR" \
        || die "Nmap script/data files are not safe to load as root: $NMAP_DATA_DIR"
    fi
  done
  path="$(resolve_tool wkhtmltopdf)"
  if [[ -n "$path" ]]; then
    "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
      --verify-root-executable "$path" \
      || die "wkhtmltopdf is not safe to execute as root: $path"
  fi
}

backup_installed_artifacts() {
  local backup_dir="$1" index path
  local paths=("$WRAPPER_PATH" "$HELPER_PATH" "$SUDOERS_PATH" "$PLIST_PATH")
  for index in "${!paths[@]}"; do
    path="${paths[$index]}"
    [[ ! -L "$path" ]] || die "refusing symlinked installed artifact: $path"
    if [[ -e "$path" ]]; then
      [[ -f "$path" ]] || die "refusing non-file installed artifact: $path"
      cp -p "$path" "$backup_dir/$index"
    else
      touch "$backup_dir/$index.absent"
    fi
  done
}

verify_installed_artifacts() {
  local path
  for path in "$WRAPPER_PATH" "$HELPER_PATH" "$SUDOERS_PATH" "$PLIST_PATH"; do
    [[ -f "$path" && ! -L "$path" ]] || die "installed service artifact is missing or symlinked: $path"
  done
  [[ -x "$WRAPPER_PATH" && -x "$HELPER_PATH" ]] \
    || die "installed launcher or scanner helper is not executable"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
    --verify-root-file "$WRAPPER_PATH" \
    --verify-root-file "$HELPER_PATH" \
    --verify-root-file "$SUDOERS_PATH" \
    --verify-root-file "$PLIST_PATH" \
    || die "installed service artifacts are not protected"
}

verify_release_artifacts() {
  local release="$1" artifacts="$1/service-artifacts" path
  [[ -d "$artifacts" && ! -L "$artifacts" ]] \
    || die "release service artifacts are missing or symlinked: $artifacts"
  for path in nmapui-run nmapui-privileged-scanner nmapui.sudoers "${LABEL}.plist"; do
    [[ -f "$artifacts/$path" && ! -L "$artifacts/$path" ]] \
      || die "release service artifact is missing or symlinked: $artifacts/$path"
  done
  [[ -x "$artifacts/nmapui-run" && -x "$artifacts/nmapui-privileged-scanner" ]] \
    || die "release launcher or scanner helper is not executable: $artifacts"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
    --verify-root-file "$artifacts/nmapui-run" \
    --verify-root-file "$artifacts/nmapui-privileged-scanner" \
    --verify-root-file "$artifacts/nmapui.sudoers" \
    --verify-root-file "$artifacts/${LABEL}.plist" \
    || die "release service artifacts are not protected: $release"
  validate_plist "$artifacts/${LABEL}.plist"
  validate_sudoers "$artifacts/nmapui.sudoers"
}

save_release_artifacts() {
  local release="$1" wrapper="$2" helper="$3" sudoers="$4" plist="$5"
  local artifacts="$release/service-artifacts" temporary="$release/.service-artifacts.$$"
  [[ ! -e "$artifacts" && ! -L "$artifacts" && ! -e "$temporary" && ! -L "$temporary" ]] \
    || die "refusing to overwrite or reuse release service artifacts: $release"
  install -d -m 0755 -o root -g wheel "$temporary"
  install -m 0755 -o root -g wheel "$wrapper" "$temporary/nmapui-run"
  install -m 0755 -o root -g wheel "$helper" "$temporary/nmapui-privileged-scanner"
  install -m 0440 -o root -g wheel "$sudoers" "$temporary/nmapui.sudoers"
  install -m 0644 -o root -g wheel "$plist" "$temporary/${LABEL}.plist"
  mv -f "$temporary" "$artifacts"
}

validate_managed_release() {
  local release="$1" canonical_root canonical_release
  [[ -d "$RELEASES_DIR" && ! -L "$RELEASES_DIR" && -d "$release" && ! -L "$release" ]] \
    || die "release is missing or symlinked: $release"
  canonical_root="$(realpath "$RELEASES_DIR")"
  canonical_release="$(realpath "$release")"
  [[ "$release" == "$canonical_release" && "$(dirname "$canonical_release")" == "$canonical_root" ]] \
    || die "release is outside the managed release directory: $release"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
    --verify-root-file "$release/release_id" \
    || die "release identity is not protected: $release"
}

read_plist_run_user() {
  "$SOURCE_PYTHON_BIN" - "$1" <<'PYTHON'
import plistlib
import sys

with open(sys.argv[1], "rb") as stream:
    user = plistlib.load(stream).get("UserName")
if not isinstance(user, str) or not user:
    raise SystemExit("installed plist has no daemon user")
print(user)
PYTHON
}

check_existing_run_user() {
  local installed_user
  installed_user="$(read_plist_run_user "$PLIST_PATH")" \
    || die "cannot read the installed daemon user: $PLIST_PATH"
  [[ "$installed_user" == "$RUN_USER" ]] \
    || die "changing daemon user from $installed_user to $RUN_USER requires uninstall/reinstall with planned downtime"
}

restore_installed_artifacts() {
  local backup_dir="$1" index path failed=0
  local paths=("$WRAPPER_PATH" "$HELPER_PATH" "$SUDOERS_PATH" "$PLIST_PATH")
  for index in "${!paths[@]}"; do
    path="${paths[$index]}"
    rm -f "$path" || failed=1
    if [[ -f "$backup_dir/$index" ]]; then
      cp -p "$backup_dir/$index" "$path" || failed=1
    fi
  done
  return "$failed"
}

rollback_failed_install() {
  local status="$1" restore_failed=0
  trap - EXIT
  set +e
  if [[ "${INSTALL_MUTATED:-0}" == 1 ]]; then
    log "restoring installed artifacts after unsuccessful deployment"
    if [[ "${INSTALL_SWITCHED:-0}" == 1 ]]; then
      launchctl bootout "system/${LABEL}" 2>/dev/null || true
    fi
    restore_installed_artifacts "$INSTALL_BACKUP_DIR" || restore_failed=1
    if [[ "${INSTALL_SWITCHED:-0}" == 1 ]]; then
      if [[ -n "${INSTALL_PREVIOUS_RELEASE:-}" ]]; then
        switch_release "$INSTALL_PREVIOUS_RELEASE" || restore_failed=1
      else
        rm -f "$ROOT_DIR" || restore_failed=1
      fi
      if [[ "${INSTALL_PREVIOUS_LINK_SWITCHED:-0}" == 1 ]]; then
        if [[ -n "${INSTALL_OLD_PREVIOUS_LINK:-}" ]]; then
          switch_managed_link "$PREVIOUS_LINK" "$INSTALL_OLD_PREVIOUS_LINK" || restore_failed=1
        else
          rm -f "$PREVIOUS_LINK" || restore_failed=1
        fi
      fi
      if [[ "${INSTALL_PREVIOUS_LOADED:-0}" == 1 ]]; then
        launchctl bootstrap system "$PLIST_PATH" || restore_failed=1
        launchctl enable "system/${LABEL}" || restore_failed=1
        launchctl kickstart -k "system/${LABEL}" || restore_failed=1
      fi
    fi
  fi
  if [[ -n "${INSTALL_BACKUP_DIR:-}" && -d "$INSTALL_BACKUP_DIR" ]]; then
    rm -rf "$INSTALL_BACKUP_DIR"
  fi
  if [[ "$restore_failed" == 1 ]]; then
    log "ERROR: automatic restoration was incomplete; inspect $PLIST_PATH and $ROOT_DIR"
  fi
  exit "$status"
}

install_daemon() {
  resolve_run_user
  [[ "$(id -u)" == "0" ]] || die "must run as root. Re-run with: sudo $0"
  [[ -x "$SOURCE_PYTHON_BIN" ]] || die "virtualenv python not found: $SOURCE_PYTHON_BIN (run ./install.sh or build.sh first)"
  [[ -f "$SOURCE_ROOT_DIR/app.py" ]] || die "app.py not found: $SOURCE_ROOT_DIR/app.py"
  [[ -f "$STAGER_PATH" ]] || die "runtime stager not found: $STAGER_PATH"
  [[ -f "$READY_CHECK_PATH" ]] || die "release readiness checker not found: $READY_CHECK_PATH"
  [[ -f "$SERVICE_ENV_CHECK_PATH" ]] || die "service env validator not found: $SERVICE_ENV_CHECK_PATH"
  if [[ "$RUN_USER" == "root" ]]; then
    "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" --verify-root-interpreter \
      || die "root service requires a root-owned Python interpreter; use --user or install a trusted Python"
  fi
  verify_service_toolchain

  id "$RUN_USER" >/dev/null 2>&1 || die "unknown daemon user: $RUN_USER"
  local previous_release old_previous_link new_release
  [[ ! -e "$ROOT_DIR" || -L "$ROOT_DIR" ]] || die "refusing non-symlink current release: $ROOT_DIR"
  [[ ! -e "$PREVIOUS_LINK" || -L "$PREVIOUS_LINK" ]] \
    || die "refusing non-symlink previous release: $PREVIOUS_LINK"
  previous_release="$(readlink "$ROOT_DIR" 2>/dev/null || true)"
  old_previous_link="$(readlink "$PREVIOUS_LINK" 2>/dev/null || true)"
  if [[ -n "$previous_release" ]]; then
    validate_managed_release "$previous_release"
    verify_installed_artifacts
    check_existing_run_user
    if [[ ! -d "$previous_release/service-artifacts" ]]; then
      save_release_artifacts "$previous_release" "$WRAPPER_PATH" "$HELPER_PATH" "$SUDOERS_PATH" "$PLIST_PATH"
    fi
    verify_release_artifacts "$previous_release"
  else
    [[ -z "$old_previous_link" ]] || die "previous release exists without a managed current release"
    local path
    for path in "$WRAPPER_PATH" "$HELPER_PATH" "$SUDOERS_PATH" "$PLIST_PATH"; do
      [[ ! -e "$path" && ! -L "$path" ]] || die "existing service artifacts have no managed current release: $path"
    done
    if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
      die "existing daemon has no managed current release"
    fi
  fi
  [[ -z "$old_previous_link" ]] || validate_managed_release "$old_previous_link"
  check_port_conflict
  check_state_paths
  log "creating data and log directories"
  mkdir -p "$DATA_DIR" "$LOG_DIR" /usr/local/bin
  chmod 0700 "$DATA_DIR"

  if [[ ! -f "$CREDENTIALS_FILE" ]]; then
    local password
    if command -v openssl >/dev/null 2>&1; then
      password="$(openssl rand -hex 16)"
    else
      password="$("$SOURCE_PYTHON_BIN" -c 'import secrets; print(secrets.token_hex(16))')"
    fi
    umask 077
    {
      echo "NMAPUI_DATA_DIR=${DATA_DIR}/data"
      echo "NMAPUI_LOG_DIR=${LOG_DIR}"
      echo "NMAPUI_HOST=127.0.0.1"
      echo "NMAPUI_PORT=9000"
      echo "NMAPUI_COOKIE_SECURE=false"
      echo "NMAPUI_STARTUP_TRACEROUTE=false"
      echo "NMAPUI_ENABLE_NETWORK_FINGERPRINT=false"
      echo "NMAPUI_ENABLE_UPDATE_CHECK=false"
      echo "NMAPUI_ENABLE_VULNERS=false"
      echo "NMAPUI_PRIVILEGED_ASSETS=${ASSET_DIR}"
      echo "PLAYWRIGHT_BROWSERS_PATH=${BROWSER_DIR}"
      echo "NMAPUI_USERNAME=admin"
      echo "NMAPUI_PASSWORD=${password}"
    } > "$CREDENTIALS_FILE"
    chmod 0600 "$CREDENTIALS_FILE"
    log "generated credentials at $CREDENTIALS_FILE (username: admin)"
    log "read the password with: sudo cat '$CREDENTIALS_FILE'"
  else
    log "reusing existing credentials at $CREDENTIALS_FILE"
    if ! grep -q '^NMAPUI_STARTUP_TRACEROUTE=' "$CREDENTIALS_FILE"; then
      echo 'NMAPUI_STARTUP_TRACEROUTE=false' >> "$CREDENTIALS_FILE"
    fi
    if ! grep -q '^PLAYWRIGHT_BROWSERS_PATH=' "$CREDENTIALS_FILE"; then
      echo "PLAYWRIGHT_BROWSERS_PATH=${BROWSER_DIR}" >> "$CREDENTIALS_FILE"
    fi
  fi
  "$SOURCE_PYTHON_BIN" "$SERVICE_ENV_CHECK_PATH" --file "$CREDENTIALS_FILE" \
    --data "$DATA_DIR/data" --log "$LOG_DIR" --browser "$BROWSER_DIR" \
    || die "service credentials do not match installer paths"
  mkdir -p "$DATA_DIR/data"
  chmod 0700 "$DATA_DIR/data"
  migrate_legacy_file "$SOURCE_ROOT_DIR/config/customers.yaml" "$DATA_DIR/data/customers.yaml"
  migrate_legacy_file "$SOURCE_ROOT_DIR/config/google_drive_credentials.json" "$DATA_DIR/data/google_drive_credentials.json"
  migrate_legacy_file "$SOURCE_ROOT_DIR/data/scan_history.json" "$DATA_DIR/data/scan_history.json"
  set_runtime_permissions

  log "staging root-owned runtime release"
  new_release="$(stage_release)"
  install -d -m 0755 -o root -g wheel "$ASSET_DIR" "$BROWSER_DIR"
  chmod 0755 "$ASSET_DIR" "$BROWSER_DIR"
  PLAYWRIGHT_BROWSERS_PATH="$BROWSER_DIR" \
    "$new_release/.venv/bin/python" -m playwright install chromium \
    || die "Chromium installation failed; install system dependencies and retry"

  # Back up the installed launcher/privilege boundary before touching it. The
  # release's scan assets are immutable, so switching back restores them too.
  INSTALL_BACKUP_DIR="$(mktemp -d)"
  INSTALL_MUTATED=0
  INSTALL_SWITCHED=0
  INSTALL_PREVIOUS_LINK_SWITCHED=0
  INSTALL_PREVIOUS_RELEASE="$previous_release"
  INSTALL_OLD_PREVIOUS_LINK="$old_previous_link"
  INSTALL_PREVIOUS_LOADED=0
  if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    INSTALL_PREVIOUS_LOADED=1
  fi
  trap 'rollback_failed_install "$?"' EXIT
  backup_installed_artifacts "$INSTALL_BACKUP_DIR"
  build_wrapper "$INSTALL_BACKUP_DIR/staged.wrapper"
  cp "$HELPER_SOURCE" "$INSTALL_BACKUP_DIR/staged.helper"
  build_sudoers "$INSTALL_BACKUP_DIR/staged.sudoers"
  validate_sudoers "$INSTALL_BACKUP_DIR/staged.sudoers"
  build_plist "$INSTALL_BACKUP_DIR/staged.plist"
  validate_plist "$INSTALL_BACKUP_DIR/staged.plist"
  save_release_artifacts "$new_release" \
    "$INSTALL_BACKUP_DIR/staged.wrapper" "$INSTALL_BACKUP_DIR/staged.helper" \
    "$INSTALL_BACKUP_DIR/staged.sudoers" "$INSTALL_BACKUP_DIR/staged.plist"
  verify_release_artifacts "$new_release"
  INSTALL_MUTATED=1
  if [[ "$INSTALL_PREVIOUS_LOADED" == 1 ]]; then
    INSTALL_SWITCHED=1
    launchctl bootout "system/${LABEL}" || die "could not stop the previous daemon"
  fi

  log "installing wrapper $WRAPPER_PATH"
  install -m 0755 -o root -g wheel "$new_release/service-artifacts/nmapui-run" "$WRAPPER_PATH"

  log "scan assets are pinned to $new_release/privileged-assets"

  log "installing privileged scanner helper $HELPER_PATH"
  [[ -f "$HELPER_SOURCE" ]] || die "helper source not found: $HELPER_SOURCE"
  install -d -m 0755 -o root -g wheel "$(dirname "$HELPER_PATH")"
  install -m 0755 -o root -g wheel "$new_release/service-artifacts/nmapui-privileged-scanner" "$HELPER_PATH"

  log "installing sudoers rule $SUDOERS_PATH"
  install -m 0440 -o root -g wheel "$new_release/service-artifacts/nmapui.sudoers" "$SUDOERS_PATH"

  log "installing LaunchDaemon $PLIST_PATH"
  install -m 0644 -o root -g wheel "$new_release/service-artifacts/${LABEL}.plist" "$PLIST_PATH"

  log "bootstrapping the daemon"
  INSTALL_SWITCHED=1
  switch_release "$new_release"
  launchctl bootstrap system "$PLIST_PATH"
  launchctl enable "system/${LABEL}"
  launchctl kickstart -k "system/${LABEL}"

  log "waiting for readiness..."
  local deadline=$((SECONDS + 120)) port host
  port="$(read_service_port)"
  host="$(read_service_host)"
  while (( SECONDS < deadline )); do
    if "$SOURCE_PYTHON_BIN" "$READY_CHECK_PATH" --release "$new_release" --port "$port" --host "$host"; then
      if [[ -n "$previous_release" ]]; then
        INSTALL_PREVIOUS_LINK_SWITCHED=1
        switch_managed_link "$PREVIOUS_LINK" "$previous_release"
      fi
      INSTALL_MUTATED=0
      trap - EXIT
      rm -rf "$INSTALL_BACKUP_DIR"
      log "NmapUI release $new_release is ready on $host:$port"
      return 0
    fi
    sleep 2
  done
  log "WARNING: server did not report ready within 120s; check $LOG_DIR/server.err.log"
  return 1
}

rollback_daemon() {
  require_root --rollback
  [[ -x "$SOURCE_PYTHON_BIN" ]] || die "virtualenv python not found: $SOURCE_PYTHON_BIN"
  verify_service_toolchain
  [[ -L "$ROOT_DIR" && -L "$PREVIOUS_LINK" ]] \
    || die "rollback requires current and previous release links"
  local current previous current_user previous_user port host deadline
  current="$(readlink "$ROOT_DIR")"
  previous="$(readlink "$PREVIOUS_LINK")"
  [[ -n "$current" && -n "$previous" && "$current" != "$previous" ]] \
    || die "no distinct previous release is available"
  validate_managed_release "$current"
  validate_managed_release "$previous"
  verify_installed_artifacts
  verify_release_artifacts "$current"
  verify_release_artifacts "$previous"
  current_user="$(read_plist_run_user "$PLIST_PATH")" || die "cannot read installed daemon user"
  previous_user="$(read_plist_run_user "$previous/service-artifacts/${LABEL}.plist")" \
    || die "cannot read previous daemon user"
  if [[ "$current_user" == root ]]; then
    "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" --verify-root-interpreter \
      || die "root rollback requires a root-owned Python interpreter"
  fi
  [[ "$current_user" == "$previous_user" ]] \
    || die "rollback changes daemon user; use a planned uninstall/reinstall"
  [[ -z "$RUN_USER" || "$RUN_USER" == "$current_user" ]] \
    || die "--user does not match the installed daemon user: $current_user"
  check_port_conflict

  INSTALL_BACKUP_DIR="$(mktemp -d)"
  INSTALL_MUTATED=0
  INSTALL_SWITCHED=0
  INSTALL_PREVIOUS_LINK_SWITCHED=0
  INSTALL_PREVIOUS_RELEASE="$current"
  INSTALL_OLD_PREVIOUS_LINK="$previous"
  INSTALL_PREVIOUS_LOADED=0
  if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    INSTALL_PREVIOUS_LOADED=1
  fi
  trap 'rollback_failed_install "$?"' EXIT
  backup_installed_artifacts "$INSTALL_BACKUP_DIR"
  INSTALL_MUTATED=1
  if [[ "$INSTALL_PREVIOUS_LOADED" == 1 ]]; then
    INSTALL_SWITCHED=1
    launchctl bootout "system/${LABEL}" || die "could not stop the current daemon"
  fi
  install -m 0755 -o root -g wheel "$previous/service-artifacts/nmapui-run" "$WRAPPER_PATH"
  install -m 0755 -o root -g wheel "$previous/service-artifacts/nmapui-privileged-scanner" "$HELPER_PATH"
  install -m 0440 -o root -g wheel "$previous/service-artifacts/nmapui.sudoers" "$SUDOERS_PATH"
  install -m 0644 -o root -g wheel "$previous/service-artifacts/${LABEL}.plist" "$PLIST_PATH"
  INSTALL_SWITCHED=1
  switch_release "$previous"
  launchctl bootstrap system "$PLIST_PATH"
  launchctl enable "system/${LABEL}"
  launchctl kickstart -k "system/${LABEL}"
  port="$(read_service_port)"
  host="$(read_service_host)"
  deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if "$SOURCE_PYTHON_BIN" "$READY_CHECK_PATH" --release "$previous" --port "$port" --host "$host"; then
      INSTALL_PREVIOUS_LINK_SWITCHED=1
      switch_managed_link "$PREVIOUS_LINK" "$current"
      INSTALL_MUTATED=0
      trap - EXIT
      rm -rf "$INSTALL_BACKUP_DIR"
      log "rolled back to $previous"
      return 0
    fi
    sleep 2
  done
  die "previous release did not become ready; see $LOG_DIR/server.err.log"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
case "$MODE" in
  dry-run) dry_run ;;
  rollback) rollback_daemon ;;
  uninstall) uninstall ;;
  install) install_daemon ;;
esac
fi
