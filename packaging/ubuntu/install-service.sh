#!/usr/bin/env bash
# Install the Flask scanner directly on an Ubuntu host as one systemd service.
# No containers or proxy networking: Nmap sees the host's real interfaces.
set -euo pipefail
SERVICE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH="$SERVICE_PATH"
NMAP_DATA_DIR=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOURCE_PYTHON_BIN="$SOURCE_ROOT_DIR/.venv/bin/python"
STAGER_PATH="$SOURCE_ROOT_DIR/packaging/stage_runtime.py"
READY_CHECK_PATH="$SOURCE_ROOT_DIR/packaging/check_release_ready.py"
SERVICE_ENV_CHECK_PATH="$SOURCE_ROOT_DIR/packaging/validate_service_env.py"
INSTALL_ROOT="/opt/nmapui"
RELEASES_DIR="$INSTALL_ROOT/releases"
CURRENT_LINK="$INSTALL_ROOT/current"
PREVIOUS_LINK="$INSTALL_ROOT/previous"
BROWSER_DIR="$INSTALL_ROOT/playwright-browsers"
DATA_DIR="/var/lib/nmapui"
LOG_DIR="/var/log/nmapui"
CONFIG_DIR="/etc/nmapui"
CREDENTIALS_FILE="$CONFIG_DIR/nmapui.env"
WRAPPER_PATH="/usr/local/bin/nmapui-run"
UNIT_PATH="/etc/systemd/system/nmapui.service"
SERVICE_NAME="nmapui.service"
MODE="install"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --uninstall) MODE="uninstall" ;;
    --rollback) MODE="rollback" ;;
    -h|--help)
      echo "Usage: $0 [--dry-run | --rollback | --uninstall]"
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '[nmapui-ubuntu] %s\n' "$*"; }
die() { printf '[nmapui-ubuntu] ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ "$(id -u)" == "0" ]] || die "run with sudo"; }

ensure_privacy_safe_egress_defaults() {
  local setting
  for setting in NMAPUI_ENABLE_NETWORK_FINGERPRINT NMAPUI_ENABLE_UPDATE_CHECK NMAPUI_ENABLE_VULNERS; do
    if ! grep -q "^$setting=" "$CREDENTIALS_FILE"; then
      printf '%s=false\n' "$setting" >> "$CREDENTIALS_FILE"
    fi
  done
}

check_source() {
  [[ -x "$SOURCE_PYTHON_BIN" ]] || die "missing virtualenv Python: $SOURCE_PYTHON_BIN"
  [[ -f "$SOURCE_ROOT_DIR/app.py" ]] || die "missing Flask app: $SOURCE_ROOT_DIR/app.py"
  [[ -f "$STAGER_PATH" ]] || die "missing runtime stager: $STAGER_PATH"
  [[ -f "$READY_CHECK_PATH" ]] || die "missing release readiness checker: $READY_CHECK_PATH"
  [[ -f "$SERVICE_ENV_CHECK_PATH" ]] || die "missing service env validator: $SERVICE_ENV_CHECK_PATH"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" --verify-root-interpreter \
    || die "root service requires a root-owned Python interpreter"
  "$SOURCE_PYTHON_BIN" -c 'import flask, flask_socketio, gunicorn, playwright, simple_websocket' \
    || die "install pinned requirements in the source virtualenv first"
  local tool tool_path
  for tool in nmap arp-scan xsltproc traceroute; do
    tool_path="$(command -v "$tool" || true)"
    [[ -n "$tool_path" ]] || die "$tool is required in the protected service PATH: $SERVICE_PATH"
    "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
      --verify-root-executable "$tool_path" \
      || die "$tool is not safe to execute as root: $tool_path"
    if [[ "$tool" == nmap ]]; then
      NMAP_DATA_DIR="$("$SOURCE_PYTHON_BIN" -c \
        'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve().parents[1] / "share/nmap")' "$tool_path")"
      "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
        --verify-root-nmap-data-dir "$NMAP_DATA_DIR" \
        || die "Nmap script/data files are not safe to load as root: $NMAP_DATA_DIR"
    fi
  done
}

build_wrapper() {
  local target="$1"
  {
    # systemd EnvironmentFile may contain PATH; do not let it select the shell
    # interpreter before the wrapper restores the protected service PATH.
    printf '%s\n' '#!/bin/bash' 'set -euo pipefail'
    printf 'app_root=%q\n' "$CURRENT_LINK"
    printf 'export PATH=%q\n' "$SERVICE_PATH"
    printf 'export NMAPUI_PRIVILEGED_ASSETS=%q\n' "$CURRENT_LINK/privileged-assets"
    if [[ -n "$NMAP_DATA_DIR" ]]; then
      printf 'export NMAPDIR=%q\n' "$NMAP_DATA_DIR"
    fi
    cat <<'WRAPPER'
port="${NMAPUI_PORT:-9000}"
if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
  echo "Invalid NMAPUI_PORT: $port" >&2
  exit 1
fi
bind_host="${NMAPUI_HOST:-127.0.0.1}"
if [[ "$bind_host" == *:* && "$bind_host" != \[*\] ]]; then
  bind_host="[$bind_host]"
fi
cd "$app_root"
exec "$app_root/.venv/bin/python" -m gunicorn \
  --bind "$bind_host:$port" \
  --workers 1 --threads 100 --timeout 180 --graceful-timeout 30 --no-control-socket \
  nmapui.wsgi:application
WRAPPER
  } > "$target"
  chmod 0755 "$target"
}

build_unit() {
  local target="$1"
  cat > "$target" <<UNIT
[Unit]
Description=NmapUI scanner service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$CURRENT_LINK
Environment="PATH=$SERVICE_PATH"
EnvironmentFile=$CREDENTIALS_FILE
ExecStart=$WRAPPER_PATH
Restart=always
RestartSec=10
KillMode=control-group
TimeoutStartSec=180
TimeoutStopSec=40
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$target"
}

switch_link() {
  local link="$1" target="$2" next="$INSTALL_ROOT/.nmapui-link-next.$$"
  [[ ! -e "$link" || -L "$link" ]] || die "refusing to replace non-symlink: $link"
  ln -s "$target" "$next"
  mv -Tf "$next" "$link"
}

dry_run() {
  check_source
  local stage
  stage="$(mktemp -d)"
  build_wrapper "$stage/nmapui-run"
  build_unit "$stage/nmapui.service"
  bash -n "$stage/nmapui-run"
  grep -q '^KillMode=control-group$' "$stage/nmapui.service" || die "unit must reap scan subprocesses"
  grep -q '^ProtectSystem=strict$' "$stage/nmapui.service" || die "unit must protect service code"
  log "wrapper, unit, Python requirements and scanner tools: OK"
  log "service root: $CURRENT_LINK"
  log "dry run complete; nothing was installed"
  rm -f "$stage/nmapui-run" "$stage/nmapui.service"
  rmdir "$stage"
}

migrate_legacy_file() {
  local source="$1" destination="$2"
  [[ ! -L "$destination" ]] || die "refusing symlinked runtime file: $destination"
  if [[ ! -e "$destination" && -f "$source" ]]; then
    install -m 0600 -o root -g root "$source" "$destination"
    log "preserved legacy runtime file at $destination"
  fi
}

prepare_state() {
  for path in "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"; do
    [[ ! -L "$path" ]] || die "refusing symlinked state path: $path"
    install -d -m 0700 -o root -g root "$path"
  done
  [[ ! -L "$CREDENTIALS_FILE" ]] || die "refusing symlinked credentials file"
  if [[ ! -f "$CREDENTIALS_FILE" ]]; then
    local password
    password="$("$SOURCE_PYTHON_BIN" -c 'import secrets; print(secrets.token_hex(24))')"
    umask 077
    {
      echo "NMAPUI_DATA_DIR=$DATA_DIR"
      echo "NMAPUI_LOG_DIR=$LOG_DIR"
      echo "NMAPUI_HOST=127.0.0.1"
      echo "NMAPUI_PORT=9000"
      echo "NMAPUI_COOKIE_SECURE=false"
      echo "NMAPUI_STARTUP_TRACEROUTE=false"
      echo "NMAPUI_ENABLE_NETWORK_FINGERPRINT=false"
      echo "NMAPUI_ENABLE_UPDATE_CHECK=false"
      echo "NMAPUI_ENABLE_VULNERS=false"
      echo "NMAPUI_USERNAME=admin"
      echo "NMAPUI_PASSWORD=$password"
      echo "PLAYWRIGHT_BROWSERS_PATH=$BROWSER_DIR"
    } > "$CREDENTIALS_FILE"
    log "generated credentials at $CREDENTIALS_FILE (username: admin)"
  fi
  ensure_privacy_safe_egress_defaults
  chown root:root "$CREDENTIALS_FILE"
  chmod 0600 "$CREDENTIALS_FILE"
  "$SOURCE_PYTHON_BIN" "$SERVICE_ENV_CHECK_PATH" --file "$CREDENTIALS_FILE" \
    --data "$DATA_DIR" --log "$LOG_DIR" --browser "$BROWSER_DIR" \
    || die "service credentials do not match systemd state paths"
  migrate_legacy_file "$SOURCE_ROOT_DIR/config/customers.yaml" "$DATA_DIR/customers.yaml"
  migrate_legacy_file "$SOURCE_ROOT_DIR/config/google_drive_credentials.json" "$DATA_DIR/google_drive_credentials.json"
  migrate_legacy_file "$SOURCE_ROOT_DIR/data/scan_history.json" "$DATA_DIR/scan_history.json"
}

stage_release() {
  local version release_path
  version="$(tr -d '\r\n' < "$SOURCE_ROOT_DIR/VERSION")"
  [[ "$version" =~ ^[A-Za-z0-9._-]+$ ]] || die "VERSION contains invalid release-path characters"
  install -d -m 0755 -o root -g root "$INSTALL_ROOT" "$RELEASES_DIR"
  chmod 0755 "$INSTALL_ROOT" "$RELEASES_DIR"
  release_path="$RELEASES_DIR/${version}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" \
    --source "$SOURCE_ROOT_DIR" --destination "$release_path"
  "$release_path/.venv/bin/python" -m compileall -q \
    "$release_path/app.py" "$release_path/nmapui" \
    || die "staged runtime failed syntax validation: $release_path"
  printf '%s\n' "$release_path"
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

wait_ready() {
  local release="$1" deadline=$((SECONDS + ${2:-180})) port host substate
  port="$(read_service_port)" || return 1
  host="$(read_service_host)"
  while (( SECONDS < deadline )); do
    if systemctl is-active --quiet "$SERVICE_NAME" && \
      "$SOURCE_PYTHON_BIN" "$READY_CHECK_PATH" --release "$release" --port "$port" --host "$host"; then
      return 0
    fi
    substate="$(systemctl show --property=SubState --value "$SERVICE_NAME" 2>/dev/null || true)"
    if [[ "$substate" == "failed" || "$substate" == "auto-restart" ]]; then
      return 1
    fi
    sleep 2
  done
  return 1
}

backup_service_files() {
  local backup_dir="$1" index path
  local paths=("$WRAPPER_PATH" "$UNIT_PATH")
  for index in "${!paths[@]}"; do
    path="${paths[$index]}"
    [[ ! -L "$path" ]] || die "refusing symlinked installed service file: $path"
    if [[ -e "$path" ]]; then
      [[ -f "$path" ]] || die "refusing non-file installed service path: $path"
      cp -p "$path" "$backup_dir/$index"
    else
      touch "$backup_dir/$index.absent"
    fi
  done
}

verify_installed_service_files() {
  [[ -f "$WRAPPER_PATH" && ! -L "$WRAPPER_PATH" && -f "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] \
    || die "installed launcher and unit must be regular files"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
    --verify-root-executable "$WRAPPER_PATH" --verify-root-file "$UNIT_PATH" \
    || die "installed launcher or unit is not protected"
}

restore_service_files() {
  local backup_dir="$1" index path failed=0
  local paths=("$WRAPPER_PATH" "$UNIT_PATH")
  for index in "${!paths[@]}"; do
    path="${paths[$index]}"
    rm -f "$path" || failed=1
    if [[ -f "$backup_dir/$index" ]]; then
      cp -p "$backup_dir/$index" "$path" || failed=1
    fi
  done
  return "$failed"
}

verify_release_service_files() {
  local release="$1" artifact_dir="$1/service-artifacts"
  [[ -d "$artifact_dir" && ! -L "$artifact_dir" ]] \
    || die "release service artifacts are missing or symlinked: $artifact_dir"
  [[ ! -L "$artifact_dir/nmapui-run" && ! -L "$artifact_dir/nmapui.service" ]] \
    || die "release service files cannot be symlinks: $artifact_dir"
  "$SOURCE_PYTHON_BIN" "$STAGER_PATH" --source "$SOURCE_ROOT_DIR" \
    --verify-root-executable "$artifact_dir/nmapui-run" \
    --verify-root-file "$artifact_dir/nmapui.service" \
    || die "release service files are missing or not root-owned: $release"
}

save_release_service_files() {
  local release="$1" wrapper="$2" unit="$3" artifact_dir="$1/service-artifacts"
  local temporary_dir="$release/.service-artifacts.$$"
  [[ ! -e "$artifact_dir" && ! -L "$artifact_dir" ]] \
    || die "refusing to overwrite release service artifacts: $artifact_dir"
  [[ ! -e "$temporary_dir" && ! -L "$temporary_dir" ]] \
    || die "refusing to reuse temporary release service artifacts: $temporary_dir"
  install -d -m 0755 -o root -g root "$temporary_dir"
  install -m 0755 -o root -g root "$wrapper" "$temporary_dir/nmapui-run"
  install -m 0644 -o root -g root "$unit" "$temporary_dir/nmapui.service"
  mv -T "$temporary_dir" "$artifact_dir"
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

rollback_failed_install() {
  local status="$1" restore_failed=0
  trap - EXIT
  set +e
  if [[ "${INSTALL_MUTATED:-0}" == 1 ]]; then
    log "restoring previous systemd deployment after unsuccessful change"
    if [[ "${INSTALL_SWITCHED:-0}" == 1 ]]; then
      systemctl stop "$SERVICE_NAME" || restore_failed=1
    fi
    restore_service_files "$INSTALL_BACKUP_DIR" || restore_failed=1
    if [[ "${INSTALL_SWITCHED:-0}" == 1 ]]; then
      if [[ -n "${INSTALL_OLD_RELEASE:-}" ]]; then
        switch_link "$CURRENT_LINK" "$INSTALL_OLD_RELEASE" || restore_failed=1
      else
        rm -f "$CURRENT_LINK" || restore_failed=1
      fi
    fi
    if [[ "${INSTALL_PREVIOUS_SWITCHED:-0}" == 1 ]]; then
      if [[ -n "${INSTALL_OLD_PREVIOUS:-}" ]]; then
        switch_link "$PREVIOUS_LINK" "$INSTALL_OLD_PREVIOUS" || restore_failed=1
      else
        rm -f "$PREVIOUS_LINK" || restore_failed=1
      fi
    fi
    systemctl daemon-reload || restore_failed=1
    if [[ "${INSTALL_OLD_ENABLED:-0}" == 1 ]]; then
      systemctl enable "$SERVICE_NAME" || restore_failed=1
    else
      systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    if [[ "${INSTALL_OLD_ACTIVE:-0}" == 1 ]]; then
      if systemctl start "$SERVICE_NAME"; then
        if [[ -n "${INSTALL_OLD_RELEASE:-}" ]]; then
          wait_ready "$INSTALL_OLD_RELEASE" 60 || restore_failed=1
        fi
      else
        restore_failed=1
      fi
    else
      systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "${INSTALL_BACKUP_DIR:-}" && -d "$INSTALL_BACKUP_DIR" ]]; then
    rm -rf "$INSTALL_BACKUP_DIR"
  fi
  if [[ "$restore_failed" == 1 ]]; then
    log "ERROR: automatic restoration was incomplete; inspect $UNIT_PATH and $CURRENT_LINK"
  fi
  exit "$status"
}

install_service() {
  require_root
  [[ -f /etc/os-release ]] || die "cannot identify Ubuntu host"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "this installer supports Ubuntu only"
  check_source
  command -v systemctl >/dev/null || die "systemd is required"
  prepare_state

  local old_release old_previous new_release
  [[ ! -e "$CURRENT_LINK" || -L "$CURRENT_LINK" ]] || die "refusing non-symlink current release: $CURRENT_LINK"
  [[ ! -e "$PREVIOUS_LINK" || -L "$PREVIOUS_LINK" ]] || die "refusing non-symlink previous release: $PREVIOUS_LINK"
  old_release="$(readlink "$CURRENT_LINK" 2>/dev/null || true)"
  old_previous="$(readlink "$PREVIOUS_LINK" 2>/dev/null || true)"
  if [[ -n "$old_release" ]]; then
    validate_managed_release "$old_release"
    verify_installed_service_files
    if [[ ! -d "$old_release/service-artifacts" ]]; then
      save_release_service_files "$old_release" "$WRAPPER_PATH" "$UNIT_PATH"
    fi
    verify_release_service_files "$old_release"
  else
    [[ ! -e "$WRAPPER_PATH" && ! -L "$WRAPPER_PATH" && ! -e "$UNIT_PATH" && ! -L "$UNIT_PATH" ]] \
      || die "existing service files have no managed current release"
    if systemctl is-active --quiet "$SERVICE_NAME" || systemctl is-enabled --quiet "$SERVICE_NAME"; then
      die "existing service has no managed current release"
    fi
  fi
  [[ -z "$old_previous" ]] || validate_managed_release "$old_previous"
  new_release="$(stage_release)"
  install -d -m 0755 -o root -g root "$INSTALL_ROOT" "$BROWSER_DIR"
  chmod 0755 "$INSTALL_ROOT" "$BROWSER_DIR"
  PLAYWRIGHT_BROWSERS_PATH="$BROWSER_DIR" \
    "$new_release/.venv/bin/python" -m playwright install chromium \
    || die "Chromium installation failed; install system dependencies and retry"

  INSTALL_BACKUP_DIR="$(mktemp -d)"
  INSTALL_MUTATED=0
  INSTALL_SWITCHED=0
  INSTALL_PREVIOUS_SWITCHED=0
  INSTALL_OLD_RELEASE="$old_release"
  INSTALL_OLD_PREVIOUS="$old_previous"
  INSTALL_OLD_ACTIVE=0
  INSTALL_OLD_ENABLED=0
  if systemctl is-active --quiet "$SERVICE_NAME"; then INSTALL_OLD_ACTIVE=1; fi
  if systemctl is-enabled --quiet "$SERVICE_NAME"; then INSTALL_OLD_ENABLED=1; fi
  trap 'rollback_failed_install "$?"' EXIT
  backup_service_files "$INSTALL_BACKUP_DIR"
  build_wrapper "$INSTALL_BACKUP_DIR/staged.wrapper"
  build_unit "$INSTALL_BACKUP_DIR/staged.service"
  save_release_service_files "$new_release" "$INSTALL_BACKUP_DIR/staged.wrapper" "$INSTALL_BACKUP_DIR/staged.service"
  verify_release_service_files "$new_release"

  INSTALL_MUTATED=1
  if [[ "$INSTALL_OLD_ACTIVE" == 1 ]]; then
    systemctl stop "$SERVICE_NAME" || die "could not stop the previous service"
  fi
  install -m 0755 -o root -g root "$new_release/service-artifacts/nmapui-run" "$WRAPPER_PATH"
  install -m 0644 -o root -g root "$new_release/service-artifacts/nmapui.service" "$UNIT_PATH"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  INSTALL_SWITCHED=1
  switch_link "$CURRENT_LINK" "$new_release"
  systemctl start "$SERVICE_NAME" || die "new release did not start"
  wait_ready "$new_release" || die "new release did not become ready; see journalctl -u $SERVICE_NAME -n 100"
  if [[ -n "$old_release" ]]; then
    INSTALL_PREVIOUS_SWITCHED=1
    switch_link "$PREVIOUS_LINK" "$old_release"
  fi
  INSTALL_MUTATED=0
  trap - EXIT
  rm -rf "$INSTALL_BACKUP_DIR"
  log "NmapUI is ready on $(read_service_host):$(read_service_port)"
  log "current release: $new_release"
}

rollback() {
  require_root
  local previous current
  [[ -L "$PREVIOUS_LINK" && -L "$CURRENT_LINK" ]] \
    || die "rollback requires current and previous release links"
  previous="$(readlink "$PREVIOUS_LINK" 2>/dev/null || true)"
  current="$(readlink "$CURRENT_LINK" 2>/dev/null || true)"
  [[ -n "$previous" && -n "$current" && "$previous" != "$current" ]] \
    || die "no distinct previous release is available"
  validate_managed_release "$previous"
  validate_managed_release "$current"
  verify_release_service_files "$previous"
  verify_release_service_files "$current"
  verify_installed_service_files

  INSTALL_BACKUP_DIR="$(mktemp -d)"
  INSTALL_MUTATED=0
  INSTALL_SWITCHED=0
  INSTALL_PREVIOUS_SWITCHED=0
  INSTALL_OLD_RELEASE="$current"
  INSTALL_OLD_PREVIOUS="$previous"
  INSTALL_OLD_ACTIVE=0
  INSTALL_OLD_ENABLED=0
  if systemctl is-active --quiet "$SERVICE_NAME"; then INSTALL_OLD_ACTIVE=1; fi
  if systemctl is-enabled --quiet "$SERVICE_NAME"; then INSTALL_OLD_ENABLED=1; fi
  trap 'rollback_failed_install "$?"' EXIT
  backup_service_files "$INSTALL_BACKUP_DIR"

  INSTALL_MUTATED=1
  if [[ "$INSTALL_OLD_ACTIVE" == 1 ]]; then
    systemctl stop "$SERVICE_NAME" || die "could not stop the current service"
  fi
  install -m 0755 -o root -g root "$previous/service-artifacts/nmapui-run" "$WRAPPER_PATH"
  install -m 0644 -o root -g root "$previous/service-artifacts/nmapui.service" "$UNIT_PATH"
  systemctl daemon-reload
  INSTALL_SWITCHED=1
  switch_link "$CURRENT_LINK" "$previous"
  systemctl start "$SERVICE_NAME" || die "previous release did not start"
  wait_ready "$previous" || die "previous release did not become ready"
  INSTALL_PREVIOUS_SWITCHED=1
  switch_link "$PREVIOUS_LINK" "$current"
  INSTALL_MUTATED=0
  trap - EXIT
  rm -rf "$INSTALL_BACKUP_DIR"
  log "rolled back to $previous"
}

uninstall_service() {
  require_root
  [[ ! -e "$CURRENT_LINK" || -L "$CURRENT_LINK" ]] \
    || die "refusing non-symlink current release: $CURRENT_LINK"
  [[ ! -e "$PREVIOUS_LINK" || -L "$PREVIOUS_LINK" ]] \
    || die "refusing non-symlink previous release: $PREVIOUS_LINK"
  if [[ ! -L "$CURRENT_LINK" && ! -L "$PREVIOUS_LINK" && \
        ! -e "$UNIT_PATH" && ! -L "$UNIT_PATH" && \
        ! -e "$WRAPPER_PATH" && ! -L "$WRAPPER_PATH" ]]; then
    if systemctl is-active --quiet "$SERVICE_NAME" || systemctl is-enabled --quiet "$SERVICE_NAME"; then
      die "systemd reports an unmanaged NmapUI service"
    fi
    log "NmapUI service is already absent; preserved data and release archives"
    return 0
  fi
  [[ -L "$CURRENT_LINK" ]] || die "cannot uninstall service files without a managed current release"
  validate_managed_release "$(readlink "$CURRENT_LINK")"
  if [[ -L "$PREVIOUS_LINK" ]]; then
    validate_managed_release "$(readlink "$PREVIOUS_LINK")"
  fi
  verify_installed_service_files
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl stop "$SERVICE_NAME" || die "could not stop service; no files removed"
  fi
  if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    systemctl disable "$SERVICE_NAME" || die "could not disable service; no files removed"
  fi
  rm -f "$UNIT_PATH" "$WRAPPER_PATH" "$CURRENT_LINK" "$PREVIOUS_LINK"
  systemctl daemon-reload
  log "removed systemd unit and launcher"
  log "data, credentials, logs and rollback releases are preserved"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "$MODE" in
    dry-run) dry_run ;;
    install) install_service ;;
    rollback) rollback ;;
    uninstall) uninstall_service ;;
  esac
fi
