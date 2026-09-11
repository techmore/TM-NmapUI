#!/bin/bash

# Build script for the NmapUI macOS wrapper
# Builds the Swift application bundle and opens it

# Runtime cleanup below is scoped to the build and installation destinations.
# A test build must not terminate other installed copies of the application.

# Set variables
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
PACKAGING_DIR="$ROOT_DIR/packaging/macos"
SRC="$PACKAGING_DIR/NmapUIMenuBarLauncher.swift"
BUILD_DIR="$ROOT_DIR/.build"
BIN="$BUILD_DIR/NmapUI"
APP_NAME="$ROOT_DIR/NmapUI.app"
SYSTEM_APPLICATIONS_DIR="/Applications"
USER_APPLICATIONS_DIR="$HOME/Applications"
BUNDLE_VENV="$APP_NAME/Contents/Resources/.venv"
BUNDLE_PLAYWRIGHT_BROWSERS="$APP_NAME/Contents/Resources/playwright-browsers"
GOOGLE_DRIVE_CREDENTIALS_SOURCE="$ROOT_DIR/config/google_drive_credentials.json"
GOOGLE_DRIVE_CREDENTIALS_BUNDLE="$APP_NAME/Contents/Resources/config/google_drive_credentials.json"
RUNTIME_SUPPORT_DIR="${NMAPUI_SUPPORT_DIR:-$HOME/Library/Application Support/NmapUI}"
RUNTIME_DATA_DIR="${NMAPUI_DATA_DIR:-$RUNTIME_SUPPORT_DIR/data}"
RUNTIME_LOG_DIR="${NMAPUI_LOG_DIR:-$RUNTIME_SUPPORT_DIR/logs}"
TEMP_MIGRATION_DB=""
SDK=$(xcrun --show-sdk-path --sdk macosx)
HOST_ARCH="$(uname -m)"
APP_VERSION="$(tr -d '\r\n' < "$ROOT_DIR/VERSION")"

if [[ -z "$APP_VERSION" ]]; then
    echo "ERROR: VERSION file is empty" >&2
    exit 1
fi

if [[ -n "${NMAPUI_SWIFT_TARGET:-}" ]]; then
    SWIFT_TARGET="$NMAPUI_SWIFT_TARGET"
elif [[ "$HOST_ARCH" == "arm64" ]]; then
    SWIFT_TARGET="arm64-apple-macosx13.0"
elif [[ "$HOST_ARCH" == "x86_64" ]]; then
    SWIFT_TARGET="x86_64-apple-macosx13.0"
else
    echo "ERROR: Unsupported macOS architecture: $HOST_ARCH" >&2
    echo "Set NMAPUI_SWIFT_TARGET explicitly if you know the correct target." >&2
    exit 1
fi

if [[ -n "${NMAPUI_APPLICATIONS_DIR:-}" ]]; then
    APP_INSTALL_DIR="$NMAPUI_APPLICATIONS_DIR"
elif [[ -d "$SYSTEM_APPLICATIONS_DIR" && -w "$SYSTEM_APPLICATIONS_DIR" ]]; then
    APP_INSTALL_DIR="$SYSTEM_APPLICATIONS_DIR"
else
    APP_INSTALL_DIR="$USER_APPLICATIONS_DIR"
fi

INSTALLED_APP_NAME="$APP_INSTALL_DIR/NmapUI.app"
INSTALLED_RUNTIME_DB="$RUNTIME_DATA_DIR/runtime.sqlite3"
if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    if [[ -n "${NMAPUI_MIGRATE_DB_FROM:-}" ]]; then
        MIGRATION_SOURCE_DB="$NMAPUI_MIGRATE_DB_FROM"
    else
        MIGRATION_SOURCE_DB="$INSTALLED_RUNTIME_DB"
    fi
fi

if [[ ! -f "$SRC" ]]; then
    echo "ERROR: Wrapper source file not found: $SRC"
    exit 1
fi

RUNTIME_PID_FILE_REL="Contents/Resources/nmapui-runtime.pid"
SHUTDOWN_MARKER_REL="Contents/Resources/nmapui-shutdown"
AUTO_SCAN_LOCK_REL="Contents/Resources/data/auto_scan_scheduler.lock"

shell_escape() {
    printf "'%s'" "${1//\'/\'\"\'\"\'}"
}

applescript_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

kill_runtime_tree() {
    local bundle_path="$1"
    local pid_file="$bundle_path/$RUNTIME_PID_FILE_REL"
    local shutdown_marker="$bundle_path/$SHUTDOWN_MARKER_REL"
    local resource_root="$bundle_path/Contents/Resources"
    local run_script="$resource_root/run.sh"

    kill_tree() {
        local target_pid="$1"
        if [[ -z "$target_pid" ]]; then
            return
        fi
        local child_pid
        while IFS= read -r child_pid; do
            [[ -z "$child_pid" ]] && continue
            kill_tree "$child_pid"
        done < <(/usr/bin/pgrep -P "$target_pid" 2>/dev/null || true)
        /bin/kill -TERM "$target_pid" 2>/dev/null || true
    }

    force_kill_tree() {
        local target_pid="$1"
        if [[ -z "$target_pid" ]]; then
            return
        fi
        local child_pid
        while IFS= read -r child_pid; do
            [[ -z "$child_pid" ]] && continue
            force_kill_tree "$child_pid"
        done < <(/usr/bin/pgrep -P "$target_pid" 2>/dev/null || true)
        /bin/kill -KILL "$target_pid" 2>/dev/null || true
    }

    /usr/bin/touch "$shutdown_marker" 2>/dev/null || true
    if [[ -f "$pid_file" ]]; then
        local target_pid
        target_pid="$(/bin/cat "$pid_file" 2>/dev/null | /usr/bin/tr -cd '0-9')"
        if [[ -n "$target_pid" ]]; then
            kill_tree "$target_pid"
            /bin/sleep 2
            force_kill_tree "$target_pid"
        fi
    fi
    /usr/bin/pkill -TERM -f "$run_script" 2>/dev/null || true
    /usr/bin/pkill -TERM -f "$resource_root/app.py" 2>/dev/null || true
    /usr/bin/pkill -TERM -f "$resource_root/.venv/bin/python3" 2>/dev/null || true
    /bin/sleep 1
    /usr/bin/pkill -KILL -f "$run_script" 2>/dev/null || true
    /usr/bin/pkill -KILL -f "$resource_root/app.py" 2>/dev/null || true
    /usr/bin/pkill -KILL -f "$resource_root/.venv/bin/python3" 2>/dev/null || true
    /bin/rm -f "$pid_file" "$shutdown_marker" "$bundle_path/$AUTO_SCAN_LOCK_REL" "$RUNTIME_DATA_DIR/auto_scan_scheduler.lock" 2>/dev/null || true
}

purge_bundle_artifacts() {
    local bundle_path="$1"
    [[ -z "$bundle_path" ]] && return
    kill_runtime_tree "$bundle_path"
}

remove_bundle_path() {
    local bundle_path="$1"
    [[ -z "$bundle_path" ]] && return

    rm -rf "$bundle_path" 2>/dev/null || true
    if [[ ! -e "$bundle_path" ]]; then
        return
    fi

    if ! command -v osascript >/dev/null 2>&1; then
        echo "ERROR: Unable to remove existing app bundle without osascript: $bundle_path" >&2
        exit 1
    fi

    echo "Existing app bundle at $bundle_path requires administrator privileges to remove."
    local shell_command
    shell_command="rm -rf $(shell_escape "$bundle_path")"
    if ! /usr/bin/osascript -e "do shell script \"$(applescript_escape "$shell_command")\" with administrator privileges"; then
        echo "ERROR: Failed to remove existing app bundle: $bundle_path" >&2
        exit 1
    fi

    if [[ -e "$bundle_path" ]]; then
        echo "ERROR: Existing app bundle still present after privileged removal: $bundle_path" >&2
        exit 1
    fi
}

stage_google_drive_credentials() {
    mkdir -p "$(dirname "$GOOGLE_DRIVE_CREDENTIALS_BUNDLE")"

    if [[ -f "$GOOGLE_DRIVE_CREDENTIALS_SOURCE" ]]; then
        cp "$GOOGLE_DRIVE_CREDENTIALS_SOURCE" "$GOOGLE_DRIVE_CREDENTIALS_BUNDLE"
        chmod 600 "$GOOGLE_DRIVE_CREDENTIALS_BUNDLE" 2>/dev/null || true
        echo "Bundled Google Drive OAuth credentials from $GOOGLE_DRIVE_CREDENTIALS_SOURCE"
        return
    fi

    if [[ -n "${NMAPUI_GOOGLE_DRIVE_CREDENTIALS_JSON_B64:-}" ]]; then
        if ! printf '%s' "$NMAPUI_GOOGLE_DRIVE_CREDENTIALS_JSON_B64" | base64 --decode > "$GOOGLE_DRIVE_CREDENTIALS_BUNDLE"; then
            echo "ERROR: Failed to decode NMAPUI_GOOGLE_DRIVE_CREDENTIALS_JSON_B64" >&2
            exit 1
        fi
        chmod 600 "$GOOGLE_DRIVE_CREDENTIALS_BUNDLE" 2>/dev/null || true
        echo "Bundled Google Drive OAuth credentials from NMAPUI_GOOGLE_DRIVE_CREDENTIALS_JSON_B64"
        return
    fi

    rm -f "$GOOGLE_DRIVE_CREDENTIALS_BUNDLE"

    if [[ "${NMAPUI_REQUIRE_GOOGLE_DRIVE_CREDENTIALS:-0}" == "1" ]]; then
        echo "ERROR: Google Drive OAuth credentials are missing." >&2
        echo "Provide $GOOGLE_DRIVE_CREDENTIALS_SOURCE or NMAPUI_GOOGLE_DRIVE_CREDENTIALS_JSON_B64 before building." >&2
        exit 1
    fi

    echo "WARNING: Google Drive OAuth credentials are missing from this build."
    echo "WARNING: Google Drive sync will require importing credentials.json from Settings after install."
}

# Ensure build output doesn't collide with the nmapui package on case-insensitive filesystems.
echo "Purging stale runtime state and build artifacts..."
purge_bundle_artifacts "$APP_NAME"
purge_bundle_artifacts "$INSTALLED_APP_NAME"
rm -rf "$BUILD_DIR"
rm -rf "$APP_NAME"
mkdir -p "$BUILD_DIR"

# Run install.sh if .venv doesn't exist yet
if [[ ! -d "$ROOT_DIR/.venv" && ! -d "$ROOT_DIR/venv" ]]; then
    echo "No virtual environment found — running install.sh first..."
    bash "$ROOT_DIR/install.sh" --no-daemon || { echo "install.sh failed"; exit 1; }
fi

echo "Building NmapUI macOS wrapper..."
echo "Source: $SRC"
echo "SDK: $SDK"
echo "Host architecture: $HOST_ARCH"
echo "Target: $SWIFT_TARGET"
echo "Install destination: $INSTALLED_APP_NAME"

if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    echo "Database migration enabled"
    echo "Database migration source: $MIGRATION_SOURCE_DB"
fi

# The Swift compiler outputs a binary at $BIN. If a file or directory exists there
# (from a previous build or manual artifact), it will cause compilation to fail.
if [[ -e "$BIN" ]]; then
    echo "Removing conflicting build output at $BIN"
    rm -rf "$BIN"
fi

# Compile the Swift binary using the requested format
swiftc \
  -sdk "$SDK" \
  -target "$SWIFT_TARGET" \
  -framework AppKit \
  "$SRC" \
  -o "$BIN"

# Check if compilation succeeded
if [[ $? -ne 0 ]]; then
    echo "Compilation failed!"
    exit 1
fi

echo "Compilation successful!"

# Create the app bundle structure
echo "Creating application bundle..."

# Remove existing app bundle if any
rm -rf "$APP_NAME"

# Create the directory structure
mkdir -p "$APP_NAME/Contents/MacOS"
mkdir -p "$APP_NAME/Contents/Resources"

# Copy the binary to the MacOS folder
cp "$BIN" "$APP_NAME/Contents/MacOS/"

# Copy the icon to Resources folder if it exists
if [[ -f "$PACKAGING_DIR/icon.jpg" ]]; then
    cp "$PACKAGING_DIR/icon.jpg" "$APP_NAME/Contents/Resources/icon.jpg"
    echo "Icon copied to resources"
else
    echo "Warning: icon.jpg not found, using default icon"
fi

echo "Copying NmapUI Python application and resources from the current workspace..."
ROOT_RUNTIME_PY=(
  app.py
  customer_fingerprint.py
  customer_fingerprint_matcher.py
  customer_fingerprint_store.py
  persistence.py
)
VULNERS_RUNTIME_FILES=(
  nmap-vulners/LICENSE
  nmap-vulners/vulners.nse
  nmap-vulners/http-vulners-regex.nse
  nmap-vulners/http-vulners-regex.json
  nmap-vulners/http-vulners-paths.txt
)
tar -cf - \
  "${ROOT_RUNTIME_PY[@]}" \
  "${VULNERS_RUNTIME_FILES[@]}" \
  nmapui \
  templates \
  static \
  scripts \
  config \
  requirements.txt \
  VERSION \
  AGENTS.md \
  nmap-modern.xsl \
  nmap-pdf-olive-legacy.xsl | tar -xf - -C "$APP_NAME/Contents/Resources"

APP_RESOURCES_DIR="$APP_NAME/Contents/Resources"
APP_VERSION_VALUE="$(cat "$ROOT_DIR/VERSION" 2>/dev/null || echo "unknown")"
APP_GIT_SHA="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
APP_BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "$APP_RESOURCES_DIR/build_info.json" << EOF
{
  "version": "$APP_VERSION_VALUE",
  "git_sha": "$APP_GIT_SHA",
  "built_at": "$APP_BUILD_TIME"
}
EOF

stage_google_drive_credentials

echo "Creating clean bundled virtual environment..."
python3 -m venv "$BUNDLE_VENV"
source "$BUNDLE_VENV/bin/activate"
python -m pip install --upgrade pip
PIP_DISABLE_PIP_VERSION_CHECK=1 python -m pip install -r "$APP_NAME/Contents/Resources/requirements.txt"
echo "Installing bundled Playwright Chromium browser..."
PLAYWRIGHT_BROWSERS_PATH="$BUNDLE_PLAYWRIGHT_BROWSERS" python -m playwright install chromium
deactivate
echo "Bundled virtual environment and Playwright browser created from current workspace requirements.txt."

# Create a run script that activates the bundled venv and runs the app.
# Dependencies must already be installed in the venv — runtime pip installs
# are not supported in packaged builds (network dependency, supply-chain risk).
cat > "$APP_NAME/Contents/Resources/run.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

VENV_ACTIVATE=".venv/bin/activate"
PID_FILE="$(pwd)/nmapui-runtime.pid"
SHUTDOWN_MARKER="$(pwd)/nmapui-shutdown"

if [[ ! -f "$VENV_ACTIVATE" ]]; then
    echo "ERROR: Virtual environment not found inside app bundle." >&2
    echo "Rebuild the app bundle with install.sh completed first." >&2
    exit 1
fi

/bin/rm -f "$SHUTDOWN_MARKER"
/bin/echo "$$" > "$PID_FILE"

source "$VENV_ACTIVATE"
CONSOLE_USER="$(stat -f%Su /dev/console 2>/dev/null || true)"
USER_HOME=""
if [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" ]]; then
    USER_HOME="$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}' | tail -1)"
fi
if [[ -z "$USER_HOME" ]]; then
    USER_HOME="$HOME"
fi
export NMAPUI_DATA_DIR="${NMAPUI_DATA_DIR:-$USER_HOME/Library/Application Support/NmapUI/data}"
export NMAPUI_LOG_DIR="${NMAPUI_LOG_DIR:-$USER_HOME/Library/Application Support/NmapUI/logs}"
mkdir -p "$NMAPUI_DATA_DIR" "$NMAPUI_LOG_DIR"
export PLAYWRIGHT_BROWSERS_PATH="$(pwd)/playwright-browsers"

# The menu bar wrapper runs a local embedded Flask-SocketIO server rather than
# a separate production WSGI stack, so allow Werkzeug explicitly for this
# packaged desktop entrypoint.
export NMAPUI_ALLOW_UNSAFE_WERKZEUG=true

# The UI requires sign-in. Reuse the appliance credentials when the
# LaunchDaemon installer created them, otherwise generate a per-install
# password stored 0600 in the data dir. The old NMAPUI_TRUST_LOCAL_UI bypass
# is deliberately not set: it made every loopback process fully trusted.
CREDENTIALS_FILE="$NMAPUI_DATA_DIR/credentials.env"
if [[ -f "$CREDENTIALS_FILE" ]]; then
    NMAPUI_USERNAME="${NMAPUI_USERNAME:-$(awk -F= '/^NMAPUI_USERNAME=/{print $2; exit}' "$CREDENTIALS_FILE")}"
    NMAPUI_PASSWORD="${NMAPUI_PASSWORD:-$(awk -F= '/^NMAPUI_PASSWORD=/{print $2; exit}' "$CREDENTIALS_FILE")}"
    export NMAPUI_USERNAME NMAPUI_PASSWORD
fi
if [[ -z "${NMAPUI_USERNAME:-}" || -z "${NMAPUI_PASSWORD:-}" ]]; then
    GENERATED_PASSWORD="$(openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(16))')"
    export NMAPUI_USERNAME="${NMAPUI_USERNAME:-admin}"
    export NMAPUI_PASSWORD="${NMAPUI_PASSWORD:-$GENERATED_PASSWORD}"
    OLD_UMASK="$(umask)"
    umask 077
    {
        echo "NMAPUI_USERNAME=$NMAPUI_USERNAME"
        echo "NMAPUI_PASSWORD=$NMAPUI_PASSWORD"
    } > "$CREDENTIALS_FILE"
    umask "$OLD_UMASK"
    echo "NmapUI sign-in generated; username: $NMAPUI_USERNAME (password in $CREDENTIALS_FILE)"
fi

# Run the NmapUI application
exec python3 app.py
EOF

chmod +x "$APP_NAME/Contents/Resources/run.sh"

echo "Resources copied successfully!"

# Create the Info.plist file
cat > "$APP_NAME/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>NmapUI</string>
    <key>CFBundleDisplayName</key>
    <string>NmapUI</string>
    <key>CFBundleIdentifier</key>
    <string>com.techmore.nmapui</string>
    <key>CFBundleVersion</key>
    <string>$APP_VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$APP_VERSION</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>LSUIElement</key>
    <true/>
    <key>CFBundleIconFile</key>
    <string>icon.jpg</string>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 TechMore. All rights reserved.</string>
</dict>
</plist>
EOF

echo "Application bundle created: $APP_NAME"

# Make the binary executable
chmod +x "$APP_NAME/Contents/MacOS/NmapUI"

# Ad-hoc code sign to satisfy macOS Gatekeeper on locally built bundles.
# This prevents "cannot be opened because Apple cannot check it for malicious
# software" dialogs without requiring a paid Apple Developer account.
# For distribution, replace '-' with a Developer ID Application certificate.
echo "Code signing the application bundle..."
if codesign --force --deep --sign - "$APP_NAME" 2>/dev/null; then
    echo "Code signing successful."
else
    echo "Warning: codesign failed — Gatekeeper may block the app on first launch."
    echo "  Workaround: xattr -d com.apple.quarantine \"$APP_NAME\""
fi

if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    if [[ ! -f "$MIGRATION_SOURCE_DB" ]]; then
        echo "ERROR: Database migration source not found: $MIGRATION_SOURCE_DB" >&2
        exit 1
    fi
    TEMP_MIGRATION_DB="$(mktemp "${TMPDIR:-/tmp}/nmapui-runtime-db.XXXXXX.sqlite3")"
    cp "$MIGRATION_SOURCE_DB" "$TEMP_MIGRATION_DB"
    echo "Captured runtime database for migration: $TEMP_MIGRATION_DB"
fi

echo "Installing application bundle..."
mkdir -p "$APP_INSTALL_DIR"
remove_bundle_path "$INSTALLED_APP_NAME"
ditto "$APP_NAME" "$INSTALLED_APP_NAME"

if [[ "${NMAPUI_MIGRATE_DB:-0}" == "1" ]]; then
    mkdir -p "$(dirname "$INSTALLED_RUNTIME_DB")"
    cp "$TEMP_MIGRATION_DB" "$INSTALLED_RUNTIME_DB"
    rm -f "$TEMP_MIGRATION_DB"
    echo "Migrated runtime database into installed app: $INSTALLED_RUNTIME_DB"
fi

echo "Installed application bundle: $INSTALLED_APP_NAME"

# Open the application
if [[ "${NMAPUI_SKIP_OPEN:-}" == "1" ]]; then
    echo "Skipping application auto-open because NMAPUI_SKIP_OPEN=1"
else
    echo "Opening the application..."
    open "$INSTALLED_APP_NAME"
fi

echo "Done! The NmapUI application is now running."
echo "Look for the network icon in your menu bar."
echo "Use the menu to open the selected local NmapUI URL or control the bundled app process."
echo "Menu options: Open NmapUI, Start NmapUI, Stop NmapUI, Quit, Uninstall"
