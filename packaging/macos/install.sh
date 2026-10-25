#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="${APP_NAME:-NmapUI}"
APP_BUNDLE="${APP_BUNDLE:-$SCRIPT_DIR/build/$APP_NAME.app}"
DEST_DIR="${NMAPUI_APPLICATIONS_DIR:-/Applications}"
DEST_BUNDLE="$DEST_DIR/$APP_NAME.app"
OPEN_AFTER_INSTALL="${OPEN_AFTER_INSTALL:-1}"

cd "$SCRIPT_DIR"
python3 "$SCRIPT_DIR/assert_bundle_stopped.py" "$DEST_BUNDLE"
./bundle.sh

mkdir -p "$DEST_DIR"
python3 "$SCRIPT_DIR/assert_bundle_stopped.py" "$DEST_BUNDLE"
rm -rf "$DEST_BUNDLE"
ditto "$APP_BUNDLE" "$DEST_BUNDLE"
# bundle.sh already signs the completed resources and nested executables.
# Preserve that seal and the helper-authorized identifiers while copying.
codesign --verify --deep --strict "$DEST_BUNDLE"

echo "Installed $DEST_BUNDLE"

if [ "$OPEN_AFTER_INSTALL" != "0" ]; then
    open "$DEST_BUNDLE"
fi
