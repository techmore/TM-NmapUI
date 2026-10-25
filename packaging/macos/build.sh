#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Reject invalid product metadata before compiling or signing any executable.
python3 "$SCRIPT_DIR/bundle_version.py" "$SCRIPT_DIR/../../VERSION" >/dev/null
cd "$SCRIPT_DIR"

CONFIGURATION="${1:-release}"
case "$CONFIGURATION" in
  debug|release) ;;
  *) CONFIGURATION="release" ;;
esac

swift build -c "$CONFIGURATION"

BUILD_DIR=".build/$CONFIGURATION"
SIGN_IDENTITY="${NMAPUI_CODESIGN_IDENTITY:-Apple Development: sdolbec1@gmail.com (DFRH5328BP)}"

# #237: stable code signature so macOS treats rebuilt binaries as the same app.
# Ad-hoc (linker) signatures make every rebuild a brand-new identity, which forces
# the privileged-helper reinstall prompt on every build.
if security find-identity -v -p codesigning | grep -q "Apple Development"; then
  for BIN in NmapUI NmapPrivilegedHelper GoogleDriveHelper RuntimeReportHelper; do
    if [ -f "$BUILD_DIR/$BIN" ]; then
      codesign --force --sign "$SIGN_IDENTITY"         --options runtime         --entitlements Sources/NmapUIApp/NmapUIApp.entitlements         "$BUILD_DIR/$BIN" 2>/dev/null       || codesign --force --sign "$SIGN_IDENTITY" "$BUILD_DIR/$BIN"
    fi
  done
  echo "Signed with: $SIGN_IDENTITY"
else
  echo "WARNING: no Apple Development identity found; binaries left ad-hoc signed." >&2
fi
