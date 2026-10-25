#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Product text is data, never evaluated as shell code or inserted into XML.
VERSION_METADATA="$(python3 "$SCRIPT_DIR/bundle_version.py" "$ROOT_DIR/VERSION")" || exit 1
IFS=$'\t' read -r APP_VERSION BUNDLE_SHORT_VERSION BUNDLE_BUILD_VERSION <<< "$VERSION_METADATA"
CONFIGURATION="${NMAPUI_BUILD_CONFIGURATION:-debug}"
case "$CONFIGURATION" in debug|release) ;; *) echo "Invalid build configuration" >&2; exit 1 ;; esac
APP_NAME="${APP_NAME:-NmapUI}"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/.build}"
PRODUCT_PATH="$BUILD_DIR/$CONFIGURATION/$APP_NAME"
HELPER_PATH="$BUILD_DIR/$CONFIGURATION/NmapPrivilegedHelper"
APP_BUNDLE="${APP_BUNDLE:-$SCRIPT_DIR/build/$APP_NAME.app}"
RESOURCES_DIR="$APP_BUNDLE/Contents/Resources"
MACOS_DIR="$APP_BUNDLE/Contents/MacOS"
REAL_EXECUTABLE="$MACOS_DIR/$APP_NAME.real"
HELPER_EXECUTABLE="$MACOS_DIR/NmapPrivilegedHelper"
WRAPPER_EXECUTABLE="$MACOS_DIR/$APP_NAME"
RESOURCE_BUNDLE_NAME="NmapUI_NmapUIApp.bundle"
RESOURCE_BUNDLE_SOURCE="$BUILD_DIR/$CONFIGURATION/$RESOURCE_BUNDLE_NAME"
ARTIFACT_DIR="$(dirname "$APP_BUNDLE")"
ICONSET_DIR="$ARTIFACT_DIR/AppIcon.iconset"
ICON_FILE="$RESOURCES_DIR/AppIcon.icns"
GENERATED_ASSETS_DIR="$ARTIFACT_DIR/generated-assets"
SIGN_IDENTITY="${CODESIGN_IDENTITY:-}"
SIGN_OPTIONS="${CODESIGN_OPTIONS:---force --sign}"
# Scan workdir stays under Application Support; do not force the repo as workdir.
DATA_DIR="${NMAPUI_DATA_DIR:-$HOME/Library/Application Support/NmapUI}"

cd "$SCRIPT_DIR"
python3 "$SCRIPT_DIR/assert_bundle_stopped.py" "$APP_BUNDLE"
swift build -c "$CONFIGURATION" --scratch-path "$BUILD_DIR"
for PRODUCT in "$APP_NAME" NmapPrivilegedHelper GoogleDriveHelper RuntimeReportHelper; do
    if [ ! -x "$BUILD_DIR/$CONFIGURATION/$PRODUCT" ]; then
        echo "Missing required native product: $PRODUCT" >&2
        exit 1
    fi
done

# Recheck after compilation, before replacing a copy started during the build.
python3 "$SCRIPT_DIR/assert_bundle_stopped.py" "$APP_BUNDLE"
rm -rf "$APP_BUNDLE"
rm -rf "$ICONSET_DIR"
rm -rf "$GENERATED_ASSETS_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$GENERATED_ASSETS_DIR"

cp "$PRODUCT_PATH" "$REAL_EXECUTABLE"
if [ -d "$RESOURCE_BUNDLE_SOURCE" ]; then
    ditto "$RESOURCE_BUNDLE_SOURCE" "$RESOURCES_DIR/$RESOURCE_BUNDLE_NAME"
else
    echo "Missing Swift Package resource bundle: $RESOURCE_BUNDLE_SOURCE" >&2
    exit 1
fi
# Starscream's pinned package declares a privacy manifest resource bundle.
# Keep it alongside the application's resources before signing the container.
STARSCREAM_RESOURCE_BUNDLE="$BUILD_DIR/$CONFIGURATION/Starscream_Starscream.bundle"
if [ ! -d "$STARSCREAM_RESOURCE_BUNDLE" ]; then
    echo "Missing Swift Package resource bundle: $STARSCREAM_RESOURCE_BUNDLE" >&2
    exit 1
fi
ditto "$STARSCREAM_RESOURCE_BUNDLE" "$RESOURCES_DIR/Starscream_Starscream.bundle"
if [ -f "$HELPER_PATH" ]; then
    cp "$HELPER_PATH" "$HELPER_EXECUTABLE"
    chmod 755 "$HELPER_EXECUTABLE"
fi
DRIVE_HELPER_PATH="$BUILD_DIR/$CONFIGURATION/GoogleDriveHelper"
if [ -f "$DRIVE_HELPER_PATH" ]; then
    cp "$DRIVE_HELPER_PATH" "$MACOS_DIR/GoogleDriveHelper"
    chmod 755 "$MACOS_DIR/GoogleDriveHelper"
fi
cp "$BUILD_DIR/$CONFIGURATION/RuntimeReportHelper" "$MACOS_DIR/RuntimeReportHelper"
chmod 755 "$MACOS_DIR/RuntimeReportHelper"
INFO_PLIST_SOURCE="$SCRIPT_DIR/Sources/NmapUIApp/Resources/Info.plist"
if [ ! -f "$INFO_PLIST_SOURCE" ]; then
    INFO_PLIST_SOURCE="$SCRIPT_DIR/Resources/Info.plist"
fi
SOURCE_REVISION="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
python3 - "$INFO_PLIST_SOURCE" "$APP_BUNDLE/Contents/Info.plist" "$APP_NAME" "$APP_VERSION" "$BUNDLE_SHORT_VERSION" "$BUNDLE_BUILD_VERSION" "$SOURCE_REVISION" <<'PYPLIST'
import plistlib
import sys
source, target, executable, raw, short, build, revision = sys.argv[1:]
with open(source, "rb") as stream:
    info = plistlib.load(stream)
info.update({
    "CFBundleIdentifier": "com.techmore.nmapui",
    "CFBundleExecutable": executable,
    "CFBundlePackageType": "APPL",
    "CFBundleVersion": build,
    "CFBundleShortVersionString": short,
    "NmapUIProductVersion": raw,
    "NmapUISourceRevision": revision,
})
with open(target, "wb") as stream:
    plistlib.dump(info, stream)
PYPLIST
printf '%s\n' "$APP_VERSION" > "$RESOURCES_DIR/VERSION"

cp "$SCRIPT_DIR/../../index.html" "$RESOURCES_DIR/index.html"
# Include the installer's former extra image before sealing the bundle.
cp "$SCRIPT_DIR/Sources/NmapUIApp/Assets/techmore.png" "$RESOURCES_DIR/techmore.png"
cp "$SCRIPT_DIR/../../nmap-modern.xsl" "$RESOURCES_DIR/nmap-modern.xsl"
rm -rf "$RESOURCES_DIR/nmap-vulners"
ditto "$SCRIPT_DIR/../../nmap-vulners" "$RESOURCES_DIR/nmap-vulners"
rm -rf "$RESOURCES_DIR/static"
ditto "$SCRIPT_DIR/../../static" "$RESOURCES_DIR/static"
cat > "$WRAPPER_EXECUTABLE" <<EOF
#!/bin/bash
set -euo pipefail
export NMAPUI_DATA_DIR="\${NMAPUI_DATA_DIR:-$DATA_DIR}"
exec "\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)/$APP_NAME.real" "\$@"
EOF
chmod +x "$REAL_EXECUTABLE" "$WRAPPER_EXECUTABLE"

if command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
    mkdir -p "$ICONSET_DIR"
    for size in 16 32 64 128 256 512; do
        sips -z "$size" "$size" "$SCRIPT_DIR/../../static/techmore.png" --out "$GENERATED_ASSETS_DIR/icon_${size}x${size}.png" >/dev/null
    done
    cp "$SCRIPT_DIR/../../static/techmore.png" "$GENERATED_ASSETS_DIR/icon_512x512@2x.png"
    cp "$GENERATED_ASSETS_DIR"/icon_*.png "$ICONSET_DIR/"
    iconutil -c icns "$ICONSET_DIR" -o "$ICON_FILE"
fi

# Sign the executable with the same stable identifier that the privileged
# helper authorizes. SwiftPM's default executable identifier is derived from
# the product name and is not stable across builds.
codesign --force --sign "${SIGN_IDENTITY:--}" --identifier com.techmore.nmapui "$REAL_EXECUTABLE"
if [ -f "$HELPER_EXECUTABLE" ]; then
    codesign --force --sign "${SIGN_IDENTITY:--}" --identifier com.techmore.nmapui.nmap-helper "$HELPER_EXECUTABLE"
fi
if [ -f "$MACOS_DIR/GoogleDriveHelper" ]; then
    codesign --force --sign "${SIGN_IDENTITY:--}" --identifier com.techmore.nmapui.GoogleDriveHelper "$MACOS_DIR/GoogleDriveHelper"
fi

codesign --force --sign "${SIGN_IDENTITY:--}" --identifier com.techmore.nmapui.RuntimeReportHelper "$MACOS_DIR/RuntimeReportHelper"

# Sign the outer bundle after its nested executables. Do not use --deep here:
# --deep would re-sign NmapUI.real and discard its stable client identity.
codesign $SIGN_OPTIONS "${SIGN_IDENTITY:--}" "$APP_BUNDLE"

SIGNED_IDENTIFIER="$(codesign -d --verbose=4 "$REAL_EXECUTABLE" 2>&1 | awk -F= '/^Identifier=/{print $2; exit}')"
if [ "$SIGNED_IDENTIFIER" != "com.techmore.nmapui" ]; then
    echo "Unexpected launched executable identifier: ${SIGNED_IDENTIFIER:-missing}" >&2
    exit 1
fi

echo "Created $APP_BUNDLE"
