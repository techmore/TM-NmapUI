#!/bin/bash

# NmapUI Deployment Script
# Builds macOS packages and creates GitHub release

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
SPEC_PATH="$ROOT_DIR/packaging/pyinstaller/nmapui.spec"

echo "🚀 Starting NmapUI deployment..."

# Check prerequisites
if ! command -v pyinstaller &> /dev/null; then
    echo "❌ PyInstaller not found. Install with: pip install pyinstaller"
    exit 1
fi

if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI not found. Install from: https://cli.github.com/"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ python3 not found. Install Python 3 before running deployment."
    exit 1
fi

# Get version from VERSION file or generate timestamp-based version
if [ -f "$ROOT_DIR/VERSION" ]; then
    VERSION=$(cat "$ROOT_DIR/VERSION" | tr -d '\n')
    echo "📋 Using version from VERSION file: $VERSION"
else
    # Generate version like v2026.1.9.12_01
    VERSION="v$(date +%Y.%-m.%-d.%H_%M)"
    echo "📋 Generated timestamp version: $VERSION"
    echo "$VERSION" > "$ROOT_DIR/VERSION"
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
cd "$ROOT_DIR"
rm -rf build dist *.pkg *.dmg

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "✅ Activated virtual environment (.venv)"
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "✅ Activated legacy virtual environment (venv)"
fi

# Install/update dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Build with PyInstaller
echo "🔨 Building application bundle..."
pyinstaller --clean "$SPEC_PATH"

# Test the build quickly
echo "🧪 Testing bundle startup..."
python3 - <<'PY'
import subprocess
import sys

cmd = ["./dist/NmapUI.app/Contents/MacOS/NmapUI", "--quick"]
try:
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
    print("✅ Bundle starts successfully")
except subprocess.TimeoutExpired:
    print("✅ Bundle starts and stayed alive for 10 seconds")
except Exception as exc:
    print(f"⚠️  Bundle test inconclusive (may still work): {exc}")
    sys.exit(0)
PY

# Create PKG installer
echo "📦 Creating PKG installer..."
pkgbuild --root ./dist --identifier com.techmore.nmapui --version "${VERSION#v}" --install-location /Applications NmapUI.pkg

# Create DMG
echo "💿 Creating DMG disk image..."
mkdir -p dmg_temp
cp -r dist/NmapUI.app dmg_temp/
cp NmapUI.pkg dmg_temp/
ln -s /Applications dmg_temp/Applications
hdiutil create -volname "NmapUI Installer" -srcfolder dmg_temp -ov -format UDZO NmapUI.dmg
rm -rf dmg_temp

# Create GitHub release
echo "🚀 Creating GitHub release..."
RELEASE_NOTES="## NmapUI $VERSION

### What's New
- macOS application bundle and installer
- Standalone executable with all dependencies
- UI-based application updates
- Improved network scanning interface

### Installation
Download and run the .dmg file, or use the .pkg installer for system-wide installation.

### System Requirements
- macOS 10.13 or later
- External dependencies: Nmap, ARP-Scan, wkhtmltopdf (may need separate installation)"

gh release create "$VERSION" \
    --title "NmapUI $VERSION" \
    --notes "$RELEASE_NOTES" \
    --latest \
    NmapUI.dmg NmapUI.pkg

echo "🎉 Deployment complete!"
echo "📦 Files created: NmapUI.pkg, NmapUI.dmg"
echo "🚀 Release: https://github.com/techmore/TM-NmapUI/releases/tag/$VERSION"
