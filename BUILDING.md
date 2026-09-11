# Building and Packaging NmapUI for macOS

> Historical PyInstaller workflow. The maintained Mac build uses the root
> `build.sh` to bundle the Swift launcher, Flask application and a Python virtual
> environment. Use Python 3.11+ and `./install.sh --no-daemon`, then
> `NMAPUI_SKIP_OPEN=1 ./build.sh`. Set `NMAPUI_APPLICATIONS_DIR` to choose the
> installation destination. The gated verification command is
> `NMAPUI_RUN_PACKAGED_SMOKE=1 .venv/bin/python -m pytest -q tests/test_packaged_app_smoke.py`.
> The instructions below are retained for the alternative PyInstaller path and
> are not the current release procedure. See README.md for current setup.

This guide explains how to build and package NmapUI for macOS distribution and how to smoke test a release candidate before publishing it.

## Prerequisites

1. **Python Environment**: Python 3.8+ with virtual environment
2. **Dependencies**: Install build tools and dependencies
   ```bash
   pip install pyinstaller
   # Also ensure Nmap, ARP-Scan, wkhtmltopdf, xsltproc are available (for testing)
   ```

3. **macOS Development Tools**: Xcode command line tools
   ```bash
   xcode-select --install
   ```

## Building the Application Bundle

1. **Activate virtual environment** (if not already active)
   ```bash
   source .venv/bin/activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run PyInstaller**
   ```bash
   pyinstaller --clean packaging/pyinstaller/nmapui.spec
   ```

   This creates `dist/NmapUI.app` - a standalone macOS application bundle.

## Testing the Bundle

1. **Test startup**
   ```bash
   ./dist/NmapUI.app/Contents/MacOS/NmapUI --quick &
   sleep 5 && kill %1
   ```
   Check for successful startup messages.

2. **Health check**
   ```bash
   NMAPUI_HOST=127.0.0.1 NMAPUI_PORT=9000 ./dist/NmapUI.app/Contents/MacOS/NmapUI --quick &
   APP_PID=$!
   sleep 5
   curl http://127.0.0.1:9000/api/health
   kill $APP_PID
   ```
   Expected result: JSON with `"status": "ok"` and an `app_version`.

3. **Full test** (optional)
   - Run the app and access `http://127.0.0.1:9000`
   - Test core functionality

## Creating Distribution Packages

### PKG Installer

```bash
pkgbuild --root ./dist --identifier com.techmore.nmapui --version 1.0.0 --install-location /Applications NmapUI.pkg
```

### DMG Disk Image

```bash
# Prepare contents
mkdir -p dmg_temp
cp -r dist/NmapUI.app dmg_temp/
cp NmapUI.pkg dmg_temp/
ln -s /Applications dmg_temp/Applications

# Create DMG
hdiutil create -volname "NmapUI Installer" -srcfolder dmg_temp -ov -format UDZO NmapUI.dmg

# Cleanup
rm -rf dmg_temp
```

## Automated Deployment

Use the provided deployment script:

```bash
./deploy.sh
```

This script will:
- Read version from `VERSION` file or generate timestamp-based version (v2026.1.9.12_01 format)
- Build the application bundle with PyInstaller
- Create PKG and DMG packages
- Create a GitHub release with the packages attached (requires `gh` CLI authentication)

The script automatically determines the version using the same method as the application.

## Release Smoke Test

Before publishing a stable build:

```bash
source .venv/bin/activate
python -m py_compile app.py
NMAPUI_HOST=127.0.0.1 NMAPUI_PORT=9000 NMAPUI_DEBUG=false python app.py --quick &
APP_PID=$!
sleep 5
curl http://127.0.0.1:9000/api/health
kill $APP_PID
```

Recommended manual checks:
- Open `http://127.0.0.1:9000`
- Confirm Quick Scan launches
- Confirm Generate PDF launches and the button disables while the job runs
- Confirm Stop cancels the active scan/report job

## Code Signing and Notarization (Production)

For production releases, you should:

1. **Code Sign** the .app bundle
2. **Sign** the .pkg installer
3. **Notarize** with Apple for macOS 10.15+

Example code signing:
```bash
codesign --deep --force --verify --verbose --sign "Developer ID Application: Your Name" dist/NmapUI.app
```

## Troubleshooting

- **Bundle fails to start**: Check PyInstaller warnings in `build/nmapui/warn-nmapui.txt`
- **Missing modules**: Add to `hiddenimports` in `packaging/pyinstaller/nmapui.spec`
- **Large bundle size**: Consider excluding unnecessary modules in the spec file

## File Structure After Build

```
dist/
├── NmapUI.app/          # macOS application bundle
└── ...

NmapUI.pkg               # Installer package
NmapUI.dmg               # Distribution disk image
```
