# TM-NMapUI

macOS-first network scanning and monitoring app powered by Nmap.

## Quick Start

```bash
git clone https://github.com/techmore/TM-NmapUI.git
cd TM-NmapUI
./install.sh
sudo npm start
```

The app will open its local UI automatically. If you need to access it directly, use the loopback URL shown by the launcher, usually `http://127.0.0.1:9000`.

`npm start` also checks for missing Node packages and installs them automatically, so a clean checkout will recover if `node_modules/` has not been created yet.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js |
| Desktop Shell | Swift menu bar app |
| Web Framework | Express |
| Real-time | Socket.IO |
| Scanner | Nmap + NSE (Nmap Scripting Engine) |
| PDF Generation | wkhtmltopdf / Chromium |
| XML Processing | xml2js |
| Scheduling | node-cron |
| HTTP Client | axios |
| Cloud Sync | Google Drive helper |

## Requirements

- **macOS** (primary target)
- **Homebrew** (for package management)
- **Node.js** (via Homebrew)
- **Nmap** (with script database updated)
- **wkhtmltopdf** or **Chromium** (for PDF generation)
- **xsltproc** (for HTML report styling)

All dependencies are installed automatically by `install.sh`.

## Installation & Quick Start (macOS)

1. Clone the repository:
   ```bash
   git clone https://github.com/techmore/TM-NmapUI.git
   cd NmapUI
   ```

2. Build and launch the menu bar app:
   ```bash
   open NmapUIMenuBar.app
   ```

   After launch, look for the network icon in your macOS menu bar. The app serves NmapUI on a local loopback URL, defaulting to `http://127.0.0.1:9000` and falling back to the next available local port if needed.
   The menu bar app now exposes a `Launch at Login` toggle and an `Uninstall NmapUI` menu action. Uninstall removes the login item registration first and then moves the app bundle to the Trash.

   > **Prerequisites**: Xcode Command Line Tools (`xcode-select --install`) and [Homebrew](https://brew.sh) are needed by `install.sh` to pull in `nmap`, `arp-scan`, etc.

## Container Build

If you want a more atomic install path, the repository now includes a container build that packages the Node runtime with its scan/report tooling.

Build the image:
```bash
docker build -t nmapui:container .
```

Run it with Docker Compose:
```bash
docker compose up --build
```

The container listens on `0.0.0.0:9000` and persists runtime data in `/data`. The app now reads mutable files from that directory, so scan history, settings, reports, and temporary scan artifacts survive restarts. If you want to override defaults locally, set `NMAPUI_DATA_DIR`, `NMAPUI_PORT`, or `PORT` in your shell or a compose `.env` file.

Notes:
- The container includes `nmap`, `xsltproc`, `wkhtmltopdf`, Chromium, `traceroute`, and `python3` for the helper scripts.
- Network scanning still depends on the runtime’s network permissions. The bundled compose file adds `NET_ADMIN` and `NET_RAW`, which are typically required for fuller scan capabilities.
- For environments like Apple Container Machines, the same image can be used as a starting point, but you may need to adjust network exposure or host access based on the target runtime’s policies.
- The container healthcheck hits `/api/app-identity`, which is a lightweight readiness signal for orchestration.

## Repository Layout

- Root: stable entrypoints and runtime files such as `server.js`, `install.sh`, and `deploy.sh`
- `NmapUI.app/` and `NmapUIMenuBar.app/`: macOS app bundles produced by the current packaging flow
- `packaging/macos/`: Swift/AppKit shell scaffold for the macOS-native direction
- `docs/guides/`: user and maintainer guides
- `docs/notes/`: internal implementation notes and working analysis
- `docs/audits/`: deeper audit writeups that are not part of the main setup flow

Runtime-only files such as `auto_scan_config.json`, generated scan outputs, local wrapper binaries, and ad hoc scratch directories should stay untracked.

## Admin Commands

Export the runtime database from the Settings tab, or download it directly:

```bash
curl -OJ http://127.0.0.1:9000/api/runtime/export
```

If you are migrating an existing runtime database into the menu bar app bundle, copy the runtime data directory into the bundle resources before launch:

```bash
cp /path/to/runtime.sqlite3 NmapUIMenuBar.app/Contents/Resources/data/runtime.sqlite3
```

The current repository does not include the old `build.sh` installer flow referenced in earlier notes.

## Build Environment Variables

The macOS wrapper build accepts the following environment variables:

- `NMAPUI_SWIFT_TARGET` - Override the Swift compilation target (defaults are picked from `uname -m`: `arm64-apple-macosx13.0` or `x86_64-apple-macosx13.0`)
- `NMAPUI_APPLICATIONS_DIR` - Override the install destination; otherwise the bundle goes to `/Applications` when writable, or `~/Applications`
- `NMAPUI_MIGRATE_DB=1 ./build.sh` - Migrate an existing runtime database during install
- `NMAPUI_MIGRATE_DB_FROM=<path>` - Explicit source database for the migration

## Runtime Maintenance

Backfill scan artifacts and customer history into the SQLite runtime store:

```bash
python3 scripts/backfill_runtime_store.py
```

## Usage

### Start the app

```bash
sudo npm start
```

The launcher starts the local runtime on port 9000 by default and opens the app shell around it. On the macOS wrapper, the menu bar icon is the primary way back into the app.

### Scans

- **Quick Scan** - Fast discovery of live hosts on the network
- **Complete Scan** - Full port scan with OS detection and vulnerability scripts
- **Dragnet Scan** - Scan all hosts from previous discovery with exhaustive options

### VPN Helper

VPN Helper is intended for remote/VPN or large-scope scans. Phase 1 discovery uses the normal scan path. After discovery completes, VPN Helper batches the successful live IPs into Phase 2.1 service/version scans and Phase 2.2 vulners scans. OS detection is disabled by default in VPN Helper mode; enable **Force OS Detection (-O)** when OS fingerprinting is worth the extra time and instability risk.

Normal Complete scans keep the faster combined Phase 2 behavior. Use VPN Helper when Phase 2 stalls, crashes, or the scan is running across a slow VPN.

### Auto-Monitor

Schedule automatic scans to run daily, weekly, monthly, or hourly. Results are saved to `reports_archive/` and optionally synced to Google Drive.

### Reports

HTML and PDF reports are generated after each scan. Reports include:
- Discovered hosts with IP, MAC, hostname, vendor
- Open ports and service versions
- Detected CVEs with CVSS scores
- Network topology fingerprint

## Directory Structure

```
.
├── server.js           # Main local runtime
├── install.sh         # Dependency installer
├── package.json      # Node dependencies
├── google_drive.py   # Google Drive sync helper
├── nmap-modern.xsl  # Report stylesheet
├── config.json      # App configuration
├── history.json    # Scan history
├── reports_archive/ # Generated reports
└── static/         # Frontend assets
```

## License

MIT
