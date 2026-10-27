# TM-NMapUI

macOS-first network scanning and monitoring app powered by Nmap.

## Quick Start

```bash
git clone https://github.com/techmore/TM-NmapUI.git
cd TM-NmapUI
./install.sh
cd packaging/macos && ./run.sh
```

The command launches the Swift-native macOS interface directly. There is no local dashboard HTTP server or loopback URL.

## Branches and platforms

One scanner engine, several front ends. The engine (Flask + Socket.IO, `app.py` and `nmapui/`)
lives on `main`; this branch adds the native macOS app and keeps a Flask fallback.

| Where | Platform | What it is |
|---|---|---|
| [`main`](https://github.com/techmore/TM-NmapUI/tree/main) | Web UI on macOS and Ubuntu scanner hosts | The product: Flask engine, browser UI, reports, scheduler, the Swift menu-bar launcher and the LaunchDaemon/systemd installers. CI-gated. |
| `swift-native` (this branch) | Native macOS (SwiftUI) | Native app with its own scan, report, Drive and privilege-helper code, qualified against a pinned commit of the shared engine. Periodically synced with `main`. |
| [TM-NmapUI-elementary](https://github.com/techmore/TM-NmapUI-elementary) | Native elementary OS (Granite/GTK 4) | Native window, Wingpanel indicator and per-user `nmapui.service` that runs the shared engine with Gunicorn on `127.0.0.1:9000`. Separate repository. |
| [TM-NMapUI-www](https://github.com/techmore/TM-NMapUI-www) | Marketing site | Static pages and screenshots. |

For the Flask engine's macOS LaunchDaemon and Ubuntu service installers, see the
[`main` README](https://github.com/techmore/TM-NmapUI/blob/main/README.md) and
[the setup guide](docs/guides/SETUP.md).

## Shared Flask engine

The scan engine merged from `main` is a Python 3.11+ Flask application (`app.py` and
the `nmapui/` package). On this branch it backs the retained Flask wrapper and the
pinned shared-engine fixture the native tests qualify against. To run it as an
unattended macOS service, use `packaging/macos/install-daemon.sh` from a root-owned
Python toolchain (see [the setup guide](docs/guides/SETUP.md)). Local loopback access
needs no sign-in; set `NMAPUI_USERNAME` and `NMAPUI_PASSWORD` to enable remote browser
or API access, or for the wrapper's strict mode (`NMAPUI_TRUST_LOCAL_UI=false`).

`server.js` and `package.json` are the legacy Node/Express build, kept only as a
rollback reference (`releases/TM-NmapUI-mac-known-good.md`).

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | SwiftUI macOS app |
| Desktop UI | Native SwiftUI views |
| HTML | Generated scan reports only |
| Real-time | Native Swift transport |
| Scanner | Nmap + NSE (Nmap Scripting Engine) |
| PDF Generation | wkhtmltopdf / Chromium |
| XML Processing | Native Swift parsers |
| Scheduling | macOS LaunchAgent + Swift runner |
| HTTP Client | URLSession |
| Cloud Sync | Google Drive helper |

## Requirements

- **macOS** (primary target)
- **Homebrew** (for package management)
- **Nmap** (with script database updated)
- **wkhtmltopdf** or **Chromium** (for PDF generation)
- **xsltproc** (for HTML report styling)

All dependencies are installed automatically by `install.sh`.

## Installation & Quick Start (macOS)

1. Clone the repository:
   ```bash
   git clone https://github.com/techmore/NmapUI.git
   cd NmapUI
   ```

2. Build and launch the native app:
   ```bash
   cd packaging/macos
   ./bundle.sh
   open build/NmapUI.app
   ```

   NmapUI opens as a normal SwiftUI window. Privileged Nmap capabilities use the separately installed scanner helper; the GUI itself remains unprivileged.

   > **Prerequisites**: Xcode Command Line Tools (`xcode-select --install`) and [Homebrew](https://brew.sh) are needed by `install.sh` to pull in `nmap`, `arp-scan`, etc.

## Repository Layout

- Root: stable entrypoints and runtime files such as `install.sh`, `deploy.sh`, and repository-level scripts
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

The current repository does not include the old installer flow referenced in earlier notes.

## Usage

### Start the app

```bash
cd packaging/macos && ./run.sh
```

The launcher starts the native macOS shell and opens the loopback UI on port 9000 by default. On the macOS wrapper, the menu bar icon is the primary way back into the app.

### Nightly Eval

```bash
./scripts/nightly_product_eval.sh --run
```

This runs the nightly product evaluation loop, which boots the Swift-native app, checks key runtime endpoints and assets, and records an evaluation artifact under `docs/notes/eval-logs/`.

For a no-side-effects preview of the loop shape, run:

```bash
./scripts/nightly_product_eval.sh --dry-run
```

To install or remove the macOS scheduler from the repo root, use:

```bash
./packaging/macos/nightly_product_eval_launchd.sh install
./packaging/macos/nightly_product_eval_launchd.sh uninstall
```

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
├── packaging/macos/    # Swift-native macOS app shell
├── install.sh         # Dependency installer
├── package.json      # Legacy Node tooling and helper scripts
├── google_drive_bridge.js   # Legacy Google Drive helper dispatch layer
├── nmap-modern.xsl  # Report stylesheet
├── config.json      # App configuration
├── history.json    # Scan history
├── reports_archive/ # Generated reports
└── static/         # Frontend assets
```

## License

MIT. See [LICENSE](LICENSE).

The retained Flask wrapper uses the selected local runtime URL (the default
local loopback URL is `http://127.0.0.1:9000`). Native SwiftUI does not need that
listener. For Flask runtime-store migration, use
`scripts/backfill_runtime_store.py --help` before changing stored data.

For the retained Flask wrapper, `NMAPUI_SWIFT_TARGET` overrides its compiler
target; `NMAPUI_APPLICATIONS_DIR` selects installation into `/Applications`,
`~/Applications`, or an isolated test destination. Export the runtime store with
`/api/runtime/export` before enabling `NMAPUI_MIGRATE_DB=1 ./build.sh`;
`NMAPUI_MIGRATE_DB_FROM` selects an explicit source SQLite database.
