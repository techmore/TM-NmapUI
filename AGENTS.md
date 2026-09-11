# PROJECT KNOWLEDGE BASE

## Current navigation (updated 2026-09-11)

The generated map below is historical. The product is Flask (`app.py` wiring,
`nmapui/` implementation), with `templates/index.html` and an optional Swift
launcher in `packaging/macos/NmapUIMenuBarLauncher.swift`. Native SwiftUI work is
on the unmerged `swift-native` branch. Read `docs/notes/PROJECT_STATUS.md` first.

- Scanning: `nmapui/scanning.py`, `nmapui/workflows.py`, `nmapui/privileged.py`.
- Routes/events: `nmapui/handlers/`; scheduling: `nmapui/auto_monitor.py`,
  `nmapui/auto_scan_runtime.py`, `nmapui/handlers/auto_scan.py`.
- Reports: `nmapui/reporting.py`; Drive: `nmapui/google_drive.py`.
- Authentication/session: `nmapui/auth.py`, `nmapui/session.py`.
- Runtime storage/recovery: `nmapui/runtime_db.py`, `nmapui/recovery.py`.
- Build: root `build.sh`; boot supervision: `packaging/macos/install-daemon.sh`.
- Verification: `.venv/bin/python -m pytest -q`. Browser and packaged tests need
  `NMAPUI_RUN_BROWSER_REGRESSION=1` / `NMAPUI_RUN_PACKAGED_SMOKE=1` respectively.
- CI tests Python 3.11. Lint is not currently enforced by CI; `.flake8` uses a
  160-column limit. Do not assume the historical lint commands are configured.
- Container packaging is retired from the active plan. Keep direct host
  networking for the scanner and share the Flask backend across frontends.
- Preserve the known-good alpha branch/tag. Do not delete legacy runtime/static
  assets without checking active Flask and report dependencies.

## Historical generated map

**Generated:** 2026-01-09 23:43:19
**Commit:** 4d345bef0712992199b2de854732d6d5e606cf05
**Branch:** dev

## OVERVIEW
Python Flask web application for network scanning using Nmap, with real-time UI, CVE detection, PDF reports, and Google Drive integration.

## STRUCTURE
```
NmapUI/
├── app.py              # Main Flask app with scan logic and API routes
├── requirements.txt    # Python dependencies (Flask, google-api-python-client, etc.)
├── templates/index.html # Main UI with Socket.IO real-time updates
├── static/             # CSS/JS assets for UI
├── nmap-vulners/       # Vulners NSE scripts for CVE detection
├── docs/guides/        # Guides, including existing AGENTS.md
├── data/scans/         # Organized scan reports (PDF, XML, HTML)
├── scripts/            # Utility scripts
└── config/             # Configuration files
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Scan implementations | app.py (lines ~800-2000) | Quick scan, deep scan, ARP scan functions |
| UI/frontend changes | templates/index.html | HTML structure, JS event handlers |
| API endpoints | app.py (routes section) | /api/scan, /api/report, /api/drive |
| Google Drive integration | app.py (GoogleDriveService class), templates/index.html | OAuth flow, upload logic |
| Report generation | app.py (report functions) | XSL transformation, PDF conversion |
| Real-time updates | app.py (Socket.IO), templates/index.html | WebSocket connections |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| app | Flask app | app.py | Main application instance |
| GoogleDriveService | Class | app.py ~250 | Handles Drive API interactions |
| start_scan | Function | app.py ~800 | Initiates scan based on type |
| generate_report | Function | app.py ~2500 | Creates HTML/XML/PDF reports |
| check_drive_status | Function | templates/index.html ~2080 | Updates Drive button UI |

## CONVENTIONS
- Python 3.x with type hints on public APIs
- Imports grouped: stdlib, third-party, local
- Functions/variables: snake_case; Classes: CamelCase
- Error handling: specific exceptions, logging
- Testing: pytest if present, mock external calls

## ANTI-PATTERNS (THIS PROJECT)
None explicitly documented.

## UNIQUE STYLES
- Optional ARP scanning with feature flags
- Traceroute-based network fingerprinting
- Encrypted token storage for Google Drive
- Real-time scan progress via Socket.IO

## COMMANDS
```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Lint
flake8 .
black --check .

# Run
python app.py

# Test (if pytest configured)
pytest
```

## NOTES
- Requires nmap, xsltproc, wkhtmltopdf system dependencies
- Google Drive needs OAuth app in production mode for seamless auth
- Scan data stored in data/scans/ with timestamped folders</content>
<parameter name="filePath">./AGENTS.md
