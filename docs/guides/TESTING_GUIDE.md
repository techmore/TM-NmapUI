# Testing Guide

This guide is for validating the current Flask/Socket.IO app before a stable release.

## Quick Start

### 1. Start the application
From the repository root:

```bash
source .venv/bin/activate
NMAPUI_HOST=127.0.0.1 NMAPUI_PORT=9000 NMAPUI_DEBUG=false python app.py --quick
```

### 2. Open the UI
Navigate to `http://127.0.0.1:9000`

### 3. Verify the health endpoint
```bash
curl http://127.0.0.1:9000/api/health
```

Expected result:
- JSON response with `"status": "ok"`
- `app_version` present
- `tool_versions` present

## Release Smoke Tests

### Test 1: Quick Scan

Steps:
1. Enter a valid target such as `192.168.1.0/24`
2. Click `Quick Scan`
3. Confirm scan feedback appears in the activity panel
4. Confirm the `Quick Scan` button disables while the job is running
5. Confirm rows populate in the results table

Expected result:
- Progress messages appear
- Results table updates
- The button re-enables after completion

### Test 2: Generate PDF Report

Steps:
1. Enter a valid target
2. Click `Generate PDF`
3. Confirm the report progress card appears
4. Confirm progress messages advance through scan/report phases
5. Confirm the button disables while the report job is running

Expected result:
- `scan.xml`, `scan_web.html`, and metadata files are created
- If PDF tooling is available, `scan_report.pdf` is created
- UI shows success and re-enables the button

### Test 3: Stop Active Work

Steps:
1. Start a `Quick Scan` or `Generate PDF`
2. Click `Stop`
3. Watch the status area

Expected result:
- UI shows cancellation in progress
- The running scan/report job stops
- Buttons return to idle state

Note:
- This path is implemented with cooperative cancellation and subprocess termination.
- Stable release signoff should include one real end-to-end cancellation test on a live scan target.

### Test 4: History Viewer

Steps:
1. Generate one or more reports
2. Click `Archive`
3. Open an HTML report
4. Download PDF/XML if available
5. Delete a historical scan

Expected result:
- History modal loads
- HTML/PDF/XML actions work
- Delete removes the scan folder and refreshes the list

## Backend Sanity Checks

Run these before cutting a stable release:

```bash
python -m py_compile app.py
python test_generate_report.py 127.0.0.1
```

Notes:
- `test_generate_report.py` defaults to `http://localhost:9000`
- Use `NMAPUI_URL` if you run the app on a different port

## Stable Release Checklist

- App starts with `--quick` and serves `http://127.0.0.1:9000`
- `/api/health` returns `status: ok`
- Quick Scan works
- Generate PDF works or fails gracefully when PDF tooling is unavailable
- Stop cancels an active scan/report job
- Report history opens and can serve saved artifacts
- Version/build metadata is visible in the UI
- No obvious JavaScript errors in the browser console
