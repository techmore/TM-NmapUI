# NmapUI Release Checklist

Use this checklist for a candidate build. It covers the current Flask app and
macOS menu-bar bundle; real appliance service operation needs a Mac capable of
installing and rebooting the LaunchDaemon.

## Build and automated checks

- [ ] Confirm `VERSION` and the release branch are current and pushed.
- [ ] Run `source .venv/bin/activate` and `python -m py_compile app.py`.
- [ ] Run `.venv/bin/python -m pytest -q`.
- [ ] Run `NMAPUI_RUN_BROWSER_REGRESSION=1 .venv/bin/python -m pytest -q tests/test_browser_regressions.py`.
- [ ] Run the packaged Mac smoke test:
  `NMAPUI_RUN_PACKAGED_SMOKE=1 .venv/bin/python -m pytest -q tests/test_packaged_app_smoke.py`.
- [ ] Run both non-mutating daemon checks:
  `packaging/macos/install-daemon.sh --dry-run` and
  `packaging/macos/install-daemon.sh --dry-run --user "$(id -un)"`.

## Browser and scan checks

- [ ] Sign in with configured credentials; confirm protected routes and the
  Socket.IO connection work after a page reload.
- [ ] Run Quick Scan against a network you are authorized to scan. Verify the
  discovered hosts and report history.
- [ ] Generate a report, open its HTML and PDF, and confirm the PDF layout.
- [ ] Stop a running scan or report and confirm its controls return to idle.
- [ ] Save and reload auto-scan settings; confirm one missed scheduled run is
  caught up after restart.

## Appliance checks

- [ ] Install on a test Mac and confirm the service is loopback-bound and
  authentication is required.
- [ ] Verify privileged SYN/OS/ARP scanning from the installed service account.
- [ ] Reboot and sleep/wake the Mac; confirm the service and scheduler recover.
- [ ] Terminate the service during a scan and confirm the scan and report state
  recover without duplicate scheduled work.
- [ ] Run an unattended soak and review service logs, data retention, and disk
  growth.

Do not treat the dry run or packaged smoke test as evidence that reboot,
privileged scanning or prolonged unattended operation passed. `deploy.sh` and
the PyInstaller spec are historical and are not supported release procedures.
