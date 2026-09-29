# NmapUI Release Checklist

Use this checklist for a candidate build. It covers the current Flask app and
macOS menu-bar bundle. Ubuntu is also a scanner-host target; complete the
Ubuntu support gate before claiming Ubuntu deployment support. That work is
tracked in [issue #241](https://github.com/techmore/TM-NmapUI/issues/241).

## Build and automated checks

- [ ] Bump `VERSION` from the current `v2026.3.14.00_10` to the approved release
  version (the latest repository tag is `v2026.4.26.4.00`), then push the
  release branch.
- [x] Run `source .venv/bin/activate` and `python -m py_compile app.py`.
- [x] Run `.venv/bin/python -m pytest -q` (**619 passed, 27 skipped** on Python 3.11).
- [x] Audit pinned dependencies with `pip-audit -r requirements.txt` (no known vulnerabilities).
- [x] Run all four hosted CI jobs on the submitted service candidate:
  [run 36624110222](https://github.com/techmore/TM-NmapUI/actions/runs/36624110222)
  passed on `df93691c`, including Ubuntu installed lifecycle and Mac packaging.
  Any later revision still requires its own green checks before merge/release.
- [x] Rebuild pinned, locally served browser assets with `npm ci --prefix scripts/ui-assets` and `npm run build --prefix scripts/ui-assets`; npm audit reports no known vulnerabilities and CI checks generated assets.
- [x] Run `NMAPUI_RUN_BROWSER_REGRESSION=1 .venv/bin/python -m pytest -q tests/test_browser_regressions.py` (**20 passed**).
- [x] Verify the main UI CSP blocks inline scripts, with delegated audit-log and
  Archive-modal actions working in Chromium.
- [x] Bundle Inter and Instrument Serif with their OFL licenses, remove Google
  Fonts requests from the app and report templates, and verify both fonts load
  locally in Chromium with no third-party font requests.
- [x] Send hostile Socket.IO history/report metadata through the browser
  renderers and verify it remains text, not injected markup.
- [x] Verify generated HTML reports use embedded compiled CSS and one
  hash-authorized first-party runtime, no CDN scripts, escaped XML payloads,
  formula-safe CSV export, working filter/highlight/collapse controls, and the
  same isolated CSP on both current and legacy HTML routes.
- [x] Verify web/PDF severity summaries count structured CVSS entries at port
  scope, and make clear that an empty Vulners result is not proof of no risk.
- [x] Visually inspect the generated HTML report in Chromium; the separate
  production scan and PDF-layout review below remain open.
- [x] Run the packaged Mac smoke test (**1 passed**, including Unicode Basic
  credentials and committed source WAL rows):
  `NMAPUI_RUN_PACKAGED_SMOKE=1 .venv/bin/python -m pytest -q tests/test_packaged_app_smoke.py`.
- [x] Verify runtime database migration snapshots committed WAL rows, validates
  before replacing the destination atomically, refuses an open destination
  with WAL sidecars, and preserves an existing database after an injected
  partial-snapshot failure (`tests/test_sqlite_backup.py`).
- [x] Verify Playwright PDF rendering blocks JavaScript and external resources
  (**1 browser-backed test passed locally and as root in the installed Ubuntu service**).
- [x] Run the CI-equivalent browser group (**22 passed**), including rendering
  and visually inspecting a representative four-page PDF fixture for metadata,
  table wrapping and page breaks. This does not replace the generated
  production-scan/PDF check below.
- [x] Run both non-mutating daemon checks. Both fail closed on this Mac because
  Nmap is absent from the protected service PATH (root mode also warns that the
  base Python is not root-owned). `sudo -n` cannot provision the toolchain, and
  no LaunchDaemon is installed:
  `packaging/macos/install-daemon.sh --dry-run` and
  `packaging/macos/install-daemon.sh --dry-run --user "$(id -un)"`.
- [x] Run `packaging/ubuntu/install-service.sh --dry-run` on Ubuntu 24.04 LTS
  (passed in the disposable Ubuntu 24.04 ARM64 VM).
- [x] Run the staged single-worker WebSocket smoke test (**4 passed, 2 skipped locally; also passed in the Ubuntu 24.04 VM**):
  `NMAPUI_RUN_PRODUCTION_SMOKE=1 NMAPUI_RUN_STAGED_SMOKE=1 .venv/bin/python -m pytest -q tests/test_production_server.py`.

## Browser and scan checks

- [x] With authentication required (`NMAPUI_TRUST_LOCAL_UI=false`), sign in
  with configured credentials; confirm protected routes and Socket.IO work
  after a page reload (staged Gunicorn/Chromium smoke passed locally and the
  installed Ubuntu service was checked in its disposable VM).
- [x] Verify remote-sync API keys are removed from legacy browser storage,
  never persisted in new browser settings, redacted from the settings API, and
  stored encrypted on the scanner; the password field clears after save.
- [x] Verify changing the configured username or password revokes existing
  long-lived session cookies; verify `NMAPUI_COOKIE_SECURE=true` marks cookies
  Secure and the installers validate/preserve the option.
- [x] Verify a same-site form from another localhost port cannot mutate a
  cookie-authenticated session, even though Chromium sends the session cookie.
  Check same-origin controls, configured frontend origins, HTTPS proxy origins,
  headerless API clients, and login POST origin protection.
- [x] Verify non-ASCII username/password pairs work through login, signed
  sessions and HTTP Basic API access rather than raising a comparison error.
- [x] Verify empty credentials and the built-in default password fail closed
  for remote auth, including a custom username with the default password; the
  default-password acknowledgement is limited to trusted loopback binding.
- [ ] With authentication required (remote access or
  `NMAPUI_TRUST_LOCAL_UI=false`), sign in with configured credentials; confirm
  the production browser flow on the chosen deployment host.
- [ ] Run Quick Scan against a network you are authorized to scan. Verify the
  discovered hosts and report history.
- [x] Managed service credentials default to no automatic network-fingerprint
  egress, no GitHub update check, and no Vulners CVE lookup. Runtime and browser
  regressions verify the disabled paths make no outbound requests; scan
  regressions verify complete scans omit the Vulners script. Operators must
  explicitly opt in per feature in the protected service credentials file and
  approve any enabled egress for the deployment.
- [ ] Generate a report, open its HTML and PDF, and confirm the PDF layout.
- [x] Verify browser Stop controls send authenticated scan and report
  cancellation and return controls to idle; real subprocess cancellation and
  cleanup are covered by process-level job regressions.
- [ ] Save and reload auto-scan settings; confirm one missed scheduled run is
  caught up after restart.
- [ ] Save a settings form while a scheduled report finishes; verify its newer
  Auto-Monitor `last_run` is preserved and no duplicate catch-up scan starts.
- [ ] Disable auto-scan or an Auto-Monitor rule while earlier scheduler work is
  pending; confirm the queued scan does not start.
- [ ] Check Auto-Monitor schedules around local daylight saving transitions
  when an IANA time zone is configured; a newly created rule must not catch up
  a scheduled slot from before its creation time.

## Appliance checks

- [x] Review and explicitly accept the default root-service trust boundary
  (accepted 2026-09-25 for a dedicated, loopback-bound scanner host):
  `NMAPUI_TRUST_LOCAL_UI=true` lets any local process on the scanner host reach
  scan/control APIs without a separate login. Use only on a dedicated trusted
  host; set it to `false` and verify credentials are required for loopback
  callers when local users are not trusted or a reverse proxy is used.

- [ ] Install on a test Mac and confirm the service is loopback-bound, local
  access follows the configured trust setting, and non-loopback access requires
  authentication.
- [x] From Chromium, verify a foreign origin such as a `localhost` lookalike
  cannot fetch the loopback socket token; the browser blocks the public-origin
  request before Flask, and request-level Origin tests require 401 if it arrives.
- [ ] If a reverse proxy fronts the loopback service, disable local trust and
  verify that proxied remote requests still require authentication; for HTTPS,
  confirm session cookies carry the `Secure` attribute.
- [ ] Confirm the installed Mac daemon runs from `/usr/local/lib/nmapui/current`,
  not the checkout; verify customer and Drive configuration survived migration.
- [ ] Confirm the active release's `privileged-assets` directory supplies the
  NSE script and stylesheets, then fail an upgrade and verify the previous
  release, launcher, helper, sudoers rule, plist and scan assets are restored.
- [ ] On an installed Mac, upgrade across two staged releases and confirm
  `current` actually changes to the new release; fail an upgrade and confirm
  the symlink returns to the old release without a nested link in either tree.
- [ ] Run `--rollback` after a successful Mac upgrade and confirm the prior
  launcher, helper, sudoers rule, plist, scan assets and `current` link match
  the prior code release. Force a failed rollback and confirm the original
  release/files/load state are restored.
- [ ] Confirm an in-place change between root and `--user` is refused before
  data ownership changes; test the planned uninstall/reinstall migration.
- [ ] Reuse credentials with a deliberately mismatched data/log/browser path
  and confirm installation refuses them before changing the active release.
- [ ] Confirm an unmanaged listener on the configured port blocks a new Mac
  install; readiness must report the active staged release identifier.
- [ ] In root mode, verify the base Python interpreter and every parent path
  are root-owned and not writable by group/other users.
- [ ] In either mode, verify Nmap, arp-scan, xsltproc and traceroute resolve
  within the protected service PATH, and their binaries, symlinks, parent
  directories and non-system linked libraries are root-owned and non-writable.
- [ ] Verify Nmap's `scripts`, `nselib`, services and OS databases are complete,
  protected from other users, and selected through the service's fixed `NMAPDIR`.
- [ ] In `--user` mode, confirm privileged Nmap output is spooled privately,
  then published as the service user; cancellation must stop helper children.
- [ ] Verify privileged SYN/OS/ARP scanning from the installed service account.
- [ ] Reboot and sleep/wake the Mac; confirm the service and scheduler recover.
- [ ] Terminate the service during a scan and confirm the scan and report state
  recover without duplicate scheduled work; verify all stale jobs are marked
  interrupted even if more than 200 persisted before the crash. Inject a
  recovery write failure and confirm later jobs are still attempted while
  readiness stays degraded until recovery succeeds.
- [ ] During service shutdown, verify a scanner/helper child that ignores
  SIGTERM is killed after the grace period and no new scan starts; repeat with
  a forced worker kill to verify the host supervisor's child cleanup.
- [ ] Run an unattended soak and review service logs, data retention, and disk
  growth.
- [ ] Document and approve the saved scan/report retention and backup policy.
  Runtime DB maintenance does not delete report folders or generated PDFs/XML;
  confirm disk-capacity monitoring or an explicitly authorized cleanup process.
- [x] SQLite regression verifies automatic retention status is persisted while
  saved artifact rows and on-disk report files remain untouched.
- [ ] Confirm the same retention status and saved-folder preservation on the
  installed host during the soak.
- [ ] Confirm readiness degrades if the scheduler thread stops, and a corrupt
  session key prevents supervised worker startup. Verify session, Drive and
  remote-sync secrets and keys are mode `0600`; restore encrypted tokens with
  their matching keys.
- [ ] Upgrade a populated version-1 runtime database and confirm report/job
  listings remain responsive, data is intact, and the preserved release can
  still read it after rollback.
- [ ] When migrating a runtime database between app data locations, stop other
  destination writers, retain an independent backup, and verify committed
  transactions still in the source WAL are present after migration.

## Ubuntu support gate

- [x] Verify the Ubuntu 24.04 LTS candidate and Python 3.11 or newer
  (Ubuntu 24.04 ARM64, Python 3.12.3).
- [ ] Install from a clean host using documented direct-host setup with access
  to the scanner's real network interfaces.
- [x] Confirm `/opt/nmapui/current` is root-owned and read-only to ordinary
  users, while `/var/lib/nmapui` and `/var/log/nmapui` remain service-writable
  (disposable Ubuntu VM).
- [ ] Verify the chosen privilege model completes SYN/OS and ARP discovery.
- [x] Verify the systemd unit's credentials, data/log ownership, readiness,
  matching release identifier, authenticated browser/Socket.IO access, restart
  behavior, and loopback binding in the disposable Ubuntu VM (auth test used
  `NMAPUI_TRUST_LOCAL_UI=false`; installer default is `true`).
- [x] Confirm the environment validator rejects a PATH assignment and the
  generated wrapper uses a trusted absolute shell before restoring protected PATH.
- [x] Test reboot, scan interruption recovery, upgrade and uninstall in the
  disposable Ubuntu VM.
- [x] Test `--rollback` after an upgrade; confirm the prior launcher and systemd
  unit match the prior code release, and data/credentials remain intact in the
  disposable Ubuntu VM.
- [x] Force a failed upgrade and a failed rollback; confirm release links,
  launcher/unit, enabled/active state and readiness all return to the prior
  working release (fresh disposable Ubuntu 24.04 ARM64 VM).
- [ ] Pass hosted Ubuntu CI on the exact release-candidate revision.
- [ ] Install that revision from the documented steps on a clean supported
  Ubuntu scanner host; record authorized SYN/OS/ARP discovery through the real
  host interface and verify the resulting scan/report data.
- [ ] Complete an unattended soak on the supported Ubuntu host and review
  readiness, service/scheduler logs, data retention and disk growth.

The Ubuntu installer/systemd candidate and primary Playwright renderer passed
the workflow-equivalent installer and systemd checks, staged-server suite
(27 passed, 2 skipped), privileged loopback scan, root-mode PDF
resource-security test, authenticated browser/Socket.IO check, crash recovery,
upgrade/rollback/uninstall, and failure-injected upgrade and rollback recovery
in a fresh disposable Ubuntu 24.04 ARM64 VM. Earlier validation also passed
reinstall/reboot readiness checks. These results do not satisfy the remaining
physical-host network-interface/authorized-subnet scan, unattended soak, or
hosted CI gates above.

Do not treat the dry run or packaged smoke test as evidence that reboot,
privileged scanning or prolonged unattended operation passed. `deploy.sh` and
the PyInstaller spec are historical and are not supported release procedures.
