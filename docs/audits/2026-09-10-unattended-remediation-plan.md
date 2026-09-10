# NmapUI — Unattended Operation Review & Remediation Plan

**Date:** 2026-09-10
**Branch reviewed:** `alpha/mac-known-good-2026-09-07-1040` (2 commits ahead of `origin/main`)
**Author:** review pass (automated)
**Status:** Draft for approval

---

## 1. Goal (as stated)

> "Functional, ongoing, without interaction — including privilege."

Restated as an engineering objective:

- The scanner runs **continuously for months** on a Mac (and in the Docker/Linux target) with **no human at the keyboard**.
- Scheduled scans / auto-monitor run **on time**, survive reboots, sleep/wake, crashes, and network changes.
- **Privileged** Nmap capabilities (SYN scan, OS detection, ARP) are available **without a password prompt** at every start.
- The system **verifies itself** and surfaces failures instead of failing silently.
- It can be **updated and rolled back safely** without hands-on support.
- Security is not traded away for convenience (least privilege, authenticated control surface).

This matches the follow-up platform requirement recorded in `releases/TM-NmapUI-mac-known-good.md:13-15`.

---

## 2. What the codebase actually is (verified)

There are **three implementations** in one tree. Only one is the product.

| Implementation | Files | Status |
|---|---|---|
| **Python Flask app** | `app.py`, `nmapui/` (≈45 modules), `templates/index.html`, `tests/` | **Authoritative.** CI installs `requirements.txt` and runs `pytest`. `build.sh` bundles it and the Swift wrapper runs `python3 app.py`. |
| Legacy Node/Express app | `server.js` (89 KB), root `index.html` (114 KB), `static/js/*`, `package.json` | **Legacy rollback reference.** Not in CI, not bundled. |
| Swift menu-bar wrapper | `packaging/macos/NmapUIMenuBarLauncher.swift`, `build.sh` | **Shipping launcher** for the Flask app on macOS. |

Verification baseline on this checkout:

- `pytest -q` → **329 passed, 8 skipped in 19.11s**
- Test/lint config: `.flake8` (max-line-length 160), `pytest.ini`. **No** `pyproject.toml`, `mypy.ini`, or black config; `flake8`/`black`/`mypy` are **not** in `requirements.txt`, and **CI runs no lint or type check**.
- Local venv is **Python 3.14.7**; CI pins **3.11**; `requirements.txt` has no `python_requires`.

---

## 3. The headline finding: unattended operation is currently **not working**

This is not a theoretical weakness. The system's own overnight check has been red for **16 consecutive nights**.

**Evidence** (`docs/notes/eval-logs/nightly-product-eval.launchd.out.log`):

```
2026-08-25T06:00:25  nightly-product-eval blocked: server did not start on port 9000
...
2026-09-10T06:00:28  nightly-product-eval blocked: server did not start on port 9000
```

**Latest report** (`nightly-product-eval.json`, 2026-09-10T06:00:28Z):

```json
{"name": "app_start",      "status": "blocked", "reason": "server did not start"},
{"name": "identity_probe", "status": "blocked", "reason": "server did not start"},
{"name": "root_probe",     "status": "blocked", "reason": "server did not start"}
```

**Root cause** (`docs/notes/eval-logs/nightly-product-eval-server.log`):

```
scripts/nightly_product_eval.sh: line 122: npm: command not found
```

`scripts/nightly_product_eval.sh:121-124` starts the server with `npm start` — the **legacy Node runtime**, not the Flask product. Under `launchd` the `PATH` does not include `~/.local/bin` or `/opt/homebrew/bin`, so `npm` is not found and the probe times out. The only automated "is it alive" signal has therefore been measuring the wrong binary and been useless for over two weeks.

Supporting operational facts at review time:

- **Nothing is listening on port 9000**; no `app.py` / `NmapUI` process is running.
- `com.nmapui.nightly-product-eval.plist` (`StartCalendarInterval` 02:00, `RunAtLoad=false`, `KeepAlive=false`) is the only supervised job touching the product, and it only runs the eval.
- `com.techmore.nmapui.autoscan.plist` invokes
  `/Applications/Xcode-beta.app/.../swiftpm-testing-helper --scheduled-scan` — a toolchain helper, not a scheduler. It cannot perform a scan.
- `reports_archive/` is empty; scan data lives in the untracked `data/` tree (38 files, 1.5 MB).

**After the Phase 0 fix (branch `fix/unattended-operation`)** the eval boots the Flask app with the project venv, probes `/api/health/live`, `/api/health`, `/`, and `/static/techmore.png`, and reports **4/4 pass** with the port released cleanly on teardown. First green run: 2026-09-10T11:57:10Z.

### 3.1 Second headline: scheduled **auto-scan** is a silent no-op (confirmed by direct inspection)

Independently verified in this pass, and it is worse than a monitoring gap — the feature itself does not work:

- `nmapui/auto_scan_runtime.py:45-52` — `execute_auto_scan` does **not** run a scan. It calls `safe_emit("trigger_generate_report", …)`, then immediately writes `auto_scan_config["last_run"]` and logs `"Auto scan executed"`.
- `nmapui/events.py:4-12` — `safe_emit` wraps `flask_socketio.emit`, which requires a Flask **request context**. The scheduler runs on a plain background thread, so it raises `RuntimeError`, which `safe_emit` swallows with `pass`.
- **No listener for `trigger_generate_report` exists anywhere** — repo-wide grep finds only the emit (`auto_scan_runtime.py:48`) and a test that asserts this broken contract (`tests/test_backend_modules.py:335`).
- Contrast: `execute_auto_monitor_rule` (`nmapui/auto_scan_runtime.py:98-136`) does it correctly — `job_registry.start(...)` then `generate_report_task(AUTO_SCAN_SID, {...})` server-side.

**Net effect:** an unattended Mac "runs" its 01:00-06:00 auto-scan, records `last_run`, logs success, and produces **zero scan output — indefinitely**. Auto-monitor rules do run, but synchronously on the scheduler thread (see H2).

### 3.2 Third headline: a missing tool kills the app at startup

`check_nmap` / `check_vulners` call `sys.exit(1)` (`nmapui/scanning.py:74, 82, 93`), and startup checks run **before** the socket server binds (`nmapui/app_runtime.py:114-116`). A Homebrew upgrade, a minimal `launchd` `PATH`, or a missing vulners file therefore turns any restart into a silent, unrecoverable death — with no boot persistence to restart it (C2).

---

## 4. Confirmed weaknesses by area

Each item cites the evidence found in this pass. The four deep-dive audits (security, reliability, performance, standards) are folded into §7-§10.

### 4.1 Privilege model — the core conflict with "no interaction"

| # | Finding | Evidence |
|---|---|---|
| P1 | **The Flask app never invokes `sudo`.** It calls bare `nmap` and chooses `-sS` only when `os.geteuid() == 0`, else `-sT`. Privileged scanning therefore requires **running the entire web server as root**. | `nmapui/scanning.py:33-40`, `:253-321` |
| P2 | **The only documented privileged launch is a GUI password prompt.** The menu-bar app starts the server via `osascript … with administrator privileges`, i.e. an admin authorization dialog on **every launch**. | `packaging/macos/NmapUIMenuBarLauncher.swift:166, 426-441` |
| P3 | **`run_quick_auto_scan` hardcodes `-sS` with no privilege fallback** — but it has **zero callers** (dead code), so it is *not* the overnight path as first assumed. The concern is real only if it is ever wired up; the actual overnight path is the broken `execute_auto_scan` (see **C1**). | `nmapui/scanning.py:126-145`; repo-wide grep → no callers |
| P4 | **Root web server + local trust = local privilege escalation.** The bundle exports `NMAPUI_TRUST_LOCAL_UI=true`, so loopback requests bypass auth; `/api/socket-token` is also loopback-only and unauthenticated. Run as root, this makes the HTTP API an unauthenticated root RPC surface for **any local process**. | `build.sh:368`, `nmapui/auth.py:30-77, 121-135`, `nmapui/handlers/routes.py:80-88` |
| P5 | No sudoers allowlist, no privileged helper, no `sudo -n` path exists in the Flask app (only in the legacy `server.js:229-243`). | repo-wide grep |
| P6 | Fresh-install auth is a dead end: with no `NMAPUI_USERNAME`/`NMAPUI_PASSWORD` set and `NMAPUI_ALLOW_DEFAULT_CREDENTIALS` unset, every route returns **503** (`auth_uses_insecure_defaults`). Nothing in `build.sh`/`run.sh` sets credentials, so the desktop bundle relies solely on the local-trust bypass. | `nmapui/auth.py:80-135`, `build.sh:337-371` |

### 4.2 Supervision & reboot recovery

| # | Finding | Evidence |
|---|---|---|
| R1 | **No boot persistence for the server.** No LaunchDaemon/LaunchAgent/plist (tracked or generated) starts the Flask app; no `KeepAlive`, no watchdog, no auto-restart. Reboot recovery depends on a login item that the code never creates. | `git ls-files | grep plist` → none; `NmapUIMenuBarLauncher.swift` contains no `Login`/`SMAppService` API |
| R2 | **No crash restart.** `isFlaskRunning` only checks the port; nothing polls or relaunches a dead server. A crash stays down until a human clicks "Restart Flask". | `NmapUIMenuBarLauncher.swift:48-53, 196-214` |
| R3 | **Docs advertise a feature that does not exist.** `README.md:58` claims a "Launch at Login" toggle; the actual menu is Open/Start/Stop/Restart/Quit/Uninstall. | `NmapUIMenuBarLauncher.swift:64-99` |
| R4 | Two bundles are installed simultaneously (`/Applications/NmapUI.app` and `~/Applications/NmapUI.app`), inviting version skew. | filesystem check |
| R5 | **No graceful shutdown, no single-instance guard, no PID file.** There is no `SIGTERM`/`SIGINT` handler, no `atexit`, and no `flock`/pidfile for the server process (only the *scheduler* is locked). A `KeepAlive` supervisor plus a lingering process is a recipe for a port-conflict crash loop; in-flight child `nmap` processes are not reaped on signal. | repo-wide grep for `signal.`/`atexit`/pid file → none; `nmapui/handlers/auto_scan.py:110-128` (scheduler lock only) |
| R6 | **Port drift defeats a watchdog.** Without an explicit `NMAPUI_PORT`, `select_runtime_port` silently moves to `9001+`. A supervisor/health check pinned to 9000 would then see the app as down while it is actually running. The bundle sets the port via the Swift launcher, but a LaunchAgent/daemon must also pin it explicitly. | `nmapui/bootstrap.py:38-54, 57-77` |

### 4.3 Scheduler correctness

| # | Finding | Evidence |
|---|---|---|
| S1 | **Auto-monitor can silently miss runs.** `get_due_auto_monitor_rules` evaluates `next_run(now - 1min) <= now`, so a rule fires only if a 60-second tick lands inside the scheduled minute. Mac sleep, a long-running scan, or loop drift past one minute means **the run is skipped with no catch-up**. | `nmapui/auto_monitor.py:276-293`, `nmapui/handlers/auto_scan.py:66-107` |
| S2 | **Auto-scan can fire repeatedly.** The duplicate guard only applies when `last_run` is set and < 1 h old; a fresh/None `last_run` inside the window re-triggers every minute. | `nmapui/handlers/auto_scan.py:78-86` |
| S3 | No missed-run reconciliation after sleep/wake or reboot; scheduling is wall-clock only (`datetime.now()`), with no timezone/DST handling. | `nmapui/auto_monitor.py:104, 196-240` |

Mitigating strengths: the loop is exception-guarded so a bad tick does not kill it (`handlers/auto_scan.py:104-105`), config writes are atomic (`auto_scan.py:10-15`), and a `flock`-based single-scheduler lock prevents duplicate schedulers across processes (`handlers/auto_scan.py:110-128`).

### 4.4 Operability

| # | Finding | Evidence |
|---|---|---|
| O1 | Liveness exists (`/api/health`, `/api/health/ready` with 200/503) and includes `auto_scan_thread_alive` — a good foundation. | `nmapui/health.py`, `nmapui/handlers/routes.py:90-118` |
| O2 | Log rotation is implemented (10 MB × 5). | `nmapui/app_runtime.py:80-83` |
| O3 | **No alerting.** A red readiness state produces no notification; the nightly failure went unnoticed for 16 days. | eval logs |
| O4 | **Updates are manual only.** `check_for_updates` reports `install_method: "manual_download"` against `techmore/NmapUI`. There is no signed, atomic, rollback-capable upgrade path. | `nmapui/runtime.py:108-148` |
| O5 | Stale state: an orphaned `active-scan.lock` (Aug 23) exists in the support dir but **no code references it**. | filesystem + repo-wide grep |

### 4.5 Repo & standards

| # | Finding | Evidence |
|---|---|---|
| H1 | **Documentation/runtime drift.** `README.md` documents Node/`sudo npm start`; `install.sh` installs Node and never creates the venv or runs `pip install -r requirements.txt`; `Dockerfile`/`docker-compose.yml` run `node server.js`; `AGENTS.md` and CI describe Flask. There is no single truthful quick-start. | files |
| H2 | `install.sh:213` — the installer's final instruction is `sudo npm start`. For the Flask product this is simply wrong. | `install.sh` |
| H3 | **543 MB `.git`**, driven by a tracked 47 MB `releases/TM-NmapUI.zip`. | `du`, `git ls-files` |
| H4 | CI has no lint/type gate despite `AGENTS.md` prescribing `flake8`/`black`/`mypy`. | `.github/workflows/ci.yml` |
| H5 | **Root-level module sprawl with one real fork.** `persistence.py`, `customer_fingerprint*.py` are **live** (imported upward by the `nmapui/` package) and merely misplaced at root — not duplicates. The genuine fork is root **`google_drive.py` (724 lines) vs `nmapui/google_drive.py` (541 lines)**: same public API, ~7 KB of divergence in OAuth/token/upload code, kept alive only by the legacy `server.js`. The Flask app and tests use `nmapui.google_drive` exclusively. `test_generate_report.py` is a manual Socket.IO client outside `testpaths` and asserts nothing. | `app.py:13,126`; `nmapui/reporting.py:12`; `build.sh:278-284`; `google_drive.py:50-113,641` vs `nmapui/google_drive.py`; `pytest.ini:2` |
| H6 | Untracked clutter present: `.hermes/`, `docs/notes/eval-logs/`, `data/`, `config/customers.yaml`, 247 MB `packaging/macos/.build/`. | `git status` |
| H7 | **Brittle "contract" tests.** `tests/test_runtime_contract.py` is 104 KB of assertions on **source text** (e.g. `assert "build_event_helpers(" in app_source`). These pass or fail on refactoring minutiae, not behaviour, and give false confidence about a system whose real risk is runtime/privilege behaviour. | `tests/test_runtime_contract.py:546, 1046-1054` |

### 4.6 Security notes (beyond privilege)

- `auth.py` compares credentials with `==` (not constant-time) — low practical risk, easy fix.
- The eval script's blocked-path JSON lists 3 scenarios while the success path lists 4, so reports are schema-inconsistent (`nightly_product_eval.sh:167-186, 200-205`).
- The loopback trust model is defensible for a single-user desktop app **only if the server is not root** (see P4).

### 4.7 Performance notes

Confirmed by direct inspection here and quantified further in §10.3. Top risks at realistic scale (200-1,000 hosts):

| # | Finding | Evidence |
|---|---|---|
| F1 | **Nmap XML is parsed 4+ times per report, and 2× per historical scan on every new report.** No caching; unchanged diffs are re-parsed on every history request. | `nmapui/reporting.py:221-222, 279-282, 786, 870`; `nmapui/runtime_history.py:155-183` |
| F2 | **List endpoints deserialize `payload_json` including a full per-scan `asset_snapshot`.** 50 saved scans can mean ~400 MB per request. | `nmapui/runtime_db.py:403-428`; `nmapui/reporting.py:797-801` |
| F3 | **No global scan concurrency limit** — a daemon thread per client scan/report on a threaded Werkzeug server, each able to launch nmap + Chromium. | `nmapui/handlers/scan_jobs.py:55,101,111`; `nmapui/jobs.py:135-161` |
| F4 | **Frontend rebuilds the whole table and re-persists all results on every per-host event** (O(N²) lookups, uncapped log rebuilds). | `static/js/table_sorter.js:106-168, 251-261`; `static/js/discovery_ui.js:174-178, 208-222`; `static/js/audit_log.js:3, 93-138, 229` |
| F5 | **Retention is manual-only and chunked-scan intermediates are never deleted**, so months of scanning grow without bound. | `nmapui/runtime_db.py:737-764`; `nmapui/workflows.py:596,660`; `nmapui/reporting.py:400-430` |

### 4.8 Strengths to preserve

A remediation plan should not break what already works. Confirmed good:

- **Green, fast, hermetic unit suite:** 329 pass in ~13-19 s with no real network/nmap calls (browser/packaged suites are env-gated and run in CI).
- **SQLite runtime store is well built:** WAL journal, `busy_timeout=5000`, explicit `synchronous`, `foreign_keys=ON`, per-operation connections behind a `@contextmanager` that always closes, schema versioning + migrations, and an export/backup path. | `nmapui/runtime_db.py:12-13, 125-146, 161`
- **Scheduler thread is exception-guarded** and guarded by a `flock` single-scheduler lock, so one bad tick cannot kill it and two processes will not double-schedule. | `nmapui/handlers/auto_scan.py:66-107, 110-128`
- **Atomic config writes** via temp-file + `replace`. | `nmapui/auto_scan.py:10-15`
- **Real health endpoints** with distinct liveness and readiness semantics (200/503) that already report `auto_scan_thread_alive`. | `nmapui/health.py`
- **Log rotation** (10 MB × 5). | `nmapui/app_runtime.py:80-83`
- **Loopback-only binds by default** (`NMAPUI_HOST=127.0.0.1`) with an explicit CORS allowlist and a per-boot Socket.IO handshake token. | `nmapui/bootstrap.py:16-25, 57-59`; `app.py:156-161`; `nmapui/handlers/connections.py:88-98`
- **Secrets encrypted at rest** for Google Drive tokens and the remote-sync key (per release note); `build.sh` bundles a venv and Playwright browsers deterministically.
- **Security headers + path-traversal containment** already present (CSP, `X-Content-Type-Options`, `Referrer-Policy`; `resolve_scan_path` confines to the scans dir), plus a target-budget DoS guard with tests. | `app.py:166-179`; `nmapui/paths.py:36-52`; `tests/test_scan_budget.py`

---

## 5. Target architecture

**Principle: the web server runs as the logged-in user, never as root. Only the scanner is privileged.**

```
launchd (user LaunchAgent, RunAtLoad + KeepAlive)
  └─ runs .venv/bin/python app.py  as the console user, loopback only
       ├─ HTTP/Socket.IO control surface (authenticated or explicit local trust)
       └─ privileged scan requests
            └─ ONE of:
               (a) scoped sudoers allowlist  -> sudo -n nmap/arp-scan   [recommended, least code]
               (b) privileged helper script  -> validates a structured JSON scan request,
                                                builds argv itself, runs nmap as root  [hardening step]
```

Why (a)/(b) over running as root:

- Removes P4 (root RPC surface) entirely.
- Removes the admin password prompt (P2): a one-time `install.sh --privileged` step writes `/etc/sudoers.d/nmapui` with `NOPASSWD` for exact command paths, then the daemon/agent starts silently forever after.
- Keeps SYN/OS/ARP capability (fixes P1/P3 by always invoking the privileged path with an unprivileged fallback on failure).
- **Caveat to document:** `NOPASSWD nmap` is effectively root-equivalent (NSE scripts, `--script`, output writes). Mitigation is (b): a helper that accepts no arbitrary flags, or an allowlist that pins the exact `nmap` binaries and validates the argument vector. This is a decision point for you (§6).

**Supervision:** a user LaunchAgent (not LaunchDaemon) with:

- `RunAtLoad = true`, `KeepAlive = true` (with `ThrottleInterval` for crash-loop backoff),
- explicit `EnvironmentVariables` incl. `PATH`, `NMAPUI_DATA_DIR`, `NMAPUI_LOG_DIR`,
- `StandardOutPath`/`StandardErrorPath` under the support dir,
- `ProcessType = Background`.

A Launch**Daemon** would only be needed if scans must run while nobody is logged in; note that on macOS Nmap needs the network stack and works fine from a user agent, but a daemon cannot use the login keychain and would need root-owned data dirs. Recommend the agent unless "scan while logged out" is a hard requirement.

**Self-verification:** the nightly eval must boot the **Flask** app (absolute `.venv/bin/python`, absolute paths, no `npm`), probe loopback endpoints, and **notify on failure** (see §9 P5).

---

## 6. Decisions (locked 2026-09-10)

1. **Privilege approach:** scoped `sudo -n` allowlist now; validating helper remains future hardening.
2. **Scans while no user is logged in?** **Yes — this is an appliance.** A **system LaunchDaemon** is therefore required (not a user LaunchAgent).
3. **Product shape:** one backend (**Flask + web UI**) is the cross-platform product; the **Swift menu-bar app is an optional Mac launcher**, not a second product. A native SwiftUI frontend, if pursued, is a separate frontend against the same API — not a rewrite of the scan engine.
4. **Canonical repo:** **`techmore/TM-NmapUI`** (update check, download fallback and docs repointed).
5. **Alerting:** launchd `KeepAlive` for restarts plus durable runtime-log records for now; an optional webhook is deferred.
6. **Hard requirement:** the appliance must run **over a year without re-authenticating** and without a password prompt. That drives the long-lived session cookie (§Phase 4.2, implemented) and the prompt-free privilege path.

**Note:** `install.sh` still installs the Node toolchain and does not create the venv; the appliance path is currently `install-daemon.sh` (which requires an existing `.venv`, created by `build.sh`). Reconciling `install.sh` remains Phase 5.1.

---

## 7. Remediation plan (phased, prioritised)

Ordering is by "does it restore unattended operation". Each phase ends with a reproducible check.

### Phase 0 — Restore the core promise (hours)

These are correctness fixes with no dependency on the privilege decision, so they are implemented first on branch `fix/unattended-operation`.

| Task | Deliverable | Acceptance | Status |
|---|---|---|---|
| 0.1 Fix scheduled auto-scan (C1) | `execute_auto_scan` runs server-side via `generate_report_task(AUTO_SCAN_SID, {...})` like `execute_auto_monitor_rule`; UI notified with a broadcast; `last_run` written only after the job is enqueued | A scheduled tick with **no clients connected** creates a real job + scan artifacts; contract test replaced | **done** |
| 0.2 Never `sys.exit` on missing tools (C4) | `check_nmap`/`check_vulners` return status, append to `startup_state["errors"]`, start degraded; readiness returns 503 | App serves HTTP with nmap absent; `/api/health/ready` says why | **done** |
| 0.3 Fix the nightly eval to boot Flask | `scripts/nightly_product_eval.sh` uses the venv interpreter + `app.py`, waits on `/api/health/ready`, absolute paths, consistent JSON schema, clear stderr on failure | One green `--run`; JSON shows all pass scenarios; broken port yields a clear report | **done** |
| 0.4 Ignore runtime state | `.gitignore` covers `data/`, `.hermes/`, `docs/notes/eval-logs/`, `config/customers.yaml`, `*.sqlite3`, `NmapUI.app/` | `git status` clean of runtime data | **done** |
| 0.5 Confirm baseline | Record commit + `pytest` result | Green suite on the branch: **335 passed, 8 skipped** (was 329 passed at review) | **done** |

**Phase 0 evidence (branch `fix/unattended-operation`, base `07221dde`):**

- `pytest -q` → **335 passed, 8 skipped in 13.33s**.
- `scripts/nightly_product_eval.sh --run` → **4/4 scenarios pass**, exit 0, port 9000 released (`lsof` clean).
- C1: `execute_auto_scan` now calls `job_registry.start(AUTO_SCAN_SID, "report", …)` then `generate_report_task(AUTO_SCAN_SID, …)`; `last_run` is written only after enqueue. Tests assert a real job is enqueued, that a busy job is skipped without recording a run, and that the broken `trigger_generate_report` emit is gone.
- C4: `check_nmap` returns `None` and `check_vulners` returns `False` instead of `sys.exit(1)`; `startup_state["errors"]` is populated and `dependencies_ok` reflects nmap + vulners, so readiness returns 503 instead of the process dying.
- 0.4: `.gitignore` now covers `data/`, `*.sqlite3`, `.hermes/`, `config/customers.yaml`, `docs/notes/eval-logs/`, `NmapUI.app/`; `git status` shows no runtime state.

### Phase 1 — Privilege without prompts (implemented on branch)

**Status:** 1.1-1.3 done — `nmapui/privileged.py` owns the prefix and the technique slot; `sudo -n` never prompts; a denied privileged scan retries as `-sT` with the full option list intact. 1.5 done — the wrapper's admin-privilege launch is deleted. 1.4 done — `install-daemon.sh` writes the scoped sudoers rule (visudo-validated) for `--user` mode; the default daemon runs as root so no sudo is needed at all. 1.6 documented in §10.1 (root-equivalent within nmap; validating helper remains Phase 1b hardening).

| Task | Deliverable | Acceptance |
|---|---|---|
| 1.1 Add a privilege abstraction | `nmapui/privileged.py`: resolve nmap/arp-scan to absolute paths, decide `sudo -n` vs direct, expose `scan_argv()` | Unit tests for root / passwordless / unprivileged |
| 1.2 Route all scans through it | `scanning.py` uses the abstraction for every nmap/arp-scan call | No hardcoded `-sS` without fallback |
| 1.3 Always keep a fallback | If privileged invocation returns permission-denied, retry `-sT` and **emit a visible warning** | Test simulated denial → scan still completes, user informed |
| 1.4 One-time sudoers install | `install.sh` (or `--privileged` subcommand) writes `/etc/sudoers.d/nmapui`, mode 0440, validated with `visudo -cf` | `sudo -n nmap --version` succeeds after install, no prompt |
| 1.5 Stop running the server as root | `build.sh`/Swift launch path drops `with administrator privileges`; server runs as console user | `ps -o user= -p <pid>` shows the user, not root |
| 1.6 Document the root-equivalence caveat | Security note in README + `docs/audits/` | Reviewed in plan doc |

### Phase 2 — Durable supervision & recovery (2.1-2.4 done, 2.5-2.6 open)

**Status:** `packaging/macos/install-daemon.sh` installs a system LaunchDaemon with `RunAtLoad` + `KeepAlive` + `ThrottleInterval` (2.1), so the server comes back after a crash and starts at boot with nobody logged in (2.2). Readiness polling and log paths are wired to `/api/health/live` and `/Library/Logs/NmapUI` (2.3). The wrapper attaches to the daemon instead of fighting it for port 9000. **2.4 done** — `nmapui/recovery.py` marks jobs left `running`/`cancelling` by a previous process as `interrupted` at startup (they used to replay as a permanently-running job that disabled the report button), and tracked child `nmap`/`arp-scan` processes are terminated on SIGTERM/SIGINT/exit (signal handlers skipped under pytest and off the main thread). Duplicate-install cleanup (2.5) and recoverable-port fallback (2.6) are open.

| Task | Deliverable | Acceptance |
|---|---|---|
| 2.1 LaunchAgent for the server | `packaging/macos/com.techmore.nmapui.server.plist` template + installer step; `RunAtLoad`, `KeepAlive`, `ThrottleInterval` | `launchctl kickstart -k` restarts; `kill -9` → auto-restart within seconds |
| 2.2 Reboot test | Documented procedure | Reboot → server up with no interaction, no password |
| 2.3 Health-based watchdog | Agent or Swift-side poll of `/api/health/ready` with backoff restart | Simulated hang → restart + log entry |
| 2.4 Orphan/zombie reaping (H3, H4) | SIGTERM/SIGINT/`atexit` handlers terminate the registered process tree; on startup mark persisted `running`/`cancelling` jobs `interrupted` and kill stray nmap PIDs; clean the orphaned `active-scan.lock` | Orphaned nmap after `kill -9` is gone on next boot; no stale "report running" UI |
| 2.5 Remove duplicate installs | Installer refuses/cleans a second bundle | Only one bundle on disk |
| 2.6 Recoverable port (H8) | Probe-and-skip to the next free port for the bundled entrypoint; log and pass the resolved port | Stale listener on 9000 does not prevent startup |

### Phase 3 — Scheduler correctness (1-2 days)

| Task | Deliverable | Acceptance |
|---|---|---|
| 3.1 Last-run-based due calculation | Replace the 60-second-window test with "next scheduled time after `last_run` is <= now" | Test: skip 3 days (sleep/off) → exactly one catch-up run |
| 3.2 Catch-up policy | Explicit `run_missed` on/off (default on, once) | Unit tests for daily/weekly/monthly |
| 3.3 Idempotent execution | Persist `last_run` **before** starting the scan, in the job store, keyed by rule+slot | No duplicate runs across restarts |
| 3.4 Timezone/DST | Schedule in local time via an awareness helper; test DST boundary | Tests for spring-forward/fall-back |
| 3.5 Unify the two schedulers | One scheduling model for auto-scan and auto-monitor | Single code path + tests |

### Phase 4 — Security hardening (1-2 days)

| Task | Deliverable | Acceptance |
|---|---|---|
| 4.1 Constant-time credential compare | `hmac.compare_digest` in `auth.py` | **done** |
| 4.2 First-run credentials + no re-auth | Installer generates a strong password (0600) ; long-lived signed session cookie (400 days) via `/login`, so the browser signs in once and stays signed in | **done** — verified live: 401 without creds, 200 with cookie/Basic, 401 on bad password, `Max-Age=34560000` |
| 4.3 Reassess `NMAPUI_TRUST_LOCAL_UI` | Default off in the packaged run; make local trust opt-in and logged loudly | **done** — removed from `build.sh`; the bundle bootstraps credentials instead |
| 4.4 Authenticate socket surface | Require a session (cookie/Basic) on Socket.IO `connect` and `get_initial_data`, and on `/api/socket-token` | **done** — the token is now CSRF-only; verified live: token 401 without creds, 200 with session/Basic |
| 4.5 Secrets at rest review | Confirm token/key file modes (0600) and that nothing logs secrets | Audit note |
| 4.6 CSP/XSS pass | Address known issue class (CSP header, `innerHTML` audit) | Header present; no unescaped sink |

### Phase 5 — Repo truth & standards (2-3 days)

| Task | Deliverable | Acceptance |
|---|---|---|
| 5.1 Single source of truth for docs | Rewrite `README.md` around Flask + macOS wrapper; fix `install.sh` (create `.venv`, `pip install -r requirements.txt`, `python -m playwright install chromium`, LaunchAgent, sudoers); align `Dockerfile`/`compose` to Flask (`CMD ["python","app.py"]`, healthcheck on `/api/health/ready`, honor `NMAPUI_PORT`); correct the `AGENTS.md` code map and `BUILDING.md` packaging story | Fresh-clone walkthrough works end-to-end; container healthcheck passes |
| 5.2 Archive the Node tree | Tag `archive/webshell`, move `server.js`, root `index.html`, `static/js`, `package*.json`, `scripts/ensure-dependencies.js`, `nmap.sh` out of the product path | Product tree has one runtime |
| 5.3 Remove the real duplicate | Delete root `google_drive.py` (fork, legacy-only; Flask uses `nmapui/google_drive.py`) and the manual `test_generate_report.py`. **Keep** `persistence.py` and `customer_fingerprint*.py` — they are live; optionally relocate them under `nmapui/` and update importers | `grep` shows no legacy-only importers; tests green |
| 5.4 CI quality gate | Add `flake8` + `black --check` (+ `mypy` once configured) as a CI job; reconcile `.flake8` 160 → 88 (only 2 lines currently exceed 160); pin one Python version | CI fails on lint regressions |
| 5.5 Shrink the repo & fix ignores | Move the 47 MB `releases/TM-NmapUI.zip` to a GitHub Release asset; add `data/`, `.hermes/`, `logs/`, `*.sqlite3`, `config/customers.yaml`, `docs/notes/eval-logs/`, `NmapUI.app/` to `.gitignore`; `git rm --cached` anything already staged; `git worktree prune` | `.git` materially smaller; `git status` clean of runtime data |
| 5.6 Branch hygiene | Retire stale branches per the 2026-08-22 triage; prune the dead `/private/tmp/nmapui-swift` worktree; make one canonical repo | `git branch -r` ≤ 4 |
| 5.7 Test gaps (unattended critical path) | Add five tests: (1) scheduler restart/downtime catch-up for `execute_auto_monitor_rule` (currently zero coverage), (2) cross-process scheduler-lock contention + dead-owner recovery, (3) privileged nmap failure modes (missing binary, permission denied, timeout, orphan reaping), (4) disk-full / corrupt-SQLite resilience in the scheduler loop, (5) truthful `/api/health/ready` when nmap/arp-scan/Vulners are absent. Replace source-text contract assertions with behavioural ones over time | All five exist and fail when the behaviour regresses |

### Phase 6 — Performance & scale (as needed)

Folded in from the performance audit (§10). Priorities: parse Nmap XML **once** per scan, avoid per-host XSLT/subprocess spawns, bound SQLite connection handling under the Socket.IO threading model, cap broadcast payloads, and add retention/compaction for the runtime DB and `data/scans/`.

### Phase 7 — Safe upgrades (later)

Signed/atomic install, versioned data dir, backup before migrate, documented rollback (the `releases/` known-good zip is the seed of this), and `check_for_updates` pointing at the canonical repo with a verified download path.

---

## 8. Verification strategy

- **Unit/contract:** extend `pytest` for privilege resolution, scheduler catch-up, DST, auth posture.
- **Integration:** boot the Flask app on a scratch port as a non-root user, run a scan against `127.0.0.1`, assert XML+HTML+PDF artifacts.
- **Unattended soak:** LaunchAgent running for ≥ 72 h with `KeepAlive`; forcibly `kill -9` the server and the Mac sleep/wake cycle; assert auto-recovery and that scheduled runs fired exactly once.
- **Nightly eval:** the repaired `nightly_product_eval.sh` becomes the regression sentinel, with failure notification (Phase 0.1 + O3).
- **Reboot check:** documented manual step, then automated if possible.

---

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| `NOPASSWD nmap` is root-equivalent | Validating helper (Phase 1.1b); pin absolute binaries; document the trust boundary; keep server non-root |
| Root LaunchDaemon needed for logged-out scans | Decide in §6.2; if required, isolate data dir and keychain usage explicitly |
| Deleting the Node tree breaks a user's workflow | Archive tag first; one release of overlap; release note |
| Large `reporting.py` / `workflows.py` rewrites destabilise behaviour | Lock behaviour with tests first (Phase 0 baseline is green), change incrementally |
| macOS permissions (Full Disk Access / Network) not grantable unattended | Preflight check in `startup_checks.py` surfaces the exact missing permission in `/api/health/ready` |
| Auto-update bricking a remote Mac | Atomic swap + versioned data + rollback to known-good zip |

---

## 10. Deep-dive audit annexes

The four focused audits are appended below as they complete (security/privilege, unattended reliability, performance, standards/hygiene). Each lists severity, `file:line` evidence, and remediation, and is intended to feed the phase tables above.

### 10.1 Security & privilege audit

Severity roll-up: **1 Critical · 4 High · 9 Medium · 8 Low** (plus 5 explicitly unconfirmed suspicions). Confirms P1-P6 above and adds H2/H3/H4/M1/M3/M5/M6/M9. Baseline: non-root user, nmap 7.991 present.

**Critical**

- **C1 — the packaged macOS product runs the entire Flask server as root with `NMAPUI_TRUST_LOCAL_UI=true` and no credentials.** `NmapUIMenuBarLauncher.swift:166,426-441`; `build.sh:367-371`; `nmapui/auth.py:30-77,121-135`; `nmapui/handlers/routes.py:80-88`. Any local process passes `remote_addr == 127.0.0.1`, so it can call `POST /api/settings`, `DELETE /api/runtime/history/<path>`, the retention and Google-Drive upload endpoints, and every Socket.IO event **as root**. The launcher also falls back to user-mode if the admin prompt is declined, but the trust flags apply in both modes. *Fix:* de-root the server; keep `python3 app.py` as the console user plus a narrow privileged-exec helper (setuid-root / SMJobBless XPC) or a scoped sudoers rule; delete `NMAPUI_TRUST_LOCAL_UI=true`; provision a per-install random credential in the Keychain. If local trust must stay, refuse to start when `geteuid()==0`.

**High**

- **H1 — privileged scanning requires the whole server to be root, and the euid-based technique chooser is dead code.** `nmapui/workflows.py:604` unconditionally sets `force_privileged_scan=True`, and `nmapui/scanning.py:271-274` gives it precedence, so `get_nmap_scan_technique()` (`:33-40`) is bypassed and `-sS` is requested even when non-root. Zero `sudo`/`setuid`/`CAP_`/helper usage exists in the Python runtime. Non-root nmap returns *"You requested a scan type which requires root privileges."* and only the fragile stderr fallback (H2) recovers.
- **H2 — the privileged→unprivileged fallback destroys `--exclude` and the retry still fails.** `nmapui/scanning.py:323-324` inserts `--exclude` at index 1; `:364-365` then does `fallback_cmd[1] = "-sT"`, overwriting the flag and leaving the exclusion list as a positional target while the original `-sS` remains. Verified argv: `["nmap","--exclude","10.0.0.5,10.0.0.9","-sS",…]` → `["nmap","-sT","10.0.0.5,10.0.0.9","-sS",…]`, which still fails as non-root. **A scope-safety control is inverted.** *Fix:* one argv builder that owns the technique slot; unit-test that the fallback preserves `--exclude` and contains exactly one `-sS/-sT`.
- **H3 — Socket.IO `connect` and `get_initial_data` bypass `require_socket_auth`, and the "loopback token" is fetchable by any local process.** `nmapui/handlers/connections.py:88-98,188-241`; `nmapui/handlers/routes.py:80-88`. With credentials set, a local process still fetches the token and receives `customer_info`, `network_key`, persisted job state, and the full replay buffer (`scan_raw_output`, `cve_array`, `scan_results`). Treat the token as CSRF protection only. *Fix:* decorate `on_connect`/`on_get_initial_data`; don't replay to unauthenticated sockets.
- **H4 — Chromium runs with `--no-sandbox` as root rendering report HTML that loads remote CDN scripts.** `nmapui/reporting.py:559-561,566-569`; `nmap-modern.xsl:81,89-97` (jQuery/DataTables/pdfmake/jszip; only jQuery has an integrity hash). A composed, not-demonstrated, chain to root code execution. *Fix:* drop `--no-sandbox`, render as non-root, abort non-`file://` requests in the Playwright context, vendor/SRI-pin report assets.

**Medium (selected)**

- **M1** — `scan_only_mode` is silently overridden: `workflows.py:480-485` announces "forcing unprivileged scan technique" but `:600-604` also sets `force_privileged_scan=True`, which wins. Contradictory feedback and a defeated least-privilege control.
- **M2** — `/api/runtime/logs` and `/api/runtime/settings-summary` have no `@require_auth` and leak targets, paths, customer names, and exception strings.
- **M3** — `assign_report_to_customer` (`nmapui/handlers/customers.py:355-391`) writes `metadata.json` into a **caller-supplied `report_path`** with no `resolve_scan_path` containment, unlike the HTTP report routes.
- **M4** — `origin_is_local_ui()` is substring matching and treats a **missing** Origin as trusted (`nmapui/auth.py:63-66`); the Host allowlist is what actually blocks DNS rebinding. Do not treat it as a boundary.
- **M5** — `NMAPUI_SOCKET_AUTH_DISABLED` is an undocumented production bypass.
- **M6** — no guardrail on `NMAPUI_HOST=0.0.0.0` + `NMAPUI_DEBUG` (Werkzeug debugger = RCE) or insecure defaults; the packaged default already forces the non-production Werkzeug server.
- **M7** — encryption keys sit beside their ciphertext in `DATA_DIR`, and files are `chmod 0600` after write rather than created with `O_EXCL, 0600`. *Fix:* Keychain, or a separate 0700 dir.
- **M8** — the container path runs the unaudited Node app with `NET_ADMIN`/`NET_RAW`, so hardening of the Python runtime does not apply there.
- **M9** — `run_quick_auto_scan` is latent (no callers) but hardcodes `-sS` with no check/fallback.

**Low (selected):** non-constant-time secret comparisons (`auth.py:95`, `google_drive.py:249`); unbounded `max_scan_minutes` (`settings.py:194`) that can pin the scheduler; an SSRF-shaped settings validation call (`settings.py:348-357`); an unescaped `innerHTML` sink (`static/js/reports_tab.js:439`); legacy plaintext API key may persist (`settings.py:236-258`); scan-folder collision overwrites within the same second (`scanning.py:113-123`); cancellation kills only the direct child, not the process group (`jobs.py:352-364`).

**Security audit's fix order:** C1 → H1+H2 → H3+M2+M3 → H4+M6 → the rest.

**Warning to preserve:** the security audit could not build a remote-web-page exploit of `NMAPUI_TRUST_LOCAL_UI` (Host allowlist + CORS + token hold), and found no report-content→script injection (0 `disable-output-escaping` in the stylesheets). The Origin substring rule is the most plausible weak link — do not treat it as a boundary.

### 10.2 Unattended reliability audit

Severity roll-up: **4 Critical · 8 High · 10 Medium · 4 Low.** Confirms R1-R6/S1-S3 above and adds the more severe items below.

**Critical**

- **C1 — Scheduled auto-scan is a silent no-op that records success** (see §3.1). `nmapui/auto_scan_runtime.py:45-52`; `nmapui/events.py:4-12`; no listener anywhere; `tests/test_backend_modules.py:305-348` locks in the broken contract. *Fix:* call `generate_report_task(AUTO_SCAN_SID, {...})` server-side as `execute_auto_monitor_rule` does; notify the UI with `socketio.emit(..., broadcast=True)`; set `last_run` only after the job is enqueued; assert a job record exists after a scheduled tick with no clients connected.
- **C2 — No boot persistence and no crash restart.** No launchd/systemd unit in the repo; the Swift wrapper never relaunches a dead process (`NmapUIMenuBarLauncher.swift:48-53, 325-378`); `README.md:58` login-item/uninstall claims are unimplemented (`:270-277`). The two installed LaunchAgents point at non-product binaries.
- **C3 — The Docker/Compose path cannot run the authoritative runtime.** `Dockerfile:22-23` `npm ci`, `:38` `CMD node server.js`, never installs `requirements.txt`; healthcheck probes `/api/app-identity`, which exists only in `server.js:73`. See drift D3-D5.
- **C4 — Missing nmap/vulners at startup calls `sys.exit(1)`** and kills the whole app before it can serve (`nmapui/scanning.py:74,82,93`; `nmapui/app_runtime.py:114-116`). *Fix:* return status + append to `startup_state["errors"]`, start degraded, let `/api/health/ready` return 503.

**High**

- **H1 — No missed-run catch-up** after sleep/reboot (also S1). A tick must land inside the exact scheduled minute.
- **H2 — Auto-monitor runs the entire scan+report synchronously on the scheduler thread** (`nmapui/auto_scan_runtime.py:126-136` → `nmapui/workflows.py:376`), blocking all other due rules and the auto-scan tick for up to 120-7200 s. *Fix:* `socketio.start_background_task` / bounded job pool; scheduler only enqueues.
- **H3 — Zombie persisted "running" jobs are replayed to the UI and block report generation** after a crash (`nmapui/jobs.py:176-195` in-memory registry; `nmapui/handlers/connections.py:46-64, 158-166`; `static/js/report_generation_ui.js:94-113,137-143`). *Fix:* mark persisted `running`/`cancelling` jobs `interrupted` at startup.
- **H4 — Orphaned nmap/arp-scan children are never reaped** — no `signal`/`atexit` handlers anywhere; processes live only in the in-memory registry (`nmapui/jobs.py:263-269, 329-371`). *Fix:* SIGTERM/SIGINT/atexit handlers + startup reconciliation.
- **H5 — Readiness cannot detect a dead/hung scheduler, `startup_state["errors"]` is never populated, and the only external sentinel is the broken eval** (also O1/O3). *Fix:* make `ready` require a recent scheduler tick timestamp, populate errors, add alerting.
- **H6 — `auto_scan_config.json` is written inside the app bundle, not `DATA_DIR`** (`nmapui/paths.py:24`), failures swallowed (`nmapui/auto_scan.py:97-103`). Schedule state resets on every app update. *Fix:* move to `DATA_DIR` + one-time migration.
- **H7 — Unbounded growth with manual-only retention.** `apply_retention_policies` (`nmapui/runtime_db.py:737-764`) is reachable only via an authenticated manual endpoint; `data/scans/` has no pruning; **chunked-scan intermediates `scan_chunk_*` are never deleted** after merge (`nmapui/workflows.py:596,660`; `nmapui/reporting.py:400-430`).
- **H8 — An occupied port 9000 is fatal, not recoverable**, despite `README.md:57` claiming fallback (`NmapUIMenuBarLauncher.swift:135-141`; `nmapui/bootstrap.py:38-45`; `app.py:153` raises at import).

**Medium (selected)**

- **M3** — "Self-update" is a manual browser download; `subprocess.run(["open", url])` (`nmapui/handlers/updates.py:47`) does not exist on Linux; `restart_application()` (`nmapui/runtime.py:151-158`) is **dead code** and would inherit the scheduler `flock` fd, disabling scheduling in the new process.
- **M4** — Runtime-DB export copies the whole DB to `/tmp` with `delete=False` (`nmapui/runtime_db.py:193-213`); leaked copies on client disconnect can fill the disk.
- **M6** — Auto-scan window semantics run **hourly** through the window, not once; validation accepts `99:99` (`nmapui/auto_scan.py:121-127, 140-165`).
- **M8** — `last_run` is recorded before scan completion and is not idempotency-keyed, so a crash loses a run and a restart can double-run.
- **M10** — Startup work (dependency checks + a 60 s traceroute) happens **before** the port binds (`nmapui/app_runtime.py:114-116`), so a supervisor's `start_period` can expire first.
- **M9** — `/api/runtime/status` and `/api/runtime/logs` have no `@require_auth`; acceptable only while the server is non-root.

**Low**

- **L1** — `run_quick_auto_scan` is dead code (see corrected P3).
- **L2** — Atomic-write temp files can be orphaned on crash (`nmapui/auto_scan.py:10-15`, `nmapui/settings.py:67,105`, `nmapui/google_drive.py:63,83`).
- **L3** — Stray dev LaunchAgents imply supervision that does not exist.
- **L4** — Contract tests lock in defects C1 and the missing login/restart path.

**Reliability audit's recommended order:** C1 → C2+C4 → C3 → H3+H4 → H1+H2 → H5-H8 → M2/M3. This ordering is adopted in §7.

### 10.3 Performance & scalability audit

Measured baseline (stdlib ElementTree, in-memory): 200 hosts / 4,000 ports / 32k CVE elements = 5.63 MB XML → **0.43 s, ~87 MB peak**; 1,000 hosts / 20k ports / 160k CVEs = 28.22 MB XML → **2.20 s, ~427 MB peak**. Treat peak as an upper bound; the multipliers below are what matter.

**Critical**

- **R1 — every new report re-parses 2 XML files for every historical scan of that customer+target.** `refresh_persisted_diff_summaries` (`nmapui/reporting.py:234-320`, parses at `:279-282`) walks all prior entries unconditionally, then rewrites every `metadata.json` and the whole index. Callers: `reporting.py:710-714, 848-852`, `handlers/scans.py:59-64`. Cost ≈ 2N parses/report → ~86 s CPU at N=100, ~7.3 min at the large scale, plus ~200 transient 87 MB trees.
- **R2 — the current scan XML is parsed ≥4× per report** (`reporting.py:221-222, 786, 870`, plus R1) → ~1.7-8.8 s wasted and 4 simultaneous tree peaks.
- **R3 — a /16 becomes up to 2,048 sequential `nmap -A -sC --script vulners` runs, then merged 2-3× in memory.** `scanning.py:148-161` (split to /29, cap 2048); `workflows.py:31-55, 579-660`; `reporting.py:400-430, 480-509`. MemoryError is plausible at scale. *Fix:* streaming single-parse merge, counters instead of re-reads, stricter address budget, bounded concurrency.
- **R11 — `list_report_artifacts()` always deserializes `payload_json`, which embeds the full per-scan `asset_snapshot`; default limit 500.** `runtime_db.py:403-428`; written at `reporting.py:797-801`. A 200-host snapshot is ~5-15 MB → 50 scans ≈ **400 MB per request**; reached by `/api/runtime/reports`, `/api/runtime/history`, `get_most_recent_scan_xml`, `find_latest_saved_scan_for_pdf`, `app.py:441`. *Fix:* never select `payload_json` for lists; move `asset_snapshot` out of the row.
- **R21 — single process, thread-per-request, and NO global scan concurrency limit.** Flask-SocketIO threading mode → Werkzeug `threaded=True`; a daemon thread per scan/report (`handlers/scan_jobs.py:55,101,111`). Only per-sid bounds (1 scan + 1 report) and a per-sid rate limit (10/h, 300 s). M clients ⇒ M concurrent `nmap -A --script vulners` + M Chromium PDF launches competing for the GIL. *Fix:* global queue with 1-2 workers + admission control; PDF in a process pool.
- **FE1-FE4 — frontend is the other cliff.** Full table re-sort + per-cell `appendChild` rebuild on **every per-host event**, with a `querySelectorAll("thead th")` inside the sort comparator (`static/js/table_sorter.js:106-168, 201-214, 251-261`); O(N²) row lookup via `Array.from(tb.rows).find(...)` per host (`static/js/discovery_ui.js:174-178`); full host list `JSON.stringify` + synchronous `localStorage` write per host (`:208-222`); log panel rebuilds every row on every appended line from an uncapped `logEntries` (`static/js/audit_log.js:3, 93-138, 229`). At N=1,000 these are hundreds of millions of node operations per scan. *Fix:* cached column-index Map, `ip → row` Map, one rAF-coalesced update/persist, incremental log append with a ring buffer.

**High**

- **R4** — XSLT run 2×/scan but **synchronously with no timeout and not cancellable** (`reporting.py:542`); a hung `xsltproc` leaves the job row `running` forever.
- **R5** — a fresh headless Chromium per report plus a 4-engine fallback cascade, no timeouts (`reporting.py:549-653`).
- **R7/R8** — the metadata index is loaded whole, re-sorted, and fully re-written (pretty-printed, ~1.6 KB/entry) on every scan (`persistence.py:29-33, 43-44, 158-183, 247-271, 349-359`); every report rewrites `metadata.json` for all historical scans of that customer+target (`reporting.py:301-303`).
- **R9** — the same heavy XML work runs in **HTTP request threads**: `runtime_history.py:155-183` re-parses 2 XMLs per scan, and its guard skips only non-`None` diffs, so **unchanged scans are re-parsed on every request**; N+1 backfill at `runtime_history.py:36-57, 150`. Exposed via `/api/runtime/history`, `/api/scans`.
- **R12/R13/R14** — ~6,000 SQLite transactions + 6,000 new connections + 24,000 PRAGMAs per deep scan (2 writes per Socket.IO event, `scan_runtime.py:13-22`, `app_bindings.py:67-70`); no connection reuse; missing indexes on the ORDER BY columns (`runtime_db.py:411, 336, 561`).
- **R15** — retention is manual-only and `report_artifacts`/`jobs` are never pruned; `VACUUM` runs in the request thread.
- **R17/R18/R20** — every new scan subscribes **all** connected clients and fans out every event to all; the replay buffer caps 500 *entries* not bytes (full nmap stdout per host); progress is not coalesced (2 DB writes + fan-out per tick). FE13 also has unescaped `innerHTML` interpolation on two report/scan paths.

**Fix order (adopted in Phase 6):** R1+R2+R9+R11 → R21 (+ PDF worker) → FE1-FE4 → R3 → R15+R12+R13+R14 → R4+R5 → R17+R18+R20 → R7+R10+R24+R25+R26.

**Already good:** atomic JSON writes, WAL + retry/backoff, bounded job_events (200) and replay entries (500), tested retention/compact primitives (just unscheduled), per-client isolation with disconnect cleanup, cancellable nmap with timeout + pid tracking, sensible existing indexes, documented VPN-Helper chunking with a hard address budget, lazy Playwright import, and O(1) progress-tick rendering with a 300 ms debounced log fetch.

### 10.4 Standards & hygiene audit

Severity roll-up: **6 High · 9 Medium · 7 Low.** Headline: the repo is a **Flask app wrapped in a Node app's documentation, installer, and container.**

**Source-of-truth drift (each row = a silent failure for a new contributor or an unattended install):**

| # | Claim | Location | Reality | Impact |
|---|---|---|---|---|
| D1 | Runtime is Node; start with `sudo npm start` | `README.md:11,22,133` | Authoritative app is Flask (`app.py`, `start.sh`, CI) | Installer exercises the deprecated app |
| D2 | `./install.sh` installs all deps | `README.md:7-16,42`; `install.sh:12-17,139-154,213` | Installs Node/express/gowitness; **never creates `.venv` or runs `pip install -r requirements.txt`**, never installs Playwright Chromium | Following the README leaves Flask with zero deps; PDF export broken |
| D3 | Container packages the Node runtime | `Dockerfile:1,42` | `FROM node:20` + `CMD node server.js`; CI never builds the image | Container runs an untested, different app |
| D4 | Healthcheck `/api/app-identity` | `Dockerfile:38-39`; `docker-compose.yml:20` | That route exists **only** in `server.js:73`; Flask exposes `/api/health[/live|/ready]` | Porting the image to Flask makes the healthcheck 404 → restart loop |
| D5 | Compose sets `NMAPUI_PORT` | `docker-compose.yml:8` | `server.js:42` reads `PORT`; works only via `Dockerfile:4` | Port overrides silently ignored |
| D6 | Lint is `flake8 .` / `black --check .`, 88 cols | `AGENTS.md:76-77`; `docs/guides/AGENTS.md:42` | `.flake8:1-3` sets **160**; `flake8`/`black`/`mypy`/`isort` not installed; **CI runs no lint/type step** | Documented commands cannot run; "enforced in CI" is false |
| D7 | Code map: scan logic at `app.py:800-2000`, `GoogleDriveService` ~250, `generate_report` ~2500 | `AGENTS.md:27,39-42` | `app.py` is **753 lines**; none of those symbols exist there | Agents edit non-existent code |
| D8 | Build path is PyInstaller | `BUILDING.md`, `deploy.sh` | Real macOS flow is `build.sh` + Swift wrapper bundling a venv; PyInstaller is a third path | Two competing packaging stories |
| D9 | "The current repository does not include the old `build.sh` installer flow" | `README.md:109` | `build.sh` is present (460 lines) and README invokes it at `:117` | Self-contradiction |
| D10 | Canonical root = `app.py`, `requirements.txt`, … | `docs/guides/REPOSITORY_LAYOUT.md:9` | README instead calls `server.js` the "Main local runtime" (`README.md:166`) | Docs disagree on what the repo is |
| D11 | Structure includes `config.json`, `history.json` | `README.md:171-172` | Both gitignored and absent; real state is `data/` + `config/customers.yaml` | Contributor hunts non-existent files |
| D12 | Python 3.8+ | `BUILDING.md:7`; `docs/guides/SETUP.md:21` | CI pins 3.11; checked-in `.venv` is 3.14.7; no `python_requires` anywhere | The version contributors run is never tested in CI |

Measured style exposure: of 12,706 lines in `app.py` + `nmapui/`, only **2 lines exceed 160 chars** and 300 exceed 88 — so retiring the 160-column `.flake8` violation is cheap and the codebase is already close to Black-88.

**Test hygiene:** `tests/conftest.py` is 8 lines (only `sys.path`); no fixtures or network guard, but hermeticity is good by default. Real gaps: `execute_auto_monitor_rule` (`nmapui/auto_scan_runtime.py:59`) has **zero** test references; no restart catch-up, no cross-process lock contention, no privileged-scan failure-mode test, no timeout/orphan-reaping test. `tests/test_runtime_contract.py` is **83 tests / 1104 asserts on source text** — it detects refactors, not regressions (see commit `2828bd36 "fix: stale-runtime-contract-tests"`).

**Code standards (quantified):** good — 0 bare `except`, 0 `print()` in app code, 0 TODO/FIXME, 202 logging calls, 0 mutable module globals. Problems — 67 `except Exception` (**14 silently swallow**, incl. `nmapui/auth.py:155`), **54 functions > 50 lines** (`nmapui/workflows.py:376` is 636 lines), **23 duplicated public symbol names** (`start_scan_task` in three modules), missing type hints on most handler modules, and ~1,824 lines of `app_*` DI wiring around a 753-line `app.py`.

**Repo hygiene:** good — no `.DS_Store`, `__pycache__`, `.build/`, or `data/` is tracked. Bad — `releases/TM-NmapUI.zip` is **47 MB of permanent git history** for a rollback artifact documented as not merged; `data/`, `config/customers.yaml`, `.hermes/`, and `docs/notes/eval-logs/` are **untracked but not ignored** (one `git add -A` from committing real scan data); a prunable dead worktree `/private/tmp/nmapui-swift [swift-native]` and stale remote branches remain.

**Standards audit's immediate highest-leverage fixes** map to this plan's Phase 5.1 (rewrite README/install/container for Flask), Phase 5.4 (CI quality gate), Phase 5.3 (delete root `google_drive.py` fork), Phase 5.5 (offload the 47 MB zip + fix `.gitignore`), and Phase 5.7 (scheduler/privileged tests before unattended rollout).
