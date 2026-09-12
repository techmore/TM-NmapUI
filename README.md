# TM-NmapUI

macOS-first network scanning and monitoring appliance powered by Nmap, with a
cross-platform web UI.

The product is a **Python Flask application** (`app.py` + the `nmapui/` package)
served over a loopback web UI, plus an optional macOS menu-bar wrapper. It is
designed to run **unattended for long periods**: scans run on a schedule, survive
reboots, and need no password prompt and no repeated sign-in.

## Quick Start (appliance)

```bash
git clone https://github.com/techmore/TM-NmapUI.git
cd TM-NmapUI

./install.sh                              # toolchain + virtualenv + Playwright
sudo packaging/macos/install-daemon.sh    # start at boot, keep alive, no prompts
```

`install-daemon.sh` installs a system LaunchDaemon and generates sign-in
credentials once, printing where to read them:

```bash
sudo cat "/Library/Application Support/NmapUI/credentials.env"
```

Then open <http://127.0.0.1:9000> and sign in once. The session lasts about 13
months, so a browser stays signed in across restarts.

Validate the daemon without changing anything:

```bash
packaging/macos/install-daemon.sh --dry-run
```

## Quick Start (development)

```bash
./install.sh --no-daemon
./start.sh          # runs .venv/bin/python app.py
```

Set credentials before starting, otherwise protected routes return HTTP 503:

```bash
export NMAPUI_USERNAME=admin
export NMAPUI_PASSWORD='choose-something-strong'
./start.sh
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Python 3.11+ |
| Web framework | Flask + Flask-SocketIO |
| Real-time | Socket.IO |
| Scanner | Nmap + NSE (Nmap Scripting Engine) |
| PDF generation | Playwright Chromium, with wkhtmltopdf / Chrome fallbacks |
| XML processing | `xml.etree.ElementTree` + `xsltproc` |
| Scheduler | In-process scheduler thread with a cross-process `flock` lock |
| Persistence | SQLite (WAL) plus JSON artifacts |
| macOS shell | Swift menu-bar wrapper (optional launcher) |

## Requirements

- **Python 3.11 or newer**
- **nmap** (with an updated script database)
- **xsltproc** (Homebrew `libxslt`)
- **Playwright Chromium**, or Chrome/wkhtmltopdf for PDF output
- macOS for the LaunchDaemon and menu-bar wrapper; the web app also runs on Linux

`install.sh` installs these with Homebrew.

## Scans

- **Quick Scan** — fast discovery of live hosts
- **Complete Scan** — full port/service scan with OS detection and vulners CVEs
- **Dragnet Scan** — rescan every host from a previous discovery
- **VPN Helper** — batched Phase 2 for remote, high-latency or very large scopes
  (see `docs/vpn-helper-design.md`)

Reports include host/IP/MAC/vendor, open ports and service versions, detected CVEs
with CVSS scores, and a network topology fingerprint. HTML and PDF are written
under the data directory.

## Scheduling

Auto-scan runs inside a daily window; Auto-Monitor runs per-customer rules daily,
weekly, biweekly, monthly or quarterly. Due-ness is derived from the persisted
`last_run` versus the most recent scheduled slot, so a run missed while the Mac
slept or was powered off is picked up **once** on the next tick rather than
silently skipped.

## Authentication

- Credentials come from `NMAPUI_USERNAME` / `NMAPUI_PASSWORD`.
- Browsers sign in at `/login` and receive a signed, long-lived session cookie.
- API clients can use HTTP Basic auth.
- `NMAPUI_TRUST_LOCAL_UI=true` disables authentication for loopback callers. It is
  **not** set by the packaged app or the daemon, because every local process is a
  loopback caller.

## Privilege model

The appliance runs as **root** by default. That is the simplest configuration
that works: nothing depends on sudoers, the scanner has full SYN/OS/ARP
capability, and there is no privilege plumbing to fail at 3am.

- `sudo packaging/macos/install-daemon.sh` installs the daemon as root. No
  sudoers entry is written, because none is needed.
- The backend binds loopback only and requires sign-in (see above), and the
  local-trust bypass is off, so "root" does not mean "open".
- `--user <name>` opts into least privilege instead: the backend runs as that
  account and sudoers grants `NOPASSWD` for **one validating helper only**
  (`/usr/local/libexec/nmapui-privileged-scanner`), never for `nmap` or
  `arp-scan` directly. That helper re-validates the program, the scan technique,
  every flag, the target, and any `--script`/`--stylesheet`/output path.
- In **both** modes the installer stages root-owned copies of `vulners.nse` and
  the stylesheets in `/usr/local/share/nmapui`, so a writable checkout cannot
  inject Lua into a root-run nmap. The helper requires those paths.
- If the helper is absent (development), the app falls back to `sudo -n nmap`
  and then to an unprivileged `-sT` scan, always surfacing the fallback.

## Administration

Export the runtime database from the Settings tab, or download it directly:

```bash
curl -OJ -u admin:"$NMAPUI_PASSWORD" http://127.0.0.1:9000/api/runtime/export
```

Health and readiness:

```bash
curl http://127.0.0.1:9000/api/health/live
curl http://127.0.0.1:9000/api/health/ready
```

Daemon lifecycle:

```bash
sudo launchctl kickstart -k system/com.techmore.nmapui   # restart
sudo launchctl print system/com.techmore.nmapui          # status
sudo packaging/macos/install-daemon.sh --uninstall       # remove
```

Logs live in `/Library/Logs/NmapUI/` (`server.out.log`, `server.err.log`), plus
the rotated application log in the data directory.

Backfill scan artifacts into the runtime store:

```bash
.venv/bin/python scripts/backfill_runtime_store.py
```

## Nightly self-check

```bash
scripts/nightly_product_eval.sh --run
```

Boots the Flask app on port 9000, probes liveness, identity, the UI and a static
asset, and writes a JSON report under `docs/notes/eval-logs/`.

## Building the macOS bundle

```bash
./build.sh
```

Compiles the Swift menu-bar wrapper, bundles a virtualenv with the Python
resources, and installs `NmapUI.app`. The wrapper attaches to the daemon when it
is running; it never requests administrator privileges.

Build environment variables:

- `NMAPUI_SWIFT_TARGET` — override the Swift target (defaults from `uname -m`)
- `NMAPUI_APPLICATIONS_DIR` — install destination (`/Applications` when writable,
  otherwise `~/Applications`)
- `NMAPUI_SKIP_OPEN=1` — build without launching
- `NMAPUI_MIGRATE_DB=1 ./build.sh` — migrate an existing runtime database during
  install; `NMAPUI_MIGRATE_DB_FROM=<path>` selects the explicit source database

## Cross-platform deployment

The deployment direction is a directly installed Flask backend with access to
the host network, serving the web UI to browsers. Native Linux installation and
service supervision still need validation; the current automated installer is
macOS-specific. Windows scanner-host support has not been established.

Container packaging is retired from the active roadmap (September 11, 2026).
The retained `Dockerfile` and `docker-compose.yml` run the **legacy Node runtime**
and are historical references, not supported installation paths.

## Repository Layout

- `/` — stable entrypoints: `app.py`, `start.sh`, `install.sh`, `build.sh`
- `nmapui/` — application package (scanning, reporting, scheduling, runtime DB)
- `nmapui/handlers/` — HTTP and Socket.IO route registration
- `tests/` — pytest suite, including browser regressions and a packaged smoke test
- `packaging/macos/` — Swift menu-bar wrapper and `install-daemon.sh`
- `packaging/pyinstaller/` — alternative standalone bundle spec
- `docs/guides/`, `docs/notes/`, `docs/audits/` — guides, notes and audits
- `server.js`, `index.html`, `static/js/`, `package.json` — **legacy Node/Express
  build kept only as a rollback reference** (`releases/TM-NmapUI-mac-known-good.md`)

Runtime state (`data/`, `*.sqlite3`, `logs/`, `config/customers.yaml`, eval logs
and app bundles) is gitignored and must stay out of version control.

## License

MIT
