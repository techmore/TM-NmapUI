# TM-NmapUI

Network scanning and monitoring appliance for macOS and Ubuntu, powered by Nmap,
with a cross-platform web UI.

The product is a **Python Flask application** (`app.py` + the `nmapui/` package)
running directly on the scanner host and serving a browser UI. macOS has an
optional menu-bar wrapper and LaunchDaemon for unattended operation. Ubuntu is
also a target scanner host; its supported installer and service setup are still
being built. See [deployment status](#cross-platform-deployment).

## Quick Start (macOS appliance)

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

For Ubuntu host setup, see [the setup guide](docs/guides/SETUP.md#ubuntu-scanner-host).

## Quick Start (macOS development)

```bash
./install.sh --no-daemon
./start.sh          # runs .venv/bin/python app.py
```

On Ubuntu, use the manual host setup below instead of the macOS Homebrew installer.

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
- **xsltproc** (Homebrew `libxslt` on macOS; Ubuntu package on Linux)
- **Playwright Chromium**, or Chrome/wkhtmltopdf for PDF output
- macOS or Ubuntu as the intended scanner host; the Swift menu-bar wrapper and
  LaunchDaemon are macOS-only

`install.sh` installs these with Homebrew on macOS. Ubuntu setup is currently
manual; see the setup guide.

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
`last_run` versus the most recent scheduled slot, so a run missed while the
scanner host slept or was powered off is picked up **once** on the next tick
rather than silently skipped.

## Authentication

- Credentials come from `NMAPUI_USERNAME` / `NMAPUI_PASSWORD`.
- Browsers sign in at `/login` and receive a signed, long-lived session cookie.
- API clients can use HTTP Basic auth.
- The server binds to loopback by default. Remote browser access requires an
  explicit `NMAPUI_HOST` and `NMAPUI_ALLOWED_ORIGINS` configuration, valid sign-in,
  and a trusted VPN or HTTPS terminated by a reverse proxy. Socket.IO checks
  the same origin allowlist and the authenticated session.
- `NMAPUI_TRUST_LOCAL_UI=true` disables authentication for loopback callers. It is
  **not** set by the packaged app or the daemon, because every local process is a
  loopback caller.

## Privilege model

The appliance runs as **root** by default. That is the simplest configuration
that works: nothing depends on sudoers, the scanner has full SYN/OS/ARP
capability, and there is no privilege plumbing to fail at 3am.

- `sudo packaging/macos/install-daemon.sh` installs the daemon as root. No
  sudoers entry is written, because none is needed.
- The backend binds loopback by default and requires sign-in (see above); the
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

The scanner-host targets are macOS and Ubuntu. Each host runs the Flask backend
directly with access to its network interfaces, and users can connect through a
browser on another platform. macOS currently has the bundled menu-bar launcher
and LaunchDaemon installer. Ubuntu can run the Flask app manually, but a
supported Ubuntu installer, `systemd` service, privileged scan setup and
deployment validation are still outstanding; track that work in
[the Ubuntu deployment issue](https://github.com/techmore/TM-NmapUI/issues/241).
Windows is not a scanner-host target in the current plan.

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
