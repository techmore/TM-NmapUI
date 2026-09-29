# TM-NmapUI

Network scanning and monitoring appliance for macOS and Ubuntu, powered by Nmap,
with a cross-platform web UI.

The product is a **Python Flask application** (`app.py` + the `nmapui/` package)
running directly on the scanner host and serving a browser UI. macOS has an
optional menu-bar wrapper and LaunchDaemon for unattended operation. Ubuntu is
also a target scanner host; an installer and systemd service candidate now
exist, but live privileged-host validation is still required. See
[deployment status](#cross-platform-deployment).

## macOS appliance candidate

The unattended installer is fail-closed until its host prerequisites pass.
Provision Python 3.11+ and scanner/report tools from a root-owned, non-writable
toolchain; on macOS, linked non-system libraries and Nmap's NSE/data directory
must meet the same rule.
Homebrew tools in a user-owned prefix are suitable for development, **not** for
the root service or privileged helper. Then, from the repository root:

```bash
git clone https://github.com/techmore/TM-NmapUI.git
cd TM-NmapUI
/path/to/root-owned/python3 -m venv .venv  # replace with your protected Python 3.11+
.venv/bin/python -m pip install -r requirements.txt
packaging/macos/install-daemon.sh --dry-run
sudo packaging/macos/install-daemon.sh
```

`install-daemon.sh` installs a system LaunchDaemon and provisions credentials
for optional remote access. It stages a root-owned runtime release and serves
Socket.IO with one threaded Gunicorn worker. The local browser opens without a
username or password. To inspect the generated credentials for optional remote
access:

```bash
sudo cat "/Library/Application Support/NmapUI/credentials.env"
```

Root mode is the default, but it requires both a protected base Python and a
protected service toolchain. The `--user <name>` mode still requires the same
scanner-tool provenance because its helper runs Nmap as root. This host's
user-owned Homebrew Python, scanner binaries and NSE data fail the gate; no service has
been installed here.

Open <http://127.0.0.1:9000> on the scanner host. Loopback access is trusted by
default; remote browser clients still need configured credentials.

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

On Ubuntu, use the Ubuntu service setup instead of the macOS Homebrew installer.

Local access does not require credentials. Set them only when enabling remote
browser or API access:

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
| PDF generation | Playwright Chromium; optional wkhtmltopdf or WeasyPrint fallbacks |
| XML processing | `xml.etree.ElementTree` + `xsltproc` |
| Scheduler | In-process scheduler thread with a cross-process `flock` lock |
| Persistence | SQLite (WAL) plus JSON artifacts |
| macOS shell | Swift menu-bar wrapper (optional launcher) |

## Requirements

- **Python 3.11 or newer**
- **nmap** (with an updated script database)
- **xsltproc** (Homebrew `libxslt` on macOS; Ubuntu package on Linux)
- **Playwright Chromium** for production PDF output; optional `wkhtmltopdf` or
  WeasyPrint fallbacks when installed
- macOS or Ubuntu as the intended scanner host; the Swift menu-bar wrapper and
  LaunchDaemon are macOS-only

`install.sh` installs Homebrew tools for macOS development. It does not
provision a protected production toolchain. Ubuntu's host toolchain must be
prepared before running its service installer; see the setup guide.

## Scans

- **Quick Scan** — fast discovery of live hosts
- **Complete Scan** — full port/service scan with OS detection and vulners CVEs
- **Dragnet Scan** — rescan every host from a previous discovery
- **VPN Helper** — batched Phase 2 for remote, high-latency or very large scopes
  (see `docs/vpn-helper-design.md`)

Reports include host/IP/MAC/vendor, open ports and service versions, detected CVEs
with CVSS scores, and a network topology fingerprint. HTML and PDF are written
under the data directory.

### Vulnerability enrichment and data egress

Complete scans can query Vulners.com over HTTPS for CVE matches. The bundled
NSE script sends detected software/CPE and version details (plus the query
type), not the scanned IP address or hostname; Vulners can still observe the
scanner's outbound public IP and learns part of the internal software
inventory. Managed service installs disable this enrichment by default; an
operator must set `NMAPUI_ENABLE_VULNERS=true` in the protected service
credentials file and restart the service to enable it. The report UI clarifies
that no Vulners results do not prove a host is vulnerability-free. Quick
discovery scans do not invoke the Vulners script. Direct/manual app starts
retain the legacy behavior, with optional enrichment enabled unless an
individual feature flag is explicitly set to `false`.

The topology fingerprint uses outbound network services: a traceroute to
`1.1.1.1` and an HTTPS public-IP lookup at `api.ipify.org`, which learns the
scanner's public IP. Managed service installs disable both by default. To opt
in, set `NMAPUI_ENABLE_NETWORK_FINGERPRINT=true` in the protected service
credentials file and restart the service. Local IP, subnet mask and CIDR
discovery remain available without outbound lookups. Inter and Instrument
Serif are self-hosted, so the app and generated scan reports do not contact
Google Fonts.

The dashboard can check GitHub's latest-release API when a browser connects to
show update notices. Managed service installs disable this check by default; an
operator can set `NMAPUI_ENABLE_UPDATE_CHECK=true` in the protected service
credentials file and restart the service. When enabled, successful results are
cached for six hours per process (one minute after a failed check). The request
reveals the scanner's outbound public IP but does not send scan targets or
results.

PDF rendering disables JavaScript and blocks external network resources in
Playwright; supported fallbacks also disable active scripting and restrict
resource access.

## Scheduling

Auto-scan runs inside a daily window; Auto-Monitor runs per-customer rules daily,
weekly, biweekly, monthly or quarterly. Due-ness is derived from the persisted
`last_run` versus the most recent scheduled slot, so a run missed while the
scanner host slept or was powered off is picked up on the next tick. A failed
report leaves the slot due for a later retry. Scheduled reports run serially
in a worker so a long report does not stop the scheduler clock.
Auto-scan settings are written atomically; failed writes are reported instead
of acknowledged as saved. Queued auto-scan and Auto-Monitor work rechecks the
current rules before it starts, so disabling a rule cancels a pending launch.
Auto-Monitor `last_run` and rule creation times are server-owned; a stale
settings form cannot roll them back and trigger duplicate catch-up scans.

Auto-Monitor defaults accept an IANA time zone such as `America/New_York`.
When set, nonexistent spring-forward times move to the corresponding time
after the clock jump; ambiguous fall-back times use the first occurrence.
Leaving the field blank keeps the scanner host's local-clock behavior.

The service admits at most two active scan/report jobs by default. Set
`NMAPUI_MAX_CONCURRENT_JOBS` to a positive integer to change the limit;
requests above the limit receive a capacity message and can be retried.
Automatic database maintenance runs daily, keeping the newest 5,000 runtime
logs, 2,000 customer history rows and 2,000 finished jobs, and removing events
belonging to pruned jobs. Operators can override those positive-integer limits
in the protected service environment with `NMAPUI_RUNTIME_LOGS_KEEP_LATEST`,
`NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST` and `NMAPUI_FINISHED_JOBS_KEEP_LATEST`;
the installers validate the values. Daily pruning does not run `VACUUM` on the
scheduler thread; use the authenticated **Prune Logs + Compact DB** action when
an explicit database compaction is appropriate. Neither operation deletes
saved reports or scan folders.

## Authentication

- Loopback browser and API access is trusted by default; no sign-in prompt is
  shown on the scanner host.
- Non-loopback browser access requires `NMAPUI_USERNAME` / `NMAPUI_PASSWORD`;
  browsers sign in at `/login`, and API clients can use HTTP Basic auth.
- Changing the configured username or password invalidates existing browser
  sessions; users must sign in again. Upgrading from an earlier build also
  requires one sign-in because its sessions were not bound to credentials.
- Empty credentials and the built-in default password are rejected for remote
  authentication. `NMAPUI_ALLOW_DEFAULT_CREDENTIALS=true` only acknowledges
  that password when local UI trust is enabled and the listener is loopback;
  do not use it with a reverse proxy or network-facing bind.
- The server binds to loopback by default. Remote browser access requires an
  explicit `NMAPUI_HOST` and `NMAPUI_ALLOWED_ORIGINS` configuration, valid sign-in,
  and a trusted VPN or HTTPS terminated by a reverse proxy. Socket.IO checks
  the same origin allowlist and the authenticated session.
- `NMAPUI_TRUST_LOCAL_UI=false` also requires sign-in for loopback callers. With
  the default setting, any local process can reach the scanner control surface;
  keep the service loopback-bound unless remote access is deliberately configured.
- If a reverse proxy forwards remote clients to the loopback listener, set
  `NMAPUI_TRUST_LOCAL_UI=false` before exposing it. Otherwise the backend sees
  the proxy's local connection and may treat remote callers as trusted locals.
  For an HTTPS proxy, set `NMAPUI_COOKIE_SECURE=true` so browser sessions are
  never sent over an accidental plain-HTTP access path.

## Privilege model

The appliance is configured to run as **root** by default for full SYN/OS/ARP
capability, subject to the Python and scanner-toolchain provenance checks.

- `sudo packaging/macos/install-daemon.sh` installs the daemon as root. No
  sudoers entry is written, because none is needed. Root mode requires a
  root-owned, non-writable base Python interpreter.
- The backend binds loopback by default. Loopback access has no separate
  username/password prompt; any process running on the machine can reach the
  control surface. Remote callers still require credentials.
- `--user <name>` opts into least privilege instead: the backend runs as that
  account and sudoers grants `NOPASSWD` for **one validating helper only**
  (`/usr/local/libexec/nmapui-privileged-scanner`), never for `nmap` or
  `arp-scan` directly. That helper re-validates the program, the scan technique,
  every flag, the target, and any `--script`/`--stylesheet`/output path.
- In **both** modes the installer stages root-owned copies of `vulners.nse` and
  the stylesheets with each release under
  `/usr/local/lib/nmapui/current/privileged-assets`, so a writable checkout
  cannot inject Lua into a root-run nmap. The helper requires those trusted
  paths. Existing shared assets under `/usr/local/share/nmapui` remain only as
  a fallback when rolling back to a release installed before this layout.
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

Readiness requires a live scheduler thread. The supervised worker also verifies
its persistent session-signing key before startup; a corrupt or unwritable key
fails the worker rather than silently rotating sessions. Session, Drive and
remote-sync secret files are owner-only. Back up each encrypted token together
with its matching key: a missing key is not regenerated while reading existing
ciphertext.
Startup recovery also has to finish cleanly for readiness to pass; failed
interrupted-job updates leave the service degraded until the underlying storage
issue is resolved and the worker is restarted.

Daemon lifecycle:

```bash
sudo launchctl kickstart -k system/com.techmore.nmapui   # restart
sudo launchctl print system/com.techmore.nmapui          # status
sudo packaging/macos/install-daemon.sh --uninstall       # remove
```

Logs live in `/Library/Logs/NmapUI/` (`server.out.log`, `server.err.log`, and
the rotated application log).

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
  install; `NMAPUI_MIGRATE_DB_FROM=<path>` selects the explicit source database.
  The build takes a consistent SQLite backup, including committed WAL data.
  If the source is already the configured runtime database, no copy is needed.
  Stop any other process using the destination before migrating from a
  different source, and retain a separate pre-upgrade backup for rollback.

## Cross-platform deployment

The scanner-host targets are macOS and Ubuntu. Each host runs the Flask backend
directly with access to its network interfaces, and users can connect through a
browser on another platform. macOS currently has the bundled menu-bar launcher
and LaunchDaemon installer. Ubuntu now has a root-owned installer and
`systemd` unit. A disposable Ubuntu 24.04 ARM64 VM validated the installed
service, authenticated browser/Socket.IO, privileged loopback SYN scanning,
reboot/crash recovery, upgrades, and failed-upgrade/rollback recovery. A real
scanner host must still validate its physical interface and authorized subnet
scan paths, followed by an unattended soak; Ubuntu is **not yet production
ready**. Track that remaining gate in [the Ubuntu deployment
issue](https://github.com/techmore/TM-NmapUI/issues/241).
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
- `packaging/ubuntu/` — systemd service installer candidate
- `packaging/pyinstaller/` — alternative standalone bundle spec
- `docs/guides/`, `docs/notes/`, `docs/audits/` — guides, notes and audits
- `server.js`, `index.html`, `static/js/`, `package.json` — **legacy Node/Express
  build kept only as a rollback reference** (`releases/TM-NmapUI-mac-known-good.md`)

Runtime state (`data/`, `*.sqlite3`, `logs/`, `config/customers.yaml`, eval logs
and app bundles) is gitignored and must stay out of version control.

## License

MIT
