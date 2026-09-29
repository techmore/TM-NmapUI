# NmapUI Setup

NmapUI is a Flask scanner service with a browser interface. The scanner-host
targets are macOS and Ubuntu. The browser can run on another operating system;
the machine running Flask must have direct access to the network interfaces and
scanner tools.

## macOS appliance

For development, install the Homebrew toolchain and Python environment:

```bash
./install.sh --no-daemon
```

Run the web app in development:

```bash
./start.sh
```

Open <http://127.0.0.1:9000>; local access does not ask for a username or
password. To start at boot when nobody is logged in, install
the system LaunchDaemon:

```bash
sudo packaging/macos/install-daemon.sh
```

It runs as root by default for full scanner capability. `--user <name>` selects
the optional non-root service mode with the validating scanner helper. The
installer stages root-owned application code and a Python environment before
switching the daemon to the new release. Check
either configuration without changing system state:

```bash
packaging/macos/install-daemon.sh --dry-run
packaging/macos/install-daemon.sh --dry-run --user "$(id -un)"
```

Root mode refuses a user-owned base Python interpreter (common with Homebrew);
the dry run warns about it. Both root and `--user` modes now also refuse
scanner binaries outside the protected service path or binaries/libraries
writable by another user, including Nmap's NSE scripts and data files. The
standard Homebrew installation on this host does
not satisfy that production gate. Provision a root-owned Python and scanner
toolchain before a root install; `--user` avoids the Python requirement but
still needs trusted Nmap and arp-scan because its helper runs them as root.
Do not run a privileged service from a writable checkout, interpreter, scanner
binary, or linked library.
Existing `credentials.env` records must keep `NMAPUI_DATA_DIR`,
`NMAPUI_LOG_DIR`, and `PLAYWRIGHT_BROWSERS_PATH` at the installer-managed
locations. The installer refuses a mismatch rather than silently starting
with a different data store; migrate any custom state before reinstalling.
Stop any unmanaged server on the configured port before installing. The
installer rejects a foreign listener and verifies that readiness belongs to
the release it just staged.
After an upgrade, the prior release and its matching launcher, helper, sudoers
rule, and plist remain available under the root-owned release archive. To
restore them together, run `sudo packaging/macos/install-daemon.sh --rollback`.
The command checks readiness before swapping the current and previous release
links. Verify this on an installed test Mac before relying on it for recovery.
An upgrade keeps the same daemon account; switching between root and `--user`
requires a planned uninstall and reinstall so data ownership cannot be changed
mid-upgrade. Uninstall preserves data and staged release archives but refuses
unmanaged service files or a non-managed `current` path; it removes both release
links.

## Ubuntu scanner host

The Ubuntu 24.04 LTS installer candidate uses one root-owned, single-worker
Gunicorn service with direct host networking. A disposable Ubuntu 24.04 ARM64
VM has validated installation, authenticated UI/Socket.IO, a privileged
loopback SYN scan, reboot/crash recovery, upgrades, and failed-upgrade and
failed-rollback recovery. A real scanner host is still required to validate
its physical interface, authorized subnet discovery (including the chosen
SYN/OS/ARP paths), and unattended soak before calling this production-ready;
track that gate in [issue #241](https://github.com/techmore/TM-NmapUI/issues/241).
Prepare the host from the repository root:

```bash
sudo apt update
sudo apt install -y build-essential python3-dev git curl python3 python3-venv python3-pip nmap arp-scan xsltproc traceroute
python3 --version  # Confirm this is 3.11 or newer
/usr/bin/python3 -m venv .venv  # root-owned system interpreter
.venv/bin/python -m pip install -r requirements.txt
sudo .venv/bin/python -m playwright install-deps chromium
packaging/ubuntu/install-service.sh --dry-run
sudo packaging/ubuntu/install-service.sh
```

The installer stages the runtime under `/opt/nmapui/releases/`, switches
`/opt/nmapui/current`, installs Chromium in `/opt/nmapui/playwright-browsers/`,
and keeps credentials in `/etc/nmapui/nmapui.env`. Mutable state and logs stay
under `/var/lib/nmapui/` and `/var/log/nmapui/`. Its systemd unit restarts on
failure, contains scan subprocesses in the service cgroup, and protects the
release directory from writes. It runs as root for SYN/OS/ARP scanning; the
privileged loopback SYN path passed in the disposable VM, but scanning the
real host's interfaces and authorized subnet has not. Startup readiness probes
the configured bind address, including interface-specific and IPv6 binds.

```bash
sudo systemctl status nmapui
curl -fsS http://127.0.0.1:9000/api/health/ready
sudo journalctl -u nmapui -n 100
sudo packaging/ubuntu/install-service.sh          # stage an upgrade
sudo packaging/ubuntu/install-service.sh --rollback
sudo packaging/ubuntu/install-service.sh --uninstall
```

An upgrade retains the previous release and its matching launcher/systemd unit.
If readiness from the new release is not observed, the installer restores the
prior service files, release link and service state. Manual `--rollback` also
restores the prior release's matching service files. Verify the rollback on a
real Ubuntu host before relying on it for production recovery.
Existing `/etc/nmapui/nmapui.env` must retain the documented data, log, and
browser paths. These path records are literal `KEY=value` lines; the installer
rejects missing, duplicated, or redirected paths instead of launching a service
whose systemd write permissions do not match its configuration.
It also rejects undocumented environment keys, including `LD_PRELOAD` and
`PYTHONPATH`, and the launcher always uses the NSE/style assets copied into the
active release. Optional `NMAPUI_RUNTIME_LOGS_KEEP_LATEST`,
`NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST`, and `NMAPUI_FINISHED_JOBS_KEEP_LATEST`
settings in the protected service environment can tune daily database
retention; each must be a positive integer and defaults to 5,000, 2,000, and
2,000 rows respectively. Daily retention avoids `VACUUM` on the scheduler
thread; use the authenticated maintenance action for explicit compaction.
Neither path deletes saved reports or scan folders.
Managed service installs also disable optional external enrichment by default:
`NMAPUI_ENABLE_NETWORK_FINGERPRINT`, `NMAPUI_ENABLE_UPDATE_CHECK`, and
`NMAPUI_ENABLE_VULNERS` are all set to `false`. Review the documented egress
before changing any to `true` in the protected service credentials file, then
restart the service. Reinstall and upgrade preserve an operator's explicit
setting.
Uninstall removes the unit and launcher but preserves data, credentials, logs
and release archives for recovery. It refuses to remove service files without
a verified managed release, so an unrelated or partial installation requires
manual inspection. The service defaults to loopback; changing
its bind address requires reviewing authentication, allowed origins and TLS or
a trusted VPN first.

## Network access

The server binds to `127.0.0.1` by default. For a browser on another computer,
configure `NMAPUI_HOST`, `NMAPUI_ALLOWED_ORIGINS`, `NMAPUI_USERNAME`, and
`NMAPUI_PASSWORD`. Remote browser/API requests and Socket.IO still require
credentials, and the socket checks its configured origin. Health endpoints stay
public for service supervision. Set `NMAPUI_TRUST_LOCAL_UI=false` to require
sign-in on the scanner host too. Keep the service loopback-bound unless remote
access is deliberately configured. A reverse proxy on the scanner host makes
remote clients appear local to the backend: set `NMAPUI_TRUST_LOCAL_UI=false`
before exposing such a proxy, and require authentication at the proxy as well.
For an HTTPS reverse proxy, also set `NMAPUI_COOKIE_SECURE=true` in the
protected service credentials so the browser only sends its session cookie over
HTTPS. The default is `false` for the loopback HTTP service.
State-changing HTTP requests from a browser must come from the app's origin
or an explicit `NMAPUI_ALLOWED_ORIGINS` entry. Use complete HTTP/HTTPS origins
with the correct port and no path; this also protects signed sessions from
forms on another localhost port or a same-site subdomain. For a proxy that
changes the backend Host header, include the public HTTPS origin in that list.
Authenticated API clients without browser-origin headers continue to work.
Non-ASCII usernames and passwords are supported for login and HTTP Basic access.
Empty credentials and the built-in default password cannot authorize remote
requests. The `NMAPUI_ALLOW_DEFAULT_CREDENTIALS=true` acknowledgement works
only with local UI trust enabled and a loopback bind.

## Validation

```bash
.venv/bin/python -m pytest -q
NMAPUI_RUN_BROWSER_REGRESSION=1 .venv/bin/python -m pytest -q tests/test_browser_regressions.py
NMAPUI_RUN_PRODUCTION_SMOKE=1 NMAPUI_RUN_STAGED_SMOKE=1 .venv/bin/python -m pytest -q tests/test_production_server.py
```

See [BUILDING.md](../../BUILDING.md) for the supported macOS bundle and
packaged smoke test.
