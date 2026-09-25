# NmapUI Setup

NmapUI is a Flask scanner service with a browser interface. The scanner-host
targets are macOS and Ubuntu. The browser can run on another operating system;
the machine running Flask must have direct access to the network interfaces and
scanner tools.

## macOS appliance

Install the supported toolchain and Python environment:

```bash
./install.sh --no-daemon
```

Run the web app in development with sign-in enabled:

```bash
export NMAPUI_USERNAME=admin
export NMAPUI_PASSWORD='choose-a-strong-password'
./start.sh
```

Open <http://127.0.0.1:9000>. To start at boot when nobody is logged in, install
the system LaunchDaemon:

```bash
sudo packaging/macos/install-daemon.sh
```

It runs as root by default for full scanner capability. `--user <name>` selects
the optional non-root service mode with the validating scanner helper. Check
either configuration without changing system state:

```bash
packaging/macos/install-daemon.sh --dry-run
packaging/macos/install-daemon.sh --dry-run --user "$(id -un)"
```

## Ubuntu scanner host

Ubuntu can run the Flask app directly on the scanner host. This is a manual
runtime setup; a supported installer and `systemd` service are tracked in
[issue #241](https://github.com/techmore/TM-NmapUI/issues/241).
Install Python 3.11 or newer, then run these commands from the repository root:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip nmap arp-scan xsltproc
python3 --version  # Confirm this is 3.11 or newer
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
sudo .venv/bin/python -m playwright install-deps chromium
.venv/bin/python -m playwright install chromium
export NMAPUI_USERNAME=admin
export NMAPUI_PASSWORD='choose-a-strong-password'
./start.sh
```

Run the app as a regular account for manual use; Nmap then uses a connect scan
and ARP enrichment may be unavailable. Ubuntu's production privilege model,
boot-time service supervision, upgrades and unattended scan behavior still need
implementation and validation. The macOS LaunchDaemon installer does not
provide Linux service supervision.

## Network access

The server binds to `127.0.0.1` by default. For a browser on another computer,
configure `NMAPUI_HOST` and include the browser's exact scheme, host and port in
`NMAPUI_ALLOWED_ORIGINS`. Keep login credentials enabled and use a trusted VPN
or terminate HTTPS at a reverse proxy. Protected web and API requests and the
Socket.IO handshake require a valid session; the socket also checks its
configured origin. Health endpoints stay public for service supervision. Do not
enable `NMAPUI_TRUST_LOCAL_UI` on a network-facing service.

## Validation

```bash
.venv/bin/python -m pytest -q
NMAPUI_RUN_BROWSER_REGRESSION=1 .venv/bin/python -m pytest -q tests/test_browser_regressions.py
```

See [BUILDING.md](../../BUILDING.md) for the supported macOS bundle and
packaged smoke test.
