# NmapUI Setup

NmapUI is a Flask scanner service with a browser interface. The browser can run
on another operating system; the machine running Flask must have direct access
to the network interfaces and scanner tools. Windows scanner-host support has
not been verified.

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

## Linux development host

Install Python 3.11 or newer, Nmap and `xsltproc` using the distribution's
package manager, then prepare the application environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
export NMAPUI_USERNAME=admin
export NMAPUI_PASSWORD='choose-a-strong-password'
./start.sh
```

The Mac LaunchDaemon installer does not provide Linux service supervision.
Run the app under a service manager configured for the Linux host if it must
start at boot.

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
