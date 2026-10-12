#!/bin/bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ -x "$repo/.venv/bin/python" ]] || { echo 'Install requirements in .venv first.' >&2; exit 1; }
/usr/bin/python3 -c 'import gi; gi.require_version("WebKit", "6.0")'
install -Dm755 "$repo/packaging/elementary/desktop.py" "$HOME/.local/lib/nmapui/desktop.py"
mkdir -p "$HOME/.local/share/applications" "$HOME/.config/systemd/user" "$HOME/.local/share/nmapui" "$HOME/.local/state/nmapui"
# systemd quotes paths; percent signs must be escaped as literal specifiers.
python3 - "$repo" <<'PY'
import sys
from pathlib import Path
repo=sys.argv[1]
def quote(value):
    return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('%','%%')+'"'
home=Path.home()
unit=f'''[Unit]
Description=TM NmapUI unprivileged local scanner
[Service]
WorkingDirectory={repo.replace("%", "%%")}
Environment="NMAPUI_HOST=127.0.0.1" "NMAPUI_PORT=9000" "NMAPUI_COOKIE_SECURE=false" "NMAPUI_STARTUP_TRACEROUTE=false" "NMAPUI_ENABLE_NETWORK_FINGERPRINT=false" "NMAPUI_ENABLE_UPDATE_CHECK=false" "NMAPUI_ENABLE_VULNERS=false"
Environment={quote('NMAPUI_DATA_DIR='+str(home/'.local/share/nmapui'))}
Environment={quote('NMAPUI_LOG_DIR='+str(home/'.local/state/nmapui'))}
ExecStart={quote(Path(repo)/'.venv/bin/python')} -m gunicorn --bind 127.0.0.1:9000 --workers 1 --threads 32 --timeout 180 --no-control-socket nmapui.wsgi:application
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=default.target
'''
(home/'.config/systemd/user/nmapui-local.service').write_text(unit)
PY
cat > "$HOME/.local/share/applications/org.techmore.NmapUI.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=TM NmapUI
Comment=Network scanner and reports
Exec=/usr/bin/python3 "$HOME/.local/lib/nmapui/desktop.py"
Icon=network-wired-symbolic
Categories=Network;Utility;
StartupWMClass=org.techmore.NmapUI
EOF
systemctl --user daemon-reload
systemctl --user enable --now nmapui-local.service
