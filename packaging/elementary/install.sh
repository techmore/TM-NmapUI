#!/usr/bin/env bash
# Install the elementary OS native window for the current user and pin it to the dock.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
id=io.github.techmore.NmapUI
install -Dm755 "$here/nmapui-elementary" "$HOME/.local/bin/nmapui-elementary"
install -Dm644 "$here/$id.desktop" "$HOME/.local/share/applications/$id.desktop"
install -Dm644 "$here/$id.svg" "$HOME/.local/share/icons/hicolor/scalable/apps/$id.svg"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
desktop=$id.desktop
current=$(dconf read /io/elementary/dock/launchers 2>/dev/null || true)
if [ -n "$current" ] && [[ "$current" != *"$desktop"* ]]; then
    dconf write /io/elementary/dock/launchers "${current%]}, '$desktop']"
fi
echo "Installed. Launch 'Network Scanner' from the dock."
