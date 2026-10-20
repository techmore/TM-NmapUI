#!/usr/bin/env bash
# Build and install the Network Scanner Wingpanel indicator and its summary helper.
# Does NOT restart Wingpanel: the module loads at the next login (or when you restart it).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
build=$(mktemp -d); trap 'rm -rf "$build"' EXIT
meson setup "$build" "$here/wingpanel" >/dev/null
meson compile -C "$build"
indicators_dir=$(pkg-config --variable=indicatorsdir wingpanel-9)
install -Dm755 "$here/nmapui-summary" "$HOME/.local/bin/nmapui-summary"
sudo install -m 0755 "$build/libnmapui.so" "$indicators_dir/libnmapui.so"
sudo install -Dm644 "$here/wingpanel/icons/mseries-nmapui-radar-symbolic.svg" \
  /usr/share/icons/hicolor/symbolic/apps/mseries-nmapui-radar-symbolic.svg
sudo gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
echo "Installed $indicators_dir/libnmapui.so. Loads at next login; Wingpanel was not restarted."
