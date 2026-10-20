#!/usr/bin/env bash
# Install everything TM-NmapUI needs on elementary OS (Ubuntu-based): scanner tools,
# Python build/runtime pieces, and the GTK4/WebKitGTK/Wingpanel toolchain for the
# native window and panel indicator. Safe to re-run.
#   packaging/elementary/install-deps.sh            # install
#   packaging/elementary/install-deps.sh --check    # report only, change nothing
set -euo pipefail

scanner=(nmap arp-scan xsltproc traceroute)
python_pkgs=(python3 python3-venv python3-dev build-essential git curl)
native=(python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-webkit-6.0 gtk-update-icon-cache)
panel=(meson ninja-build valac pkg-config libwingpanel-9-dev libgranite-7-dev libjson-glib-dev)
all=("${scanner[@]}" "${python_pkgs[@]}" "${native[@]}" "${panel[@]}")

missing=()
for pkg in "${all[@]}"; do
  dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done

if [[ ${1:-} == --check ]]; then
  if ((${#missing[@]})); then printf 'Missing packages: %s\n' "${missing[*]}"; exit 1; fi
  echo "All system packages are installed."; exit 0
fi

if ((${#missing[@]})); then
  echo "Installing: ${missing[*]}"
  sudo apt-get update -qq
  sudo apt-get install -y "${missing[@]}"
else
  echo "All system packages are already installed."
fi

# Python 3.12-3.13 have prebuilt wheels for every pinned dependency; newer system
# Pythons may need to compile netifaces, which python3-dev and build-essential cover.
for tool in nmap xsltproc traceroute arp-scan; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool is still missing" >&2; exit 1; }
done
echo "Scanner tools: $(nmap --version | head -1)"
