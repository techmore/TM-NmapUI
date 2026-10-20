#!/usr/bin/env bash
# Render the indicator for fixture states under Xvfb with a fake HOME. Usage: run-probe.sh BUILD_DIR OUT_DIR
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
build=$1; out=$2; mkdir -p "$out"
for state in scanning attention idle offline; do
  home=$(mktemp -d); mkdir -p "$home/.local/bin"
  printf '#!/bin/sh\ncat %s\n' "$here/fixtures/$state.json" > "$home/.local/bin/nmapui-summary"
  chmod +x "$home/.local/bin/nmapui-summary"
  xvfb-run -a -s "-screen 0 800x900x24" env HOME="$home" NMAPUI_ICONS="$here/../icons" GSK_RENDERER=cairo \
    "$build/render-probe" "$out/$state.png" 1500 2>&1 | grep -v -i "dri3\|mesa\|egl" || true
  rm -rf "$home"
done
