#!/bin/bash
#
# NmapUI dependency installer.
#
# Installs the toolchain the Flask app actually needs: nmap, xsltproc, a Python
# interpreter, the project virtualenv, Playwright's Chromium and gowitness.
# It deliberately does not install Node: the Express app in this repository is a
# legacy rollback reference, not the product.
#
# Usage:
#   ./install.sh              # install everything, then offer the daemon
#   ./install.sh --no-daemon  # skip the LaunchDaemon offer (used by build.sh)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DAEMON_PROMPT=1
for arg in "$@"; do
    case "$arg" in
        --no-daemon) INSTALL_DAEMON_PROMPT=0 ;;
        -h|--help)
            echo "NmapUI dependency installer"
            echo ""
            echo "  ./install.sh              install toolchain, then offer the LaunchDaemon"
            echo "  ./install.sh --no-daemon  skip the LaunchDaemon offer (used by build.sh)"
            echo "  ./install.sh --help       show this help"
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

VENV_DIR="$SCRIPT_DIR/.venv"

echo "========================================"
echo "TM-NmapUI - Dependency Installer"
echo "========================================"

BREW_PACKAGES=(
    "nmap"
    "libxslt"
    "python"
    "go"
)

OPTIONAL_BREW_PACKAGES=(
    "arp-scan"
    "wkhtmltopdf"
)

find_chrome() {
    if [ -n "${CHROME_PATH:-}" ] && [ -x "$CHROME_PATH" ]; then
        echo "$CHROME_PATH"
        return 0
    fi
    local candidates=(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        "/Applications/Chromium.app/Contents/MacOS/Chromium"
        "/usr/bin/google-chrome"
        "/usr/bin/chromium"
        "/usr/bin/chromium-browser"
    )
    for candidate in "${candidates[@]}"; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

echo ""
echo "[1/6] Checking for Homebrew..."
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo "Homebrew found."
fi

echo ""
echo "[2/6] Updating Homebrew..."
brew update

echo ""
echo "[3/6] Installing system packages with Homebrew..."
for pkg in "${BREW_PACKAGES[@]}"; do
    if brew list "$pkg" &> /dev/null; then
        echo "$pkg already installed."
    else
        echo "Installing $pkg..."
        brew install "$pkg"
    fi
done

for pkg in "${OPTIONAL_BREW_PACKAGES[@]}"; do
    if brew list "$pkg" &> /dev/null; then
        echo "$pkg already installed."
    else
        echo "Installing optional package $pkg..."
        if ! brew install "$pkg"; then
            echo "WARNING: optional package $pkg is unavailable; continuing."
        fi
    fi
done

if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found after installing Homebrew 'python'." >&2
    exit 1
fi

echo ""
echo "[4/6] Creating the project virtualenv and installing Python dependencies..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "Created $VENV_DIR"
else
    echo "$VENV_DIR already exists."
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "Installing the Playwright Chromium runtime used for PDF rendering..."
if ! python -m playwright install chromium; then
    echo "WARNING: Playwright Chromium install failed. PDF export can still fall back to wkhtmltopdf or Chrome."
fi

find_gowitness() {
    if command -v gowitness &> /dev/null; then
        command -v gowitness
        return 0
    fi
    if command -v go &> /dev/null; then
        local gobin gopath
        gobin="$(go env GOBIN 2>/dev/null || true)"
        gopath="$(go env GOPATH 2>/dev/null || true)"
        if [ -n "$gobin" ] && [ -x "$gobin/gowitness" ]; then
            echo "$gobin/gowitness"
            return 0
        fi
        if [ -n "$gopath" ] && [ -x "$gopath/bin/gowitness" ]; then
            echo "$gopath/bin/gowitness"
            return 0
        fi
    fi
    if [ -x "$HOME/go/bin/gowitness" ]; then
        echo "$HOME/go/bin/gowitness"
        return 0
    fi
    return 1
}

echo ""
echo "Installing gowitness with Go when needed..."
if GOWITNESS_BIN="$(find_gowitness)"; then
    echo "gowitness already installed at $GOWITNESS_BIN"
elif command -v go &> /dev/null; then
    go install github.com/sensepost/gowitness@latest
    GOWITNESS_BIN="$(find_gowitness || true)"
    if [ -n "$GOWITNESS_BIN" ]; then
        echo "gowitness installed at $GOWITNESS_BIN"
    else
        echo "WARNING: gowitness install completed, but the binary was not found under GOBIN or GOPATH/bin."
    fi
else
    echo "WARNING: Go is unavailable. Web screenshot capture will be skipped until gowitness is installed."
fi

echo ""
echo "[5/6] Verifying installations..."
MISSING=0

for cmd in nmap xsltproc python3; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "MISSING: $cmd"
        MISSING=1
    else
        echo "OK: $cmd - $("$cmd" --version 2>&1 | head -n1)"
    fi
done

if python -c "import flask, flask_socketio, playwright" &> /dev/null; then
    echo "OK: python dependencies (flask, flask_socketio, playwright)"
else
    echo "MISSING: python dependencies — re-run ./install.sh"
    MISSING=1
fi

if GOWITNESS_BIN="$(find_gowitness)"; then
    echo "OK: gowitness - $GOWITNESS_BIN"
else
    echo "OPTIONAL MISSING: gowitness"
fi

if CHROME_BIN="$(find_chrome)"; then
    echo "OK: Chrome/Chromium - $CHROME_BIN"
else
    echo "OPTIONAL MISSING: Chrome/Chromium (PDF falls back to Playwright/wkhtmltopdf)"
fi

echo ""
echo "[6/6] Service installation"
if [ "$INSTALL_DAEMON_PROMPT" = "1" ] && [ -t 0 ]; then
    echo "Install NmapUI as a system service so it starts at boot and scans while"
    echo "nobody is logged in (recommended for an appliance)?"
    read -r -p "Install LaunchDaemon now? [y/N] " reply
    if [[ "$reply" =~ ^[Yy]$ ]]; then
        if sudo "$SCRIPT_DIR/packaging/macos/install-daemon.sh"; then
            echo "LaunchDaemon installed."
        else
            echo "WARNING: LaunchDaemon install failed; run it later with:"
            echo "  sudo packaging/macos/install-daemon.sh"
        fi
    else
        echo "Skipped. Install later with: sudo packaging/macos/install-daemon.sh"
    fi
else
    echo "Skipped. Install later with: sudo packaging/macos/install-daemon.sh"
fi

echo ""
echo "========================================"
if [ $MISSING -eq 0 ]; then
    echo "Installation complete!"
    echo "Start it with: ./start.sh    (or install the daemon above)"
else
    echo "Some required dependencies are missing."
    echo "Please restart your terminal and re-run this script."
    exit 1
fi
echo "========================================"
