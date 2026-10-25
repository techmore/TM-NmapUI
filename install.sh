#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================"
echo "TM-NMapUI - Dependency Installer"
echo "========================================"

BREW_PACKAGES=(
    "node"
    "nmap"
    "libxslt"
    "go"
)

OPTIONAL_BREW_PACKAGES=(
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
echo "[1/5] Checking for Homebrew..."
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo "Homebrew found."
fi

echo ""
echo "[2/5] Updating Homebrew..."
brew update

echo ""
echo "[3/5] Installing system packages with Homebrew..."
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
            echo "WARNING: optional package $pkg is unavailable. PDF export can still use Chromium/Chrome when installed."
        fi
    fi
done

echo ""
echo "Checking for Chrome/Chromium PDF renderer..."
if CHROME_BIN="$(find_chrome)"; then
    echo "Chrome/Chromium found at $CHROME_BIN"
else
    echo "Chrome/Chromium not found. Attempting to install Google Chrome with Homebrew cask..."
    if brew list --cask google-chrome &> /dev/null; then
        echo "google-chrome cask already installed."
    elif brew install --cask google-chrome; then
        echo "Google Chrome installed."
    else
        echo "WARNING: Google Chrome could not be installed automatically."
        echo "PDF export can fall back to wkhtmltopdf, but Chrome produces the most reliable cover/header rendering."
        echo "Install manually from https://www.google.com/chrome/ or set CHROME_PATH to a Chromium-compatible executable."
    fi
fi

find_gowitness() {
    if command -v gowitness &> /dev/null; then
        command -v gowitness
        return 0
    fi
    if command -v go &> /dev/null; then
        local gobin
        local gopath
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
# The retained Flask wrapper needs its own reproducible Python runtime.
ROOT_DIR="$SCRIPT_DIR"
python3 -m venv "$ROOT_DIR/.venv"
source "$ROOT_DIR/.venv/bin/activate"
python -m pip install -r "$ROOT_DIR/requirements.txt"
PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.playwright-browsers" python -m playwright install chromium
export PLAYWRIGHT_BROWSERS_PATH="$ROOT_DIR/.playwright-browsers"

echo "[4/5] Installing npm packages..."
if [ -f "package.json" ]; then
    if command -v npm &> /dev/null; then
        if [ -f "package-lock.json" ]; then
            npm ci
        else
            npm install
        fi
        echo "npm packages installed."
    else
        echo "ERROR: npm not found. Please install Node.js via Homebrew: brew install node"
        exit 1
    fi
else
    echo "WARNING: package.json not found. Skipping npm install."
fi

echo ""
echo "[5/5] Verifying installations..."
verify_commands=(
    "node:node"
    "npm:npm"
    "nmap:nmap"
    "xsltproc:xsltproc"
    "express:node"
)

MISSING=0
for cmd in "${verify_commands[@]}"; do
    BINARY="${cmd%%:*}"
    CHECK_CMD="${cmd##*:}"
    if [[ "$BINARY" == "express" ]]; then
        if ! node -e "require('express')" &> /dev/null; then
            echo "MISSING: express"
            echo "Expected Express under: $(npm root 2>/dev/null || echo "$SCRIPT_DIR/node_modules")"
            echo "Try re-running ./install.sh from $SCRIPT_DIR"
            MISSING=1
        else
            echo "OK: express - installed"
        fi
    elif ! command -v "$CHECK_CMD" &> /dev/null; then
        echo "MISSING: $BINARY"
        MISSING=1
    else
        VERSION=$($CHECK_CMD --version 2>&1 | head -n1 || echo "installed")
        echo "OK: $BINARY - $VERSION"
    fi
done

if GOWITNESS_BIN="$(find_gowitness)"; then
    VERSION=$("$GOWITNESS_BIN" version 2>&1 | awk '/v[0-9]+/ { print; found=1; exit } END { if (!found) print "installed" }')
    echo "OK: gowitness - $VERSION"
    echo "Path: $GOWITNESS_BIN"
    echo "If your shell cannot run gowitness directly, add this to your shell profile:"
    echo "  export PATH=\"\$PATH:$(dirname "$GOWITNESS_BIN")\""
else
    echo "OPTIONAL MISSING: gowitness"
    echo "Web screenshot capture will be skipped until gowitness is installed."
fi

if CHROME_BIN="$(find_chrome)"; then
    VERSION=$("$CHROME_BIN" --version 2>&1 | head -n1 || echo "installed")
    echo "OK: Chrome/Chromium - $VERSION"
    echo "Path: $CHROME_BIN"
else
    echo "OPTIONAL MISSING: Chrome/Chromium"
    echo "PDF export will use wkhtmltopdf if available, but Chrome is recommended for reliable cover-page rendering."
fi

echo ""
echo "========================================"
if [ $MISSING -eq 0 ]; then
    echo "Installation complete!"
    echo "Run 'sudo npm start' to start the application."
else
    echo "Some dependencies are missing."
    echo "Please restart your terminal and re-run this script."
    exit 1
fi
echo "========================================"
