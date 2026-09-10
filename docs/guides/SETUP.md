# NmapUI Setup Requirements

## Quick Start

```bash
# Run the installation script (creates .venv and installs requirements)
chmod +x install.sh
./install.sh --no-daemon

# Set sign-in credentials (protected routes return 503 without them)
export NMAPUI_USERNAME=admin
export NMAPUI_PASSWORD='choose-something-strong'

# Start the application through the virtualenv
./start.sh
```

Then visit: http://127.0.0.1:9000 and sign in at `/login`.

For an appliance that starts at boot and scans while nobody is logged in:

```bash
sudo packaging/macos/install-daemon.sh
```

## Manual Installation

### 1. System Dependencies

**Required:**
- Python 3.8+
- nmap
- git

**Optional (but recommended):**
- arp-scan (for MAC/vendor detection)
- xsltproc (for XML to HTML conversion)
- wkhtmltopdf (fallback PDF generation)
- Playwright Chromium (preferred PDF generation fidelity)

### 2. Install Commands

**macOS:**
```bash
# Install system dependencies
brew install python3 nmap git arp-scan

# Install Chrome (if not already installed)
# Download from https://www.google.com/chrome/
```

**Ubuntu/Debian:**
```bash
# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv nmap git arp-scan

# Install Chrome
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
sudo apt update
sudo apt install google-chrome-stable
```

### 3. Python Environment Setup

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install -r requirements.txt

# Install the Playwright Chromium runtime used for high-fidelity PDF rendering
python -m playwright install chromium
```

### 4. Verify Installation

```bash
# Check nmap
nmap --version

# Check arp-scan (optional)
arp-scan --version

# Check Python dependencies
python -c "import flask, socketio, requests, netifaces; print('Core dependencies OK')"
```

## Dependencies Breakdown

### Python Packages (requirements.txt)
- **Flask** - Web framework
- **Flask-SocketIO** - Real-time communication
- **Flask-CORS** - Cross-origin resource sharing
- **playwright** - Preferred browser-quality PDF rendering
- **netifaces** - Network interface discovery
- **requests** - HTTP client
- **PyYAML** - YAML parsing utilities

### System Tools
- **nmap** - Network scanning (core functionality)
- **arp-scan** - ARP scanning for MAC/vendor detection
- **git** - For vulners script management
- **xsltproc** - XML to HTML report conversion
- **wkhtmltopdf** - HTML to PDF fallback when browser rendering is unavailable

### Optional Components
- **nmap-vulners** script - Automatically cloned from GitHub
- **ARP scanning** - Requires sudo privileges on some systems

## Running the Application

```bash
# Standard startup (with dependency checks)
python app.py

# Quick startup (skip checks)
python app.py --quick
```

## Auto Scan Configuration

The app writes local scheduler state to `auto_scan_config.json` in the repository root at runtime. The tracked default lives at `config/auto_scan_config.example.json` and is used only as a fallback template.

## Troubleshooting

### Common Issues

1. **Permission denied with arp-scan**
   - arp-scan may require sudo: `sudo arp-scan --localnet`

2. **PDF generation issues**
   - Install `xsltproc`
   - Preferred renderer: `python -m playwright install chromium`
   - Fallback renderer: install `wkhtmltopdf`
   - Optional fallback: `pip install weasyprint`

3. **nmap not found**
   - Ensure nmap is installed and in PATH
   - macOS: `brew install nmap`
   - Ubuntu: `sudo apt install nmap`

4. **Virtual environment issues**
   - Delete .venv directory and recreate
   - Ensure using correct Python version

5. **Port 9000 already in use**
   - Kill existing process: `lsof -ti:9000 | xargs kill`
   - Or change port in app.py

### Development Mode

For development with debugging:
```bash
export FLASK_DEBUG=1
python app.py
```

### Testing

Run tests if available:
```bash
pytest -q
```

## Security Notes

- ARP scanning may require elevated privileges
- nmap scans should only be run on networks you own
- Chrome automation should be used responsibly
- Keep all dependencies updated regularly
