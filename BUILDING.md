# Building NmapUI for macOS

NmapUI's supported Mac application is a Swift menu-bar launcher bundled with the
Flask app and a project virtual environment. It is built by the root `build.sh`;
PyInstaller is not the current release path.

## Prepare the toolchain

Use macOS 13 or later, Xcode command-line tools, Homebrew and Python 3.11 or
newer. From the repository root:

```bash
./install.sh --no-daemon
source .venv/bin/activate
```

The installer prepares the scanner dependencies, Python packages and the
Playwright Chromium runtime used for PDF output.

## Build browser assets

The Flask runtime serves compiled CSS and pinned JavaScript libraries from
`static/`, so installed and packaged apps do not need Node or a CDN at runtime.
After changing Tailwind classes or updating the browser libraries, regenerate
those committed assets with Node.js 24 or newer:

```bash
npm ci --prefix scripts/ui-assets
npm run build --prefix scripts/ui-assets
```

The CI unit job rebuilds the assets and fails if the generated output differs
from the committed files.

## Build and run

```bash
NMAPUI_SKIP_OPEN=1 ./build.sh
```

The script compiles the Swift launcher, bundles the Flask application and its
virtual environment, then installs `NmapUI.app` into `/Applications` when
permitted or `~/Applications` otherwise. It opens the app after a normal build;
`NMAPUI_SKIP_OPEN=1` skips that launch. Set `NMAPUI_APPLICATIONS_DIR` to choose
the install directory.

To migrate an existing runtime SQLite database from a different data location,
stop processes using the destination, retain a separate pre-upgrade backup, and
set `NMAPUI_MIGRATE_DB=1 NMAPUI_MIGRATE_DB_FROM=/path/to/runtime.sqlite3` for the
build. The migration uses SQLite's backup API so committed WAL transactions are
included. With no explicit source, the default points at the existing runtime
database and no copy is performed. This option is for the menu-bar app build;
the staged LaunchDaemon installer keeps mutable data outside its code releases.

To launch the Flask app directly during development:

```bash
source .venv/bin/activate
export NMAPUI_USERNAME=admin
export NMAPUI_PASSWORD='choose-a-strong-password'
./start.sh
```

## Validate a build

The packaged smoke test builds in an isolated temporary application directory,
checks that a committed WAL row survives database migration, starts the bundled
server with temporary data and credentials, and checks the authenticated UI and
health endpoint:

```bash
NMAPUI_RUN_PACKAGED_SMOKE=1 .venv/bin/python -m pytest -q tests/test_packaged_app_smoke.py
```

Check the appliance installer without installing or starting a LaunchDaemon:

```bash
packaging/macos/install-daemon.sh --dry-run
packaging/macos/install-daemon.sh --dry-run --user "$(id -un)"
```

The first validates the default root service configuration. The second checks
the optional non-root service account and validating scanner helper. Neither
command installs a service.

## Legacy packaging

`packaging/pyinstaller/nmapui.spec` and `deploy.sh` are retained as historical
references. `deploy.sh` can publish a GitHub release and does not build the
supported Swift menu-bar application; do not use it for current releases.
