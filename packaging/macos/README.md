# macOS Native Shell

This directory contains the Swift-native macOS application and its helper executables.

## Goal

Launch a normal (non-root) SwiftUI macOS app, run privileged Nmap operations through a one-time-installed helper, and support unattended scheduled scans.

### Privilege model

- The GUI app always runs as the logged-in user.
- Full nmap scans (`-sS`, `-O`, etc.) go through `NmapPrivilegedHelper` (root LaunchDaemon).
- First complete/dragnet scan (or enabling auto-scan) prompts once for admin to install the helper.
- After install, interactive and scheduled scans need no further password prompts.
- Quick host discovery can run without the helper.

### UI model

- The dashboard, scan controls, history, reports, settings, and customer workflows are native SwiftUI.
- Generated HTML and PDF reports remain available for detailed review and export.
- Legacy HTML assets are retained only where report generation or migration compatibility still requires them.

### Scheduling

- Enabling auto-scan installs `~/Library/LaunchAgents/com.techmore.nmapui.autoscan.plist`.
- The agent runs `NmapUI --scheduled-scan`, which uses the privileged helper with no UI.

## Suggested Shape

- `Sources/NmapUIApp/` for the Swift app code
- `Resources/` for the app icon, Info.plist, and menu assets
- `build.sh` or Xcode project configuration for bundling and codesigning

## Build

```bash
cd packaging/macos
./build.sh
```

Or directly with SwiftPM:

```bash
cd packaging/macos
swift build
```

To assemble a native `.app` without launching or installing it:

```bash
APP_BUNDLE=/tmp/nmapui-native/NmapUI.app \
BUILD_DIR=/tmp/nmapui-native-swift-build \
CODESIGN_IDENTITY=- ./bundle.sh
```

`NMAPUI_BUILD_CONFIGURATION=release` selects an optimized build (default:
`debug`). Temporary assets follow the bundle output directory. The bundle
contains all four SwiftPM products, the resource bundle, icon, report styles
and runtime assets. `codesign --verify --deep --strict /path/NmapUI.app` verifies
its local signatures. Ad-hoc signing (`-`) provides local integrity checks;
Developer ID signing, notarization and installed-helper authorization require
separate distribution qualification.

`bundle_version.py` validates VERSION before build/cleanup. Marketing metadata
is numeric `YYYY.M.D`; build metadata is `YYYY.M.P`, where
`P = (day - 1) * 1440 + hour * 60 + minute`. Historical `.HH_MM` and `.HH.MM`
suffixes retain chronological ordering, and date-only versions mean midnight.
For example, `v2026.3.14.00_10` becomes marketing `2026.3.14` and build
`2026.3.18730`. Advance VERSION before redistributing changed binaries.
The raw product version stays in `NmapUIProductVersion`, bundled `VERSION`,
and native UI/runtime identity; `NmapUISourceRevision` records the source commit.

The native app currently requests privileged-helper authorization shortly after
startup, even with empty temporary state. Do not launch it merely to preview a
bundle when service authorization or host changes are outside the task scope.

To install the bundle into Applications:

```bash
cd packaging/macos
./install.sh
```

To install the nightly product evaluation loop as a LaunchAgent:

```bash
cd packaging/macos
./nightly_product_eval_launchd.sh install
```

To inspect or remove it later:

```bash
cd packaging/macos
./nightly_product_eval_launchd.sh status
./nightly_product_eval_launchd.sh uninstall
```

## Run

```bash
cd packaging/macos
./run.sh
```

The app is designed to present a menu bar icon, wait for the readiness endpoint, and then open the loopback UI at `http://127.0.0.1:9000`. If startup takes too long, it shows a native prompt, the menu status row changes to `Waiting`, and the main action becomes `Open UI Anyway`. If the runtime exits unexpectedly, the app automatically attempts one restart before surfacing a native alert so the backend failure is visible right away.
The bundle uses the existing `static/techmore.png` asset to generate a macOS icon at build time when `sips` and `iconutil` are available.
The menu bar icon includes a `Runtime:` status row plus an `About NmapUI` item and a `Preferences...` item for editing the runtime command and data directory from inside the app, plus `Restart Runtime` and `Open Data Folder` actions for quicker recovery and jumping straight to the mutable data location. The main action switches between `Starting NmapUI...`, `Open UI Anyway`, and `Open NmapUI` depending on backend state. The standard About panel now also picks up the bundle version and copyright strings from `Info.plist` and shows a short credits line. The status row shows `Starting`, `Waiting`, `Ready`, `Restarting`, or `Error` depending on backend state. The data directory uses a native folder picker, can be revealed in Finder, and the panel includes a `Reset to Defaults` action.

## Runtime Overrides

- In-app Preferences control the runtime executable and argument list.
- `NMAPUI_RUNTIME_EXECUTABLE` and `NMAPUI_RUNTIME_ARGUMENTS` are stored by the Swift launcher when a custom runtime is enabled.
- The default launch path now goes through the Swift-native shell in `packaging/macos/`, with the runtime command reconstructed from structured preferences rather than stored as a single shell string.
- `NMAPUI_DATA_DIR` sets the runtime data directory, defaulting to `~/Library/Application Support/NmapUI`.
- `NMAPUI_APPLICATIONS_DIR` sets the destination for `./install.sh`, defaulting to `~/Applications`.
- The nightly eval LaunchAgent installs to `~/Library/LaunchAgents/` and runs `scripts/nightly_product_eval.sh --run`.
- In-app Preferences persist the launcher overrides in `UserDefaults`, so they survive relaunches. The data directory is selected with a folder picker from the SwiftUI Preferences view, can be copied with short confirmation feedback, can be revealed in Finder, can be reset to defaults, and is also reachable from the `Open Data Folder` menu action. The copy confirmation uses a short cancellable delay so repeated clicks behave predictably and is cancelled when the view closes. The copy control uses a labeled icon button, the SwiftUI fields now include short helper captions, the data directory path is shown as selectable monospaced text for readability, the Save button stays disabled until there are unsaved changes, and Reset to Defaults asks for confirmation first. If launch-at-login registration fails during save, the app now shows a native warning alert instead of silently logging the error. The status bar menu also exposes a runtime status row that reflects startup, waiting, ready, restart, and error states, `About NmapUI` for the standard app panel, `Restart Runtime` to bounce the backend without opening Preferences first, startup timeouts now offer a single native prompt with `Open UI Anyway`, and runtime exits get one automatic restart attempt before a native warning prompt with a restart action. The About panel reads its version and copyright strings from the bundle metadata and includes the short credits line.
- `CODESIGN_IDENTITY` signs the app bundle if you have a valid Apple signing identity.
- `CODESIGN_OPTIONS` overrides the codesign flags, defaulting to `--force --deep --sign`.
- `OPEN_AFTER_INSTALL` opens the installed app after `./install.sh`, defaulting to `1`.

## Notes

- The backend should stay external, not embedded.
- The runtime should write its working data into Application Support, not inside the app bundle.
- The shell should open the local loopback UI once the runtime is healthy.
- This directory intentionally starts small so the migration can grow without forcing a rewrite all at once.

The retained Flask wrapper uses the selected local runtime URL (the default
local loopback URL is `http://127.0.0.1:9000`). Native SwiftUI does not need that
listener. For Flask runtime-store migration, use
`scripts/backfill_runtime_store.py --help` before changing stored data.

## Verification and compatibility clients

### Shared scanner review in SwiftUI

The **Shared scanner** tab connects explicitly to an existing scanner on this Mac.
Enter `http://127.0.0.1:9000` (or `http://[::1]:PORT`) and, when required, its
username/password, then choose **Attach / check access**. Credentials stay in
memory for the attachment; the address and credentials are not saved. Strict
authentication works with `NMAPUI_TRUST_LOCAL_UI=false`. This tab never starts a
host service or changes its authentication settings.

The view shows actual shared-engine activity, saved scan history and report
artifacts, updating every ten seconds only after attachment. Leaving the tab
detaches it. Disconnected observations remain visibly out of date, and artifact
actions stay disabled until a fresh attachment succeeds. Native scanner controls,
the **Native archive**, customer records and native LaunchAgent schedules remain
separate; this view neither starts shared scans nor imports or changes schedules.

PDF/XML/HTML actions download using the same authenticated connection before
opening a private local copy in the default document viewer. Every redirect is
refused; only literal loopback HTTP endpoints and validated relative artifact
paths are accepted. JSON responses are limited to 2 MiB and each report to 64 MiB.
Private copies use an owner-only cache, with a 128 MiB limit per live library
session. Copies survive Detach, are removed when the owning session is disposed,
and validated crash leftovers from inactive processes are pruned on a later
download. Unrecognized files, symlinks and active sessions are never pruned.

Offline HTML gets a restrictive policy before all original document bytes and
retains applicable server policy. Only the server's SHA-256-authorized runtime
or no scripts are accepted. HTTP-only sandbox/frame-ancestor protections cannot
be reproduced by a meta policy; the offline policy separately blocks network
subresources, forms, objects and base URLs. Unsupported policies fail explicitly with PDF/XML
as alternatives. HTML is opened externally, never in a privileged application
WebView. Meta policy does not provide HTTP sandbox isolation: an external viewer
may still navigate, including through a document's meta-refresh directive.
The client does not place engine credentials in the downloaded document or
forward them to an external viewer/navigation request. The policy guards script
execution and subresource requests; it is not arbitrary-HTML network isolation.

Canonical integration tests verify the exact clean shared-engine revision
`0e7d22ed8f60ea325dd6cbc77192ea9ff64340b9`, using its real app, authentication,
routes, SQLite store and report renderer with temporary data and no scan calls.
Its scheduler thread runs for readiness with automatic scanning disabled. CI
checks out that revision separately; fault-injection Flask fixtures are additional
transport tests. To run canonical tests locally, set `NMAPUI_SHARED_ENGINE_SOURCE`
to a clean checkout of that revision and optionally
`NMAPUI_SHARED_ENGINE_CANONICAL_PYTHON` to its Python environment. The regular
fixture interpreter (`NMAPUI_SHARED_ENGINE_FIXTURE_PYTHON`, default `python3`)
needs Flask 3.1.3. Tests render the SwiftUI view through `NSHostingView` without
launching the application delegate, and Chromium verifies offline policy,
report layout and hash-authorized filter/CSV behavior.

Moving execution to the shared engine is a separate migration: native
`history.json`/`reports_archive` and `customers.json` do not match the shared
`scans/*/metadata.json`, SQLite artifacts and customer registry. Native hourly
schedules also have no exact counterpart in current shared customer monitoring.
Preserve native files and their existing scheduler until an explicit, reversible
import and single-owner scheduling handoff are implemented.

CI keeps the Flask unit/browser/wrapper jobs and additionally requires the full
SwiftPM test suite and an optimized native bundle with strict signature/resource
checks. Tests use temporary data and loopback listeners; they never launch the
native GUI or install its service. The browser suite uses real Socket.IO clients
and has no expected-failure masks.

`templates/index.html` uses the compatible Flask API modules. The retained native
web bridge in root `index.html` loads its transport-specific variants from
`static/js/native/`; the production SwiftUI controls remain in `Sources/NmapUIApp`.
The shared Monitoring Hub display lives in `static/js/monitoring_hub.js` for the
Flask page. Desktop Flask startup skips public traceroute by default; an explicit
`NMAPUI_STARTUP_TRACEROUTE=true` still opts in. Readiness requires the scanner and
scheduler, independently of optional public topology discovery.

Build/bundle/install replacement now refuses active or unverified destinations.
It never signals processes from a stale PID marker or command substring, and it
never removes the scanner's shared scheduler lock. Quit the selected copy first;
review stale markers manually. Temporary-destination installer smoke checks
preserve the completed resource seal and nested helper identities without
launching the app or registering services.
