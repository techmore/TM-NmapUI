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
The menu bar icon includes a `Runtime:` status row plus an `About NmapUI` item and a `Settings…` item (⌘,) for editing the runtime command and data directory from inside the app, plus `Restart Runtime` and `Open Data Folder` actions for quicker recovery and jumping straight to the mutable data location. The main action switches between `Starting NmapUI…`, `Open UI Anyway`, and `Open NmapUI` depending on backend state. The standard About panel now also picks up the bundle version and copyright strings from `Info.plist` and shows a short credits line. The status row shows `Starting`, `Waiting`, `Ready`, `Restarting`, or `Error` depending on backend state. The data directory uses a native folder picker, can be revealed in Finder, and the panel includes a `Reset to Defaults` action.

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

### Explicit execution source in SwiftUI

New installations start with an execution-source choice and recommend **Shared
scanner**. Shared mode connects explicitly to an existing canonical Flask
scanner on this Mac. Enter `http://127.0.0.1:PORT` (or `http://[::1]:PORT`) and,
when required, its credentials, then choose **Attach / check access**. The HTTP
and Socket.IO clients are constructed together before the password field is
cleared. Credentials and the endpoint remain in memory only. Strict
`NMAPUI_TRUST_LOCAL_UI=false` access uses UTF-8 Basic authentication plus the
separately fetched Socket.IO CSRF token. Nothing connects before Attach, and
Shared startup never installs/starts a service or initializes native preferences,
helper authorization, Keychain access, network fingerprinting or LaunchAgent
synchronization.

Shared controls start the canonical discovery/scan workflow with the scanner's
settings and an explicit optional host-discovery override. Live job status,
source run UUIDs, pause/resume and Stop use the canonical Socket.IO events. UI,
menu, keyboard and both compatibility bridge ports consult the same execution
router. Unknown statuses remain unknown; stale UUIDs cannot control a replacement
run. Disconnected commands are rejected rather than queued. An uncertain start
is never replayed; both fresh job statuses must arrive before the operator can
acknowledge its uncertainty. Native Complete/Dragnet/VPN presets are rejected in
Shared mode instead of being silently assigned different canonical semantics.
New report generation is not yet exposed in this native Shared mode; saved
reports/history remain available through the authenticated shared HTTP client.

Detach and Quit disconnect only. Service jobs continue until explicitly stopped
by an authenticated frontend with their observed source run ID. A cached HTTP
history snapshot is labeled separately from authoritative live job state.

An existing native installation (runtime metadata, native schedule configuration
or LaunchAgent) without a source marker remains in **Legacy compatibility**.
This preserves already enabled schedules on upgrade. Changing source is an
explicit, restart-required operation: the actual cross-process scan lock must
be free, deferred Legacy work is revoked, and active Legacy authorization or
downloads must finish or be explicitly cancelled. Pending restart blocks new
local UI, menu and bridge work. Shared source selection suppresses subsequent
native scheduled-run admission without deleting or translating its config.
An existing agent that launches a different/unreadable older app copy blocks the
Shared transition; disable that schedule explicitly in Legacy first. Histories,
customer records and recurrence/configuration bytes are never auto-imported.
The selected source alone is saved in
`~/Library/Application Support/com.techmore.NmapUI/execution-source.json`.
It contains no address, credentials or shared-job state.

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

Lossless data/schedule migration remains an open release gate: native
`history.json`/`reports_archive` and UUID customers differ from shared SQLite
artifacts, scan folders and opaque customer IDs. Native hourly schedules have no
exact shared recurrence equivalent. Legacy compatibility is a separate engine,
not evidence of shared-backend parity. Preserve its files and original branch
until explicit reversible import, canonical report/customer writes and a
single-owner scheduling handoff are qualified. Installed older binaries and
physical-host/service migration still require deployment qualification.

CI keeps the Flask unit/browser/wrapper jobs and additionally requires the full
SwiftPM test suite and an optimized native bundle with strict signature/resource
checks. Tests use temporary data and loopback listeners, render isolated native views
and inject local effects; they never run the app's live bootstrap or register
its service. The browser suite uses real Socket.IO clients
and has no expected-failure masks.

`templates/index.html` uses the compatible Flask API modules. The retained native
web bridge in root `index.html` loads its transport-specific variants from
`static/js/native/`; the production SwiftUI controls remain in `Sources/NmapUIApp`.
The shared Monitoring Hub display lives in `static/js/monitoring_hub.js` for the
Flask page. Desktop Flask startup skips public traceroute by default; an explicit
`NMAPUI_STARTUP_TRACEROUTE=true` still opts in. Readiness requires the scanner and
scheduler, independently of optional public topology discovery.

The retained Flask wrapper (`NmapUIMenuBarLauncher.swift`) appears as a network icon in the menu bar. Use the menu to start, stop, or open NmapUI.
When activity ends, the recent-activity clock means the work is no longer active;
open NmapUI to review whether the scan or report succeeded, failed or was cancelled.
The status reader accepts mixed-type runtime metadata, polls one request at a
time and discards responses from an earlier start/stop cycle. Strict-auth
installations can supply `NMAPUI_USERNAME` and `NMAPUI_PASSWORD` to the launcher.
Without them, the status reader reports that credentials are needed; opening
NmapUI still provides the browser sign-in. Browser sessions are not shared with
the native status reader.
The packaged desktop entrypoint defaults `NMAPUI_STARTUP_TRACEROUTE=false` so
public topology discovery cannot block server startup. Set it explicitly to
`true` to opt in; this does not disable later network fingerprinting by itself.
Shutdown allows the owned runtime a two-second TERM grace period, then freezes
its remaining process tree before collecting and killing descendants. PID marker
files and port listeners never grant ownership of another process.

Build/bundle/install replacement now refuses active or unverified destinations.
It never signals processes from a stale PID marker or command substring, and it
never removes the scanner's shared scheduler lock. Quit the selected copy first;
review stale markers manually. Temporary-destination installer smoke checks
preserve the completed resource seal and nested helper identities without
launching the app or registering services.

### Drive secure-state failures

The native Drive helper distinguishes a missing Keychain item from a locked,
denied, unavailable or corrupt item. Only a genuinely missing item can migrate
legacy state; migration saves successfully to Keychain before removing the
legacy JSON. Reads are limited to 1 MiB, and migration or cleanup failures are
reported. Status, credential replacement and uploads cannot silently select an
older account after a Keychain read error. Explicit Disconnect still attempts
local deletion when a token cannot be read or revoked, and separately reports
unconfirmed Google revocation; failed local deletion is not reported as success.

`DriveKeychainTests` inject Security results for local tests. Its actual Keychain
round trip runs only when explicitly enabled in the GitHub-hosted macOS job,
with every item query scoped to a newly created private Keychain. It verifies
write/read/update, root/account separation, deletion and unchanged search-list
metadata after deleting its owned Keychain. It does not read or write default
Keychain items, authorize Google, upload account data or prove real consent and
revocation. Local runs skip this hosted-only test.

## Bundle versions

The product `VERSION` remains unchanged in the bundled runtime and UI. Before
building or cleaning existing artifacts, `build.sh` validates it as a real
calendar date in `vYYYY.M.D` format, optionally followed by `.HH_MM` or `.HH.MM`
(24-hour time). Invalid dates, times, whitespace and shell/XML text fail closed.

Apple's [marketing version](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleshortversionstring)
is the numeric `YYYY.M.D`. The [build version](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleversion)
is `YYYY.M.P`, where `P = (day - 1) * 1440 + hour * 60 + minute`.
This keeps three numeric components and increases chronologically, including
historical time suffixes. A date without a time means midnight; equivalent
`.HH_MM` and `.HH.MM` spellings identify the same build. For example:

| Product VERSION | Marketing version | Build version |
| --- | --- | --- |
| `v2026.3.14.00_10` | `2026.3.14` | `2026.3.18730` |
| `v2026.4.26.4.00` | `2026.4.26` | `2026.4.36240` |
| `v2026.10.25` | `2026.10.25` | `2026.10.34560` |

Rebuilding the same VERSION is reproducible. Before distributing a changed
build, advance VERSION; use a later time suffix for another build on the same
date. This mapping does not select a release channel or qualify a release.
