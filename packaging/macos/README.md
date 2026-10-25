# NmapUI Swift Menu Bar Wrapper

A lightweight macOS menu bar application that launches the bundled NmapUI server and opens the local web interface.

## Features

- Network icon in the menu bar
- Opens NmapUI on a local loopback URL, defaulting to `http://127.0.0.1:9000`
- Starts and stops the bundled Python app process
- Runs as a menu bar app with no dock icon
- Uses a single supported Swift entrypoint: `NmapUIMenuBarLauncher.swift`
- Shows scanner activity and paused/pausing state in the menu and VoiceOver label
- Attaches to an existing scanner service without launching a second runtime;
  Stop/Restart controls apply only to the runtime this wrapper owns

## Files

- `NmapUIMenuBarLauncher.swift` - Supported wrapper source code
- `build.sh` - Canonical build script for the wrapper app bundle

## Building the Application

### Prerequisites

- Xcode command line tools
- macOS 13.0 or later
- The Python application prepared with `install.sh`

### Build Command

```bash
./build.sh
```

## Running the Application

`build.sh` compiles the wrapper, creates the app bundle, copies the Python resources, and opens the app.

The app appears as a network icon in the menu bar. Use the menu to start, stop, or open NmapUI.
When activity ends, the recent-activity clock means the work is no longer active;
open NmapUI to review whether the scan or report succeeded, failed or was cancelled.
The status reader accepts mixed-type runtime metadata, polls one request at a
time and discards responses from an earlier start/stop cycle. Strict-auth
installations can supply `NMAPUI_USERNAME` and `NMAPUI_PASSWORD` to the launcher.
Without them, the status reader reports that credentials are needed; opening
NmapUI still provides the browser sign-in. Browser sessions are not shared with
the native status reader.
Shutdown allows the owned runtime a two-second TERM grace period, then freezes
its remaining process tree before collecting and killing descendants. PID marker
files and port listeners never grant ownership of another process.

## How It Works

1. Creates a menu bar item with a network icon.
2. Starts the bundled `run.sh` helper from the app bundle resources.
3. Opens the browser at the selected local runtime URL.
4. Terminates the child process on quit.

## Support Contract

Only `NmapUIMenuBarLauncher.swift` is supported. Older popover and relay prototypes have been removed from the tracked build path so the wrapper release flow and port contract stay deterministic (fixed at port 9000). The built bundle is installed as `NmapUI.app`.

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
