# NmapUI Swift Wrapper - Setup Instructions

This guide documents the supported macOS wrapper implementation for launching the local NmapUI server and opening its web interface.

## Supported Wrapper Source

Use [NmapUIMenuBarLauncher.swift](NmapUIMenuBarLauncher.swift) as the only supported source file. It launches the bundled `run.sh` helper and opens the local runtime URL at `http://127.0.0.1:9000`.

## Build and Run

1. Ensure the Python app has been prepared with `install.sh`.
2. Build the wrapper bundle with:

```bash
./build.sh
```

3. The app bundle launches automatically.
4. You should see a network icon in your menu bar.
5. Use the menu to start, stop, or open NmapUI.

## Development Contract

- The wrapper opens the selected local runtime URL and defaults to `http://127.0.0.1:9000`
- The wrapper source of truth is `NmapUIMenuBarLauncher.swift`
- Older `9999` popover examples are deprecated and removed from the supported path

## Customization Options

### Changing the Menu Bar Icon

Modify this line in [NmapUIMenuBarLauncher.swift](NmapUIMenuBarLauncher.swift):

```swift
button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "NmapUI")
```

Replace `"network"` with any SF Symbol name.

### Changing the Target URL

Modify the `appURL` computed property in [NmapUIMenuBarLauncher.swift](NmapUIMenuBarLauncher.swift):

```swift
var appURL: URL {
    URL(string: "http://127.0.0.1:\\(runtimePort)")!
}
```

## Removed Prototype

The older relay and API-key prototype is no longer part of the supported wrapper path. If remote report forwarding is needed later, it should be built as a separate feature with explicit authentication, loopback-only binding, and release coverage.
