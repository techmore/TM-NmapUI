import AppKit
import Foundation
import ServiceManagement

@MainActor
final class RuntimeMenuPresenter {
    private weak var statusItem: NSStatusItem?
    private weak var runtimeStatusMenuItem: NSMenuItem?
    private weak var openAppMenuItem: NSMenuItem?
    private weak var openDataDirectoryMenuItem: NSMenuItem?
    private weak var restartRuntimeMenuItem: NSMenuItem?
    private weak var launchAtLoginMenuItem: NSMenuItem?

    func configureStatusItem(
        _ statusItem: NSStatusItem?,
        runtimeStatusMenuItem: NSMenuItem?,
        openAppMenuItem: NSMenuItem?,
        openDataDirectoryMenuItem: NSMenuItem?,
        restartRuntimeMenuItem: NSMenuItem?,
        launchAtLoginMenuItem: NSMenuItem?
    ) {
        self.statusItem = statusItem
        self.runtimeStatusMenuItem = runtimeStatusMenuItem
        self.openAppMenuItem = openAppMenuItem
        self.openDataDirectoryMenuItem = openDataDirectoryMenuItem
        self.restartRuntimeMenuItem = restartRuntimeMenuItem
        self.launchAtLoginMenuItem = launchAtLoginMenuItem
    }

    func syncLaunchAtLoginState() {
        guard #available(macOS 13.0, *) else {
            launchAtLoginMenuItem?.isEnabled = false
            launchAtLoginMenuItem?.state = .off
            return
        }
        launchAtLoginMenuItem?.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }

    func syncRuntimeMenuState(isReady: Bool, statusText: String, sourceLabel: String = "Native", allowsLegacyControls: Bool = true) {
        runtimeStatusMenuItem?.title = "\(sourceLabel): \(statusText)"
        let canOpenUIAnyway = statusText == "Waiting"
        openAppMenuItem?.title = isReady ? "Open NmapUI" : (canOpenUIAnyway ? "Open UI Anyway" : "Starting NmapUI...")
        openAppMenuItem?.isEnabled = isReady || canOpenUIAnyway
        restartRuntimeMenuItem?.isEnabled = true
        openDataDirectoryMenuItem?.isEnabled = allowsLegacyControls
        launchAtLoginMenuItem?.isEnabled = allowsLegacyControls
        updateStatusIcon(isReady: isReady)
    }

    private func updateStatusIcon(isReady: Bool) {
        guard let button = statusItem?.button else { return }
        let symbolName = isReady ? "network" : "hourglass"
        let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "NmapUI")
        image?.isTemplate = true
        button.image = image
        button.contentTintColor = isReady ? .controlAccentColor : .secondaryLabelColor
    }
}
