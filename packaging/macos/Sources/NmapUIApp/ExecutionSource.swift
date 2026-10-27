import Darwin
import Foundation
import Combine

/// A source is an explicit execution boundary, never a network-error fallback.
enum ExecutionSource: String, Codable, CaseIterable { case unselected, shared, legacy }

struct ExecutionSourceResolution: Equatable {
    let source: ExecutionSource
    let existingLegacyInstallation: Bool
}

/// Read-only startup detection. No preferences, Keychain, helpers or network
/// bootstrap are initialized to decide which execution source owns this app.
struct ExecutionSourceStore {
    let choiceURL: URL
    private let legacyDirectoryProvider: () -> URL
    var legacyDataDirectory: URL { legacyDirectoryProvider() }
    let legacyLaunchAgentURL: URL
    let scheduledExecutables: [URL]

    init(choiceURL: URL, legacyDataDirectory: URL, legacyLaunchAgentURL: URL, legacyDirectoryProvider: (() -> URL)? = nil, scheduledExecutables: [URL] = []) {
        self.choiceURL = choiceURL
        self.legacyDirectoryProvider = legacyDirectoryProvider ?? { legacyDataDirectory }
        self.legacyLaunchAgentURL = legacyLaunchAgentURL
        self.scheduledExecutables = scheduledExecutables
    }

    static var live: Self {
        Self(choiceURL: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("com.techmore.NmapUI/execution-source.json"),
             legacyDataDirectory: RuntimeSettingsStore.currentDataDirectoryURL(),
             legacyLaunchAgentURL: AutoScanScheduler.launchAgentPlistURL,
             legacyDirectoryProvider: { RuntimeSettingsStore.currentDataDirectoryURL() },
             scheduledExecutables: currentScheduledExecutables)
    }
    private static var currentScheduledExecutables: [URL] {
        guard let executable = Bundle.main.executableURL else { return [] }
        var paths = [executable]
        if ["NmapUI", "NmapUI.real"].contains(executable.lastPathComponent) {
            paths += ["NmapUI", "NmapUI.real"].map { executable.deletingLastPathComponent().appendingPathComponent($0) }
        }
        return paths
    }
    /// An older copy at another path cannot be assumed to implement this gate.
    /// Refuse migration instead of removing or rewriting its native schedule.
    var existingScheduleHonorsSourceChoice: Bool {
        guard FileManager.default.fileExists(atPath: legacyLaunchAgentURL.path) else { return true }
        guard let data = try? Data(contentsOf: legacyLaunchAgentURL), data.count <= 1024 * 1024,
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let arguments = plist["ProgramArguments"] as? [String], arguments.contains("--scheduled-scan"),
              let command = arguments.first, command.hasPrefix("/") else { return false }
        let target = URL(fileURLWithPath: command).resolvingSymlinksInPath().standardizedFileURL
        return scheduledExecutables.contains { $0.resolvingSymlinksInPath().standardizedFileURL == target }
    }
    func resolve() -> ExecutionSourceResolution {
        if FileManager.default.fileExists(atPath: choiceURL.path) {
            guard let data = try? Data(contentsOf: choiceURL), data.count <= 1024,
                  let choice = try? JSONDecoder().decode(Choice.self, from: data) else {
                return ExecutionSourceResolution(source: .unselected, existingLegacyInstallation: false)
            }
            return ExecutionSourceResolution(source: choice.source, existingLegacyInstallation: choice.source == .legacy && existingLegacyInstallation)
        }
        // Older installs have no mode marker. Their enabled native schedules
        // must continue until the operator explicitly changes execution source.
        let existing = existingLegacyInstallation
        return ExecutionSourceResolution(source: existing ? .legacy : .unselected, existingLegacyInstallation: existing)
    }
    private var existingLegacyInstallation: Bool {
        let manager = FileManager.default
        if manager.fileExists(atPath: legacyLaunchAgentURL.path) { return true }
        for name in ["runtime-settings.json", "runtime-identity.json", "active-scan.lock"] {
            if manager.fileExists(atPath: legacyDataDirectory.appendingPathComponent(name).path) { return true }
        }
        if let data = try? Data(contentsOf: legacyDataDirectory.appendingPathComponent("config.json")),
           data.count <= 1024 * 1024,
           let config = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           config["autoScan"] is [String: Any] { return true }
        return false
    }
    private struct Choice: Codable { let source: ExecutionSource }
    func persist(_ source: ExecutionSource) throws {
        let parent = choiceURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let temporary = parent.appendingPathComponent(".execution-choice-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: temporary) }
        guard FileManager.default.createFile(atPath: temporary.path, contents: try JSONEncoder().encode(Choice(source: source)), attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        guard rename(temporary.path, choiceURL.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }
}

enum SharedMenuAction: CaseIterable { case start, stop, pause, resume }

enum LegacyExecutionAction: String, CaseIterable {
    case bootstrap, scan, stop, report, network, helperStatus, installHelper, preferences, scheduler, bridge
    case drive, customers, archive, capabilities, installTools, launchAtLogin
}

/// All entrypoints consult the same production gate, including stale WebKit
/// callbacks. A persisted change in another process also revokes local effects.
@MainActor
final class ApplicationExecutionRouter: ObservableObject {
    @Published private(set) var source: ExecutionSource
    @Published private(set) var restartPending = false
    @Published private(set) var notice = ""
    let sourceStore: ExecutionSourceStore
    let existingLegacyInstallation: Bool
    let sharedScanner: SharedEngineLibraryModel
    private var transitionLock: ScanRunLock?
    private var didBootstrapLegacy = false

    init(store: ExecutionSourceStore = .live, sharedScanner: SharedEngineLibraryModel = SharedEngineLibraryModel()) {
        sourceStore = store
        self.sharedScanner = sharedScanner
        let resolution = store.resolve()
        source = resolution.source
        existingLegacyInstallation = resolution.existingLegacyInstallation
        sharedScanner.routeControl = { [weak self] intent in self?.shared(intent) }
    }
    var allowsShared: Bool { source == .shared && !restartPending && sourceStore.resolve().source == .shared }
    func shared(_ intent: SharedControlIntent) {
        guard allowsShared else { notice = "Shared controls are unavailable until Shared scanner is the active execution source. No local action was taken."; return }
        sharedScanner.performSharedControl(intent)
    }
    /// Existing native and WebKit entrypoints retain their declared semantics.
    /// Quick/discovery can use the canonical workflow; native report/preset
    /// variants are not silently relabelled as a different canonical operation.
    func start(target: String, preset: String, vpnHelper: Bool, skipHostDiscovery: Bool = false, legacyEffect: () -> Void) {
        if allowsLegacy { _ = legacy(.scan, perform: legacyEffect); return }
        guard allowsShared else { notice = "Choose an execution source before starting a scan."; return }
        guard ["quick", "discovery"].contains(preset), !vpnHelper else {
            notice = "Native Complete, Dragnet and VPN presets belong to Legacy compatibility. Use the shared scanner's canonical Discovery controls; no local scan was started."
            return
        }
        shared(.start(target: target, skipHostDiscovery: skipHostDiscovery))
    }
    func stop(observedID: UUID?, legacyEffect: () -> Void) {
        if allowsLegacy { _ = legacy(.stop, perform: legacyEffect); return }
        guard let observedID else { notice = "Refresh the shared scan and use its observed run's Stop control."; return }
        shared(.cancel(.scan, observedID))
    }
    var allowsLegacy: Bool {
        source == .legacy && !restartPending && sourceStore.resolve().source == .legacy
    }
    @discardableResult
    func legacy(_ action: LegacyExecutionAction, perform: () -> Void) -> Bool {
        guard allowsLegacy else {
            notice = restartPending ? "Restart is pending. New local work is blocked." : "This action belongs to Legacy compatibility mode. Shared mode never starts the local scanner or helper."
            return false
        }
        if action == .bootstrap {
            guard !didBootstrapLegacy else { return false }
            didBootstrapLegacy = true
        }
        perform()
        return true
    }
    /// Acquiring the actual scan lock makes this atomic with UI and scheduled
    /// scans. Retain it until exit, so a runner that read the old choice cannot
    /// start between persisting the new choice and restarting this application.
    @discardableResult
    func choose(_ next: ExecutionSource, localScanActive: Bool) -> Bool {
        guard !restartPending, !localScanActive else { notice = "Finish or explicitly cancel the active Legacy scan, authorization or download before changing source."; return false }
        if next == .legacy, source == .shared, sharedScanner.controlState.jobs.values.contains(where: { !$0.status.isTerminal }) {
            notice = "An observed shared job is active or its state is unknown. Refresh and finish or explicitly cancel it before switching to the separate Legacy engine. Detach and Quit continue to leave service jobs running."
            return false
        }
        guard next != .shared || sourceStore.existingScheduleHonorsSourceChoice else {
            notice = "The existing native LaunchAgent is unreadable or launches another app copy. Disable that schedule explicitly in Legacy before switching to Shared; its configuration and archive are preserved."
            return false
        }
        let needsLock = FileManager.default.fileExists(atPath: sourceStore.legacyDataDirectory.path)
        let lock = needsLock ? ScanRunLock.acquire(in: sourceStore.legacyDataDirectory, recordMarker: false) : nil
        guard !needsLock || lock != nil else { notice = "A Legacy UI or scheduled scan owns the scan lock. Wait for it to finish before changing source."; return false }
        do {
            try sourceStore.persist(next)
            if source == .unselected && !didBootstrapLegacy {
                source = next
                // The choice remains protected during this first activation;
                // no native scanner can start before its fresh source check.
            } else {
                restartPending = true
                transitionLock = lock
                notice = "Source saved. Quit and reopen to use \(next == .shared ? "Shared scanner" : "Legacy compatibility"). New local work is blocked. Shared service jobs continue unless you explicitly cancel them."
            }
            return true
        } catch {
            notice = "The source choice could not be saved. No execution source was changed."
            return false
        }
    }
    func reject(_ message: String) { notice = message }
}

/// Injected effects let app-entrypoint tests observe attempted local work without
/// ever touching helpers, Keychain or service registration. Production executes
/// each effect only after the source router's gate succeeds.
@MainActor
struct LegacyRuntimeServices {
    var permit: (LegacyExecutionAction) -> Bool
    static let live = Self(permit: { _ in true })
}
