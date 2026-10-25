import Foundation

/// Owns the native runtime lifecycle responsibilities that previously lived in
/// AppDelegate (issue #226):
/// - startup sequencing for the native shell (bootstrap state, snapshots,
///   report refresh monitor, auto-scan LaunchAgent sync)
/// - readiness state transitions ("Starting..." → "Native ready")
/// - privileged helper authorization at launch
/// - capability refresh polling
///
/// AppDelegate keeps only menu coordination and delegates here.
@MainActor
final class RuntimeLifecycleController {
    let sessionState: AppSessionState
    private let allowsLegacy: () -> Bool
    private let reportRefreshMonitor = RuntimeReportRefreshMonitor()
    private var helperAuthorizationTask: Task<Void, Never>?
    private var capabilityRefreshTask: Task<Void, Never>?
    /// Called when readiness changes so the owner can sync menus.
    var onReadinessChange: (() -> Void)?

    init(sessionState: AppSessionState, allowsLegacy: @escaping () -> Bool = { ExecutionSourceStore.live.resolve().source == .legacy }) {
        self.sessionState = sessionState
        self.allowsLegacy = allowsLegacy
    }

    // MARK: - Startup

    /// Runs the native shell startup sequence after bootstrap data is loaded.
    func startStartupSequence(dataDirectory: URL) {
        guard allowsLegacy() else { return }
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Starting..."
        sessionState.startupHint = "Preparing native shell..."
        sessionState.preloadMessage = "Loading dashboard..."
        sessionState.showLoadingStrip = true
        sessionState.emitBootstrapState(
            version: RuntimeIdentity.productVersion(),
            hosts: []
        )
        sessionState.emitHistoryData()
        sessionState.emitReportsData()
        sessionState.emitAutoScanConfig()
        sessionState.emitGoogleDriveStatus()
        sessionState.emitCustomerProfile()
        refreshCapabilities()

        // Re-sync LaunchAgent if auto-scan was already enabled.
        if sessionState.runtimeAutoScanSnapshot.enabled {
            AutoScanScheduler.sync(
                enabled: true,
                recurrence: sessionState.runtimeAutoScanSnapshot.recurrence,
                startTime: sessionState.runtimeAutoScanSnapshot.startTime
            )
        }
        reportRefreshMonitor.start(dataDirectory: dataDirectory) { [weak self] in
            self?.sessionState.emitReportsRefresh()
        }
        sessionState.clearScanSession()

        helperAuthorizationTask = Task { [weak self] in
            await self?.authorizePrivilegedHelperAfterLaunchDelay()
        }
        markReady()
    }

    /// Waits briefly so the initial window appears before macOS presents the
    /// one-time privileged-helper authorization prompt.
    private func authorizePrivilegedHelperAfterLaunchDelay() async {
        try? await Task.sleep(nanoseconds: 500_000_000)
        guard !Task.isCancelled, allowsLegacy() else { return }
        do {
            try await PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
            guard !Task.isCancelled, allowsLegacy() else { return }
            RuntimeDiagnosticsLogger.log("Launch-time privileged scanner authorization is ready")
        } catch {
            guard !Task.isCancelled, allowsLegacy() else { return }
            RuntimeDiagnosticsLogger.error("Launch-time privileged scanner authorization was not completed: \(error.localizedDescription)")
        }
        emitPrivilegeHelperStatusFromOwner()
    }

    private func emitPrivilegeHelperStatusFromOwner() {
        onPrivilegeHelperStatusRefresh?()
    }

    /// Hook set by AppDelegate to forward privilege status emission.
    var onPrivilegeHelperStatusRefresh: (() -> Void)?

    // MARK: - Readiness

    func markReady() {
        sessionState.runtimeIsReady = true
        sessionState.runtimeStatusText = "Native ready"
        sessionState.startupHint = "Ready to scan"
        sessionState.preloadMessage = "Dashboard ready"
        sessionState.showLoadingStrip = false
        onReadinessChange?()
    }

    // MARK: - Capabilities

    func stop() {
        helperAuthorizationTask?.cancel()
        capabilityRefreshTask?.cancel()
        reportRefreshMonitor.stop()
    }

    func refreshCapabilities() {
        guard allowsLegacy() else { return }
        capabilityRefreshTask?.cancel()
        capabilityRefreshTask = Task { [weak self] in
            guard let self, !Task.isCancelled, self.allowsLegacy() else { return }
            let capabilities = await Task.detached(priority: .utility) {
                RuntimeCapabilities.current()
            }.value
            guard !Task.isCancelled, self.allowsLegacy() else { return }
            self.sessionState.runtimeCapabilities = capabilities
            RuntimeMetadataStore.persistCapabilities(
                capabilities,
                to: RuntimeSettingsStore.currentDataDirectoryURL()
            )
        }
    }
}
