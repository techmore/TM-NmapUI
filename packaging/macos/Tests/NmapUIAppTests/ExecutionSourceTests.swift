import Darwin
import Foundation
import RuntimeContracts
import SharedEngineCore
import Testing
@testable import NmapUIApp

@Suite("Application execution source", .serialized)
@MainActor
struct ExecutionSourceTests {
    func temporary() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-source-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }
    func store(_ root: URL) -> ExecutionSourceStore {
        ExecutionSourceStore(choiceURL: root.appendingPathComponent("choice/execution-source.json"),
            legacyDataDirectory: root.appendingPathComponent("legacy"),
            legacyLaunchAgentURL: root.appendingPathComponent("LaunchAgents/com.techmore.nmapui.autoscan.plist"))
    }
    func seedLegacy(_ store: ExecutionSourceStore) throws -> Data {
        try FileManager.default.createDirectory(at: store.legacyDataDirectory, withIntermediateDirectories: true)
        let config = Data(#"{"autoScan":{"enabled":true,"recurrence":"custom-legacy-rule","startTime":"02:15"},"keep":"opaque"}"#.utf8)
        try config.write(to: store.legacyDataDirectory.appendingPathComponent("config.json"))
        try Data("legacy archive sentinel".utf8).write(to: store.legacyDataDirectory.appendingPathComponent("history.json"))
        return config
    }
    @Test func newInstallHasNoEngineUntilExplicitSelection() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root)
        let router = ApplicationExecutionRouter(store: source)
        #expect(router.source == .unselected)
        #expect(ScheduledScanRunner.admit(store: source) == nil)
        #expect(!FileManager.default.fileExists(atPath: source.legacyDataDirectory.path))
        #expect(router.choose(.shared, localScanActive: false))
        #expect(router.source == .shared)
        #expect(!router.restartPending)
        #expect(!FileManager.default.fileExists(atPath: source.legacyDataDirectory.path))
        #expect((try FileManager.default.attributesOfItem(atPath: source.choiceURL.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    }
    @Test func oldScheduleIsPreservedWithoutAnImplicitSourceMigration() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); let bytes = try seedLegacy(source)
        let router = ApplicationExecutionRouter(store: source)
        #expect(router.source == .legacy)
        #expect(router.existingLegacyInstallation)
        var admission = ScheduledScanRunner.admit(store: source)
        #expect(admission != nil)
        #expect(!router.choose(.shared, localScanActive: false))
        #expect(!FileManager.default.fileExists(atPath: source.choiceURL.path))
        admission = nil
        let marker = try Data(contentsOf: source.legacyDataDirectory.appendingPathComponent("active-scan.lock"))
        #expect(router.choose(.shared, localScanActive: false))
        #expect(router.restartPending)
        #expect(!router.allowsLegacy)
        #expect(ScheduledScanRunner.admit(store: source) == nil)
        #expect(try Data(contentsOf: source.legacyDataDirectory.appendingPathComponent("config.json")) == bytes)
        #expect(try String(contentsOf: source.legacyDataDirectory.appendingPathComponent("history.json"), encoding: .utf8) == "legacy archive sentinel")
        #expect(try Data(contentsOf: source.legacyDataDirectory.appendingPathComponent("active-scan.lock")) == marker)
        #expect(ScanRunLock.acquire(in: source.legacyDataDirectory) == nil)
    }
    @Test func launchAgentAloneDetectsCompatibilityWithoutReadingSecrets() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root)
        try FileManager.default.createDirectory(at: source.legacyLaunchAgentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("opaque original agent".utf8).write(to: source.legacyLaunchAgentURL)
        #expect(source.resolve().source == .legacy)
        try source.persist(.shared)
        #expect(source.resolve().source == .shared)
        #expect(ScheduledScanRunner.admit(store: source) == nil)
        #expect(try String(contentsOf: source.legacyLaunchAgentURL, encoding: .utf8) == "opaque original agent")
    }
    @Test func separateScheduledProcessLockRefusesSourceChangeWithoutStoppingIt() async throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); let original = try seedLegacy(source)
        let child = Process(), pipe = Pipe()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        child.arguments = [ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_CANONICAL_PYTHON"] ?? "python3", "-u", "-c",
            "import fcntl,sys,time; f=open(sys.argv[1],'a+'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('locked',flush=True); time.sleep(30)",
            source.legacyDataDirectory.appendingPathComponent("active-scan.lock").path]
        child.standardOutput = pipe
        try child.run()
        try pipe.fileHandleForWriting.close()
        defer { if child.isRunning { kill(child.processIdentifier, SIGTERM) } }
        let ready: Data = try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var descriptor = pollfd(fd: pipe.fileHandleForReading.fileDescriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
                guard poll(&descriptor, 1, 5000) > 0 else { continuation.resume(throwing: CocoaError(.fileReadUnknown)); return }
                continuation.resume(returning: pipe.fileHandleForReading.availableData)
            }
        }
        #expect(ready == Data("locked\n".utf8))
        let router = ApplicationExecutionRouter(store: source)
        #expect(!router.choose(.shared, localScanActive: false))
        #expect(kill(child.processIdentifier, 0) == 0)
        #expect(!FileManager.default.fileExists(atPath: source.choiceURL.path))
        #expect(try Data(contentsOf: source.legacyDataDirectory.appendingPathComponent("config.json")) == original)
    }

    @Test func unmanagedLegacyAgentCannotBeSilentlyAssumedToHonorTheNewSource() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); _ = try seedLegacy(source)
        try FileManager.default.createDirectory(at: source.legacyLaunchAgentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = try PropertyListSerialization.data(fromPropertyList: ["ProgramArguments": ["/another/old/NmapUI", "--scheduled-scan"], "KeepAlive": false], format: .xml, options: 0)
        try original.write(to: source.legacyLaunchAgentURL)
        let router = ApplicationExecutionRouter(store: source)
        #expect(!router.choose(.shared, localScanActive: false))
        #expect(!FileManager.default.fileExists(atPath: source.choiceURL.path))
        #expect(try Data(contentsOf: source.legacyLaunchAgentURL) == original)
        let managed = ExecutionSourceStore(choiceURL: source.choiceURL, legacyDataDirectory: source.legacyDataDirectory,
            legacyLaunchAgentURL: source.legacyLaunchAgentURL, scheduledExecutables: [URL(fileURLWithPath: "/another/old/NmapUI")])
        #expect(ApplicationExecutionRouter(store: managed).choose(.shared, localScanActive: false))
        #expect(try Data(contentsOf: source.legacyLaunchAgentURL) == original)
    }

    @Test func pendingRestartBlocksEveryLegacyEffectAndExternalChoiceIsFresh() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); _ = try seedLegacy(source)
        let first = ApplicationExecutionRouter(store: source)
        let other = ApplicationExecutionRouter(store: source)
        #expect(first.choose(.shared, localScanActive: false))
        var effects = 0
        for action in LegacyExecutionAction.allCases {
            #expect(!first.legacy(action) { effects += 1 })
            #expect(!other.legacy(action) { effects += 1 })
        }
        #expect(effects == 0)
        #expect(!other.allowsLegacy)
        #expect(ScheduledScanRunner.admit(store: source) == nil)
    }
    @Test func currentLegacyDirectoryRatherThanStartupDirectoryOwnsTransitionLock() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        var current = root.appendingPathComponent("first")
        let source = ExecutionSourceStore(choiceURL: root.appendingPathComponent("choice/source.json"), legacyDataDirectory: current,
            legacyLaunchAgentURL: root.appendingPathComponent("absent-agent"), legacyDirectoryProvider: { current })
        try source.persist(.legacy)
        let router = ApplicationExecutionRouter(store: source)
        current = root.appendingPathComponent("new-data-folder")
        let lock = try #require(ScanRunLock.acquire(in: current))
        #expect(!router.choose(.shared, localScanActive: false))
        #expect(source.resolve().source == .legacy)
        _ = lock
    }
    @Test("production AppDelegate, dispatcher, and scheduler perform zero local effects", arguments: [ExecutionSource.shared, .unselected])
    func sharedEntrypointsHaveNoLocalEffects(mode: ExecutionSource) async throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); try source.persist(mode)
        let router = ApplicationExecutionRouter(store: source)
        var effects: [LegacyExecutionAction] = []
        var driveCalls = 0, schedulerCalls = 0, authCalls = 0
        let state = AppSessionState(googleDriveStatusProvider: { _ in
            driveCalls += 1
            return GoogleDriveService.Status(success: false, status: "isolated", configured: false, connected: false, error: "not configured")
        })
        let app = AppDelegate(executionRouter: router, legacyServices: LegacyRuntimeServices(permit: { effects.append($0); return false }), sessionState: state)
        app.beginSelectedRuntime()
        app.startQuickScanFromNativeShell()
        for preset in ["quick", "complete", "dragnet"] { app.startScanFromNativeShell(target: "127.0.0.1", scanKind: preset, vpnHelper: true) }
        app.stopSwiftManagedScan()
        app.stopSwiftManagedScan(observedID: UUID())
        let result = await app.startSwiftManagedScan(target: "127.0.0.1", usePn: false, vpnHelper: false, scanKind: "quick")
        #expect(!result.completed)
        #expect(await app.generateAndPublishReport(xmlPath: root.appendingPathComponent("missing.xml"), target: "127.0.0.1", duration: "0", hostCount: 0, scanKind: "quick", status: "completed", error: nil) == nil)
        app.emitPrivilegeHelperStatus(); app.installPrivilegeHelperFromSettings(); app.installGowitness()
        app.savePreferences(); app.resetPreferences(); app.chooseDataDirectory(); app.openDataDirectory()
        app.connectGoogleDriveFromSettings(); app.disconnectGoogleDriveFromSettings()
        app.saveGoogleDriveSettingsFromNative(enabled: true, folderID: "opaque")
        app.saveGoogleDriveCredentialsFromNative("{}")
        app.saveAppSettingsFromWeb([:]); app.createCustomer("opaque"); app.selectCustomer(nil); app.updateCustomerPrefix("opaque")
        app.emitCurrentRuntimeSnapshotToWebView(); app.refreshSelectedRuntime()
        let services = RuntimeAutoScanServices(ensureHelperReady: { authCalls += 1 }, sync: { _, _, _ in schedulerCalls += 1; return .success(()) }, presentFailure: { _ in })
        let dispatcher = RuntimeRequestDispatcher(sessionState: state, autoScanServices: services, allowsLegacy: { router.allowsLegacy })
        for event in RuntimeClientRequest.allCases {
            let request = RuntimeClientRequestEnvelope(event: event, payload: [:])
            #expect(app.routeNonLegacyBridge(request))
            _ = dispatcher.dispatch(request, dataDirectory: source.legacyDataDirectory, version: "fixture")
            #expect(dispatcher.scanCoordinatorRequest(from: request) == nil)
        }
        for action in ["start_quick_scan", "start_complete_scan", "start_dragnet_scan", "stop_scan", "cancel_job", "pause_job", "resume_job"] {
            app.handleRuntimeBridgeAction(action, payload: ["target": "127.0.0.1", "source_job_id": UUID().uuidString, "job_type": "scan"])
        }
        for action in SharedMenuAction.allCases { app.sharedMenuAction(action, observedID: UUID()) }
        #expect(ScheduledScanRunner.admit(store: source) == nil)
        await Task.yield()
        #expect(effects.isEmpty)
        #expect(driveCalls == 0 && schedulerCalls == 0 && authCalls == 0)
        #expect(!FileManager.default.fileExists(atPath: source.legacyDataDirectory.path))
    }
    @Test func deferredLegacyWorkCannotStartInTheRestartGap() async throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); _ = try seedLegacy(source)
        let router = ApplicationExecutionRouter(store: source)
        let app = AppDelegate(executionRouter: router, legacyServices: LegacyRuntimeServices(permit: { _ in false }))
        var effects = 0
        app.legacyWorkQueue.enqueue { effects += 1 }
        // No await: the operation is queued but has not started.
        #expect(app.chooseExecutionSource(.shared))
        await Task.yield(); await Task.yield()
        #expect(effects == 0)
        #expect(app.legacyWorkQueue.runningCount == 0)
    }
    @Test func inFlightLegacyActionsMustUnwindBeforeChangingSource() async throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); _ = try seedLegacy(source)
        let router = ApplicationExecutionRouter(store: source)
        let app = AppDelegate(executionRouter: router, legacyServices: LegacyRuntimeServices(permit: { _ in false }))
        var afterAwaitEffects = 0
        app.legacyWorkQueue.enqueue {
            try? await Task.sleep(for: .seconds(10))
            guard !Task.isCancelled, router.allowsLegacy else { return }
            afterAwaitEffects += 1
        }
        for _ in 0..<100 {
            if app.legacyWorkQueue.runningCount > 0 { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(app.legacyWorkQueue.runningCount == 1)
        #expect(!app.chooseExecutionSource(.shared))
        app.cancelPendingLegacyActions()
        for _ in 0..<100 {
            if app.legacyWorkQueue.runningCount == 0 { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(app.legacyWorkQueue.runningCount == 0)
        #expect(app.chooseExecutionSource(.shared))
        #expect(afterAwaitEffects == 0)
    }

    @Test func legacyBootstrapIsExplicitAndAtMostOnce() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let source = store(root); try source.persist(.legacy)
        let router = ApplicationExecutionRouter(store: source)
        var effects: [LegacyExecutionAction] = []
        let app = AppDelegate(executionRouter: router, legacyServices: LegacyRuntimeServices(permit: { effects.append($0); return false }))
        app.beginSelectedRuntime(); app.beginSelectedRuntime()
        #expect(effects == [.bootstrap])
    }
}
