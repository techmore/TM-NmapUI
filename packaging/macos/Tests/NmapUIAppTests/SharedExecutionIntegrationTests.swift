import AppKit
import Darwin
import Foundation
import RuntimeContracts
import SharedEngineCore
import SwiftUI
import Testing
@testable import NmapUIApp

@Suite("Shared execution UI", .serialized)
@MainActor
struct SharedExecutionIntegrationTests {
    func wait(_ label: String, _ check: () -> Bool) async throws {
        for _ in 0..<400 {
            if check() { return }
            try await Task.sleep(for: .milliseconds(25))
        }
        Issue.record("Timed out: \(label)")
        throw CocoaError(.validationMissingMandatoryProperty)
    }
    @Test("actual shared UI/menu/bridge controls never invoke the native runtime",
          .enabled(if: ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_SOURCE"] != nil))
    func canonicalNativeUI() async throws {
        _ = NSApplication.shared
        let fixture = try await NativeControlFixture()
        defer { fixture.signalStop() }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-ui-controls-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ExecutionSourceStore(choiceURL: root.appendingPathComponent("mode/source.json"),
            legacyDataDirectory: root.appendingPathComponent("legacy-must-not-be-created"),
            legacyLaunchAgentURL: root.appendingPathComponent("absent-agent.plist"))
        try store.persist(.shared)
        var opened: URL?
        let model = SharedEngineLibraryModel(openDocument: { opened = $0; return true }, revealDocument: { _ in
            Issue.record("Expected the injected document opener")
        }, reportStore: SharedEngineReportStore(root: root.appendingPathComponent("private-documents")))
        let router = ApplicationExecutionRouter(store: store, sharedScanner: model)
        var localEffects: [LegacyExecutionAction] = []
        let app = AppDelegate(executionRouter: router, legacyServices: LegacyRuntimeServices(permit: { localEffects.append($0); return false }))
        app.beginSelectedRuntime()
        model.address = fixture.endpoint.url.absoluteString
        model.username = "fixture-user"
        model.password = "fixture-contraseña-🔐"
        model.scanTarget = "127.0.0.1"
        model.attach()
        #expect(model.password.isEmpty)
        var windows: [NSWindow] = []
        defer { model.stop(); windows.forEach { $0.close() } }
        do {
            try await wait("authenticated HTTP plus canonical Socket.IO readiness") { model.connected && model.controlState.connection == .ready }
            let report = try #require(model.snapshot?.reports.first)
            model.download(report, format: .pdf)
            try await wait("authenticated shared report opened privately") { opened != nil && !model.busy }
            let file = try #require(opened)
            #expect(try Data(contentsOf: file) == Data("%PDF-1.4\nshared-ui-fixture\n%%EOF\n".utf8))
            #expect((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
            try await render(app, router, name: "ready", windows: &windows)

            // SwiftUI's model intent takes the same production source router.
            model.send(.start(target: model.scanTarget, skipHostDiscovery: false))
            try await wait("UI scan owns a canonical source run") { fixture.pids.count == 1 && model.controlState.jobs[.scan]?.status == .running }
            let first = try #require(model.controlState.jobs[.scan]?.sourceJobID)
            let firstPID = try #require(fixture.pids.first)
            #expect(!app.chooseExecutionSource(.legacy))
            #expect(store.resolve().source == .shared)
            app.sharedMenuAction(.pause, observedID: first)
            try await wait("menu paused actual scanner process") { model.controlState.jobs[.scan]?.paused == true }
            #expect(model.controlState.jobs[.scan]?.pauseMode == "process")
            try await render(app, router, name: "paused", windows: &windows)
            app.handleRuntimeBridgeAction("resume_job", payload: ["job_type": "scan", "source_job_id": first.uuidString])
            try await wait("WebKit port resumes canonical job") { model.controlState.jobs[.scan]?.paused == false }

            model.stop()
            try await Task.sleep(for: .milliseconds(100))
            #expect(kill(firstPID, 0) == 0) // Detach sends no cancellation.
            try await render(app, router, name: "detached-stale", windows: &windows)
            model.password = "fixture-contraseña-🔐"
            model.attach()
            try await wait("reattach observes existing service run without replay") { model.controlState.connection == .ready && model.controlState.jobs[.scan]?.sourceJobID == first }
            #expect(fixture.pids.count == 1)
            let stop = RuntimeClientRequestEnvelope(event: .stopScan, payload: ["source_job_id": .string(first.uuidString)])
            #expect(app.routeNonLegacyBridge(stop))
            try await wait("typed WebKit port cancels observed source") { model.controlState.latestCompletion[.scan]?.sourceJobID == first && model.controlState.latestCompletion[.scan]?.status == .cancelled }
            try await wait("first owned scanner reaped") { kill(firstPID, 0) == -1 && errno == ESRCH }

            let start = RuntimeClientRequestEnvelope(event: .startQuickScan, payload: ["target": .string("127.0.0.1")])
            #expect(app.routeNonLegacyBridge(start))
            try await wait("typed WebKit port starts next canonical run") { fixture.pids.count == 2 && model.controlState.jobs[.scan]?.status == .running && model.controlState.jobs[.scan]?.sourceJobID != first }
            let next = try #require(model.controlState.jobs[.scan]?.sourceJobID)
            app.sharedMenuAction(.stop, observedID: first)
            #expect(model.controlState.jobs[.scan]?.sourceJobID == next && model.controlState.jobs[.scan]?.status == .running)
            app.sharedMenuAction(.pause, observedID: next)
            try await wait("next run paused") { model.controlState.jobs[.scan]?.paused == true }
            app.sharedMenuAction(.stop, observedID: next)
            try await wait("menu stop wakes and cancels paused process") { model.controlState.latestCompletion[.scan]?.sourceJobID == next && model.controlState.latestCompletion[.scan]?.status == .cancelled }
            let secondPID = try #require(fixture.pids.last)
            try await wait("second owned scanner reaped") { kill(secondPID, 0) == -1 && errno == ESRCH }

            app.sharedMenuAction(.start, observedID: nil)
            try await wait("canonical cooldown remains an uncertain unscoped rejection") {
                model.controlNotice.localizedCaseInsensitiveContains("cooldown") && model.controlState.connection == .ready
            }
            #expect(model.controlState.startOutcome == .uncertain)
            #expect(fixture.pids.count == 2)
            try await render(app, router, name: "uncertain-cooldown", windows: &windows)
            model.send(.acknowledgeUncertain)
            #expect(model.controlState.startOutcome == .none)
            model.send(.reconnect)
            #expect(model.controlState.connection == .disconnected)
            try await wait("explicit fresh connection after acknowledgement") { model.controlState.connection == .ready }
            app.sharedMenuAction(.start, observedID: nil)
            try await wait("menu start uses canonical engine") { fixture.pids.count == 3 && model.controlState.jobs[.scan]?.status == .running }
            let final = try #require(model.controlState.jobs[.scan]?.sourceJobID)
            let finalPID = try #require(fixture.pids.last)
            app.applicationWillTerminate(Notification(name: NSApplication.willTerminateNotification))
            try await Task.sleep(for: .milliseconds(100))
            #expect(kill(finalPID, 0) == 0) // Quit also leaves service ownership intact.
            let observer = SharedEngineSocketClient(endpoint: fixture.endpoint, username: "fixture-user", password: "fixture-contraseña-🔐")
            defer { observer.disconnect() }
            try await observer.connect()
            try await wait("another authenticated frontend sees continuing service job") { observer.state.connection == .ready && observer.state.jobs[.scan]?.sourceJobID == final }
            try observer.cancel(.scan, observedID: final)
            try await wait("explicit subsequent cancellation reaps final scanner") { kill(finalPID, 0) == -1 && errno == ESRCH }
            #expect(localEffects.isEmpty)
            #expect(!FileManager.default.fileExists(atPath: store.legacyDataDirectory.path))
        } catch {
            print("Shared UI diagnostics:", model.notice, model.controlNotice, model.controlState)
            print((try? String(contentsOf: fixture.root.appendingPathComponent("server.log"), encoding: .utf8)) ?? "No server log")
            throw error
        }
        await fixture.stop()
    }

    private func render(_ app: AppDelegate, _ router: ApplicationExecutionRouter, name: String, windows: inout [NSWindow]) async throws {
        let directory = URL(fileURLWithPath: ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_UI_ARTIFACTS"]
            ?? FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-shared-controls-ui").path).appendingPathComponent("shared-controls")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for (label, scheme) in [("light", ColorScheme.light), ("dark", ColorScheme.dark)] {
            let content = ExecutionRootView(appDelegate: app, router: router).frame(width: 1100, height: 1250)
                .background(Color(NSColor.windowBackgroundColor)).environment(\.colorScheme, scheme)
            let hosting = NSHostingView(rootView: content)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 1250), styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = hosting
            window.appearance = NSAppearance(named: scheme == .dark ? .darkAqua : .aqua)
            hosting.frame = NSRect(x: 0, y: 0, width: 1100, height: 1250)
            windows.append(window) // Keep attachment owners alive throughout the control flow.
            hosting.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(100))
            let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
            hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
            try #require(bitmap.representation(using: .png, properties: [:])).write(to: directory.appendingPathComponent("\(name)-\(label).png"))
        }
    }
}

@MainActor
private final class NativeControlFixture {
    let process = Process()
    let endpoint: SharedEngineEndpoint
    let root: URL
    init() async throws {
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_CANONICAL_PYTHON"] ?? "python3",
            URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("SharedEngineCoreTests/Fixtures/canonical_control_server.py").path]
        process.environment = ProcessInfo.processInfo.environment.merging(["NMAPUI_CONTROL_FIXTURE_HTTP_READY": "1"]) { _, new in new }
        process.standardOutput = pipe; process.standardError = FileHandle.standardError
        try process.run(); try pipe.fileHandleForWriting.close()
        do {
            let data: Data = try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    var descriptor = pollfd(fd: pipe.fileHandleForReading.fileDescriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
                    guard poll(&descriptor, 1, 25000) > 0 else { continuation.resume(throwing: CocoaError(.fileReadUnknown)); return }
                    continuation.resume(returning: pipe.fileHandleForReading.availableData)
                }
            }
            struct Ready: Decodable { let port: Int; let root: String }
            let ready = try JSONDecoder().decode(Ready.self, from: data)
            endpoint = try SharedEngineEndpoint("http://127.0.0.1:\(ready.port)")
            root = URL(fileURLWithPath: ready.root)
        } catch {
            if process.isRunning { kill(process.processIdentifier, SIGTERM) }
            throw error
        }
    }
    var pids: [Int32] {
        guard let text = try? String(contentsOf: root.appendingPathComponent("invocations.jsonl"), encoding: .utf8) else { return [] }
        return text.split(separator: "\n").compactMap { line in
            guard let data = String(line).data(using: .utf8), let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
            return value["pid"] as? Int32
        }
    }
    func signalStop() { if process.isRunning { kill(process.processIdentifier, SIGTERM) } }
    func stop() async {
        signalStop()
        for _ in 0..<250 {
            if !process.isRunning { return }
            try? await Task.sleep(for: .milliseconds(20))
        }
        Issue.record("Owned native-control fixture cleanup exceeded five seconds")
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    }
}
