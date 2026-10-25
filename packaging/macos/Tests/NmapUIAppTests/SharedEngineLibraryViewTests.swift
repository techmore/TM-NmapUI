import AppKit
import Darwin
import Foundation
import SharedEngineCore
import SwiftUI
import Testing
@testable import NmapUIApp

@Suite("Shared engine native library", .serialized)
@MainActor
struct SharedEngineLibraryViewTests {
    @Test("native view renders connected long names, stale data, 401 and unavailable in light and dark")
    func renderedStates() async throws {
        _ = NSApplication.shared
        let fixture = try LibraryFixture(mode: "long")
        defer { fixture.stop() }
        let model = SharedEngineLibraryModel(openDocument: { _ in true }, revealDocument: { _ in })
        model.address = fixture.address
        model.username = "fixture-user"
        model.password = "fixture-contraseña-🔐"
        model.attach()
        try await finish(model)
        #expect(model.connected)
        #expect(model.password.isEmpty)
        try await capture(model, name: "connected-long")
        model.stop()
        #expect(model.snapshot != nil)
        #expect(model.notice.contains("out of date"))
        try await capture(model, name: "disconnected-stale")
        model.password = "incorrect"
        model.attach()
        try await finish(model)
        #expect(!model.connected)
        #expect(model.snapshot == nil)
        #expect(model.notice.contains("credentials"))
        try await capture(model, name: "credentials-401")
        let unavailable = try LibraryFixture(mode: "unavailable")
        defer { unavailable.stop() }
        model.address = unavailable.address
        model.password = "fixture-contraseña-🔐"
        model.attach()
        try await finish(model)
        #expect(!model.connected)
        #expect(model.notice.contains("unavailable"))
        try await capture(model, name: "unavailable")
    }

    @Test("native artifact action opens authenticated owner-only document bytes, never an HTTP URL")
    func nativeDownload() async throws {
        let fixture = try LibraryFixture(mode: "valid")
        defer { fixture.stop() }
        var opened: URL?
        let cacheRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: cacheRoot) }
        let model = SharedEngineLibraryModel(openDocument: { opened = $0; return true }, revealDocument: { _ in Issue.record("Unexpected fallback viewer") }, reportStore: SharedEngineReportStore(root: cacheRoot))
        model.address = fixture.address
        model.username = "fixture-user"
        model.password = "fixture-contraseña-🔐"
        model.attach()
        try await finish(model)
        let report = try #require(model.snapshot?.reports.first)
        model.download(report, format: .pdf)
        try await finish(model)
        #expect(model.downloadNotice.contains("Opened"))
        let file = try #require(opened)
        #expect(file.isFileURL)
        #expect(try Data(contentsOf: file) == Data("%PDF-1.4\nfixture-report\n%%EOF\n".utf8))
        #expect((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        model.stop()
        #expect(FileManager.default.fileExists(atPath: file.path)) // Detach retains a viewer's document.
    }

    @Test("cancelled attachment and rapid refresh cannot overwrite a newer idle state")
    func cancellation() async throws {
        let fixture = try LibraryFixture(mode: "valid")
        defer { fixture.stop() }
        let model = SharedEngineLibraryModel()
        model.address = fixture.address
        model.username = "fixture-user"
        model.password = "fixture-contraseña-🔐"
        model.attach()
        let firstGeneration = model.generation
        model.stop()
        for _ in 0..<10 { await Task.yield() }
        #expect(!model.busy)
        #expect(!model.connected)
        #expect(model.snapshot == nil)
        model.password = "fixture-contraseña-🔐"
        model.attach()
        model.stop(ifGeneration: firstGeneration) // A disappearing old view cannot detach the new attachment.
        try await finish(model)
        #expect(model.connected)
        model.refreshNow()
        #expect(model.busy)
        model.refreshNow()
        model.stop()
        for _ in 0..<10 { await Task.yield() }
        #expect(!model.busy)
        #expect(!model.connected)
        #expect(model.notice.contains("out of date"))
    }

    private func finish(_ model: SharedEngineLibraryModel) async throws {
        for _ in 0..<2000 {
            if !model.busy { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        model.stop()
        Issue.record("Shared engine operation exceeded fixture timeout")
    }

    private func capture(_ model: SharedEngineLibraryModel, name: String) async throws {
        let output = URL(fileURLWithPath: ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_UI_ARTIFACTS"]
            ?? FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-shared-engine-ui").path)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        var windows: [NSWindow] = []
        for (label, scheme) in [("light", ColorScheme.light), ("dark", ColorScheme.dark)] {
            let content = ScrollView {
                SharedEngineLibraryView(model: model).padding(24)
            }.frame(width: 1100, height: 900).background(Color(NSColor.windowBackgroundColor))
                .environment(\.colorScheme, scheme)
            let hosting = NSHostingView(rootView: content)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 900), styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false
            windows.append(window)
            window.contentView = hosting
            hosting.frame = NSRect(x: 0, y: 0, width: 1100, height: 900)
            window.appearance = NSAppearance(named: scheme == .dark ? .darkAqua : .aqua)
            hosting.layoutSubtreeIfNeeded()
            try await Task.sleep(nanoseconds: 150_000_000)
            let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
            hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            try png.write(to: output.appendingPathComponent("\(name)-\(label).png"))
        }
        windows.forEach { $0.close() }
        try await Task.sleep(nanoseconds: 100_000_000) // Settle the real onDisappear cleanup before the next attachment.
    }
}

private final class LibraryFixture {
    let process: Process
    let address: String
    init(mode: String) throws {
        process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_FIXTURE_PYTHON"] ?? "python3",
            URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("SharedEngineCoreTests/Fixtures/server.py").path]
        process.environment = ProcessInfo.processInfo.environment.merging(["SHARED_FIXTURE_MODE": mode]) { _, new in new }
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let ready = try JSONDecoder().decode(Ready.self, from: pipe.fileHandleForReading.availableData)
        address = "http://127.0.0.1:\(ready.port)"
    }
    private struct Ready: Decodable { let port: Int }
    func stop() {
        if process.isRunning {
            process.terminate()
            for _ in 0..<100 {
                if kill(process.processIdentifier, 0) == -1 && errno == ESRCH { return }
                usleep(10_000)
            }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
    }
}
