import Foundation
import Darwin
import SharedEngineCore
import Testing

@Suite("Shared engine HTTP client", .serialized)
struct SharedEngineClientTests {
    @Test("fixture startup has a bounded readiness deadline rather than blocking the test executor")
    func fixtureDeadline() throws {
        let start = Date()
        #expect(throws: FixtureStartupError.timeout) { try FlaskFixture(mode: "never-ready", startupTimeout: 0.15) }
        #expect(Date().timeIntervalSince(start) < 3)
    }
    @Test("endpoint is literal loopback without userinfo, alternate encodings or ambient proxies")
    func endpoints() throws {
        for value in ["http://127.0.0.1:9000", "http://[::1]:9000/"] { _ = try SharedEngineEndpoint(value) }
        for value in ["http://localhost:9000", "https://127.0.0.1", "http://127.1", "http://2130706433", "http://user:password@127.0.0.1", "http://127.0.0.1?secret=value", "http://127.0.0.1/#fragment", "http://127.0.0.1/api", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://%31%32%37.0.0.1", " http://127.0.0.1"] {
            #expect(throws: SharedEngineError.endpoint) { try SharedEngineEndpoint(value) }
        }
    }

    @Test("artifact routes encode legitimate nested paths and reject traversal and URL ambiguity")
    func paths() throws {
        let endpoint = try SharedEngineEndpoint("http://127.0.0.1:9000")
        let url = try endpoint.artifactURL(path: "Customer 雪/scan with spaces", format: .pdf)
        #expect(url.absoluteString == "http://127.0.0.1:9000/api/runtime/reports/Customer%20%E9%9B%AA/scan%20with%20spaces/pdf")
        for value in ["", "/absolute", "../secret", "a/../secret", "a/./b", "a//b", "a/", "a\\b", "https://example.org/a", "a%2fb", "a%252fb", "a%5cb", "a?x=y", "a#fragment", "runtime-job:abc", "a\nb"] {
            #expect(throws: SharedEngineError.path) { try endpoint.artifactURL(path: value, format: .pdf) }
        }
    }

    @Test("real Flask strict Basic access accepts Unicode credentials without requiring a browser session")
    func strictFlask() async throws {
        let fixture = try FlaskFixture()
        defer { fixture.stop() }
        let client = fixture.client()
        let snapshot = try await client.snapshot()
        #expect(snapshot.version == "v2026.10.25")
        #expect(!snapshot.localTrust)
        #expect(snapshot.status.hasActiveJobs)
        #expect(snapshot.history.count == 2)
        #expect(!snapshot.history[1].isArtifact)
        #expect(!snapshot.history[1].has(.pdf))
        #expect(snapshot.reports[0].has(.pdf))
        let path = snapshot.reports[0].path
        let pdf = try await client.report(path: path, format: .pdf)
        #expect(pdf == Data("%PDF-1.4\nfixture-report\n%%EOF\n".utf8))
        let xml = try await client.report(path: path, format: .xml)
        #expect(String(decoding: xml, as: UTF8.self).contains("<nmaprun>"))
        let html = try await client.report(path: path, format: .html)
        let text = String(decoding: html, as: UTF8.self)
        #expect(text.contains("http-equiv=\"Content-Security-Policy\""))
        #expect(text.contains("script-src 'none'"))
    }

    @Test("strict engine rejects missing and incorrect credentials without empty-state masking")
    func rejectedCredentials() async throws {
        let fixture = try FlaskFixture()
        defer { fixture.stop() }
        for client in [SharedEngineClient(endpoint: fixture.endpoint), SharedEngineClient(endpoint: fixture.endpoint, username: "fixture-user", password: "wrong")] {
            await #expect(throws: SharedEngineError.http(401)) { try await client.snapshot() }
        }
    }

    @Test("malformed, incompatible and bounded JSON errors are explicit", arguments: ["bad-json", "bad-schema", "oversized-json", "streamed-json", "not-ready", "unavailable"])
    func responseErrors(mode: String) async throws {
        let fixture = try FlaskFixture(mode: mode)
        defer { fixture.stop() }
        let expected: SharedEngineError = ["oversized-json", "streamed-json"].contains(mode) ? .oversized : mode == "not-ready" ? .notReady : mode == "unavailable" ? .http(503) : .schema
        await #expect(throws: expected) { try await fixture.client().snapshot() }
    }

    @Test("report redirects, oversized declarations, wrong document bytes and missing HTML policy are rejected", arguments: ["redirect-report", "bad-pdf", "bad-policy", "oversized-report"])
    func reportErrors(mode: String) async throws {
        let fixture = try FlaskFixture(mode: mode)
        defer { fixture.stop() }
        let format: SharedReportFormat = mode == "bad-policy" ? .html : .pdf
        let expected: SharedEngineError = mode == "redirect-report" ? .http(302) : mode == "bad-policy" ? .policy : mode == "oversized-report" ? .oversized : .artifact
        await #expect(throws: expected) { try await fixture.client().report(path: "Example customer/scan with spaces 雪", format: format) }
    }

    @Test("representative four MiB report transfer and cancellation")
    func largeReport() async throws {
        let fixture = try FlaskFixture(mode: "large-pdf")
        defer { fixture.stop() }
        let start = Date()
        let data = try await fixture.client().report(path: "Example customer/scan with spaces 雪", format: .pdf)
        #expect(data.count == 4_194_313)
        print("Shared engine 4 MiB authenticated download: \(Date().timeIntervalSince(start)) seconds")
        let slow = try FlaskFixture(mode: "slow-report")
        defer { slow.stop() }
        let slowClient = slow.client()
        let task = Task { try await slowClient.report(path: "Example customer/scan with spaces 雪", format: .pdf) }
        try await Task.sleep(nanoseconds: 50_000_000)
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test("frozen shared app, actual auth/routes/runtime DB and report files", .enabled(if: ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_SOURCE"] != nil))
    func canonicalEngine() async throws {
        let fixture = try FlaskFixture(canonical: true)
        defer { fixture.stop() }
        await #expect(throws: SharedEngineError.http(401)) { try await SharedEngineClient(endpoint: fixture.endpoint).snapshot() }
        let client = fixture.client()
        let snapshot = try await client.snapshot()
        #expect(snapshot.version == "v2026.10.25")
        #expect(!snapshot.localTrust)
        #expect(!snapshot.status.hasActiveJobs)
        #expect(snapshot.history.contains { $0.recordType == "scan_run" })
        let report = try #require(snapshot.reports.first)
        #expect(report.path == "Example customer/scan with spaces 雪")
        #expect(try await client.report(path: report.path, format: .pdf) == Data("%PDF-1.4\nfixture-report\n%%EOF\n".utf8))
        #expect(try await client.report(path: report.path, format: .xml).count > 0)
        let html = try await client.report(path: report.path, format: .html)
        #expect(String(decoding: html, as: UTF8.self).contains("Content-Security-Policy"))
        if let output = ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_UI_ARTIFACTS"], let baseline = fixture.baselinePath {
            let folder = URL(fileURLWithPath: output)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try Data(contentsOf: baseline).write(to: folder.appendingPathComponent("canonical-baseline.html"))
            try html.write(to: folder.appendingPathComponent("canonical-offline.html"))
        }
    }

    @Test("offline policy precedes decoy markup and refuses ineffective or executable policies")
    func offlinePolicy() throws {
        let policy = "default-src 'none'; script-src 'none'; base-uri 'none'; object-src 'none'"
        let canary = "<script>window.__canary=true;fetch('http://127.0.0.1:9/blocked-canary')</script>"
        let documents = [
            "comment": "<!-- <head> --> <html><head></head><body>\(canary)</body></html>",
            "rawtext": "<html><textarea><head></textarea><head></head><body>\(canary)</body></html>",
            "header": "<html><header>before head</header><head></head><body>\(canary)</body></html>",
            "attribute": "<html data-decoy=\"><head>\"><head></head><body>\(canary)</body></html>",
        ]
        for (name, original) in documents {
            let data = try SharedOfflineHTML.secure(Data(original.utf8), serverPolicy: policy)
            #expect(String(decoding: data, as: UTF8.self).hasPrefix("<!doctype html><meta http-equiv="))
            if let output = ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_UI_ARTIFACTS"] {
                let folder = URL(fileURLWithPath: output)
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                try data.write(to: folder.appendingPathComponent("adversarial-\(name).html"))
            }
        }
        for bad in ["frame-ancestors 'none'", "default-src 'none'; script-src 'unsafe-inline'", "default-src 'none'; script-src *", "default-src 'none'; script-src 'none'; script-src 'unsafe-inline'"] {
            #expect(throws: SharedEngineError.policy) { try SharedOfflineHTML.secure(Data("<html><head></head></html>".utf8), serverPolicy: bad) }
        }
    }
}

/// Launches only a disposable Flask fixture, never the app/scanner or a service.
final class FlaskFixture {
    let process: Process
    let endpoint: SharedEngineEndpoint
    let baselinePath: URL?

    init(mode: String = "valid", canonical: Bool = false, startupTimeout: TimeInterval = 30) throws {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [ProcessInfo.processInfo.environment[canonical ? "NMAPUI_SHARED_ENGINE_CANONICAL_PYTHON" : "NMAPUI_SHARED_ENGINE_FIXTURE_PYTHON"] ?? "python3",
                             URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent(canonical ? "Fixtures/canonical_server.py" : "Fixtures/server.py").path]
        process.environment = ProcessInfo.processInfo.environment.merging(["SHARED_FIXTURE_MODE": mode]) { _, new in new }
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        self.process = process
        print("Shared fixture startup: \(canonical ? "canonical" : mode)")
        do {
            let line = try readFixtureReady(pipe.fileHandleForReading, timeout: startupTimeout)
            let ready = try JSONDecoder().decode(Ready.self, from: line)
            endpoint = try SharedEngineEndpoint("http://127.0.0.1:\(ready.port)")
            baselinePath = ready.baselinePath.map { URL(fileURLWithPath: $0) }
            print("Shared fixture ready: \(canonical ? "canonical" : mode)")
        } catch {
            if process.isRunning { kill(process.processIdentifier, SIGTERM) }
            throw error
        }
    }

    private struct Ready: Decodable { let port: Int; let baselinePath: String? }
    func client() -> SharedEngineClient {
        SharedEngineClient(endpoint: endpoint, username: "fixture-user", password: "fixture-contraseña-🔐")
    }
    func stop() {
        if process.isRunning {
            process.terminate()
            // NSTask.waitUntilExit can deadlock Swift Testing's cooperative
            // executor after child exit. Reaping remains owned by Foundation.
            for _ in 0..<100 {
                if kill(process.processIdentifier, 0) == -1 && errno == ESRCH { return }
                usleep(10_000)
            }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
    }
}

private enum FixtureStartupError: Error { case timeout, ended, oversized }

private func readFixtureReady(_ handle: FileHandle, timeout: TimeInterval) throws -> Data {
    let descriptor = handle.fileDescriptor
    _ = fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK)
    let deadline = ProcessInfo.processInfo.systemUptime + timeout
    var data = Data()
    var chunk = [UInt8](repeating: 0, count: 512)
    while ProcessInfo.processInfo.systemUptime < deadline {
        var descriptorState = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        let result = poll(&descriptorState, 1, 50)
        if result < 0 && errno == EINTR { continue }
        guard result >= 0 else { throw FixtureStartupError.ended }
        if result == 0 { continue }
        let count = read(descriptor, &chunk, chunk.count)
        if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
        guard count > 0 else { throw FixtureStartupError.ended }
        data.append(contentsOf: chunk.prefix(count))
        guard data.count <= 4096 else { throw FixtureStartupError.oversized }
        if let newline = data.firstIndex(of: 10) { return data.prefix(through: newline) }
    }
    throw FixtureStartupError.timeout
}
