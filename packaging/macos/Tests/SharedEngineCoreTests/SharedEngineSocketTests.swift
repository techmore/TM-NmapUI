import Foundation
import Testing
@preconcurrency import SocketIO
@testable import SharedEngineCore

@Suite(.serialized)
@MainActor
struct SharedEngineSocketTests {
    func wait(_ description: String, _ predicate: () -> Bool) async throws {
        for _ in 0..<240 {
            if predicate() { return }
            try await Task.sleep(for: .milliseconds(50))
        }
        Issue.record("Timed out: \(description)")
        throw SharedControlError.invalidResponse
    }
    @Test("strict canonical Gunicorn Socket.IO: identity, pause, reconnect, cancellation, errors",
          .enabled(if: ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_SOURCE"] != nil))
    func canonicalControls() async throws {
        let fixture = try ControlFixture(); defer { fixture.stop() }
        let client = SharedEngineSocketClient(endpoint: fixture.endpoint, username: "fixture-user", password: "fixture-contraseña-🔐")
        defer { client.disconnect() }
        let cookie = try #require(HTTPCookie(properties: [.domain: "127.0.0.1", .path: "/", .name: "nmapui-decoy-" + UUID().uuidString,
                                                        .value: "never-send-this-cookie"]))
        HTTPCookieStorage.shared.setCookie(cookie)
        let space = URLProtectionSpace(host: "127.0.0.1", port: fixture.endpoint.url.port!, protocol: "http", realm: "NmapUI-fixture", authenticationMethod: NSURLAuthenticationMethodHTTPBasic)
        let credential = URLCredential(user: "decoy-" + UUID().uuidString, password: "never-send-this-credential", persistence: .forSession)
        URLCredentialStorage.shared.set(credential, for: space)
        defer { HTTPCookieStorage.shared.deleteCookie(cookie); URLCredentialStorage.shared.remove(credential, for: space) }

        var observed: [String] = []
        client.onChange = { observed.append("\($0.connection) \($0.jobs[.scan]?.sourceJobID?.uuidString ?? "-") \($0.jobs[.scan]?.rawStatus ?? "-") \($0.lastError ?? "")") }
        do {
        #expect(throws: SharedControlError.disconnected) { try client.startScan(target: "127.0.0.1") }
        for password in ["", "wrong"] {
            let denied = SharedEngineSocketClient(endpoint: fixture.endpoint, username: "fixture-user", password: password)
            await #expect(throws: SharedControlError.http(401)) { try await denied.connect() }
            #expect(denied.state.connection == .disconnected)
        }
        try await client.connect()
        try await wait("initial snapshots") { client.state.connection == .ready }
        try client.startScan(target: "127.0.0.1")
        try await wait("owned fake scanner launched") { fixture.invocations.count == 1 && client.state.jobs[.scan]?.status == .running }
        let id = try #require(client.state.jobs[.scan]?.sourceJobID)
        let pid = try #require(fixture.invocations.first?["pid"] as? Int32)
        #expect(kill(pid, 0) == 0)
        #expect(throws: SharedControlError.staleJob) { try client.cancel(.scan, observedID: UUID()) }
        try client.pause(.scan, observedID: id)
        try await wait("real process paused") { client.state.jobs[.scan]?.paused == true }
        #expect(client.state.jobs[.scan]?.pauseMode == "process")
        try client.resume(.scan, observedID: id)
        try await wait("real process resumed") { client.state.jobs[.scan]?.paused == false }
        client.disconnect()
        #expect(throws: SharedControlError.disconnected) { try client.cancel(.scan, observedID: id) }
        #expect(throws: SharedControlError.disconnected) { try client.startScan(target: "127.0.0.1") }
        try await client.reconnect()
        try await wait("reconnected snapshot retains original identity") { client.state.connection == .ready && client.state.jobs[.scan]?.sourceJobID == id }
        #expect(fixture.invocations.count == 1)
        try client.cancel(.scan, observedID: id)
        try await wait("canonical cancellation terminal") { client.state.latestCompletion[.scan]?.sourceJobID == id && client.state.latestCompletion[.scan]?.status == .cancelled && client.state.jobs[.scan]?.status.isTerminal == true }
        try await wait("cancelled process reaped") { kill(pid, 0) == -1 && errno == ESRCH }
        try client.startScan(target: "not valid ;; target")
        try await wait("canonical target validation error") { client.state.lastError?.localizedCaseInsensitiveContains("invalid target") == true }
        #expect(fixture.invocations.count == 1)
        #expect(client.state.startOutcome == .none)
        // Reconnecting before a second run also demonstrates no mutation replay.
        try await client.reconnect(); try await wait("second reconnect") { client.state.connection == .ready }
        try client.startScan(target: "127.0.0.1")
        try await wait("new run") { fixture.invocations.count == 2 && client.state.jobs[.scan]?.sourceJobID != nil && client.state.jobs[.scan]?.sourceJobID != id && client.state.jobs[.scan]?.status == .running }
        let next = try #require(client.state.jobs[.scan]?.sourceJobID)
        let nextPID = try #require(fixture.invocations.last?["pid"] as? Int32)
        #expect(throws: SharedControlError.staleJob) { try client.cancel(.scan, observedID: id) }
        #expect(client.state.jobs[.scan]?.status == .running)
        // Bypass only the client-side stale-ID guard to verify the actual
        // canonical server independently refuses a stale UUID.
        let probe = try await RawControlProbe(endpoint: fixture.endpoint)
        defer { probe.close() }
        try await wait("authenticated raw probe") { probe.connected }
        probe.socket.emit("cancel_job", ["job_type": "scan", "source_job_id": id.uuidString.lowercased()])
        try await wait("server stale identity rejection") { probe.error?.contains("no longer active") == true }
        #expect(client.state.jobs[.scan]?.status == .running)
        try client.pause(.scan, observedID: next)
        try await wait("second process paused") { client.state.jobs[.scan]?.paused == true }
        try client.cancel(.scan, observedID: next)
        try await wait("cancel wakes stopped group") { client.state.latestCompletion[.scan]?.sourceJobID == next && client.state.latestCompletion[.scan]?.status == .cancelled && client.state.jobs[.scan]?.status.isTerminal == true }
        try await wait("stopped scanner process reaped") { kill(nextPID, 0) == -1 && errno == ESRCH }
        #expect(fixture.invocations.count == 2)
        #expect(HTTPCookieStorage.shared.cookies?.contains(where: { $0.name == cookie.name }) == true)
        #expect(URLCredentialStorage.shared.credentials(for: space)?[credential.user!] == credential)
        let requests = try String(contentsOf: fixture.root.appendingPathComponent("requests.jsonl"), encoding: .utf8)
        #expect(!requests.contains("never-send-this-cookie"))
        #expect(!requests.contains("fixture-contraseña"))
        #expect(!requests.contains("never-send-this-credential"))
        } catch {
            print("Canonical control state transitions:", observed.joined(separator: "\n"))
            print("Canonical server diagnostics:", (try? String(contentsOf: fixture.root.appendingPathComponent("server.log"), encoding: .utf8)) ?? "unavailable")
            throw error
        }
    }



    @Test("vendored Engine.IO copies private session configuration on every reset")
    func engineSessionReset() async throws {
        let fixture = try ControlFixture(policy: "socket-redirect"); defer { fixture.stop() }
        let configuration = SharedEngineSocketClient.privateSessionConfiguration()
        let manager = SocketManager(socketURL: fixture.endpoint.url, config: [.forcePolling(true), .reconnects(false),
            .log(false), .handleQueue(.main), .sessionConfiguration(configuration)])
        manager.connect()
        defer { manager.disconnect() }
        let engine = try #require(manager.engine as? SocketEngine)
        try await wait("first private session") { engine.session != nil }
        let first = try #require(engine.session)
        // Mutation of the caller's object cannot change the configured engine.
        configuration.urlCredentialStorage = URLCredentialStorage.shared
        configuration.httpCookieStorage = HTTPCookieStorage.shared
        #expect(first.configuration.urlCredentialStorage == nil)
        #expect(first.configuration.httpCookieStorage == nil)
        manager.disconnect()
        try await wait("engine stopped before reset") { engine.closed }
        manager.connect()
        try await wait("fresh private session after reset") { engine.session !== first }
        let second = try #require(engine.session)
        #expect(second.configuration.urlCredentialStorage == nil)
        #expect(second.configuration.httpCookieStorage == nil)
        #expect(second.configuration.connectionProxyDictionary?.isEmpty == true)
    }

    @Test("token and Engine.IO redirects and authentication challenges never use ambient credentials",
          arguments: ["token-redirect", "socket-redirect", "challenge"])
    func privateSessionPolicy(mode: String) async throws {
        let fixture = try ControlFixture(policy: mode); defer { fixture.stop() }
        let client = SharedEngineSocketClient(endpoint: fixture.endpoint, username: "private-user", password: "private-password")
        defer { client.disconnect() }
        if mode == "socket-redirect" {
            try await client.connect()
            try await wait("polling redirect rejected") { client.state.connection == .disconnected }
        } else {
            do { try await client.connect(); Issue.record("Token policy unexpectedly accepted") }
            catch { #expect(client.state.connection == .disconnected) }
        }
        let requests = try String(contentsOf: fixture.root.appendingPathComponent("requests.jsonl"), encoding: .utf8)
        #expect(!requests.contains("decoy"))
        #expect(!requests.contains("private-user"))
        #expect(!requests.contains("private-password"))
    }

    @Test("a valid CSRF token alone cannot authenticate a real Socket.IO connection",
          .enabled(if: ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_SOURCE"] != nil))
    func tokenIsNotCredential() async throws {
        let fixture = try ControlFixture(); defer { fixture.stop() }
        let config = URLSessionConfiguration.ephemeral; config.urlCredentialStorage = nil; config.httpCookieStorage = nil
        let session = URLSession(configuration: config); defer { session.invalidateAndCancel() }
        var request = URLRequest(url: fixture.endpoint.api("/api/socket-token"))
        request.setValue("Basic " + Data("fixture-user:fixture-contraseña-🔐".utf8).base64EncodedString(), forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: request)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        let token = try #require((JSONSerialization.jsonObject(with: data) as? [String: String])?["token"])
        let manager = SocketManager(socketURL: fixture.endpoint.url, config: [.forcePolling(true), .reconnects(false), .log(false), .handleQueue(.main),
            .sessionConfiguration(SharedEngineSocketClient.privateSessionConfiguration())])
        let socket = manager.defaultSocket
        var connected = false, rejected = false
        socket.on(clientEvent: .connect) { _, _ in MainActor.assumeIsolated { connected = true } }
        socket.on(clientEvent: .error) { _, _ in MainActor.assumeIsolated { rejected = true } }
        socket.on(clientEvent: .disconnect) { _, _ in MainActor.assumeIsolated { rejected = true } }
        socket.connect(withPayload: ["token": token])
        defer { socket.removeAllHandlers(); socket.disconnect() }
        try await wait("token-only Socket.IO rejection") { rejected }
        #expect(!connected)
        let engine = try #require(manager.engine as? SocketEngine)
        let configuration = try #require(engine.session?.configuration)
        #expect(configuration.urlCredentialStorage == nil)
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.urlCache == nil)
        #expect(configuration.connectionProxyDictionary?.isEmpty == true)
    }
}

private final class ControlFixture {
    let process: Process
    let endpoint: SharedEngineEndpoint
    let root: URL
    let diagnostics: URL
    init(policy: String? = nil) throws {
        process = Process()
        let ready = Pipe()
        diagnostics = FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-control-fixture-\(UUID()).log")
        FileManager.default.createFile(atPath: diagnostics.path, contents: nil)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [ProcessInfo.processInfo.environment["NMAPUI_SHARED_ENGINE_CANONICAL_PYTHON"] ?? "python3",
            URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent(policy == nil ? "Fixtures/canonical_control_server.py" : "Fixtures/control_policy_server.py").path]
        process.environment = ProcessInfo.processInfo.environment
        process.environment?["NMAPUI_CONTROL_POLICY"] = policy
        process.standardOutput = ready; process.standardError = try FileHandle(forWritingTo: diagnostics)
        try process.run()
        // The Python launcher has its own bounded readiness deadline and
        // prints diagnostics on failure; EOF also resolves this read.
        let data = ready.fileHandleForReading.availableData
        struct Ready: Decodable { let port: Int; let root: String }
        do {
            let info = try JSONDecoder().decode(Ready.self, from: data)
            endpoint = try SharedEngineEndpoint("http://127.0.0.1:\(info.port)")
            root = URL(fileURLWithPath: info.root)
        } catch {
            kill(process.processIdentifier, SIGTERM)
            throw error
        }
    }
    var invocations: [[String: Any]] {
        guard let data = try? Data(contentsOf: root.appendingPathComponent("invocations.jsonl")) else { return [] }
        return data.split(separator: 10).compactMap { try? JSONSerialization.jsonObject(with: Data($0)) as? [String: Any] }
    }
    func stop() {
        if kill(process.processIdentifier, 0) == 0 { kill(process.processIdentifier, SIGTERM) }
        for _ in 0..<600 {
            if kill(process.processIdentifier, 0) == -1 && errno == ESRCH { return }
            usleep(10_000)
        }
        Issue.record("Owned fixture cleanup exceeded six seconds; diagnostics: \(diagnostics.path)")
        kill(process.processIdentifier, SIGKILL)
    }
}

@MainActor
private final class RawControlProbe {
    let manager: SocketManager
    let socket: SocketIOClient
    var connected = false
    var error: String?
    init(endpoint: SharedEngineEndpoint) async throws {
        let basic = "Basic " + Data("fixture-user:fixture-contraseña-🔐".utf8).base64EncodedString()
        let configuration = SharedEngineSocketClient.privateSessionConfiguration()
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: endpoint.api("/api/socket-token"))
        request.setValue(basic, forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        let token = try #require((JSONSerialization.jsonObject(with: data) as? [String: String])?["token"])
        manager = SocketManager(socketURL: endpoint.url, config: [.forcePolling(true), .reconnects(false), .log(false),
            .handleQueue(.main), .extraHeaders(["Authorization": basic]), .sessionConfiguration(configuration)])
        socket = manager.defaultSocket
        socket.on(clientEvent: .connect) { [weak self] _, _ in MainActor.assumeIsolated { self?.connected = true } }
        socket.on("scan_error") { [weak self] values, _ in MainActor.assumeIsolated { self?.error = values.first as? String } }
        socket.connect(withPayload: ["token": token])
    }
    func close() { socket.removeAllHandlers(); socket.disconnect() }
}
