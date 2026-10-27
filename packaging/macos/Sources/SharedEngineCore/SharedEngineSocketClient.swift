import Foundation
@preconcurrency import SocketIO

/// No ambient credentials, redirects, or interactive authentication challenges.
private final class ControlSessionPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) { completionHandler(.cancelAuthenticationChallenge, nil) }
}

/// Canonical Socket.IO controls. Credentials remain in memory and never enter
/// URLs. Reconnection is explicit, fetches fresh CSRF credentials, reconciles
/// status, and never replays an uncertain mutation.
@MainActor
public final class SharedEngineSocketClient {
    public private(set) var state = SharedControlState()
    public var onChange: (@MainActor (SharedControlState) -> Void)?
    public let endpoint: SharedEngineEndpoint
    private let authorization: String?
    private let policy = ControlSessionPolicy()
    private var manager: SocketManager?
    private var socket: SocketIOClient?
    private var epoch = UUID()
    private var timeout: Task<Void, Never>?

    public init(endpoint: SharedEngineEndpoint, username: String = "", password: String = "") {
        self.endpoint = endpoint
        self.authorization = username.isEmpty && password.isEmpty ? nil : "Basic " + Data("\(username):\(password)".utf8).base64EncodedString()
    }
    private func publish() { onChange?(state) }
    public func connect() async throws {
        disconnect()
        let attempt = UUID(); epoch = attempt
        state.authenticating(); publish()
        do {
            let token = try await fetchToken()
            guard epoch == attempt else { throw CancellationError() }
            var headers: [String: String] = [:]
            if let authorization { headers["Authorization"] = authorization }
            let manager = SocketManager(socketURL: endpoint.url, config: [
                .version(.three), .forcePolling(true), .reconnects(false), .handleQueue(.main),
                .log(false), .extraHeaders(headers), .sessionDelegate(policy),
                .sessionConfiguration(Self.privateSessionConfiguration()), .connectParams([:])
            ])
            let socket = manager.defaultSocket
            self.manager = manager; self.socket = socket
            // Install every listener before connecting; initial job snapshots
            // may arrive in the same polling response as the connect packet.
            socket.on(clientEvent: .connect) { [weak self] _, _ in
                MainActor.assumeIsolated {
                    guard let self, self.epoch == attempt else { return }
                    self.state.connected(); self.publish()
                    self.socket?.emit("get_job_status")
                }
            }
            socket.on("job_status") { [weak self] values, _ in
                MainActor.assumeIsolated {
                    guard let self, self.epoch == attempt, let value = values.first,
                          JSONSerialization.isValidJSONObject(value),
                          let data = try? JSONSerialization.data(withJSONObject: value), data.count <= 65_536,
                          let job = try? JSONDecoder().decode(SharedControlledJob.self, from: data) else { return }
                    self.state.receive(job)
                    if self.state.connection == .ready { self.timeout?.cancel() }
                    self.publish()
                }
            }
            socket.on("scan_error") { [weak self] values, _ in
                MainActor.assumeIsolated {
                    guard let self, self.epoch == attempt else { return }
                    self.state.receiveError(values.first as? String ?? "The scanner rejected the request.")
                    self.publish(); self.socket?.emit("get_job_status")
                }
            }
            for event: SocketClientEvent in [.disconnect, .error] {
                socket.on(clientEvent: event) { [weak self] _, _ in
                    MainActor.assumeIsolated {
                        guard let self, self.epoch == attempt else { return }
                        self.timeout?.cancel(); self.state.disconnected()
                        self.state.receiveError("The scanner connection ended. Reconnect to refresh its status.")
                        self.publish()
                    }
                }
            }
            socket.connect(withPayload: ["token": token])
            timeout = Task { [weak self] in
                try? await Task.sleep(for: .seconds(15))
                guard !Task.isCancelled, let self, self.epoch == attempt, self.state.connection != .ready else { return }
                self.disconnect()
                self.state.receiveError("The scanner did not finish authenticating and synchronizing within 15 seconds.")
                self.publish()
            }
        } catch {
            if epoch == attempt { state.disconnected(); publish() }
            throw error
        }
    }
    public func reconnect() async throws { try await connect() }
    public func disconnect() {
        epoch = UUID(); timeout?.cancel(); timeout = nil
        socket?.removeAllHandlers(); socket?.disconnect(); socket = nil; manager = nil
        state.disconnected(); publish()
    }
    public func startScan(target: String, skipHostDiscovery: Bool? = nil) throws {
        try state.validateStart(target: target)
        var payload: [String: any SocketData] = ["target": target]
        if let skipHostDiscovery { payload["skip_host_discovery"] = skipHostDiscovery }
        try emit("start_scan", payload)
        state.submittedStart(); publish()
    }
    public func cancel(_ kind: SharedJobKind, observedID: UUID) throws { try control("cancel_job", kind, observedID) }
    public func pause(_ kind: SharedJobKind, observedID: UUID) throws { try control("pause_job", kind, observedID) }
    public func resume(_ kind: SharedJobKind, observedID: UUID) throws { try control("resume_job", kind, observedID) }
    public func acknowledgeUncertainStart() throws { try state.acknowledgeUncertainStart(); publish() }
    private func control(_ event: String, _ kind: SharedJobKind, _ id: UUID) throws {
        try state.validateControl(kind, observedID: id, action: event)
        try emit(event, ["job_type": kind.rawValue, "source_job_id": id.uuidString.lowercased()])
    }
    private func emit(_ event: String, _ payload: [String: any SocketData]) throws {
        guard let socket, socket.status == .connected else { throw SharedControlError.disconnected }
        // The SDK also refuses emits while disconnected. No mutation queue exists.
        socket.emit(event, payload)
    }
    private func fetchToken() async throws -> String {
        let configuration = Self.privateSessionConfiguration()
        configuration.timeoutIntervalForRequest = 10; configuration.timeoutIntervalForResource = 15
        let session = URLSession(configuration: configuration, delegate: policy, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: endpoint.api("/api/socket-token"))
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse else { throw SharedControlError.invalidResponse }
        guard response.statusCode == 200 else { throw SharedControlError.http(response.statusCode) }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 16_384 else { throw SharedControlError.invalidResponse }
            data.append(byte)
        }
        struct Token: Decodable { let token: String }
        guard data.count <= 16_384, let token = try? JSONDecoder().decode(Token.self, from: data).token,
              !token.isEmpty, token.utf8.count <= 4096 else { throw SharedControlError.invalidResponse }
        return token
    }
    static func privateSessionConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCredentialStorage = nil; configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false; configuration.urlCache = nil
        configuration.connectionProxyDictionary = [:]
        configuration.timeoutIntervalForRequest = 60; configuration.timeoutIntervalForResource = 60
        return configuration
    }
}
