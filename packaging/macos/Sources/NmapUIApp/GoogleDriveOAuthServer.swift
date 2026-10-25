import Foundation
import Network

private final class StartState: @unchecked Sendable {
    var error: Error?
}

/// Temporary localhost HTTP server used for Google OAuth redirects.
final class GoogleDriveOAuthSession: @unchecked Sendable {
    struct Callback: Sendable {
        let code: String
        let state: String
    }

    enum SessionError: LocalizedError {
        case listenFailed
        case timeout
        case invalidCallback
        case alreadyFinished

        var errorDescription: String? {
            switch self {
            case .listenFailed: return "Could not start the local Google OAuth callback server."
            case .timeout: return "Timed out waiting for Google sign-in."
            case .invalidCallback: return "Google returned an incomplete OAuth callback."
            case .alreadyFinished: return "OAuth callback already completed."
            }
        }
    }

    let path: String
    private(set) var port: UInt16
    var redirectURI: String { "http://127.0.0.1:\(port)\(path)" }

    private let lock = NSLock()
    private var listener: NWListener?
    private var continuation: CheckedContinuation<Callback, Error>?
    private var expectedState: String?
    private var finished = false
    private var outcome: Result<Callback, Error>?

    private init(path: String, port: UInt16, listener: NWListener) {
        self.path = path
        self.port = port
        self.listener = listener
    }

    static func start(
        path: String = "/google-drive/oauth2callback",
        preferredPort: UInt16 = 0
    ) throws -> GoogleDriveOAuthSession {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: preferredPort) ?? .any)
        let port = NWEndpoint.Port(rawValue: preferredPort) ?? .any
        let listener = try NWListener(using: parameters, on: port)
        let session = GoogleDriveOAuthSession(path: path, port: preferredPort, listener: listener)

        let started = DispatchSemaphore(value: 0)
        let startState = StartState()

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let actual = listener.port?.rawValue {
                    session.port = actual
                }
                started.signal()
            case .failed(let error):
                startState.error = error
                started.signal()
            default:
                break
            }
        }
        listener.newConnectionHandler = { connection in
            session.handle(connection: connection)
        }
        listener.start(queue: DispatchQueue.global(qos: .userInitiated))

        let result = started.wait(timeout: .now() + 3)
        if result == .timedOut || startState.error != nil {
            listener.cancel()
            throw SessionError.listenFailed
        }
        return session
    }

    func expectState(_ state: String) {
        lock.lock()
        expectedState = state
        lock.unlock()
    }

    private func acceptsState(_ state: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return !finished && expectedState == state
    }

    func waitForCallback(timeoutSeconds: TimeInterval = 180) async throws -> Callback {
        try await withThrowingTaskGroup(of: Callback.self) { group in
            group.addTask {
                try await self.waitIndefinitely()
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                self.cancel(with: .timeout)
                throw SessionError.timeout
            }
            let value = try await group.next()!
            group.cancelAll()
            return value
        }
    }

    func cancel(with error: SessionError = .timeout) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        outcome = .failure(error)
        listener?.cancel()
        let cont = continuation
        continuation = nil
        finished = true
        lock.unlock()
        cont?.resume(throwing: error)
    }

    private func waitIndefinitely() async throws -> Callback {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let outcome {
                lock.unlock()
                continuation.resume(with: outcome)
                return
            }
            self.continuation = continuation
            lock.unlock()
        }
    }

    private func handle(connection: NWConnection) {
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, _, _ in
            guard let self else {
                connection.cancel()
                return
            }
            guard let data, let request = String(data: data, encoding: .utf8) else {
                self.respond(connection: connection, status: 400, body: "Bad Request")
                return
            }

            let firstLine = request.split(separator: "\r\n", maxSplits: 1).first.map(String.init) ?? ""
            let parts = firstLine.split(separator: " ")
            guard parts.count == 3, parts[0] == "GET" else {
                self.respond(connection: connection, status: 400, body: "Bad Request")
                return
            }
            let target = String(parts[1])
            guard let url = URL(string: "http://localhost\(target)") else {
                self.respond(connection: connection, status: 400, body: "Bad Request")
                return
            }
            guard url.path == self.path else {
                self.respond(connection: connection, status: 404, body: "Not Found")
                return
            }

            let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
            let code = items.first(where: { $0.name == "code" })?.value
            let state = items.first(where: { $0.name == "state" })?.value
            guard items.filter({ $0.name == "code" }).count == 1, items.filter({ $0.name == "state" }).count == 1,
                  let code, let state, !code.isEmpty, !state.isEmpty, self.acceptsState(state) else {
                self.respond(connection: connection, status: 400, body: "Missing code/state")
                return
            }

            self.respond(
                connection: connection,
                status: 200,
                body: """
                <html><body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 2rem; color: #2f341c;">
                <h1>Google sign-in received</h1>
                <p>Return to NmapUI to check whether the connection succeeded.</p>
                </body></html>
                """
            )
            self.finish(Callback(code: code, state: state))
        }
    }

    private func respond(connection: NWConnection, status: Int, body: String) {
        let reason = status == 200 ? "OK" : (status == 404 ? "Not Found" : "Bad Request")
        let payload = """
        HTTP/1.1 \(status) \(reason)\r
        Content-Type: text/html; charset=utf-8\r
        Content-Length: \(body.utf8.count)\r
        Connection: close\r
        \r
        \(body)
        """
        connection.send(content: Data(payload.utf8), completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private func finish(_ callback: Callback) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        outcome = .success(callback)
        listener?.cancel()
        let cont = continuation
        continuation = nil
        finished = true
        lock.unlock()
        cont?.resume(returning: callback)
    }

    private func fail(_ error: SessionError) {
        cancel(with: error)
    }
}
