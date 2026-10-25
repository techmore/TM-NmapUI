import Foundation
import GoogleDriveCore
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
        case authorizationDenied
        case authorizationFailed

        var errorDescription: String? {
            switch self {
            case .listenFailed: return "Could not start the local Google OAuth callback server."
            case .timeout: return "Timed out waiting for Google sign-in."
            case .invalidCallback: return "Google returned an incomplete OAuth callback."
            case .alreadyFinished: return "OAuth callback already completed."
            case .authorizationFailed: return "Google sign-in failed. Google Drive was not connected."
            case .authorizationDenied: return "Google sign-in was denied or cancelled. Google Drive was not connected."
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

    private func expectedCallbackState() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return finished ? nil : expectedState
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
        // A slow or incomplete local request cannot retain a connection indefinitely.
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 10) {
            connection.cancel()
        }
        receiveHeaders(connection: connection, accumulated: Data())
    }

    private func receiveHeaders(connection: NWConnection, accumulated: Data) {
        let remaining = DriveCallbackRequest.maximumBytes - accumulated.count
        guard remaining > 0 else { respond(connection: connection, status: 400, body: "Request too large"); return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { [weak self] data, _, complete, error in
            guard let self else { connection.cancel(); return }
            var buffer = accumulated
            if let data { buffer.append(data) }
            switch DriveCallbackRequest.parse(buffer, path: self.path, expectedState: self.expectedCallbackState()) {
            case .awaitingHeaders:
                if error != nil || complete || buffer.count >= DriveCallbackRequest.maximumBytes {
                    self.respond(connection: connection, status: 400, body: "Incomplete callback")
                } else {
                    self.receiveHeaders(connection: connection, accumulated: buffer)
                }
            case .invalid:
                self.respond(connection: connection, status: 400, body: "Invalid callback")
            case .failed:
                self.respond(connection: connection, status: 200, body: "Google sign-in failed. Return to NmapUI.")
                self.fail(.authorizationFailed)
            case .denied:
                self.respond(connection: connection, status: 200, body: "Google sign-in was denied or cancelled. Return to NmapUI.")
                self.fail(.authorizationDenied)
            case .authorized(let code, let state):
                self.respond(connection: connection, status: 200, body: "Google sign-in received. Return to NmapUI to check whether the connection succeeded.")
                self.finish(Callback(code: code, state: state))
            }
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
