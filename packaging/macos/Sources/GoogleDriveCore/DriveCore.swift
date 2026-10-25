import Foundation
import Darwin

public enum DriveFailure: Error, LocalizedError {
    case invalid(String)
    public var errorDescription: String? { switch self { case .invalid(let message): return message } }
}

public enum DrivePolicy {
    public static func accessUsable(_ token: String?, expiresAt: String?, now: Date = Date()) -> Bool {
        guard let token, !token.isEmpty, let expiresAt,
              let expiry = ISO8601DateFormatter().date(from: expiresAt) else { return false }
        return expiry.timeIntervalSince(now) > 60
    }
    public static func validateState(expected: String, received: String, createdAt: String, now: Date = Date()) throws {
        guard !expected.isEmpty, expected == received,
              let created = ISO8601DateFormatter().date(from: createdAt),
              (0..<300).contains(now.timeIntervalSince(created)) else {
            throw DriveFailure.invalid("Invalid or expired Google Drive auth state.")
        }
    }
    public static func redirect(_ value: String) throws {
        guard let url = URLComponents(string: value), url.scheme == "http", url.host == "127.0.0.1",
              let port = url.port, (1...65535).contains(port), url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.path == "/google-drive/oauth2callback" else {
            throw DriveFailure.invalid("OAuth redirect must use the local callback listener.")
        }
    }
    public static func authorizationURL(clientID: String, redirect: String, state: String, challenge: String) throws -> String {
        try self.redirect(redirect)
        var url = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        url.queryItems = ["client_id": clientID, "redirect_uri": redirect, "response_type": "code",
            "scope": "https://www.googleapis.com/auth/drive.file", "access_type": "offline", "prompt": "consent",
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256"].map { URLQueryItem(name: $0.key, value: $0.value) }
        return url.url!.absoluteString
    }
    public static func browserAuthorizationURL(_ value: String) throws -> URL {
        guard let url = URLComponents(string: value), url.scheme == "https", url.host == "accounts.google.com",
              url.port == nil, url.user == nil, url.password == nil, url.fragment == nil,
              url.path == "/o/oauth2/v2/auth", let result = url.url else {
            throw DriveFailure.invalid("Untrusted Google authorization URL.")
        }
        return result
    }
    public static func sessionURL(_ value: String) throws -> URL {
        guard let url = URLComponents(string: value), url.scheme == "https", url.host == "www.googleapis.com",
              url.port == nil || url.port == 443, url.user == nil, url.password == nil,
              url.fragment == nil, url.path == "/upload/drive/v3/files",
              url.queryItems?.contains(where: { $0.name == "upload_id" && !($0.value ?? "").isEmpty }) == true,
              let result = url.url else { throw DriveFailure.invalid("Untrusted Drive upload session URL.") }
        return result
    }
}

public struct DriveResponse {
    public let status: Int
    public let body: Data
    public let headers: [String: String]
    public init(_ status: Int, body: Data = Data(), headers: [String: String] = [:]) {
        self.status = status; self.body = body
        self.headers = Dictionary(headers.map { ($0.key.lowercased(), $0.value) }, uniquingKeysWith: { _, last in last })
    }
}

/// No OS storage or network dependencies: production supplies its HTTP/token adapters.
public final class DriveUploader {
    public typealias Transport = (URLRequest) throws -> DriveResponse
    private let send: Transport
    private let token: (Bool) throws -> String
    private let sleep: (TimeInterval) -> Void
    public let chunkSize: Int
    public let maximumRequests: Int
    public init(chunkSize: Int = 1024 * 1024, maximumRequests: Int = 4096,
                token: @escaping (Bool) throws -> String, sleep: @escaping (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) },
                send: @escaping Transport) {
        self.chunkSize = chunkSize; self.maximumRequests = maximumRequests
        self.token = token; self.sleep = sleep; self.send = send
    }
    public func upload(file: URL, metadata: [String: Any]) throws -> [String: Any] {
        guard chunkSize > 0, chunkSize % (256 * 1024) == 0, maximumRequests > 0 else { throw DriveFailure.invalid("Invalid upload bounds.") }
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        func fingerprint(_ info: stat) -> [Int64] {
            [Int64(info.st_dev), Int64(info.st_ino), info.st_size,
             Int64(info.st_mtimespec.tv_sec), Int64(info.st_mtimespec.tv_nsec),
             Int64(info.st_ctimespec.tv_sec), Int64(info.st_ctimespec.tv_nsec)]
        }
        var original = stat()
        guard fstat(handle.fileDescriptor, &original) == 0, (original.st_mode & S_IFMT) == S_IFREG else {
            throw DriveFailure.invalid("Report must be a regular file.")
        }
        let identity = fingerprint(original)
        func validateSource() throws {
            var descriptor = stat()
            var path = stat()
            let pathStatus = file.withUnsafeFileSystemRepresentation { pointer in
                pointer.map { fstatat(AT_FDCWD, $0, &path, AT_SYMLINK_NOFOLLOW) } ?? -1
            }
            guard fstat(handle.fileDescriptor, &descriptor) == 0, pathStatus == 0,
                  (path.st_mode & S_IFMT) == S_IFREG,
                  fingerprint(descriptor) == identity, fingerprint(path) == identity else {
                throw DriveFailure.invalid("Report changed during upload.")
            }
        }
        try validateSource()
        let total = try handle.seekToEnd()
        guard total > 0, total <= UInt64(chunkSize) * UInt64(maximumRequests) else { throw DriveFailure.invalid("Report exceeds upload bounds or is empty.") }
        var requests = 0
        func request(_ url: URL, method: String, body: Data, headers: [String: String]) throws -> DriveResponse {
            var refreshed = false
            while true {
                requests += 1
                guard requests <= maximumRequests else { throw DriveFailure.invalid("Drive upload request limit reached.") }
                try validateSource()
                var req = URLRequest(url: url)
                req.httpMethod = method; req.httpBody = body; req.timeoutInterval = 60
                headers.forEach { req.setValue($0.value, forHTTPHeaderField: $0.key) }
                req.setValue("Bearer \(try token(refreshed))", forHTTPHeaderField: "Authorization")
                let response = try send(req)
                if response.status == 401 && !refreshed { refreshed = true; continue }
                return response
            }
        }
        let start = try request(URL(string: "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,name,webViewLink")!, method: "POST",
            body: JSONSerialization.data(withJSONObject: metadata), headers: ["Content-Type": "application/json", "X-Upload-Content-Type": "application/octet-stream", "X-Upload-Content-Length": String(total)])
        guard (200...299).contains(start.status), let location = start.headers["location"] else { throw DriveFailure.invalid("Could not start Drive resumable upload (HTTP \(start.status)).") }
        let session = try DrivePolicy.sessionURL(location)
        var offset: UInt64 = 0
        var highestSent: UInt64 = 0
        var failures = 0
        var probe = false
        while true {
            let sentFrom = offset
            let body: Data
            if probe { body = Data() } else {
                try handle.seek(toOffset: offset)
                let expected = min(chunkSize, Int(total - offset))
                body = try handle.read(upToCount: expected) ?? Data()
                guard body.count == expected else { throw DriveFailure.invalid("Report changed during upload.") }
            }
            try validateSource()
            if !probe { highestSent = max(highestSent, offset + UInt64(body.count)) }
            let range = probe ? "bytes */\(total)" : "bytes \(offset)-\(offset + UInt64(body.count) - 1)/\(total)"
            let response: DriveResponse
            do { response = try request(session, method: "PUT", body: body, headers: ["Content-Range": range, "Content-Type": "application/octet-stream"]) }
            catch {
                if error is DriveFailure { throw error }
                failures += 1
                guard failures <= 3, requests < maximumRequests else { throw error }
                sleep(pow(2, Double(failures - 1))); probe = true; continue
            }
            try validateSource()
            if (200...299).contains(response.status) {
                guard highestSent == total else { throw DriveFailure.invalid("Drive reported completion before the entire report was sent.") }
                guard let result = try JSONSerialization.jsonObject(with: response.body) as? [String: Any],
                      let id = result["id"] as? String, !id.isEmpty else { throw DriveFailure.invalid("Drive completion response lacks file ID.") }
                return result
            }
            if response.status == 308 {
                var acknowledged: UInt64 = 0
                if let range = response.headers["range"] {
                    guard range.hasPrefix("bytes=0-"), let last = UInt64(range.dropFirst(8)), last < total else { throw DriveFailure.invalid("Invalid Drive upload acknowledgement.") }
                    acknowledged = last + 1
                }
                let maximumAcknowledged = probe ? highestSent : sentFrom + UInt64(body.count)
                guard acknowledged >= offset, acknowledged <= maximumAcknowledged else { throw DriveFailure.invalid("Drive acknowledgement outside sent range.") }
                if acknowledged == offset { failures += 1 } else { failures = 0 }
                guard failures <= 3, acknowledged < total else { throw DriveFailure.invalid("Drive upload made no progress or lacks completion.") }
                offset = acknowledged; probe = false
            } else if response.status == 429 || (500...599).contains(response.status) {
                failures += 1
                guard failures <= 3 else { throw DriveFailure.invalid("Drive retry limit reached.") }
                sleep(pow(2, Double(failures - 1))); probe = true
            } else { throw DriveFailure.invalid("Drive upload failed (HTTP \(response.status)); reconnect or retry explicitly.") }
        }
    }
}

public struct DrivePendingAuth: Codable {
    public var state: String
    public var codeVerifier: String
    public var redirectUri: String
    public var createdAt: String
    public init(state: String, codeVerifier: String, redirectUri: String, createdAt: String) {
        self.state = state; self.codeVerifier = codeVerifier; self.redirectUri = redirectUri; self.createdAt = createdAt
    }
    /// Caller persists the consumed state before making the token request.
    public static func consume(_ pending: inout DrivePendingAuth?, received: String, now: Date = Date()) throws -> DrivePendingAuth {
        guard let current = pending else { throw DriveFailure.invalid("OAuth state already consumed.") }
        try DrivePolicy.validateState(expected: current.state, received: received, createdAt: current.createdAt, now: now)
        pending = nil
        return current
    }
}

public enum DriveRefreshError: Error { case revoked; case failed }
public enum DriveTokenRefresher {
    public static func refresh(clientID: String, clientSecret: String, refreshToken: String,
                               send: DriveUploader.Transport) throws -> (access: String, refresh: String?, lifetime: TimeInterval) {
        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"; request.timeoutInterval = 60
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let fields = ["client_id": clientID, "client_secret": clientSecret, "refresh_token": refreshToken, "grant_type": "refresh_token"]
        request.httpBody = Data(fields.sorted { $0.key < $1.key }.map {
            "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: allowed)!)"
        }.joined(separator: "&").utf8)
        let response = try send(request)
        let payload = (try? JSONSerialization.jsonObject(with: response.body)) as? [String: Any] ?? [:]
        if payload["error"] as? String == "invalid_grant" { throw DriveRefreshError.revoked }
        guard (200...299).contains(response.status), let access = payload["access_token"] as? String, !access.isEmpty,
              let lifetime = payload["expires_in"] as? Double, lifetime > 60, lifetime.isFinite, lifetime <= 86400 else {
            throw DriveRefreshError.failed
        }
        return (access, payload["refresh_token"] as? String, lifetime)
    }
}

public enum DriveCallbackParseResult: Equatable {
    case awaitingHeaders, invalid, denied, failed
    case authorized(code: String, state: String)
}
public enum DriveCallbackRequest {
    public static let maximumBytes = 16 * 1024
    public static func parse(_ data: Data, path: String, expectedState: String?) -> DriveCallbackParseResult {
        guard data.count <= maximumBytes else { return .invalid }
        guard data.range(of: Data("\r\n\r\n".utf8)) != nil else { return .awaitingHeaders }
        guard let text = String(data: data, encoding: .utf8), let line = text.components(separatedBy: "\r\n").first else { return .invalid }
        let parts = line.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "GET", parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0",
              parts[1].hasPrefix("/"), !parts[1].hasPrefix("//"),
              let url = URLComponents(string: String(parts[1])), url.scheme == nil, url.host == nil,
              url.fragment == nil, url.path == path, let expectedState, !expectedState.isEmpty else { return .invalid }
        let items = url.queryItems ?? []
        func value(_ name: String) -> String? {
            let matches = items.filter { $0.name == name }
            return matches.count == 1 ? matches[0].value : nil
        }
        guard value("state") == expectedState else { return .invalid }
        if let error = value("error"), !error.isEmpty, !items.contains(where: { $0.name == "code" }) { return error == "access_denied" ? .denied : .failed }
        guard !items.contains(where: { $0.name == "error" }), let code = value("code"), !code.isEmpty else { return .invalid }
        return .authorized(code: code, state: expectedState)
    }
}

public enum DriveCredentialPolicy {
    public static func validated(_ value: [String: String]) throws -> [String: String] {
        guard let client = value["client_id"]?.trimmingCharacters(in: .whitespacesAndNewlines), !client.isEmpty,
              let secret = value["client_secret"]?.trimmingCharacters(in: .whitespacesAndNewlines), !secret.isEmpty else {
            throw DriveFailure.invalid("OAuth credentials require a nonempty client_id and client_secret.")
        }
        return ["client_id": client, "client_secret": secret]
    }
    /// Production wires these closures to its existing Keychain and legacy-file adapters.
    public static func replace(_ candidate: [String: String], current: () throws -> [String: String],
                               clearAuthorization: () throws -> Void, save: ([String: String]) throws -> Void) throws {
        let validated = try self.validated(candidate)
        let loaded = try current()
        let previous = try? self.validated(loaded)
        if previous != validated { try clearAuthorization() }
        try save(validated)
    }
}
public struct DriveAuthorizationTokens {
    public let access: String
    public let refresh: String?
    public let expiresAt: String
    public static func decode(_ payload: [String: Any], now: Date = Date()) throws -> DriveAuthorizationTokens {
        guard let access = payload["access_token"] as? String, !access.isEmpty,
              let lifetime = payload["expires_in"] as? Double, lifetime.isFinite, lifetime > 60, lifetime <= 86400 else {
            throw DriveFailure.invalid("Invalid Google authorization token response.")
        }
        // An authorization-code response establishes a new grant. Never inherit another account's token.
        let refresh = (payload["refresh_token"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return DriveAuthorizationTokens(access: access, refresh: refresh,
            expiresAt: ISO8601DateFormatter().string(from: now.addingTimeInterval(lifetime)))
    }
}
