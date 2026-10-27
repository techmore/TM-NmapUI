import Foundation

public enum SharedEngineError: Error, LocalizedError, Equatable {
    case endpoint, path, transport, http(Int), oversized, schema, notReady, artifact, policy

    public var errorDescription: String? {
        switch self {
        case .endpoint: "Use http://127.0.0.1:PORT or http://[::1]:PORT. Enter credentials in the separate sign-in fields."
        case .path: "This artifact has an unsafe or unsupported relative path."
        case .transport: "The scanner could not be reached. Check its address and that it is running."
        case .http(401): "The scanner rejected these credentials."
        case .http(503): "The scanner is unavailable or sign-in is not configured securely."
        case .http(let code): "The scanner returned HTTP \(code)."
        case .oversized: "The scanner response or report copies exceed this view's download limit."
        case .schema: "This scanner response could not be read. Check that its version is compatible."
        case .notReady: "The scanner is not ready."
        case .artifact: "The downloaded document does not match its report format."
        case .policy: "The HTML report lacks a usable security policy. Open its PDF or XML instead."
        }
    }
}

public struct SharedEngineEndpoint: Sendable, Equatable {
    public let url: URL

    public init(_ text: String) throws {
        guard text.range(of: #"^http://(?:127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?/?$"#, options: .regularExpression) != nil,
              let parts = URLComponents(string: text), parts.scheme == "http",
              ["127.0.0.1", "::1", "[::1]"].contains(parts.host),
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/",
              parts.port.map({ (1...65535).contains($0) }) ?? true,
              let url = parts.url else { throw SharedEngineError.endpoint }
        self.url = url
    }

    public func artifactURL(path: String, format: SharedReportFormat) throws -> URL {
        let pieces = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.isEmpty, path.utf8.count <= 2048, pieces.count <= 16,
              !path.hasPrefix("runtime-job:"),
              pieces.allSatisfy({ piece in
                  !piece.isEmpty && piece != "." && piece != ".."
                  && !piece.contains(where: { "\\%?#:".contains($0) || $0.isNewline })
                  && !piece.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
              }) else { throw SharedEngineError.path }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let encoded = try pieces.map { piece in
            guard let encoded = String(piece).addingPercentEncoding(withAllowedCharacters: allowed) else { throw SharedEngineError.path }
            return encoded
        }.joined(separator: "/")
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        components.percentEncodedPath = "/api/runtime/reports/\(encoded)/\(format.rawValue)"
        guard let result = components.url else { throw SharedEngineError.path }
        return result
    }

    func api(_ path: String) -> URL {
        var parts = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        parts.path = path
        return parts.url!
    }
}

public enum SharedReportFormat: String, Sendable, CaseIterable {
    case pdf, xml, html
}

public struct SharedEngineRow: Decodable, Sendable, Identifiable {
    public let path: String
    public let recordType: String?
    public let jobId: String?
    public let timestamp: String?
    public let target: String?
    public let status: String?
    public let hostCount: Int?
    public let customerName: String?
    public let hasHtml: Bool?
    public let hasPdf: Bool?
    public let hasXml: Bool?
    public var id: String { path }
    public var isArtifact: Bool { recordType != "scan_run" && !path.hasPrefix("runtime-job:") }
    public func has(_ format: SharedReportFormat) -> Bool {
        guard isArtifact else { return false }
        switch format { case .html: return hasHtml == true; case .pdf: return hasPdf == true; case .xml: return hasXml == true }
    }
}

public struct SharedEngineStatus: Decodable, Sendable {
    public let hasActiveJobs: Bool
    public let maintenanceActive: Bool
    public let activeJobs: [SharedEngineJob]
}

public struct SharedEngineJob: Decodable, Sendable {
    public let jobType: String?
    public let status: String?
    public let details: Details?
    public struct Details: Decodable, Sendable { public let target: String? }
}

public struct SharedEngineSnapshot: Sendable {
    public let version: String
    public let localTrust: Bool
    public let status: SharedEngineStatus
    public let history: [SharedEngineRow]
    public let reports: [SharedEngineRow]
    public let observedAt: Date
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

public final class SharedEngineClient: Sendable {
    public let endpoint: SharedEngineEndpoint
    private let authorization: String?
    private let session: URLSession
    public static let jsonLimit = 2 * 1024 * 1024
    public static let reportLimit = 64 * 1024 * 1024

    public init(endpoint: SharedEngineEndpoint, username: String = "", password: String = "") {
        self.endpoint = endpoint
        authorization = username.isEmpty && password.isEmpty ? nil : "Basic " + Data("\(username):\(password)".utf8).base64EncodedString()
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 45
        session = URLSession(configuration: config, delegate: NoRedirects(), delegateQueue: nil)
    }

    deinit { session.invalidateAndCancel() }

    public func snapshot() async throws -> SharedEngineSnapshot {
        struct Health: Decodable { let ready: Bool?; let status: String?; let appVersion: String? }
        struct Access: Decodable { let localTrust: Bool }
        struct History: Decodable { let history: [SharedEngineRow] }
        struct Reports: Decodable { let reports: [SharedEngineRow] }
        let access: Access = try await json("/api/session/status")
        // The session's authenticated boolean is browser-session state. A 200
        // protected API response is also valid for Basic credentials.
        let health: Health = try await json("/api/health/ready")
        guard health.ready == true || health.status == "ready" else { throw SharedEngineError.notReady }
        let status: SharedEngineStatus = try await json("/api/runtime/status")
        let history: History = try await json("/api/runtime/history")
        let reports: Reports = try await json("/api/runtime/reports")
        for rows in [history.history, reports.reports] {
            guard rows.allSatisfy({ !$0.path.isEmpty }), Set(rows.map(\.path)).count == rows.count else { throw SharedEngineError.schema }
        }
        return SharedEngineSnapshot(version: health.appVersion ?? "Unknown version", localTrust: access.localTrust,
                                    status: status, history: history.history, reports: reports.reports, observedAt: Date())
    }

    public func report(path: String, format: SharedReportFormat) async throws -> Data {
        let url = try endpoint.artifactURL(path: path, format: format)
        let (data, response) = try await request(url, limit: Self.reportLimit)
        let mime = response.mimeType?.lowercased() ?? ""
        switch format {
        case .pdf:
            guard mime == "application/pdf", data.starts(with: Data("%PDF-".utf8)) else { throw SharedEngineError.artifact }
        case .xml:
            guard ["application/xml", "text/xml"].contains(mime) else { throw SharedEngineError.artifact }
            let validator = NmapXMLValidator()
            let parser = XMLParser(data: data)
            parser.shouldResolveExternalEntities = false
            parser.delegate = validator
            guard parser.parse(), validator.isNmap else { throw SharedEngineError.artifact }
        case .html:
            guard mime == "text/html" else { throw SharedEngineError.artifact }
            return try SharedOfflineHTML.secure(data, serverPolicy: response.value(forHTTPHeaderField: "Content-Security-Policy"))
        }
        return data
    }

    private func json<T: Decodable>(_ path: String) async throws -> T {
        let (data, response) = try await request(endpoint.api(path), limit: Self.jsonLimit)
        guard response.mimeType?.lowercased() == "application/json" else { throw SharedEngineError.schema }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        do { return try decoder.decode(T.self, from: data) } catch { throw SharedEngineError.schema }
    }

    private func request(_ url: URL, limit: Int) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        request.setValue("application/json, application/pdf, application/xml, text/html", forHTTPHeaderField: "Accept")
        do {
            let (bytes, response) = try await session.bytes(for: request)
            defer { bytes.task.cancel() }
            guard let http = response as? HTTPURLResponse else { throw SharedEngineError.transport }
            guard http.statusCode == 200 else { throw SharedEngineError.http(http.statusCode) }
            guard http.expectedContentLength <= Int64(limit) else { throw SharedEngineError.oversized }
            var data = Data()
            for try await byte in bytes {
                try Task.checkCancellation()
                guard data.count < limit else { throw SharedEngineError.oversized }
                data.append(byte)
            }
            return (data, http)
        } catch is CancellationError { throw CancellationError() }
        catch let error as SharedEngineError { throw error }
        catch {
            if Task.isCancelled { throw CancellationError() }
            throw SharedEngineError.transport
        }
    }
}

public enum SharedOfflineHTML {
    public static func secure(_ data: Data, serverPolicy: String?) throws -> Data {
        guard let html = String(data: data, encoding: .utf8) else { throw SharedEngineError.artifact }
        guard let policy = serverPolicy, policy.utf8.count <= 16_384 else { throw SharedEngineError.policy }
        var directives: [String: [String]] = [:]
        for clause in policy.split(separator: ";") {
            let words = clause.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let name = words.first?.lowercased(), directives[name] == nil else { throw SharedEngineError.policy }
            directives[name] = Array(words.dropFirst())
        }
        guard directives["default-src"] == ["'none'"], let scripts = directives["script-src"], !scripts.isEmpty else { throw SharedEngineError.policy }
        if scripts != ["'none'"] {
            guard scripts.allSatisfy({ token in
                guard token.hasPrefix("'sha256-"), token.hasSuffix("'") else { return false }
                let value = String(token.dropFirst(8).dropLast())
                guard let hash = Data(base64Encoded: value), hash.count == 32 else { return false }
                return hash.base64EncodedString() == value
            }) else { throw SharedEngineError.policy }
        }
        // This is deliberately first, before any original comments, raw text,
        // markup or scripts. No substring search pretends to parse HTML5.
        // Meta cannot reproduce HTTP sandbox/frame-ancestors. A separate,
        // narrow offline policy bounds execution/resources instead, while the
        // server's applicable policy is retained as an additional restriction.
        let offline = "default-src 'none'; script-src \(scripts.joined(separator: " ")); style-src 'unsafe-inline'; font-src 'none'; img-src data: blob:; connect-src 'none'; base-uri 'none'; object-src 'none'; form-action 'none'"
        func escaped(_ value: String) -> String {
            value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "\"", with: "&quot;")
                .replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
        }
        let prefix = "<!doctype html><meta http-equiv=\"Content-Security-Policy\" content=\"\(escaped(offline))\"><meta http-equiv=\"Content-Security-Policy\" content=\"\(escaped(policy))\">"
        return Data((prefix + html).utf8)
    }
}

private final class NmapXMLValidator: NSObject, XMLParserDelegate {
    var isNmap = false
    private var rootSeen = false
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String]) {
        if !rootSeen { isNmap = elementName == "nmaprun"; rootSeen = true }
    }
    func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) {
        isNmap = false
        parser.abortParsing()
    }
    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) {
        isNmap = false
        parser.abortParsing()
    }
}
