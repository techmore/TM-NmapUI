@preconcurrency import Foundation
import CryptoKit
import Security

private enum HelperError: Error {
    case invalidCommand
    case invalidPayload(String)
}

private struct TokenState: Codable {
    var schemaVersion: Int = 1
    var ciphertext: String?
    var refreshToken: String?
    var accessToken: String?
    var expiresAt: String?
    var pendingAuth: PendingAuth?
}

private struct Credentials: Codable {
    var clientId: String?
    var clientSecret: String?
}

private struct PendingAuth: Codable {
    var state: String
    var codeVerifier: String
    var redirectUri: String
    var createdAt: String
}

private struct HelperResponse: Codable {
    var success: Bool
    var status: String?
    var error: String?
    var configured: Bool?
    var connected: Bool?
    var expiresAt: String?
    var authURL: String?
    var uploaded: [[String: String]]? = nil
    var folderId: String? = nil
}

private func readJSON<T: Decodable>(_ type: T.Type, from path: URL) -> T? {
    guard let data = try? Data(contentsOf: path) else { return nil }
    return try? JSONDecoder().decode(T.self, from: data)
}

private func writeJSON<T: Encodable>(_ value: T, to path: URL) throws {
    let data = try JSONEncoder().encode(value)
    try data.write(to: path, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
}

private enum SecureState {
    private static let service = "com.techmore.nmapui.google-drive"

    static func data(root: URL, account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account + ":" + root.standardizedFileURL.path,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func set(_ data: Data, root: URL, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account + ":" + root.standardizedFileURL.path,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var insert = query
            attributes.forEach { insert[$0.key] = $0.value }
            guard SecItemAdd(insert as CFDictionary, nil) == errSecSuccess else { throw HelperError.invalidPayload("Could not store Google Drive state in Keychain") }
        } else if status != errSecSuccess {
            throw HelperError.invalidPayload("Could not update Google Drive state in Keychain")
        }
    }

    static func remove(root: URL, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account + ":" + root.standardizedFileURL.path,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

private func loadCredentials(root: URL, paths: (credentials: URL, token: URL, key: URL)) -> [String: String] {
    if let data = SecureState.data(root: root, account: "credentials"), let value = try? JSONDecoder().decode([String: String].self, from: data) { return value }
    guard let value = readJSON([String: String].self, from: paths.credentials) else { return [:] }
    if let data = try? JSONEncoder().encode(value) { try? SecureState.set(data, root: root, account: "credentials") }
    return value
}

private func loadToken(root: URL, paths: (credentials: URL, token: URL, key: URL)) -> TokenState? {
    if let data = SecureState.data(root: root, account: "token"), let value = try? JSONDecoder().decode(TokenState.self, from: data) { return value }
    guard let value = readJSON(TokenState.self, from: paths.token) else { return nil }
    if let data = try? JSONEncoder().encode(value) { try? SecureState.set(data, root: root, account: "token") }
    return value
}

private func saveToken(_ value: TokenState, root: URL, paths: (credentials: URL, token: URL, key: URL)) throws {
    try SecureState.set(JSONEncoder().encode(value), root: root, account: "token")
    try? FileManager.default.removeItem(at: paths.token)
}

private func defaultPaths(root: URL) -> (credentials: URL, token: URL, key: URL) {
    let state = root.appendingPathComponent(".google_drive", isDirectory: true)
    return (
        state.appendingPathComponent("credentials.json"),
        state.appendingPathComponent("token.json"),
        state.appendingPathComponent("token.key")
    )
}

private func printJSON(_ value: HelperResponse) {
    if let data = try? JSONEncoder().encode(value),
       let jsonObject = try? JSONSerialization.jsonObject(with: data),
       let pretty = try? JSONSerialization.data(withJSONObject: jsonObject, options: [.prettyPrinted]),
       let string = String(data: pretty, encoding: .utf8) {
        print(string)
    } else {
        print("{}")
    }
}

private func randomURLSafeToken(byteCount: Int) -> String {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func sha256URLSafe(_ input: String) -> String {
    let digest = SHA256.hash(data: Data(input.utf8))
    return Data(digest).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private struct SimpleResponse {
    let statusCode: Int
    let body: Data
}

private final class ResultBox<Value>: @unchecked Sendable {
    var value: Value?
}

private func postForm(url: URL, body: [String: String]) throws -> SimpleResponse {
    var request = URLRequest(url: url)
    request.timeoutInterval = 60
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = body
        .map { "\(formURLEncode($0.key))=\(formURLEncode($0.value))" }
        .joined(separator: "&")
        .data(using: .utf8)

    let semaphore = DispatchSemaphore(value: 0)
    let output = ResultBox<SimpleResponse>()
    let caught = ResultBox<Error>()

    URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error {
            caught.value = error
            return
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            caught.value = HelperError.invalidPayload("Missing HTTP response")
            return
        }
        output.value = SimpleResponse(statusCode: httpResponse.statusCode, body: data ?? Data())
    }.resume()

    guard semaphore.wait(timeout: .now() + 60) == .success else {
        throw HelperError.invalidPayload("Google request timed out")
    }
    if let caught = caught.value { throw caught }
    guard let output = output.value else { throw HelperError.invalidPayload("Missing response body") }
    return output
}

private func jsonObject(from data: Data) -> [String: Any] {
    (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
}

private func formURLEncode(_ value: String) -> String {
    var allowed = CharacterSet.urlQueryAllowed
    allowed.remove(charactersIn: "&+=?")
    return value
        .replacingOccurrences(of: " ", with: "+")
        .addingPercentEncoding(withAllowedCharacters: allowed) ?? value
}

private func makeMultipartBody(metadata: [String: Any], fileName: String, fileData: Data) -> (body: Data, boundary: String) {
    let boundary = "----nmapui-\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
    var body = Data()
    func append(_ string: String) { body.append(Data(string.utf8)) }

    append("--\(boundary)\r\n")
    append("Content-Disposition: form-data; name=\"metadata\"; filename=\"metadata.json\"\r\n")
    append("Content-Type: application/json; charset=UTF-8\r\n\r\n")
    body.append((try? JSONSerialization.data(withJSONObject: metadata)) ?? Data())
    append("\r\n")

    append("--\(boundary)\r\n")
    append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
    append("Content-Type: application/octet-stream\r\n\r\n")
    body.append(fileData)
    append("\r\n")

    append("--\(boundary)--\r\n")
    return (body, boundary)
}

private func formURLEncoded(_ fields: [String: String]) -> Data {
    fields
        .map { "\(formURLEncode($0.key))=\(formURLEncode($0.value))" }
        .joined(separator: "&")
        .data(using: .utf8) ?? Data()
}

private func httpGET(url: String, query: [String: String]? = nil, headers: [String: String] = [:]) throws -> SimpleResponse {
    guard var components = URLComponents(string: url) else {
        throw HelperError.invalidPayload("Invalid Google request URL")
    }
    if let query {
        components.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) }
    }
    guard let requestURL = components.url else {
        throw HelperError.invalidPayload("Invalid Google request URL")
    }
    var request = URLRequest(url: requestURL)
    request.timeoutInterval = 60
    request.httpMethod = "GET"
    headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
    let semaphore = DispatchSemaphore(value: 0)
    let output = ResultBox<SimpleResponse>()
    let caught = ResultBox<Error>()
    URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error {
            caught.value = error
            return
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            caught.value = HelperError.invalidPayload("Missing HTTP response")
            return
        }
        output.value = SimpleResponse(statusCode: httpResponse.statusCode, body: data ?? Data())
    }.resume()
    guard semaphore.wait(timeout: .now() + 60) == .success else {
        throw HelperError.invalidPayload("Google request timed out")
    }
    if let caught = caught.value { throw caught }
    guard let output = output.value else { throw HelperError.invalidPayload("Missing response body") }
    return output
}

private func httpPOST(
    url: String,
    headers: [String: String] = [:],
    body: Data = Data()
) throws -> SimpleResponse {
    guard let requestURL = URL(string: url) else {
        throw HelperError.invalidPayload("Invalid Google request URL")
    }
    var request = URLRequest(url: requestURL)
    request.timeoutInterval = 60
    request.httpMethod = "POST"
    headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
    request.httpBody = body
    let semaphore = DispatchSemaphore(value: 0)
    let output = ResultBox<SimpleResponse>()
    let caught = ResultBox<Error>()
    URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error {
            caught.value = error
            return
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            caught.value = HelperError.invalidPayload("Missing HTTP response")
            return
        }
        output.value = SimpleResponse(statusCode: httpResponse.statusCode, body: data ?? Data())
    }.resume()
    guard semaphore.wait(timeout: .now() + 60) == .success else {
        throw HelperError.invalidPayload("Google request timed out")
    }
    if let caught = caught.value { throw caught }
    guard let output = output.value else { throw HelperError.invalidPayload("Missing response body") }
    return output
}

private func revokeGoogleToken(_ token: String) throws {
    guard let url = URL(string: "https://oauth2.googleapis.com/revoke") else {
        throw HelperError.invalidPayload("Invalid Google token revocation endpoint")
    }
    let response = try postForm(url: url, body: ["token": token])
    guard response.statusCode < 300 else {
        let payload = jsonObject(from: response.body)
        throw HelperError.invalidPayload((payload["error_description"] as? String) ?? "Google Drive token revocation failed.")
    }
}

private func ensureAccessToken(root: URL, paths: (credentials: URL, token: URL, key: URL)) throws -> String {
    guard let tokenState = loadToken(root: root, paths: paths) else {
        throw HelperError.invalidPayload("Google Drive is not connected.")
    }
    if let accessToken = tokenState.accessToken, !accessToken.isEmpty {
        return accessToken
    }
    if let refreshToken = tokenState.refreshToken, !refreshToken.isEmpty {
        let credentials = loadCredentials(root: root, paths: paths)
        guard let clientId = credentials["client_id"], let clientSecret = credentials["client_secret"] else {
            throw HelperError.invalidPayload("Google Drive OAuth credentials file not found. Upload your credentials.json from the Google Cloud Console.")
        }
        let response = try httpPOST(url: "https://oauth2.googleapis.com/token", headers: ["Content-Type": "application/x-www-form-urlencoded"], body: formURLEncoded([
            "client_id": clientId,
            "client_secret": clientSecret,
            "refresh_token": refreshToken,
            "grant_type": "refresh_token",
        ]))
        let payload = jsonObject(from: response.body)
        guard response.statusCode < 400, let refreshed = payload["access_token"] as? String else {
            throw HelperError.invalidPayload((payload["error_description"] as? String) ?? (payload["error"] as? String) ?? "Failed to refresh Google Drive access token.")
        }
        var updated = tokenState
        updated.accessToken = refreshed
        updated.expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(TimeInterval((payload["expires_in"] as? Double).map { Int($0) } ?? 3600)))
        try saveToken(updated, root: root, paths: paths)
        return refreshed
    }
    throw HelperError.invalidPayload("Google Drive is not connected.")
}

private func ensureReportsFolder(
    root: URL,
    paths: (credentials: URL, token: URL, key: URL),
    folderName: String,
    parentID: String?
) throws -> String {
    let accessToken = try ensureAccessToken(root: root, paths: paths)
    let escaped = folderName.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "'", with: "\\'")
    var query = "mimeType='application/vnd.google-apps.folder' and name='\(escaped)' and trashed=false"
    if let parentID {
        query += " and '\(parentID)' in parents"
    }
    let list = try httpGET(url: "https://www.googleapis.com/drive/v3/files", query: ["q": query, "fields": "files(id,name,webViewLink)"], headers: ["Authorization": "Bearer \(accessToken)"])
    let listPayload = jsonObject(from: list.body)
    if let files = listPayload["files"] as? [[String: Any]], let first = files.first, let id = first["id"] as? String {
        return id
    }
    var folderPayload: [String: Any] = ["name": folderName, "mimeType": "application/vnd.google-apps.folder"]
    if let parentID { folderPayload["parents"] = [parentID] }
    let body = (try? JSONSerialization.data(withJSONObject: folderPayload)) ?? Data()
    let create = try httpPOST(
        url: "https://www.googleapis.com/drive/v3/files",
        headers: [
            "Authorization": "Bearer \(accessToken)",
            "Content-Type": "application/json",
        ],
        body: body
    )
    let createPayload = jsonObject(from: create.body)
    if let id = createPayload["id"] as? String {
        return id
    }
    throw HelperError.invalidPayload("Failed to create Drive folder.")
}

private func uploadFile(
    root: URL,
    path: URL,
    folderID: String,
    fileNameMap: [String: String],
    paths: (credentials: URL, token: URL, key: URL)
) throws -> [String: Any] {
    let accessToken = try ensureAccessToken(root: root, paths: paths)
    let overrideName = fileNameMap[path.path]
    let metadata: [String: Any] = {
        var value: [String: Any] = ["name": overrideName ?? path.lastPathComponent]
        if !folderID.isEmpty { value["parents"] = [folderID] }
        return value
    }()
    let fileData = try Data(contentsOf: path)
    let (multipartBody, boundary) = makeMultipartBody(metadata: metadata, fileName: path.lastPathComponent, fileData: fileData)
    let response = try httpPOST(
        url: "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink",
        headers: [
            "Authorization": "Bearer \(accessToken)",
            "Content-Type": "multipart/form-data; boundary=\(boundary)",
        ],
        body: multipartBody
    )
    let payload = jsonObject(from: response.body)
    if response.statusCode >= 400 {
        throw HelperError.invalidPayload((payload["error"] as? [String: Any])?["message"] as? String ?? "Drive upload failed.")
    }
    return payload
}

@main
struct GoogleDriveHelper {
    static func main() {
        var args = Array(CommandLine.arguments.dropFirst())
        guard let command = args.first else {
            printJSON(HelperResponse(success: false, status: nil, error: "Missing command", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
            exit(1)
        }
        args.removeFirst()

        var root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        var redirectURI = ""
        var credentialsJSON = ""
        var code = ""
        var state = ""
        var folderID = ""
        var positionalArguments: [String] = []

        var i = 0
        while i < args.count {
            let arg = args[i]
            switch arg {
            case "--root":
                i += 1
                guard i < args.count else { printJSON(HelperResponse(success: false, status: nil, error: "Missing --root value", configured: nil, connected: nil, expiresAt: nil, authURL: nil)); exit(1) }
                root = URL(fileURLWithPath: args[i])
            case "--redirect-uri":
                i += 1
                guard i < args.count else { printJSON(HelperResponse(success: false, status: nil, error: "Missing --redirect-uri value", configured: nil, connected: nil, expiresAt: nil, authURL: nil)); exit(1) }
                redirectURI = args[i]
            case "--credentials-json":
                i += 1
                guard i < args.count else { printJSON(HelperResponse(success: false, status: nil, error: "Missing --credentials-json value", configured: nil, connected: nil, expiresAt: nil, authURL: nil)); exit(1) }
                credentialsJSON = args[i]
            case "--code":
                i += 1
                guard i < args.count else { printJSON(HelperResponse(success: false, status: nil, error: "Missing --code value", configured: nil, connected: nil, expiresAt: nil, authURL: nil)); exit(1) }
                code = args[i]
            case "--state":
                i += 1
                guard i < args.count else { printJSON(HelperResponse(success: false, status: nil, error: "Missing --state value", configured: nil, connected: nil, expiresAt: nil, authURL: nil)); exit(1) }
                state = args[i]
            case "--folder-id":
                i += 1
                guard i < args.count else { printJSON(HelperResponse(success: false, status: nil, error: "Missing --folder-id value", configured: nil, connected: nil, expiresAt: nil, authURL: nil)); exit(1) }
                folderID = args[i]
            default:
                positionalArguments.append(arg)
            }
            i += 1
        }

        if command == "save-credentials" && credentialsJSON.isEmpty {
            credentialsJSON = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) ?? ""
        }

        let paths = defaultPaths(root: root)

        do {
            switch command {
            case "status":
                let credentials = loadCredentials(root: root, paths: paths)
                let tokenState = loadToken(root: root, paths: paths)
                let configured = (credentials["client_id"]?.isEmpty == false) && (credentials["client_secret"]?.isEmpty == false)
                let connected = (tokenState?.refreshToken?.isEmpty == false) || (tokenState?.accessToken?.isEmpty == false)
                let status: String = connected ? "Connected" : (configured ? "Not connected" : "OAuth credentials missing. Import credentials.json to enable Google Drive.")
                printJSON(HelperResponse(success: true, status: status, error: nil, configured: configured, connected: connected, expiresAt: tokenState?.expiresAt, authURL: nil))
                exit(0)

            case "save-credentials":
                let payloadData = credentialsJSON.isEmpty ? Data("{}".utf8) : Data(credentialsJSON.utf8)
                guard let _ = try? JSONSerialization.jsonObject(with: payloadData) else {
                    throw HelperError.invalidPayload("Invalid credentials payload")
                }
                guard let credentials = try? JSONDecoder().decode([String: String].self, from: payloadData) else {
                    throw HelperError.invalidPayload("Credentials must contain a JSON object")
                }
                try SecureState.set(JSONEncoder().encode(credentials), root: root, account: "credentials")
                try? FileManager.default.removeItem(at: paths.credentials)
                printJSON(HelperResponse(success: true, status: "Google Drive credentials saved", error: nil, configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                exit(0)

            case "auth-url":
                let credentials = loadCredentials(root: root, paths: paths)
                guard let clientId = credentials["client_id"], !clientId.isEmpty,
                      let _ = credentials["client_secret"], !redirectURI.isEmpty else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Google Drive OAuth credentials file not found. Upload your credentials.json from the Google Cloud Console.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                let stateToken = randomURLSafeToken(byteCount: 24)
                let verifier = randomURLSafeToken(byteCount: 48)
                let challenge = sha256URLSafe(verifier)
                let pending = PendingAuth(state: stateToken, codeVerifier: verifier, redirectUri: redirectURI, createdAt: ISO8601DateFormatter().string(from: Date()))
                try saveToken(TokenState(schemaVersion: 1, ciphertext: nil, refreshToken: nil, accessToken: nil, expiresAt: nil, pendingAuth: pending), root: root, paths: paths)
                let authURL = "https://accounts.google.com/o/oauth2/v2/auth?client_id=\(clientId)&redirect_uri=\(redirectURI)&response_type=code&scope=https://www.googleapis.com/auth/drive.file&access_type=offline&prompt=consent&include_granted_scopes=true&state=\(stateToken)&code_challenge=\(challenge)&code_challenge_method=S256"
                printJSON(HelperResponse(success: true, status: nil, error: nil, configured: nil, connected: nil, expiresAt: nil, authURL: authURL))
                exit(0)

            case "disconnect":
                if let tokenState = loadToken(root: root, paths: paths) {
                    var tokens = [String]()
                    if let refreshToken = tokenState.refreshToken, !refreshToken.isEmpty { tokens.append(refreshToken) }
                    if let accessToken = tokenState.accessToken, !accessToken.isEmpty { tokens.append(accessToken) }
                    for token in Set(tokens) {
                        try revokeGoogleToken(token)
                    }
                }
                SecureState.remove(root: root, account: "token")
                SecureState.remove(root: root, account: "credentials")
                try? FileManager.default.removeItem(at: paths.token)
                try? FileManager.default.removeItem(at: paths.credentials)
                try? FileManager.default.removeItem(at: paths.key)
                printJSON(HelperResponse(success: true, status: "Google Drive disconnected", error: nil, configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                exit(0)

            case "exchange-code":
                let tokenState = loadToken(root: root, paths: paths)
                guard let pending = tokenState?.pendingAuth else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Invalid or expired Google Drive auth state.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                guard pending.state == state else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Invalid or expired Google Drive auth state.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                let credentials = loadCredentials(root: root, paths: paths)
                guard let clientId = credentials["client_id"], let clientSecret = credentials["client_secret"] else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Google Drive OAuth credentials file not found. Upload your credentials.json from the Google Cloud Console.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                guard let tokenURL = URL(string: "https://oauth2.googleapis.com/token") else {
                    throw HelperError.invalidPayload("Invalid Google token endpoint")
                }
                let response = try postForm(url: tokenURL, body: [
                    "client_id": clientId,
                    "client_secret": clientSecret,
                    "code": code,
                    "code_verifier": pending.codeVerifier,
                    "grant_type": "authorization_code",
                    "redirect_uri": pending.redirectUri,
                ])
                let payload = jsonObject(from: response.body)
                if response.statusCode >= 400 || payload["access_token"] == nil {
                    printJSON(HelperResponse(success: false, status: nil, error: (payload["error_description"] as? String) ?? (payload["error"] as? String) ?? "Failed to exchange Google Drive auth code.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                let expiresIn = (payload["expires_in"] as? Double).map { Int($0) } ?? 3600
                let updatedState = TokenState(schemaVersion: 1, ciphertext: nil, refreshToken: tokenState?.refreshToken ?? (payload["refresh_token"] as? String), accessToken: payload["access_token"] as? String, expiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(TimeInterval(expiresIn))), pendingAuth: nil)
                try saveToken(updatedState, root: root, paths: paths)
                printJSON(HelperResponse(success: true, status: "Google Drive connected", error: nil, configured: nil, connected: nil, expiresAt: updatedState.expiresAt, authURL: nil))
                exit(0)

            case "upload":
                let filePaths = positionalArguments.map { URL(fileURLWithPath: $0) }
                guard !filePaths.isEmpty else {
                    throw HelperError.invalidPayload("No report files were supplied")
                }
                for fileURL in filePaths {
                    var isDirectory: ObjCBool = false
                    guard FileManager.default.fileExists(atPath: fileURL.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
                        throw HelperError.invalidPayload("Upload operand is not a regular file: \(fileURL.path)")
                    }
                }
                let folderName = "Nmap Reports"
                let destinationFolderID = folderID.isEmpty
                    ? try ensureReportsFolder(root: root, paths: paths, folderName: folderName, parentID: nil)
                    : folderID
                var uploaded: [[String: Any]] = []
                var failures: [String] = []
                for fileURL in filePaths {
                    do {
                        let result = try uploadFile(root: root, path: fileURL, folderID: destinationFolderID, fileNameMap: [:], paths: paths)
                        uploaded.append(result)
                    } catch {
                        failures.append("\(fileURL.lastPathComponent): \(error.localizedDescription)")
                    }
                }
                let uploadedRows = uploaded.map { row in
                    row.reduce(into: [String: String]()) { result, entry in
                        if let value = entry.value as? String { result[entry.key] = value }
                    }
                }
                let error = failures.isEmpty ? nil : failures.joined(separator: "; ")
                printJSON(HelperResponse(success: failures.isEmpty, status: "Uploaded \(uploaded.count) of \(filePaths.count) file(s) to Google Drive", error: error, configured: nil, connected: nil, expiresAt: nil, authURL: nil, uploaded: uploadedRows, folderId: destinationFolderID))
                exit(failures.isEmpty ? 0 : 1)

            default:
                throw HelperError.invalidCommand
            }
        } catch {
            printJSON(HelperResponse(success: false, status: nil, error: String(describing: error), configured: nil, connected: nil, expiresAt: nil, authURL: nil))
            exit(1)
        }
    }
}
