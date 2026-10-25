import XCTest
@testable import GoogleDriveCore

final class DriveCoreTests: XCTestCase {
    let session = "https://www.googleapis.com/upload/drive/v3/files?upload_id=opaque"
    let complete = DriveResponse(200, body: Data("{\"id\":\"file-1\"}".utf8))
    func fixture(_ count: Int = 600_000) throws -> URL {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data(repeating: 42, count: count).write(to: file)
        addTeardownBlock { try? FileManager.default.removeItem(at: file) }
        return file
    }
    func testRefreshHTTPEncodingRotationAndRevocation() throws {
        let result = try DriveTokenRefresher.refresh(clientID: "client", clientSecret: "secret+ &", refreshToken: "refresh") { request in
            XCTAssertEqual(request.url?.absoluteString, "https://oauth2.googleapis.com/token")
            XCTAssertTrue(String(data: request.httpBody!, encoding: .utf8)!.contains("client_secret=secret%2B%20%26"))
            return DriveResponse(200, body: Data("{\"access_token\":\"new\",\"refresh_token\":\"rotated\",\"expires_in\":3600}".utf8))
        }
        XCTAssertEqual(result.access, "new")
        XCTAssertEqual(result.refresh, "rotated")
        XCTAssertEqual(result.lifetime, 3600)
        XCTAssertThrowsError(try DriveTokenRefresher.refresh(clientID: "c", clientSecret: "s", refreshToken: "r") { _ in
            DriveResponse(400, body: Data("{\"error\":\"invalid_grant\"}".utf8))
        }) { error in XCTAssertTrue(error is DriveRefreshError) }
        XCTAssertThrowsError(try DriveTokenRefresher.refresh(clientID: "c", clientSecret: "s", refreshToken: "r") { _ in
            DriveResponse(200, body: Data("{\"access_token\":\"new\"}".utf8))
        })
    }
    func testExpirySkewAndUnknownExpiryFailClosed() {
        let now = Date(timeIntervalSince1970: 1000)
        let iso = ISO8601DateFormatter()
        XCTAssertFalse(DrivePolicy.accessUsable("token", expiresAt: nil, now: now))
        XCTAssertFalse(DrivePolicy.accessUsable("token", expiresAt: iso.string(from: now.addingTimeInterval(59)), now: now))
        XCTAssertTrue(DrivePolicy.accessUsable("token", expiresAt: iso.string(from: now.addingTimeInterval(61)), now: now))
    }
    func testStateTTLWrongStateAndFutureState() throws {
        let now = Date(timeIntervalSince1970: 1000)
        let iso = ISO8601DateFormatter()
        try DrivePolicy.validateState(expected: "one", received: "one", createdAt: iso.string(from: now), now: now)
        for age in [-1.0, 300.0, 900.0] {
            XCTAssertThrowsError(try DrivePolicy.validateState(expected: "one", received: "one", createdAt: iso.string(from: now.addingTimeInterval(-age)), now: now))
        }
        XCTAssertThrowsError(try DrivePolicy.validateState(expected: "one", received: "two", createdAt: iso.string(from: now), now: now))
    }
    func testOneTimeStateConsumedBeforeExchangeIncludingFailedExchange() throws {
        let now = Date()
        var pending: DrivePendingAuth? = DrivePendingAuth(state: "state", codeVerifier: "verifier", redirectUri: "http://127.0.0.1:1234/google-drive/oauth2callback", createdAt: ISO8601DateFormatter().string(from: now))
        let consumed = try DrivePendingAuth.consume(&pending, received: "state", now: now)
        XCTAssertEqual(consumed.codeVerifier, "verifier")
        XCTAssertNil(pending)
        // No exchange result restores the consumed state.
        XCTAssertThrowsError(try DrivePendingAuth.consume(&pending, received: "state", now: now))
    }
    func testAuthorizationEncodingAndNarrowScope() throws {
        let url = try DrivePolicy.authorizationURL(clientID: "client&evil=1", redirect: "http://127.0.0.1:1234/google-drive/oauth2callback", state: "state", challenge: "challenge")
        XCTAssertEqual(try DrivePolicy.browserAuthorizationURL(url).host, "accounts.google.com")
        XCTAssertThrowsError(try DrivePolicy.browserAuthorizationURL("https://accounts.google.com.evil.test/o/oauth2/v2/auth"))
        XCTAssertThrowsError(try DrivePolicy.browserAuthorizationURL("file:///tmp/oauth"))
        let items = URLComponents(string: url)!.queryItems!
        XCTAssertEqual(items.first { $0.name == "client_id" }?.value, "client&evil=1")
        XCTAssertEqual(items.first { $0.name == "scope" }?.value, "https://www.googleapis.com/auth/drive.file")
        XCTAssertThrowsError(try DrivePolicy.redirect("http://evil.test:1234/google-drive/oauth2callback"))
    }
    func testUntrustedSessionNeverReceivesBearer() throws {
        let file = try fixture()
        for url in ["http://www.googleapis.com/upload/drive/v3/files?upload_id=x", "https://evil.test/upload/drive/v3/files?upload_id=x", "https://www.googleapis.com.evil.test/upload/drive/v3/files?upload_id=x", "https://user@www.googleapis.com/upload/drive/v3/files?upload_id=x"] {
            var calls = 0
            let uploader = DriveUploader(token: { _ in "secret" }, send: { _ in calls += 1; return DriveResponse(200, headers: ["Location": url]) })
            XCTAssertThrowsError(try uploader.upload(file: file, metadata: [:]))
            XCTAssertEqual(calls, 1)
        }
    }
    func testPartialAcknowledgementAnd401Refresh() throws {
        let file = try fixture()
        var calls = 0
        var refreshes = 0
        var ranges: [String] = []
        let uploader = DriveUploader(chunkSize: 262144, token: { force in if force { refreshes += 1 }; return force ? "new" : "old" }, sleep: { _ in }, send: { req in
            calls += 1
            if calls == 1 { return DriveResponse(200, headers: ["Location": self.session]) }
            ranges.append(req.value(forHTTPHeaderField: "Content-Range")!)
            XCTAssertLessThanOrEqual(req.httpBody!.count, 262144)
            if calls == 2 { return DriveResponse(401) }
            if calls == 3 { XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer new"); return DriveResponse(308, headers: ["Range": "bytes=0-131071"]) }
            if calls == 4 { return DriveResponse(308, headers: ["Range": "bytes=0-393215"]) }
            return self.complete
        })
        XCTAssertEqual(try uploader.upload(file: file, metadata: [:])["id"] as? String, "file-1")
        XCTAssertEqual(refreshes, 1)
        XCTAssertEqual(ranges, ["bytes 0-262143/600000", "bytes 0-262143/600000", "bytes 131072-393215/600000", "bytes 393216-599999/600000"])
    }
    func testLostResponseProbesBeforeResending() throws {
        let file = try fixture(300000)
        var calls = 0
        let uploader = DriveUploader(chunkSize: 262144, token: { _ in "token" }, sleep: { _ in }, send: { req in
            calls += 1
            switch calls {
            case 1: return DriveResponse(200, headers: ["Location": self.session])
            case 2: throw URLError(.networkConnectionLost)
            case 3:
                XCTAssertEqual(req.httpBody?.count, 0)
                XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Range"), "bytes */300000")
                return DriveResponse(308, headers: ["Range": "bytes=0-262143"])
            default:
                XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Range"), "bytes 262144-299999/300000")
                return self.complete
            }
        })
        XCTAssertEqual(try uploader.upload(file: file, metadata: [:])["id"] as? String, "file-1")
    }
    func testNoProgressAndRequestBounds() throws {
        let file = try fixture(1)
        var calls = 0
        let uploader = DriveUploader(maximumRequests: 3, token: { _ in "token" }, sleep: { _ in }, send: { _ in
            calls += 1
            return calls == 1 ? DriveResponse(200, headers: ["Location": self.session]) : DriveResponse(308)
        })
        XCTAssertThrowsError(try uploader.upload(file: file, metadata: [:]))
        XCTAssertEqual(calls, 3)
    }
    func testInvalidAckAndExpiredSessionFailExplicitly() throws {
        let file = try fixture(1)
        for response in [DriveResponse(308, headers: ["Range": "bytes=0-999"]), DriveResponse(404), DriveResponse(401)] {
            var calls = 0
            let uploader = DriveUploader(token: { _ in "token" }, sleep: { _ in }, send: { _ in
                calls += 1
                return calls == 1 ? DriveResponse(200, headers: ["Location": self.session]) : response
            })
            XCTAssertThrowsError(try uploader.upload(file: file, metadata: [:]))
        }
    }
}
