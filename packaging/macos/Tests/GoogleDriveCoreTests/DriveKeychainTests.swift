import Foundation
import Darwin
import Security
import XCTest
@testable import GoogleDriveCore

final class DriveKeychainTests: XCTestCase {
    private let root = URL(fileURLWithPath: "/owned-fixture/account")
    private let sample = Data("{\"client_id\":\"current-account\",\"client_secret\":\"fixture\"}".utf8)

    func testDeniedOrUnavailableSecureReadNeverUsesLegacyCredentials() throws {
        for status in [errSecAuthFailed, errSecInteractionNotAllowed, errSecNotAvailable, errSecDecode, errSecParam] {
            var legacyReads = 0
            let calls = DriveKeychainOperations(read: { _ in (status, nil) })
            XCTAssertThrowsError(try DriveStateLoader.load([String: String].self, secure: {
                try DriveKeychain.data(root: self.root, account: "credentials", operations: calls)
            }, legacy: { legacyReads += 1; return self.sample }, persist: { _ in XCTFail("Must not write after denied read") }, removeLegacy: { XCTFail("Must preserve legacy evidence") }))
            XCTAssertEqual(legacyReads, 0)
        }
    }

    func testMissingItemMigratesBeforeRemovingLegacyBytes() throws {
        var events: [String] = []
        let calls = DriveKeychainOperations(read: { _ in (errSecItemNotFound, nil) })
        let value = try DriveStateLoader.load([String: String].self, secure: {
            try DriveKeychain.data(root: self.root, account: "credentials", operations: calls)
        }, legacy: { events.append("read"); return self.sample }, persist: { data in
            XCTAssertEqual(data, self.sample); events.append("persist")
        }, removeLegacy: { events.append("remove") })
        XCTAssertEqual(value?["client_id"], "current-account")
        XCTAssertEqual(events, ["read", "persist", "remove"])
    }

    func testCorruptOrOversizedSecureDataCannotResurrectLegacyAccount() {
        for data in [Data("broken".utf8), Data(repeating: 0, count: 1024 * 1024 + 1)] {
            XCTAssertThrowsError(try DriveStateLoader.load([String: String].self, secure: { data }, legacy: {
                XCTFail("Corrupt secure state must not select an older account"); return self.sample
            }, persist: { _ in XCTFail("Must not overwrite corrupt secure state") }, removeLegacy: { XCTFail("Must not remove evidence") }))
        }
    }

    func testLegacyFileReadIsBoundedAndOnlyAbsenceIsMissing() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-legacy-state-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("credentials.json")
        XCTAssertNil(try DriveStateLoader.legacyData(at: path))
        try sample.write(to: path)
        XCTAssertEqual(try DriveStateLoader.legacyData(at: path), sample)
        try Data(repeating: 0, count: 1024 * 1024 + 1).write(to: path)
        XCTAssertThrowsError(try DriveStateLoader.legacyData(at: path))
        XCTAssertThrowsError(try DriveStateLoader.legacyData(at: directory))
        let alias = directory.appendingPathComponent("alias.json")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: path)
        XCTAssertThrowsError(try DriveStateLoader.legacyData(at: alias))
        let pipe = directory.appendingPathComponent("state-pipe")
        XCTAssertEqual(mkfifo(pipe.path, 0o600), 0)
        XCTAssertThrowsError(try DriveStateLoader.legacyData(at: pipe))
    }

    func testMigrationWriteFailurePreservesLegacyState() {
        var removed = false
        XCTAssertThrowsError(try DriveStateLoader.load([String: String].self, secure: { nil }, legacy: { self.sample }, persist: { _ in
            throw DriveFailure.invalid("owned fixture failure")
        }, removeLegacy: { removed = true }))
        XCTAssertFalse(removed)
    }

    func testMigrationCleanupFailureIsReportedAfterPersistence() {
        var persisted = false
        XCTAssertThrowsError(try DriveStateLoader.load([String: String].self, secure: { nil }, legacy: { self.sample }, persist: { _ in
            persisted = true
        }, removeLegacy: { throw DriveFailure.invalid("owned cleanup failure") }))
        XCTAssertTrue(persisted)
    }

    func testAbsentStateReturnsNilAndExistingSecureStateDoesNotReadLegacy() throws {
        let absent = try DriveStateLoader.load([String: String].self, secure: { nil }, legacy: { nil }, persist: { _ in XCTFail() }, removeLegacy: { XCTFail() })
        XCTAssertNil(absent)
        let current = try DriveStateLoader.load([String: String].self, secure: { self.sample }, legacy: { XCTFail(); return nil }, persist: { _ in XCTFail() }, removeLegacy: { XCTFail() })
        XCTAssertEqual(current?["client_id"], "current-account")
    }

    func testReadQueryKeepsExistingServiceAndRootAccountNamespace() throws {
        var captured: [String: Any] = [:]
        let calls = DriveKeychainOperations(read: { query in captured = query; return (errSecSuccess, self.sample) })
        XCTAssertEqual(try DriveKeychain.data(root: root, account: "token", operations: calls), sample)
        XCTAssertEqual(captured[kSecAttrService as String] as? String, "com.techmore.nmapui.google-drive")
        XCTAssertEqual(captured[kSecAttrAccount as String] as? String, "token:/owned-fixture/account")
        XCTAssertNil(captured[kSecMatchSearchList as String])
    }

    func testSuccessfulReadWithoutBytesIsAnError() {
        XCTAssertThrowsError(try DriveKeychain.data(root: root, account: "token", operations: .init(read: { _ in (errSecSuccess, nil) })))
    }

    func testOnlyMissingUpdateAttemptsAnInsert() throws {
        for status in [errSecAuthFailed, errSecInteractionNotAllowed, errSecNotAvailable] {
            var added = false
            XCTAssertThrowsError(try DriveKeychain.set(sample, root: root, account: "token", operations: .init(update: { _, _ in status }, add: { _ in added = true; return errSecSuccess })))
            XCTAssertFalse(added)
        }
        var addedData: Data?
        try DriveKeychain.set(sample, root: root, account: "token", operations: .init(update: { _, _ in errSecItemNotFound }, add: {
            addedData = $0[kSecValueData as String] as? Data; return errSecSuccess
        }))
        XCTAssertEqual(addedData, sample)
    }

    func testDeleteRejectsDeniedButMissingIsIdempotent() throws {
        for status in [errSecSuccess, errSecItemNotFound] {
            try DriveKeychain.remove(root: root, account: "token", operations: .init(delete: { _ in status }))
        }
        XCTAssertThrowsError(try DriveKeychain.remove(root: root, account: "token", operations: .init(delete: { _ in errSecAuthFailed })))
    }

    func testCredentialReplacementReadFailureDoesNotClearOrOverwriteGrant() {
        var mutated = false
        XCTAssertThrowsError(try DriveCredentialPolicy.replace(["client_id": "new", "client_secret": "new-secret"], current: {
            throw DriveFailure.invalid("Keychain unavailable")
        }, clearAuthorization: { mutated = true }, save: { _ in mutated = true }))
        XCTAssertFalse(mutated)
    }

    func testExplicitDisconnectClearsLocalStateWhenSecureReadIsUnavailable() throws {
        var cleared = false
        let confirmed = try DriveDisconnectionPolicy.disconnect(tokens: {
            throw DriveFailure.invalid("Owned unavailable-Keychain fixture")
        }, revoke: { _ in XCTFail("An unreadable token cannot be revoked or replaced by a legacy token") }, clearLocal: { cleared = true })
        XCTAssertFalse(confirmed)
        XCTAssertTrue(cleared)
    }

    func testExplicitDisconnectReportsRevocationAndLocalDeletionFailuresSeparately() throws {
        var cleared = false
        let confirmed = try DriveDisconnectionPolicy.disconnect(tokens: { ["same", "same"] }, revoke: { _ in
            throw DriveFailure.invalid("Owned failed-revocation fixture")
        }, clearLocal: { cleared = true })
        XCTAssertFalse(confirmed)
        XCTAssertTrue(cleared)
        XCTAssertThrowsError(try DriveDisconnectionPolicy.disconnect(tokens: { [] }, revoke: { _ in XCTFail() }, clearLocal: {
            throw DriveFailure.invalid("Owned denied-deletion fixture")
        }))
    }

}

extension DriveKeychainTests {
    /// Never runs on a developer host or self-hosted runner. Every item query is
    /// explicitly limited to this test's private, disposable Keychain.
    func testIsolatedHostedKeychainPersistsUpdatesSeparatesRootsAndDeletes() throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["GITHUB_ACTIONS"] == "true", environment["RUNNER_OS"] == "macOS",
              environment["NMAPUI_RUN_ISOLATED_KEYCHAIN_TESTS"] == "1",
              environment["NMAPUI_KEYCHAIN_TEST_ENVIRONMENT"] == "github-hosted" else {
            throw XCTSkip("Actual Keychain calls require the explicitly enabled disposable hosted Mac job")
        }
        func searchPaths() throws -> [String] {
            var list: CFArray?
            guard SecKeychainCopySearchList(&list) == errSecSuccess, let values = list as? [SecKeychain] else {
                throw DriveFailure.invalid("Cannot inspect hosted Keychain search-list metadata")
            }
            return try values.map { item in
                var length: UInt32 = 4096
                var buffer = [CChar](repeating: 0, count: Int(length))
                guard SecKeychainGetPath(item, &length, &buffer) == errSecSuccess else {
                    throw DriveFailure.invalid("Cannot inspect hosted Keychain path")
                }
                return String(cString: buffer)
            }.sorted()
        }
        let before = try searchPaths()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-keychain-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("fixture.keychain-db")
        let password = UUID().uuidString
        var created: SecKeychain?
        let status = password.withCString { bytes in
            SecKeychainCreate(path.path, UInt32(password.utf8.count), bytes, false, nil, &created)
        }
        guard status == errSecSuccess, let keychain = created else {
            throw DriveFailure.invalid("Could not create the hosted private Keychain (status \(status))")
        }
        defer {
            XCTAssertEqual(SecKeychainDelete(keychain), errSecSuccess)
            XCTAssertEqual(try? searchPaths(), before, "Only the owned private Keychain may be removed")
        }
        let second = directory.appendingPathComponent("different-root")
        XCTAssertNil(try DriveKeychain.data(root: directory, account: "token", keychain: keychain))
        try DriveKeychain.set(Data("first synthetic token".utf8), root: directory, account: "token", keychain: keychain)
        XCTAssertEqual(try DriveKeychain.data(root: directory, account: "token", keychain: keychain), Data("first synthetic token".utf8))
        XCTAssertNil(try DriveKeychain.data(root: second, account: "token", keychain: keychain))
        XCTAssertNil(try DriveKeychain.data(root: directory, account: "credentials", keychain: keychain))
        try DriveKeychain.set(Data("rotated synthetic token".utf8), root: directory, account: "token", keychain: keychain)
        XCTAssertEqual(try DriveKeychain.data(root: directory, account: "token", keychain: keychain), Data("rotated synthetic token".utf8))
        try DriveKeychain.remove(root: directory, account: "token", keychain: keychain)
        XCTAssertNil(try DriveKeychain.data(root: directory, account: "token", keychain: keychain))
        try DriveKeychain.remove(root: directory, account: "token", keychain: keychain)
    }
}
