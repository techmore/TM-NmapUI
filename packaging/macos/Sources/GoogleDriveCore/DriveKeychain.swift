import Foundation
import Darwin
import Security

/// System calls are injectable so failure handling never requires an operator's Keychain.
public struct DriveKeychainOperations {
    public var read: ([String: Any]) -> (OSStatus, Data?)
    public var update: ([String: Any], [String: Any]) -> OSStatus
    public var add: ([String: Any]) -> OSStatus
    public var delete: ([String: Any]) -> OSStatus
    public init(
        read: @escaping ([String: Any]) -> (OSStatus, Data?) = { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result as? Data)
        },
        update: @escaping ([String: Any], [String: Any]) -> OSStatus = { SecItemUpdate($0 as CFDictionary, $1 as CFDictionary) },
        add: @escaping ([String: Any]) -> OSStatus = { SecItemAdd($0 as CFDictionary, nil) },
        delete: @escaping ([String: Any]) -> OSStatus = { SecItemDelete($0 as CFDictionary) }
    ) { self.read = read; self.update = update; self.add = add; self.delete = delete }
}

public enum DriveKeychain {
    private static func query(root: URL, account: String, keychain: SecKeychain?) -> [String: Any] {
        var result: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.techmore.nmapui.google-drive",
            kSecAttrAccount as String: account + ":" + root.standardizedFileURL.path,
        ]
        if let keychain { result[kSecMatchSearchList as String] = [keychain] }
        return result
    }
    private static func failure(_ operation: String, _ status: OSStatus) -> DriveFailure {
        .invalid("Google Drive Keychain \(operation) failed (status \(status)). Unlock Keychain and check access before trying again.")
    }
    public static func data(root: URL, account: String, keychain: SecKeychain? = nil,
                            operations: DriveKeychainOperations = .init()) throws -> Data? {
        var lookup = query(root: root, account: account, keychain: keychain)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, value) = operations.read(lookup)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw failure("read", status) }
        guard let value else { throw failure("decode", errSecDecode) }
        return value
    }
    public static func set(_ data: Data, root: URL, account: String, keychain: SecKeychain? = nil,
                           operations: DriveKeychainOperations = .init()) throws {
        let lookup = query(root: root, account: account, keychain: keychain)
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock]
        let status = operations.update(lookup, attributes)
        if status == errSecItemNotFound {
            var insert = lookup
            insert.removeValue(forKey: kSecMatchSearchList as String)
            if let keychain { insert[kSecUseKeychain as String] = keychain }
            attributes.forEach { insert[$0.key] = $0.value }
            let added = operations.add(insert)
            guard added == errSecSuccess else { throw failure("write", added) }
        } else if status != errSecSuccess { throw failure("update", status) }
    }
    public static func remove(root: URL, account: String, keychain: SecKeychain? = nil,
                              operations: DriveKeychainOperations = .init()) throws {
        let status = operations.delete(query(root: root, account: account, keychain: keychain))
        guard status == errSecSuccess || status == errSecItemNotFound else { throw failure("removal", status) }
    }
}

public enum DriveStateLoader {
    public static func legacyData(at path: URL) throws -> Data? {
        let descriptor = open(path.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw DriveFailure.invalid("Saved Google Drive state could not be opened safely.")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
            throw DriveFailure.invalid("Saved Google Drive state is not a regular file.")
        }
        var data = Data()
        while data.count <= 1024 * 1024 {
            let chunk = try handle.read(upToCount: min(65536, 1024 * 1024 + 1 - data.count)) ?? Data()
            if chunk.isEmpty { break }
            data.append(chunk)
        }
        guard data.count <= 1024 * 1024 else { throw DriveFailure.invalid("Saved Google Drive state exceeds its size limit.") }
        return data
    }

    /// Only a genuinely missing secure item permits migration. Persist before removing legacy bytes.
    public static func load<T: Decodable>(_ type: T.Type, secure: () throws -> Data?,
        legacy: () throws -> Data?, persist: (Data) throws -> Void, removeLegacy: () throws -> Void) throws -> T? {
        func decode(_ data: Data) throws -> T {
            guard data.count <= 1024 * 1024 else { throw DriveFailure.invalid("Saved Google Drive state exceeds its size limit.") }
            do { return try JSONDecoder().decode(type, from: data) }
            catch { throw DriveFailure.invalid("Saved Google Drive state could not be decoded; no older credentials were used.") }
        }
        if let data = try secure() { return try decode(data) }
        guard let data = try legacy() else { return nil }
        let value = try decode(data)
        try persist(data)
        try removeLegacy()
        return value
    }
}

public enum DriveDisconnectionPolicy {
    /// Explicit disconnect still clears local state if a token cannot be read or revoked.
    /// A local deletion failure throws; unknown remote revocation is reported separately.
    public static func disconnect(tokens: () throws -> [String], revoke: (String) throws -> Void,
                                  clearLocal: () throws -> Void) throws -> Bool {
        var confirmed = true
        do {
            for token in Set(try tokens()) {
                do { try revoke(token) } catch { confirmed = false }
            }
        } catch { confirmed = false }
        try clearLocal()
        return confirmed
    }
}
