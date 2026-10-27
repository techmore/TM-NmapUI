import Darwin
import Foundation

/// Private document copies survive Detach, then are removed on store disposal.
/// A later download prunes crash leftovers only for validated, inactive sessions.
public final class SharedEngineReportStore: @unchecked Sendable {
    private let root: URL
    private let limit: Int
    private let lock = NSLock()
    private var directory: URL?
    private var bytes = 0

    public init(root: URL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("com.techmore.NmapUI.SharedEngineReports"), limit: Int = 128 * 1024 * 1024) {
        self.root = root
        self.limit = limit
    }

    deinit {
        if let directory, Self.isOwnedSession(directory, root: root) { try? FileManager.default.removeItem(at: directory) }
    }

    public func save(_ data: Data, format: SharedReportFormat) throws -> URL {
        lock.lock()
        defer { lock.unlock() }
        guard data.count <= limit - bytes else { throw SharedEngineError.oversized }
        if directory == nil {
            if !FileManager.default.fileExists(atPath: root.path) {
                try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            }
            guard Self.isPrivate(root, directory: true) else { throw SharedEngineError.artifact }
            try pruneInactiveSessions()
            let next = root.appendingPathComponent("session-\(getpid())-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: next, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            directory = next
        }
        guard let directory, Self.isOwnedSession(directory, root: root) else { throw SharedEngineError.artifact }
        let file = directory.appendingPathComponent(UUID().uuidString).appendingPathExtension(format.rawValue)
        let descriptor = Darwin.open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw SharedEngineError.artifact }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: file)
            throw error
        }
        bytes += data.count
        return file
    }

    private func pruneInactiveSessions() throws {
        for candidate in try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) {
            guard let pid = Self.sessionPID(candidate.lastPathComponent),
                  kill(pid, 0) == -1, errno == ESRCH,
                  Self.isOwnedSession(candidate, root: root) else { continue }
            try FileManager.default.removeItem(at: candidate)
        }
    }

    private static func sessionPID(_ name: String) -> pid_t? {
        let parts = name.split(separator: "-", maxSplits: 2)
        guard parts.count == 3, parts[0] == "session", UUID(uuidString: String(parts[2])) != nil,
              let pid = Int32(parts[1]), pid > 0 else { return nil }
        return pid
    }

    private static func isPrivate(_ url: URL, directory: Bool) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == (directory ? .typeDirectory : .typeRegular),
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue,
              permissions & 0o777 == (directory ? 0o700 : 0o600) else { return false }
        return true
    }

    private static func isOwnedSession(_ url: URL, root: URL) -> Bool {
        guard url.deletingLastPathComponent().standardizedFileURL.path == root.standardizedFileURL.path,
              sessionPID(url.lastPathComponent) != nil, isPrivate(root, directory: true), isPrivate(url, directory: true),
              let files = try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil) else { return false }
        return files.allSatisfy { file in
            SharedReportFormat(rawValue: file.pathExtension) != nil
            && UUID(uuidString: file.deletingPathExtension().lastPathComponent) != nil
            && isPrivate(file, directory: false)
        }
    }
}
