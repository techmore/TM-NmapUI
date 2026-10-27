import Darwin
import Foundation
import SharedEngineCore
import Testing

@Suite("Private shared report copies", .serialized)
struct SharedEngineReportStoreTests {
    @Test("bounded owner-only copies are removed on store disposal")
    func lifetime() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        var store: SharedEngineReportStore? = SharedEngineReportStore(root: root, limit: 8)
        let file = try store!.save(Data("%PDF-".utf8), format: .pdf)
        #expect(try Data(contentsOf: file) == Data("%PDF-".utf8))
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(throws: SharedEngineError.oversized) { try store!.save(Data("more".utf8), format: .xml) }
        #expect(FileManager.default.fileExists(atPath: file.path))
        store = nil
        #expect(!FileManager.default.fileExists(atPath: file.deletingLastPathComponent().path))
    }

    @Test("crash pruning removes only owned inactive exact namespaces and refuses symlinks")
    func pruning() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        func directory(_ pid: Int32) throws -> URL {
            let directory = root.appendingPathComponent("session-\(pid)-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            return directory
        }
        let old = try directory(Int32.max)
        let live = try directory(getpid())
        let unexpected = try directory(Int32.max)
        try Data("preserve".utf8).write(to: unexpected.appendingPathComponent("unrecognized.txt"))
        let link = root.appendingPathComponent("session-2147483647-\(UUID().uuidString)")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: unexpected)
        let store = SharedEngineReportStore(root: root)
        _ = try store.save(Data("fixture".utf8), format: .xml)
        #expect(!FileManager.default.fileExists(atPath: old.path))
        #expect(FileManager.default.fileExists(atPath: live.path))
        #expect(FileManager.default.fileExists(atPath: unexpected.appendingPathComponent("unrecognized.txt").path))
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == unexpected.path)
    }

    @Test("a symlink at the cache root is refused without writing through it")
    func symlinkRoot() throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: parent) }
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        let destination = parent.appendingPathComponent("private")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let root = parent.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: root, withDestinationURL: destination)
        #expect(throws: SharedEngineError.artifact) { try SharedEngineReportStore(root: root).save(Data(), format: .pdf) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: destination.path).isEmpty)
    }
}
