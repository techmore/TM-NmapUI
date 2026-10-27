import Foundation
import RuntimeContracts
import Testing
@testable import NmapPrivilegedHelper

@Suite("Privileged helper install stamp")
struct HelperInstallStampTests {
    @Test("writes a known binary digest and current protocol to a readable stamp")
    func writesStamp() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let binary = directory.appendingPathComponent("helper")
        let stamp = directory.appendingPathComponent("state/helper-stamp.json")
        try Data("abc".utf8).write(to: binary)

        try writeHelperInstallStamp(binaryURL: binary, stampURL: stamp, installedAt: Date(timeIntervalSince1970: 0))

        let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: stamp)) as? [String: Any])
        #expect(object["binarySHA256"] as? String == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(object["protocolVersion"] as? Int == NmapPrivilegedHelperContract.protocolVersion)
        #expect(object["installedAt"] as? String == "1970-01-01T00:00:00Z")
        let attributes = try FileManager.default.attributesOfItem(atPath: stamp.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o644)

        // A later startup replaces the old stamp instead of leaving stale binary metadata.
        try Data().write(to: binary)
        try writeHelperInstallStamp(binaryURL: binary, stampURL: stamp)
        let updated = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: stamp)) as? [String: Any])
        #expect(updated["binarySHA256"] as? String == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("a missing binary fails without overwriting an existing stamp")
    func missingBinaryDoesNotReplaceStamp() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let stamp = directory.appendingPathComponent("helper-stamp.json")
        let original = Data("existing stamp".utf8)
        try original.write(to: stamp)
        #expect(throws: (any Error).self) {
            try writeHelperInstallStamp(binaryURL: directory.appendingPathComponent("missing"), stampURL: stamp)
        }
        #expect(try Data(contentsOf: stamp) == original)
    }
}
