import Foundation
import RuntimeContracts
import Testing
@testable import NmapPrivilegedHelper

@Suite("Privileged helper --script validation")
struct PrivilegedScriptValidationTests {
    @Test("root-owned system paths pass the immutable path check")
    func rootOwnedPathPasses() {
        #expect(NmapPrivilegedHelperContract.isRootOwnedImmutablePath("/usr/bin/true"))
    }

    @Test("user-owned, symlinked, relative and doubled-slash paths fail")
    func unsafePathsFail() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let script = directory.appendingPathComponent("vulners.nse")
        try Data("-- lua".utf8).write(to: script)
        #expect(!NmapPrivilegedHelperContract.isRootOwnedImmutablePath(script.path))
        #expect(!NmapPrivilegedHelperContract.isRootOwnedImmutablePath("/tmp"))  // symlink to /private/tmp
        #expect(!NmapPrivilegedHelperContract.isRootOwnedImmutablePath("usr/bin/true"))
        #expect(!NmapPrivilegedHelperContract.isRootOwnedImmutablePath("/usr//bin/true"))
    }

    @Test("--script accepts nothing but the fixed install path", arguments: [
        "/tmp/x.nse,\(NmapPrivilegedHelperContract.privilegedVulnersScriptPath)",
        "\(NmapPrivilegedHelperContract.privilegedVulnersScriptPath),/tmp/evil.nse",
        "\(NmapPrivilegedHelperContract.privilegedVulnersScriptPath) or all",
        "vulners",
        "/usr/bin/true",
    ])
    func scriptValuesRejected(value: String) {
        #expect(throws: (any Error).self) {
            try validateNmapArguments(["-sS", "--script", value, "10.0.0.5"])
        }
    }
}
