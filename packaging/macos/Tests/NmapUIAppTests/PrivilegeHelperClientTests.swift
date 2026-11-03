import Foundation
import RuntimeContracts
import Testing
@testable import NmapUIApp

@Suite("Privileged helper client")
struct PrivilegeHelperClientTests {
    private let bundledSHA = String(repeating: "ab", count: 32)

    private func stamp(protocolVersion: Int, sha: String?) throws -> Data {
        var object: [String: Any] = ["protocolVersion": protocolVersion, "installedAt": "2026-11-02T00:00:00Z"]
        if let sha { object["binarySHA256"] = sha }
        return try JSONSerialization.data(withJSONObject: object)
    }

    @Test("a stamp counts only with this protocol and the bundled helper's exact hash")
    func stampNeedsMatchingHash() throws {
        let current = NmapPrivilegedHelperContract.protocolVersion
        #expect(NmapPrivilegedHelperContract.helperStampMatches(try stamp(protocolVersion: current, sha: bundledSHA), bundledSHA256: bundledSHA))
        #expect(NmapPrivilegedHelperContract.helperStampMatches(try stamp(protocolVersion: current, sha: bundledSHA.uppercased()), bundledSHA256: bundledSHA))
        // Same protocol, different binary: the old behaviour accepted this.
        #expect(!NmapPrivilegedHelperContract.helperStampMatches(try stamp(protocolVersion: current, sha: String(repeating: "cd", count: 32)), bundledSHA256: bundledSHA))
        #expect(!NmapPrivilegedHelperContract.helperStampMatches(try stamp(protocolVersion: current, sha: nil), bundledSHA256: bundledSHA))
        #expect(!NmapPrivilegedHelperContract.helperStampMatches(try stamp(protocolVersion: current - 1, sha: bundledSHA), bundledSHA256: bundledSHA))
        #expect(!NmapPrivilegedHelperContract.helperStampMatches(Data("not json".utf8), bundledSHA256: bundledSHA))
    }

    @Test("the stamp the helper writes matches the helper's own hash")
    func writtenStampMatchesHash() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let binary = directory.appendingPathComponent("helper")
        try Data("helper bytes".utf8).write(to: binary)
        let sha = try #require(PrivilegeHelperClient.sha256Hex(of: binary))
        let stampObject: [String: Any] = ["protocolVersion": NmapPrivilegedHelperContract.protocolVersion, "binarySHA256": sha]
        #expect(NmapPrivilegedHelperContract.helperStampMatches(try JSONSerialization.data(withJSONObject: stampObject), bundledSHA256: sha))
    }

    @Test("requests carry targets instead of a targets file, and the fixed Vulners path")
    func requestCarriesTargets() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try "10.0.0.1\n10.0.0.2\n\n# note\n".write(to: directory.appendingPathComponent("targets.tmp"), atomically: true, encoding: .utf8)
        let scanID = UUID()
        let arguments = ScanCoordinator.completeScanArguments(usePn: false, vpnHelper: false)

        let request = try PrivilegeHelperClient.makeRunRequest(arguments: arguments, workDirectory: directory, scanID: scanID)

        #expect(request.targets == ["10.0.0.1", "10.0.0.2"])
        #expect(!request.arguments.contains("-iL"))
        #expect(!request.arguments.contains("targets.tmp"))
        let script = try #require(request.arguments.firstIndex(of: "--script"))
        #expect(request.arguments[script + 1] == NmapPrivilegedHelperContract.privilegedVulnersScriptPath)
        #expect(request.scanID == scanID.uuidString)
        #expect(PrivilegeHelperClient.requestedArtifacts(in: request.arguments) == ["phase2_results.xml", "phase2_progress.gnmap"])
    }

    @Test("a targets file outside the work directory is refused", arguments: ["../targets.tmp", "/etc/hosts", ".hidden"])
    func targetsFileMustBeLocal(name: String) throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(throws: (any Error).self) {
            try PrivilegeHelperClient.makeRunRequest(arguments: ["-sn", "-iL", name], workDirectory: directory, scanID: UUID())
        }
    }

    @Test("returned artifacts are written only under their known names")
    func artifactsWrittenByName() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let work = directory.appendingPathComponent("work")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        try PrivilegeHelperClient.writeArtifacts([
            "phase1_results.xml": Data("<nmaprun/>".utf8),
            "../escaped.xml": Data("x".utf8),
            "targets.tmp": Data("x".utf8),
        ], to: work)
        #expect(try String(contentsOf: work.appendingPathComponent("phase1_results.xml"), encoding: .utf8) == "<nmaprun/>")
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("escaped.xml").path))
        #expect(!FileManager.default.fileExists(atPath: work.appendingPathComponent("targets.tmp").path))
    }

    @Test("the installer copies the helper unchanged and installs the planned nmap")
    func installScriptKeepsHelperSignature() {
        let plan = PrivilegedNmapInstallPlan(
            destinations: .init(),
            nmap: .init(source: "/opt/homebrew/Cellar/nmap/7.991/bin/nmap", destination: NmapPrivilegedHelperContract.privilegedNmapPath),
            libraries: [],
            dataDirectory: .init(source: "/opt/homebrew/Cellar/nmap/7.991/share/nmap", destination: NmapPrivilegedHelperContract.privilegedNmapDataDirectory),
            changes: [:],
            identifiers: [:],
            deletedRpaths: [:],
            installNameTool: nil
        )
        let script = PrivilegeHelperClient.installScript(helperSource: "/Applications/NmapUI.app/Contents/MacOS/NmapPrivilegedHelper", vulnersSourceDirectory: "/Applications/NmapUI.app/Contents/Resources/nmap-vulners", nmapPlan: plan)
        #expect(!script.contains("--identifier"))
        #expect(!script.contains("--remove-signature"))
        #expect(!script.contains("codesign --force --sign - '\(NmapPrivilegedHelperContract.helperInstallPath)'"))
        #expect(script.contains("cp '/Applications/NmapUI.app/Contents/MacOS/NmapPrivilegedHelper' '\(NmapPrivilegedHelperContract.helperInstallPath)'"))
        #expect(script.contains("cp -RL '/opt/homebrew/Cellar/nmap/7.991/share/nmap' '\(NmapPrivilegedHelperContract.privilegedNmapDataDirectory)'"))
        #expect(script.contains("chown -R root:wheel '\(NmapPrivilegedHelperContract.privilegedNmapLibraryDirectory)'"))
    }
}
