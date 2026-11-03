import Darwin
import Foundation
import RuntimeContracts
import Security
import Testing
@testable import NmapPrivilegedHelper

@Suite("Privileged helper caller authorization")
struct HelperClientAuthorizationTests {
    private let team = "ABCDE12345"

    private func requirement() throws -> SecRequirement {
        let text = try #require(NmapPrivilegedHelperContract.clientCodeSigningRequirement(teamID: team))
        return try #require(HelperClientAuthorization.makeRequirement(text))
    }

    private func staticCode(_ path: String) throws -> SecStaticCode {
        var code: SecStaticCode?
        #expect(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess)
        return try #require(code)
    }

    /// An ad-hoc signature with the app's identifier is what any local
    /// process can produce with `codesign -s - -i com.techmore.nmapui`.
    private func adHocBinary(identifier: String, in directory: URL, name: String = "client") async throws -> URL {
        let binary = directory.appendingPathComponent(name)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: binary.path)
        let result = try await PrivilegedTestSupport.run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime", "--identifier", identifier, binary.path])
        #expect(result.status == 0, "codesign failed: \(result.stderr)")
        return binary
    }

    @Test("the requirement pins Apple-issued certificates, the app identifier and the team")
    func requirementIsTeamScoped() throws {
        let text = try #require(NmapPrivilegedHelperContract.clientCodeSigningRequirement(teamID: team))
        #expect(text == #"anchor apple generic and identifier "com.techmore.nmapui" and certificate leaf[subject.OU] = "ABCDE12345""#)
        #expect(HelperClientAuthorization.makeRequirement(text) != nil)
    }

    @Test("no team means no requirement, so the helper accepts no clients", arguments: [
        nil, "", "abcde12345", "ABCDE1234", "ABCDE123456", #"ABCDE12345" or anchor apple"#, "ABCDE 2345",
    ] as [String?])
    func invalidTeamsGiveNoRequirement(team: String?) {
        #expect(NmapPrivilegedHelperContract.clientCodeSigningRequirement(teamID: team) == nil)
    }

    @Test("an ad-hoc client carrying the app identifier is rejected")
    func adHocClientWithAppIdentifierIsRejected() async throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let binary = try await adHocBinary(identifier: NmapPrivilegedHelperContract.authorizedBundleIdentifier, in: directory)
        let code = try staticCode(binary.path)

        #expect(HelperClientAuthorization.teamIdentifier(of: code) == nil)
        let decision = HelperClientAuthorization.evaluate(staticCode: code, requirement: try requirement())
        #expect(!decision.accepted)
    }

    @Test("an Info.plist next to the client's executable is not trusted")
    func infoPlistFallbackIsGone() async throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let macOS = directory.appendingPathComponent("Evil.app/Contents/MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        let plist: [String: Any] = ["CFBundleIdentifier": NmapPrivilegedHelperContract.authorizedBundleIdentifier]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: macOS.deletingLastPathComponent().appendingPathComponent("Info.plist"))
        let binary = try await adHocBinary(identifier: "evil", in: macOS, name: "evil")
        let code = try staticCode(binary.path)

        #expect(!HelperClientAuthorization.evaluate(staticCode: code, requirement: try requirement()).accepted)
        // Even a requirement that checks only the identifier refuses it: the
        // signed identifier, not the plist, is what counts.
        let identifierOnly = try #require(HelperClientAuthorization.makeRequirement(#"identifier "com.techmore.nmapui""#))
        #expect(!HelperClientAuthorization.evaluate(staticCode: code, requirement: identifierOnly, requireHardenedRuntime: false).accepted)
    }

    @Test("a client that satisfies the requirement still needs the hardened runtime")
    func hardenedRuntimeIsRequired() throws {
        // /usr/bin/true is Apple-signed, so it satisfies an "anchor apple"
        // requirement, but it is not flagged with the hardened runtime.
        let code = try staticCode("/usr/bin/true")
        let apple = try #require(HelperClientAuthorization.makeRequirement(#"anchor apple and identifier "com.apple.true""#))
        #expect(HelperClientAuthorization.evaluate(staticCode: code, requirement: apple, requireHardenedRuntime: false) == .accept)
        let decision = HelperClientAuthorization.evaluate(staticCode: code, requirement: apple)
        #expect(!decision.accepted)
        #expect(decision.reason.contains("hardened runtime"))
    }

    @Test("a running client is found by audit token and checked against the requirement")
    func runningClientIsCheckedByAuditToken() throws {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let status = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        #expect(status == KERN_SUCCESS)
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        let code = try #require(HelperClientAuthorization.guestCode(auditToken: tokenData))
        // The test runner is not signed by the requirement's team.
        #expect(!HelperClientAuthorization.evaluate(code: code, requirement: try requirement()).accepted)
    }
}
