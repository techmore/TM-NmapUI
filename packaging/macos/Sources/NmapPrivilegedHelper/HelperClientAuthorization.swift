import Darwin
import Foundation
import RuntimeContracts
import Security

/// Decides which XPC clients may drive the root helper.
///
/// The requirement is built from the helper's own signing team, so it is set
/// at build time by the identity `bundle.sh` signs with (`CODESIGN_IDENTITY`):
///
///     anchor apple generic and identifier "com.techmore.nmapui"
///         and certificate leaf[subject.OU] = "<helper's team ID>"
///
/// A helper with no team (ad-hoc or unsigned) accepts no clients. Clients must
/// also be signed with the hardened runtime, so DYLD_* injection into the real
/// app cannot borrow its identity. The client is identified by its audit
/// token, never by PID, and nothing next to the client's executable (such as
/// an Info.plist) is trusted.
enum HelperClientAuthorization {
    struct Decision: Equatable {
        let accepted: Bool
        let reason: String

        static let accept = Decision(accepted: true, reason: "accepted")
        static func reject(_ reason: String) -> Decision { Decision(accepted: false, reason: reason) }
    }

    /// The requirement text for this running helper, or nil if it has no team.
    static func clientRequirementForRunningHelper() -> String? {
        NmapPrivilegedHelperContract.clientCodeSigningRequirement(teamID: ownTeamIdentifier())
    }

    static func ownTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        return teamIdentifier(of: staticCode)
    }

    static func teamIdentifier(of staticCode: SecStaticCode) -> String? {
        guard let team = signingInformation(staticCode)?[kSecCodeInfoTeamIdentifier as String] as? String,
              NmapPrivilegedHelperContract.isValidTeamIdentifier(team) else { return nil }
        return team
    }

    static func makeRequirement(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else { return nil }
        return requirement
    }

    /// Checks a running client found by its audit token.
    static func evaluate(code: SecCode, requirement: SecRequirement, requireHardenedRuntime: Bool = true) -> Decision {
        let status = SecCodeCheckValidity(code, [], requirement)
        guard status == errSecSuccess else { return .reject("code signature does not satisfy the client requirement (\(status))") }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return .reject("could not read the client's static code")
        }
        return checkRuntimeFlag(staticCode, required: requireHardenedRuntime)
    }

    /// Checks code on disk. Used by tests and by the app's own preflight.
    static func evaluate(staticCode: SecStaticCode, requirement: SecRequirement, requireHardenedRuntime: Bool = true) -> Decision {
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        let status = SecStaticCodeCheckValidity(staticCode, flags, requirement)
        guard status == errSecSuccess else { return .reject("code signature does not satisfy the client requirement (\(status))") }
        return checkRuntimeFlag(staticCode, required: requireHardenedRuntime)
    }

    static func evaluate(connection: NSXPCConnection, requirement: SecRequirement) -> Decision {
        guard connection.effectiveUserIdentifier != 0 else { return .reject("root clients are not served") }
        guard let token = auditToken(of: connection) else { return .reject("no audit token for the connection") }
        guard let code = guestCode(auditToken: token) else { return .reject("could not find the client's code by audit token") }
        return evaluate(code: code, requirement: requirement)
    }

    static func guestCode(auditToken: Data) -> SecCode? {
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess else { return nil }
        return code
    }

    /// NSXPCConnection keeps the peer's audit token in a property that is not
    /// in the public headers. Read it only if present; otherwise reject.
    static func auditToken(of connection: NSXPCConnection) -> Data? {
        guard connection.responds(to: NSSelectorFromString("auditToken")),
              let value = connection.value(forKey: "auditToken") as? NSValue else { return nil }
        var token = audit_token_t()
        value.getValue(&token, size: MemoryLayout<audit_token_t>.size)
        return withUnsafeBytes(of: &token) { Data($0) }
    }

    private static func checkRuntimeFlag(_ staticCode: SecStaticCode, required: Bool) -> Decision {
        guard required else { return .accept }
        guard let flags = (signingInformation(staticCode)?[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value,
              flags & SecCodeSignatureFlags.runtime.rawValue != 0 else {
            return .reject("client is not signed with the hardened runtime")
        }
        return .accept
    }

    private static func signingInformation(_ staticCode: SecStaticCode) -> [String: Any]? {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess else {
            return nil
        }
        return information as? [String: Any]
    }
}
