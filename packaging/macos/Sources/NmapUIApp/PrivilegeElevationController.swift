import AppKit
import LocalAuthentication
import Darwin
import Foundation

/// Privilege UX for NmapUI.
///
/// The app process always stays a normal user GUI. When privileged nmap is required,
/// we install/use a root helper daemon once (admin password), then subsequent
/// interactive and scheduled scans run without elevating the whole app.
enum PrivilegeElevationController {
    static var isRunningAsRoot: Bool {
        geteuid() == 0
    }

    /// Legacy whole-app root relaunch is intentionally disabled.
    @MainActor
    @discardableResult
    static func relaunchAsRootIfNeeded() -> Bool {
        if isRunningAsRoot {
            RuntimeDiagnosticsLogger.log("App is running as root; continuing in user-oriented mode is preferred going forward")
        }
        return false
    }

    static var isPrivilegedHelperReady: Bool {
        PrivilegeHelperClient.isCurrentHelperReachable
    }

    /// Ensures the privileged nmap helper is installed. Prompts for admin once if needed.
    static func ensurePrivilegedHelperReady(interactive: Bool) async throws {
        let helperReady = await Task.detached(priority: .utility) {
            PrivilegeHelperClient.isCurrentHelperReachable
        }.value
        if helperReady {
            return
        }
        guard interactive else {
            throw PrivilegeHelperClient.ClientError.notAvailable
        }
        // The helper only trusts clients signed by its own team; don't ask
        // for Touch ID or an administrator when that can never succeed.
        guard PrivilegeHelperClient.runningAppTeamIdentifier != nil else {
            throw PrivilegeHelperClient.ClientError.unsignedBuild
        }
        try await confirmWithBiometrics(reason: "Authorize NmapUI to install its privileged scanner helper.")
        try await PrivilegeHelperClient.ensureInstalled()
        RuntimeDiagnosticsLogger.log("Privileged nmap helper is ready")
    }

    /// #237: gate the rare admin-install behind LocalAuthentication so TouchID (or the
    /// login password) is what the user actually interacts with first. The subsequent
    /// macOS admin dialog only appears on genuine installs, which are now rare thanks
    /// to the version-stamped handshake.
    @MainActor
    private static func confirmWithBiometrics(reason: String) async throws {
        let context = LAContext()
        var error: NSError?
        // Fall back to .deviceOwnerPassword when TouchID is unavailable - the policy
        // degrades gracefully instead of failing.
        let policy: LAPolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        do {
            try await context.evaluatePolicy(policy, localizedReason: reason)
            RuntimeDiagnosticsLogger.log("Local authentication succeeded (biometric or password)")
        } catch {
            throw PrivilegeHelperClient.ClientError.installFailed("Local authentication failed: \(error.localizedDescription)")
        }
    }

    @MainActor
    static func presentHelperInstallFailure(_ error: Error) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Administrator helper required"
        alert.informativeText = """
        Full nmap scans (SYN / OS detection) need a one-time administrator approval to install NmapUI's scanner helper.

        After that, interactive and scheduled scans can run with root nmap privileges without restarting the app as root.

        \(error.localizedDescription)
        """
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
