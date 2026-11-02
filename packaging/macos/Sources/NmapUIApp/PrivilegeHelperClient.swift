import AppKit
import Foundation
import RuntimeContracts

/// Client for the root-only nmap helper.
///
/// The GUI app stays a normal user process. Privileged nmap runs either:
/// 1. Through the installed LaunchDaemon helper (preferred, no prompt after install), or
/// 2. Via a one-shot `osascript` admin elevation of the helper `run` mode (interactive fallback).
enum PrivilegeHelperClient {
    static let helperLabel = "com.techmore.nmapui.nmap-helper"
    static let helperInstallPath = "/Library/PrivilegedHelperTools/com.techmore.nmapui.nmap-helper"
    static let nmapInstallPath = NmapPrivilegedHelperContract.privilegedNmapPath
    static let vulnersInstallPath = NmapPrivilegedHelperContract.privilegedVulnersScriptPath
    static let launchDaemonPlistPath = "/Library/LaunchDaemons/com.techmore.nmapui.nmap-helper.plist"
    static let socketPath = "/Library/Application Support/NmapUI/helper.sock"
    static let machServiceName = NmapPrivilegedHelperContract.machServiceName
    private static let installationQueue = DispatchQueue(label: "com.techmore.nmapui.helper-install", qos: .userInitiated)

    struct RunResult: Sendable {
        let exitCode: Int32
        let stdout: String
        let stderr: String
    }

    enum ClientError: LocalizedError {
        case helperBinaryMissing
        case installFailed(String)
        case communicationFailed(String)
        case notAvailable

        var errorDescription: String? {
            switch self {
            case .helperBinaryMissing:
                return "The privileged nmap helper binary is missing from the app bundle."
            case .installFailed(let message):
                return "Could not install the privileged scanner helper. \(message)"
            case .communicationFailed(let message):
                return "Could not talk to the privileged scanner helper. \(message)"
            case .notAvailable:
                return "Privileged scanner helper is not available."
            }
        }
    }

    static var isHelperReachable: Bool {
        (try? ping()) == true
    }

    static var isCurrentHelperReachable: Bool {
        (try? sendViaXPC(requestJSON: #"{"cmd":"ping"}"#).stdout) == "pong:\(NmapPrivilegedHelperContract.protocolVersion)"
    }

    static var installedHelperMatchesBundledHelper: Bool {
        guard let bundled = resolveHelperBinaryURL() else { return false }
        if FileManager.default.contentsEqual(atPath: bundled.path, andPath: helperInstallPath) {
            return true
        }
        // #237: byte-inequality can be benign (rebuild with identical protocol).
        // Only treat as stale when the daemon's own install stamp disagrees.
        return installedStampMatchesBundledProtocol()
    }

    /// The root daemon writes helper-stamp.json at startup containing its protocol
    /// version. If it matches ours, the installed helper speaks our contract and no
    /// reinstall (admin prompt) is needed despite binary drift.
    private static func installedStampMatchesBundledProtocol() -> Bool {
        let stampPath = "/Library/Application Support/NmapUI/helper-stamp.json"
        guard let data = FileManager.default.contents(atPath: stampPath),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (obj["protocolVersion"] as? Int) == NmapPrivilegedHelperContract.protocolVersion
        else { return false }
        return true
    }

    static func ping() throws -> Bool {
        let response = try pingResponse()
        return response.ok && response.stdout == "pong:\(NmapPrivilegedHelperContract.protocolVersion)"
    }

    private static func pingResponse() throws -> HelperResponse {
        try send(requestJSON: #"{"cmd":"ping"}"#)
    }

    static func ensureInstalled() async throws {
        try await withCheckedThrowingContinuation { continuation in
            installationQueue.async {
                do {
                    // A launch preflight and a scan request share this queue, so only
                    // one macOS authorization dialog can ever be active at a time.
                    if installationIsComplete {
                        continuation.resume()
                        return
                    }
                    try installHelper()
                    let deadline = Date().addingTimeInterval(8)
                    while Date() < deadline {
                        if installationIsComplete {
                            continuation.resume()
                            return
                        }
                        Thread.sleep(forTimeInterval: 0.25)
                    }
                    throw ClientError.installFailed("Helper installed but is not responding yet. Try again in a moment.")
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    static func cancelActiveScan(scanID: UUID) {
        let payload: [String: Any] = ["cmd": "cancel", "scanID": scanID.uuidString]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let requestJSON = String(data: data, encoding: .utf8) else { return }
        // Cancellation is best-effort and must never block the main actor on a
        // broken helper connection.
        DispatchQueue.global(qos: .userInitiated).async {
            _ = try? send(requestJSON: requestJSON)
        }
    }

    /// Runs nmap with root privileges via the helper daemon, or interactive elevation fallback.
    static func runNmap(
        nmapPath: String,
        arguments: [String],
        workDirectory: URL,
        scanID: UUID,
        allowInteractiveFallback: Bool
    ) throws -> RunResult {
        try FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: true)

        if isHelperReachable {
            // The installed helper exposes only the versioned XPC contract.
            return try runViaHelper(nmapPath: nmapPath, arguments: arguments, workDirectory: workDirectory, scanID: scanID)
        }

        guard allowInteractiveFallback else {
            throw ClientError.notAvailable
        }

        return try runViaInteractiveElevation(nmapPath: nmapPath, arguments: arguments, workDirectory: workDirectory, scanID: scanID)
    }

    // MARK: - Install

    static func launchDaemonPlistContents() -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(helperLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(helperInstallPath)</string>
                <string>daemon</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>MachServices</key>
            <dict>
                <key>\(machServiceName)</key>
                <true/>
            </dict>
            <key>KeepAlive</key>
            <true/>
            <key>StandardErrorPath</key>
            <string>/var/log/nmapui-helper.err.log</string>
            <key>StandardOutPath</key>
            <string>/var/log/nmapui-helper.out.log</string>
        </dict>
        </plist>
        """
    }

    private static func installHelper() throws {
        guard let helperURL = resolveHelperBinaryURL() else {
            throw ClientError.helperBinaryMissing
        }
        guard let nmapPath = RuntimeToolchain.current().nmapPath,
              FileManager.default.isExecutableFile(atPath: nmapPath) else {
            throw ClientError.installFailed("Nmap is not installed or executable.")
        }
        let vulnersURL = URL(fileURLWithPath: RuntimeVulners.scriptPath())
        guard vulnersURL.lastPathComponent == "vulners.nse",
              FileManager.default.fileExists(atPath: vulnersURL.path) else {
            throw ClientError.installFailed("The bundled Vulners script is missing.")
        }

        let helperSource = shellQuoted(helperURL.path)
        let installPath = shellQuoted(helperInstallPath)
        let plistPath = shellQuoted(launchDaemonPlistPath)
        let socketDir = shellQuoted("/Library/Application Support/NmapUI")
        let nmapSource = shellQuoted(nmapPath)
        let nmapInstall = shellQuoted(nmapInstallPath)
        let vulnersSource = shellQuoted(vulnersURL.deletingLastPathComponent().path)
        let vulnersInstallDir = shellQuoted(URL(fileURLWithPath: vulnersInstallPath).deletingLastPathComponent().path)

        let plistBody = launchDaemonPlistContents()

        let encodedPlist = plistBody
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")

        let script = """
        set -eu
        mkdir -p /Library/PrivilegedHelperTools
        mkdir -p \(socketDir)
        rm -f \(nmapInstall)
        cp -L \(nmapSource) \(nmapInstall)
        chown root:wheel \(nmapInstall)
        chmod 755 \(nmapInstall)
        rm -rf \(vulnersInstallDir)
        cp -R \(vulnersSource) \(vulnersInstallDir)
        chown -R root:wheel \(vulnersInstallDir)
        find \(vulnersInstallDir) -type d -exec chmod 755 {} +
        find \(vulnersInstallDir) -type f -exec chmod 644 {} +
        rm -f \(shellQuoted(socketPath))
        cp \(helperSource) \(installPath)
        xattr -cr \(installPath) 2>/dev/null || true
        codesign --remove-signature \(installPath) 2>/dev/null || true
        codesign --force --sign - --identifier \(machServiceName) \(installPath)
        chown root:wheel \(installPath)
        chmod 755 \(installPath)
        printf "%b" "\(encodedPlist)" > \(plistPath)
        chown root:wheel \(plistPath)
        chmod 644 \(plistPath)
        launchctl bootout system/\(helperLabel) 2>/dev/null || true
        launchctl bootstrap system \(plistPath)
        launchctl enable system/\(helperLabel)
        launchctl kickstart -k system/\(helperLabel)
        """

        let result = try ExternalProcessRunner.run(
            executable: URL(fileURLWithPath: "/usr/bin/osascript"),
            arguments: [
                "-e",
                "do shell script \(appleScriptString(script)) with administrator privileges"
            ],
            timeout: 10 * 60
        )
        guard result.exitCode == 0, !result.timedOut else {
            let message = result.timedOut ? "administrator authorization timed out" : (result.stderr.isEmpty ? "administrator installation exited with status \(result.exitCode)" : result.stderr)
            throw ClientError.installFailed(message.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    private static var installationIsComplete: Bool {
        isCurrentHelperReachable
            && FileManager.default.isExecutableFile(atPath: nmapInstallPath)
            && FileManager.default.fileExists(atPath: vulnersInstallPath)
            && installedHelperMatchesBundledHelper
    }

    private static func resolveHelperBinaryURL() -> URL? {
        let fileManager = FileManager.default
        var candidates: [URL] = []

        if let resourceURL = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/NmapPrivilegedHelper") as URL? {
            candidates.append(resourceURL)
        }
        if let executable = Bundle.main.executableURL {
            candidates.append(executable.deletingLastPathComponent().appendingPathComponent("NmapPrivilegedHelper"))
            // SwiftPM run: .build/debug/NmapUI sibling
            candidates.append(executable.deletingLastPathComponent().appendingPathComponent("NmapPrivilegedHelper"))
        }

        let sourceFile = URL(fileURLWithPath: #filePath)
        let packagingMacOS = sourceFile
            .deletingLastPathComponent() // NmapUIApp
            .deletingLastPathComponent() // Sources
            .deletingLastPathComponent() // packaging/macos
        candidates.append(packagingMacOS.appendingPathComponent(".build/debug/NmapPrivilegedHelper"))
        candidates.append(packagingMacOS.appendingPathComponent(".build/release/NmapPrivilegedHelper"))

        return candidates.first(where: { fileManager.isExecutableFile(atPath: $0.path) })
    }

    // MARK: - Helper run

    private static func runViaHelper(
        nmapPath: String,
        arguments: [String],
        workDirectory: URL,
        scanID: UUID
    ) throws -> RunResult {
        let privilegedArguments = replaceArgumentValue(
            in: arguments,
            flag: "--script",
            with: vulnersInstallPath
        )
        let payload: [String: Any] = [
            "cmd": "run",
            "run": [
                "nmapPath": nmapInstallPath,
                "arguments": privilegedArguments,
                "workDirectory": workDirectory.path,
                "scanID": scanID.uuidString
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: payload)
        guard let json = String(data: data, encoding: .utf8) else {
            throw ClientError.communicationFailed("could not encode request")
        }
        let response = try send(requestJSON: json)
        return RunResult(exitCode: Int32(response.exitCode), stdout: response.stdout, stderr: response.stderr)
    }

    private static func replaceArgumentValue(in arguments: [String], flag: String, with replacement: String) -> [String] {
        var result = arguments
        guard let index = result.firstIndex(of: flag), index + 1 < result.count else { return result }
        result[index + 1] = replacement
        return result
    }

    private static func runViaInteractiveElevation(
        nmapPath: String,
        arguments: [String],
        workDirectory: URL,
        scanID: UUID
    ) throws -> RunResult {
        guard let helperURL = resolveHelperBinaryURL() else {
            throw ClientError.helperBinaryMissing
        }

        var commandParts = [
            shellQuoted(helperURL.path),
            "run",
            "--work-dir",
            shellQuoted(workDirectory.path),
            "--scan-id",
            shellQuoted(scanID.uuidString),
            "--",
            shellQuoted(nmapPath)
        ]
        commandParts.append(contentsOf: arguments.map(shellQuoted))
        let shellCommand = commandParts.joined(separator: " ")

        let result = try ExternalProcessRunner.run(
            executable: URL(fileURLWithPath: "/usr/bin/osascript"),
            arguments: [
                "-e",
                "do shell script \(appleScriptString(shellCommand)) with administrator privileges"
            ],
            timeout: 15 * 60
        )
        return RunResult(exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr)
    }

    // MARK: - Framing

    private struct HelperResponse: Decodable {
        let ok: Bool
        let exitCode: Int
        let stdout: String
        let stderr: String
        let error: String?
    }

    private final class XPCResponseBox: @unchecked Sendable {
        let lock = NSLock()
        var data: Data?
        var error: Error?

        func set(data: Data) {
            lock.lock(); defer { lock.unlock() }
            self.data = data
        }

        func set(error: Error) {
            lock.lock(); defer { lock.unlock() }
            self.error = error
        }

        func values() -> (Data?, Error?) {
            lock.lock(); defer { lock.unlock() }
            return (data, error)
        }
    }

    private static func send(requestJSON: String) throws -> HelperResponse {
        try sendViaXPC(requestJSON: requestJSON)
    }

    private static func sendViaXPC(requestJSON: String) throws -> HelperResponse {
        guard let data = requestJSON.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let command = object["cmd"] as? String else {
            throw ClientError.communicationFailed("could not decode XPC request")
        }
        let connection = NSXPCConnection(machServiceName: machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: NmapPrivilegedServiceProtocol.self)
        connection.resume()
        defer { connection.invalidate() }
        let semaphore = DispatchSemaphore(value: 0)
        let responseBox = XPCResponseBox()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            responseBox.set(error: error)
            semaphore.signal()
        }) as? NmapPrivilegedServiceProtocol else {
            throw ClientError.communicationFailed("could not create XPC proxy")
        }
        switch command {
        case "ping":
            proxy.ping { response in responseBox.set(data: response); semaphore.signal() }
        case "cancel":
            proxy.cancel(request: data) { response in responseBox.set(data: response); semaphore.signal() }
        case "run":
            proxy.run(request: data) { response in responseBox.set(data: response); semaphore.signal() }
        default:
            throw ClientError.communicationFailed("unsupported XPC request")
        }
        let responseTimeout: DispatchTime
        if command == "ping" || command == "cancel" {
            responseTimeout = .now() + 2
        } else {
            responseTimeout = .now()
                + NmapPrivilegedHelperContract.maximumScanRuntime
                + NmapPrivilegedHelperContract.responseGracePeriod
        }
        guard semaphore.wait(timeout: responseTimeout) == .success else {
            throw ClientError.communicationFailed("XPC helper timed out")
        }
        let (responseData, responseError) = responseBox.values()
        if let responseError { throw ClientError.communicationFailed(responseError.localizedDescription) }
        guard let responseData else { throw ClientError.communicationFailed("empty XPC helper response") }
        if command == "ping" {
            let pong = String(data: responseData, encoding: .utf8) ?? ""
            return HelperResponse(ok: pong == "pong:\(NmapPrivilegedHelperContract.protocolVersion)", exitCode: 0, stdout: pong, stderr: "", error: nil)
        }
        guard let response = try? JSONDecoder().decode(HelperResponse.self, from: responseData) else {
            throw ClientError.communicationFailed("invalid XPC helper response")
        }
        return response
    }

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func appleScriptString(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "\"" + escaped + "\""
    }
}
