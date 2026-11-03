import AppKit
import CryptoKit
import Darwin
import Foundation
import RuntimeContracts
import Security

/// Client for the root-only nmap helper.
///
/// The GUI app stays a normal user process. Privileged nmap runs either:
/// 1. Through the installed LaunchDaemon helper (preferred, no prompt after install), or
/// 2. Via a one-shot `osascript` admin elevation of the helper `run` mode (interactive fallback).
///
/// The helper never opens files in the user's work directory. The client
/// sends targets in the request and writes the returned scan output itself.
enum PrivilegeHelperClient {
    static let helperLabel = "com.techmore.nmapui.nmap-helper"
    static let helperInstallPath = NmapPrivilegedHelperContract.helperInstallPath
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
        case unsignedBuild
        case invalidRequest(String)

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
            case .unsignedBuild:
                return "This build of NmapUI is not signed with an Apple team identity, so the privileged scanner helper cannot verify it. Build with CODESIGN_IDENTITY set to a Developer ID or Apple Development identity to run privileged scans."
            case .invalidRequest(let message):
                return "Invalid privileged scan request. \(message)"
            }
        }
    }

    static var isHelperReachable: Bool {
        (try? ping()) == true
    }

    static var isCurrentHelperReachable: Bool {
        isHelperReachable
    }

    /// The helper accepts only clients signed by its own team, so a build
    /// without a team can never use it (see `HelperClientAuthorization`).
    static var runningAppTeamIdentifier: String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let team = (information as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String,
              NmapPrivilegedHelperContract.isValidTeamIdentifier(team) else { return nil }
        return team
    }

    /// True only when the installed helper is the exact bundled binary: either
    /// the bytes match, or the root daemon's stamp records the bundled
    /// helper's SHA-256 and this protocol version.
    static var installedHelperMatchesBundledHelper: Bool {
        guard let bundled = resolveHelperBinaryURL() else { return false }
        if FileManager.default.contentsEqual(atPath: bundled.path, andPath: helperInstallPath) {
            return true
        }
        guard let bundledSHA256 = sha256Hex(of: bundled),
              let stamp = readRootOwnedFile(NmapPrivilegedHelperContract.helperStampPath) else { return false }
        return NmapPrivilegedHelperContract.helperStampMatches(stamp, bundledSHA256: bundledSHA256)
    }

    static func sha256Hex(of url: URL) -> String? {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// A stamp a user could write would let them pin an old helper, so only
    /// a root-owned regular file counts.
    private static func readRootOwnedFile(_ path: String) -> Data? {
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0, info.st_mode & 0o022 == 0 else {
            return nil
        }
        return FileManager.default.contents(atPath: path)
    }

    static func ping() throws -> Bool {
        let response = try callHelper(timeout: 2) { proxy, reply in proxy.ping(withReply: reply) }
        return String(decoding: response, as: UTF8.self) == "pong:\(NmapPrivilegedHelperContract.protocolVersion)"
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
                    // Installing would prompt for an administrator and still
                    // leave a helper that rejects this unsigned client.
                    guard runningAppTeamIdentifier != nil else {
                        throw ClientError.unsignedBuild
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
        guard let data = try? JSONEncoder().encode(NmapPrivilegedScanReference(scanID: scanID.uuidString)) else { return }
        // Cancellation is best-effort and must never block the main actor on a
        // broken helper connection.
        DispatchQueue.global(qos: .userInitiated).async {
            _ = try? callHelper(timeout: 2) { proxy, reply in proxy.cancel(request: data, withReply: reply) }
        }
    }

    /// Runs nmap with root privileges via the helper daemon, or interactive elevation fallback.
    ///
    /// The helper always runs its own installed nmap; `nmapPath` is ignored.
    /// `arguments` may name artifacts with `-oX`/`-oG` and a targets file in
    /// `workDirectory` with `-iL`; the client reads that file and writes the
    /// returned artifacts into `workDirectory` as the current user.
    static func runNmap(
        nmapPath: String,
        arguments: [String],
        workDirectory: URL,
        scanID: UUID,
        allowInteractiveFallback: Bool
    ) throws -> RunResult {
        try FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: true)
        let request = try makeRunRequest(arguments: arguments, workDirectory: workDirectory, scanID: scanID)
        removeArtifacts(named: requestedArtifacts(in: request.arguments), in: workDirectory)

        let response: NmapPrivilegedRunResponse
        if isHelperReachable {
            response = try runViaHelper(request, workDirectory: workDirectory)
        } else if allowInteractiveFallback {
            response = try runViaInteractiveElevation(request)
        } else {
            throw ClientError.notAvailable
        }
        try writeArtifacts(response.artifacts, to: workDirectory)
        return RunResult(exitCode: Int32(clamping: response.exitCode), stdout: response.stdout, stderr: response.stderr)
    }

    /// Builds the wire request: pins --script to the installed Vulners path
    /// and turns `-iL <file>` into an explicit target list.
    static func makeRunRequest(arguments: [String], workDirectory: URL, scanID: UUID) throws -> NmapPrivilegedRunRequest {
        var result: [String] = []
        var targets: [String] = []
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument == "--script", index + 1 < arguments.count {
                result.append(contentsOf: [argument, vulnersInstallPath])
                index += 2
            } else if argument == "-iL", index + 1 < arguments.count {
                let name = arguments[index + 1]
                guard !name.contains("/"), !name.hasPrefix(".") else {
                    throw ClientError.invalidRequest("targets file must be in the scan work directory")
                }
                let contents = try String(contentsOf: workDirectory.appendingPathComponent(name), encoding: .utf8)
                // nmap's -iL format: whitespace-separated, "#" starts a comment.
                for line in contents.split(whereSeparator: \.isNewline) {
                    let uncommented = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
                    targets.append(contentsOf: uncommented.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init))
                }
                index += 2
            } else {
                result.append(argument)
                index += 1
            }
        }
        return NmapPrivilegedRunRequest(arguments: result, targets: targets, scanID: scanID.uuidString)
    }

    static func requestedArtifacts(in arguments: [String]) -> [String] {
        zip(arguments, arguments.dropFirst())
            .filter { $0.0 == "-oX" || $0.0 == "-oG" }
            .map(\.1)
            .filter(NmapPrivilegedHelperContract.artifactNames.contains)
    }

    private static func removeArtifacts(named names: [String], in workDirectory: URL) {
        for name in names {
            try? FileManager.default.removeItem(at: workDirectory.appendingPathComponent(name))
        }
    }

    static func writeArtifacts(_ artifacts: [String: Data], to workDirectory: URL) throws {
        for (name, data) in artifacts where NmapPrivilegedHelperContract.artifactNames.contains(name) {
            try data.write(to: workDirectory.appendingPathComponent(name), options: .atomic)
        }
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
        let nmapPlan: PrivilegedNmapInstallPlan
        do {
            nmapPlan = try PrivilegedNmapInstallPlan.make(nmapPath: nmapPath)
        } catch {
            throw ClientError.installFailed(error.localizedDescription)
        }
        let script = installScript(helperSource: helperURL.path, vulnersSourceDirectory: vulnersURL.deletingLastPathComponent().path, nmapPlan: nmapPlan)

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

    static func installScript(helperSource: String, vulnersSourceDirectory: String, nmapPlan: PrivilegedNmapInstallPlan) -> String {
        let installPath = shellQuoted(helperInstallPath)
        let plistPath = shellQuoted(launchDaemonPlistPath)
        let supportDirectory = shellQuoted(NmapPrivilegedHelperContract.supportDirectory)
        let vulnersSource = shellQuoted(vulnersSourceDirectory)
        let vulnersInstallDir = shellQuoted(URL(fileURLWithPath: vulnersInstallPath).deletingLastPathComponent().path)
        let encodedPlist = launchDaemonPlistContents()
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")

        // The helper is copied byte-for-byte (not re-signed), so it keeps the
        // team signature it derives its client requirement from, and its
        // SHA-256 matches the bundled helper's.
        return ([
            "set -eu",
            "mkdir -p /Library/PrivilegedHelperTools",
            "mkdir -p \(supportDirectory)",
            "chown root:wheel \(supportDirectory)",
            "chmod 755 \(supportDirectory)",
        ] + nmapPlan.shellCommands() + [
            "rm -rf \(vulnersInstallDir)",
            "cp -RL \(vulnersSource) \(vulnersInstallDir)",
            "chown -R root:wheel \(vulnersInstallDir)",
            "find \(vulnersInstallDir) -type d -exec chmod 755 {} +",
            "find \(vulnersInstallDir) -type f -exec chmod 644 {} +",
            "rm -rf \(shellQuoted(NmapPrivilegedHelperContract.helperRunRoot))",
            "rm -f \(shellQuoted(socketPath)) \(shellQuoted(NmapPrivilegedHelperContract.helperStampPath))",
            "rm -f \(installPath)",
            "cp \(shellQuoted(helperSource)) \(installPath)",
            "xattr -c \(installPath) 2>/dev/null || true",
            "chown root:wheel \(installPath)",
            "chmod 755 \(installPath)",
            "printf \"%b\" \"\(encodedPlist)\" > \(plistPath)",
            "chown root:wheel \(plistPath)",
            "chmod 644 \(plistPath)",
            "launchctl bootout system/\(helperLabel) 2>/dev/null || true",
            "launchctl bootstrap system \(plistPath)",
            "launchctl enable system/\(helperLabel)",
            "launchctl kickstart -k system/\(helperLabel)",
        ]).joined(separator: "\n")
    }

    private static var installationIsComplete: Bool {
        isCurrentHelperReachable
            && FileManager.default.isExecutableFile(atPath: nmapInstallPath)
            && FileManager.default.fileExists(atPath: vulnersInstallPath)
            && FileManager.default.fileExists(atPath: NmapPrivilegedHelperContract.privilegedNmapDataDirectory + "/nse_main.lua")
            && installedHelperMatchesBundledHelper
    }

    private static func resolveHelperBinaryURL() -> URL? {
        let fileManager = FileManager.default
        var candidates: [URL] = []

        candidates.append(Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/NmapPrivilegedHelper"))
        if let executable = Bundle.main.executableURL {
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

    private static func runViaHelper(_ request: NmapPrivilegedRunRequest, workDirectory: URL) throws -> NmapPrivilegedRunResponse {
        let data = try JSONEncoder().encode(request)
        // The helper keeps grepable progress in its own directory; mirror it
        // into the work directory so the scan coordinator can show live hosts.
        let mirror = request.arguments.contains(NmapPrivilegedHelperContract.progressArtifactName)
            ? startProgressMirror(scanID: request.scanID, workDirectory: workDirectory)
            : nil
        defer { mirror?.cancel() }
        let response = try callHelper(timeout: NmapPrivilegedHelperContract.maximumScanRuntime + NmapPrivilegedHelperContract.responseGracePeriod) { proxy, reply in
            proxy.run(request: data, withReply: reply)
        }
        guard let decoded = try? JSONDecoder().decode(NmapPrivilegedRunResponse.self, from: response) else {
            throw ClientError.communicationFailed("invalid XPC helper response")
        }
        return decoded
    }

    private static func startProgressMirror(scanID: String?, workDirectory: URL) -> DispatchSourceTimer? {
        guard let request = try? JSONEncoder().encode(NmapPrivilegedScanReference(scanID: scanID)) else { return nil }
        let destination = workDirectory.appendingPathComponent(NmapPrivilegedHelperContract.progressArtifactName)
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "com.techmore.nmapui.helper-progress"))
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler {
            guard let progress = try? callHelper(timeout: 2, { proxy, reply in proxy.progress(request: request, withReply: reply) }),
                  !progress.isEmpty else { return }
            try? progress.write(to: destination, options: .atomic)
        }
        timer.resume()
        return timer
    }

    private static func runViaInteractiveElevation(_ request: NmapPrivilegedRunRequest) throws -> NmapPrivilegedRunResponse {
        guard let helperURL = resolveHelperBinaryURL() else {
            throw ClientError.helperBinaryMissing
        }
        let encoded = try JSONEncoder().encode(request).base64EncodedString()
        let shellCommand = [helperURL.path, "run", "--request-base64", encoded].map(shellQuoted).joined(separator: " ")

        let result = try ExternalProcessRunner.run(
            executable: URL(fileURLWithPath: "/usr/bin/osascript"),
            arguments: [
                "-e",
                "do shell script \(appleScriptString(shellCommand)) with administrator privileges"
            ],
            timeout: 15 * 60,
            // The reply carries the scan output (base64 in JSON), not just logs.
            maxOutputBytes: 4 * NmapPrivilegedHelperContract.maximumArtifactBytes
        )
        guard result.exitCode == 0 else {
            throw ClientError.communicationFailed(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let line = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let response = try? JSONDecoder().decode(NmapPrivilegedRunResponse.self, from: Data(line.utf8)) else {
            throw ClientError.communicationFailed("invalid one-shot helper response")
        }
        return response
    }

    // MARK: - XPC

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

    private static func callHelper(
        timeout: TimeInterval,
        _ invoke: (NmapPrivilegedServiceProtocol, @escaping @Sendable (Data) -> Void) -> Void
    ) throws -> Data {
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
        invoke(proxy) { response in
            responseBox.set(data: response)
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            throw ClientError.communicationFailed("XPC helper timed out")
        }
        let (responseData, responseError) = responseBox.values()
        if let responseError { throw ClientError.communicationFailed(responseError.localizedDescription) }
        guard let responseData else { throw ClientError.communicationFailed("empty XPC helper response") }
        return responseData
    }

    private static func shellQuoted(_ value: String) -> String {
        PrivilegedNmapInstallPlan.shellQuoted(value)
    }

    private static func appleScriptString(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "\"" + escaped + "\""
    }
}
