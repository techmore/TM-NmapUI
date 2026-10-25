import Darwin
import Foundation
import Security
import RuntimeContracts

/// Root-only helper that runs allowlisted nmap invocations for NmapUI.
///
/// Modes:
/// - `daemon`: listen on the authorized Mach service and service run/cancel/ping requests
/// - `run --work-dir DIR -- nmapPath arg...`: one-shot elevated run (used by interactive fallback)
enum HelperConstants {
    static let protocolVersion = NmapPrivilegedHelperContract.protocolVersion
    static let machServiceName = NmapPrivilegedHelperContract.machServiceName
    static let authorizedBundleIdentifier = NmapPrivilegedHelperContract.authorizedBundleIdentifier
    static let maxArgumentCount = 64
    static let maxArgumentLength = 4096
    static let maxResponseBytes = 2 * 1024 * 1024
    static let maximumScanRuntime = NmapPrivilegedHelperContract.maximumScanRuntime
}

@main
struct NmapPrivilegedHelperMain {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let mode = args.first else {
            fputs("usage: NmapPrivilegedHelper daemon | run --work-dir DIR -- <nmapPath> [args...]\n", stderr)
            exit(2)
        }

        switch mode {
        case "daemon":
            runDaemon()
        case "run":
            do {
                try runOneShot(Array(args.dropFirst()))
            } catch {
                fputs("\(error.localizedDescription)\n", stderr)
                exit(1)
            }
        default:
            fputs("unknown mode: \(mode)\n", stderr)
            exit(2)
        }
    }
}

// MARK: - One-shot

private func runOneShot(_ args: [String]) throws {
    guard geteuid() == 0 else {
        throw HelperError.notRoot
    }
    let request = try parseRunCLIArguments(args)
    let invokingUID = uid_t(ProcessInfo.processInfo.environment["SUDO_UID"].flatMap(UInt32.init) ?? getuid())
    let result = try executeNmap(request, clientUID: invokingUID)
    if !result.stdout.isEmpty {
        fputs(result.stdout, stdout)
    }
    if !result.stderr.isEmpty {
        fputs(result.stderr, stderr)
    }
    exit(Int32(result.exitCode))
}

private func parseRunCLIArguments(_ args: [String]) throws -> HelperRunRequest {
    var workDirectory: String?
    var scanID: String?
    var command: [String] = []
    var index = 0
    while index < args.count {
        let arg = args[index]
        if arg == "--work-dir" {
            index += 1
            guard index < args.count else { throw HelperError.invalidRequest("missing --work-dir value") }
            workDirectory = args[index]
        } else if arg == "--scan-id" {
            index += 1
            guard index < args.count else { throw HelperError.invalidRequest("missing --scan-id value") }
            scanID = args[index]
        } else if arg == "--" {
            command = Array(args.suffix(from: index + 1))
            break
        } else {
            command = Array(args.suffix(from: index))
            break
        }
        index += 1
    }
    guard let workDirectory, !workDirectory.isEmpty else {
        throw HelperError.invalidRequest("work directory required")
    }
    guard let nmapPath = command.first, command.count >= 1 else {
        throw HelperError.invalidRequest("nmap command required")
    }
    return HelperRunRequest(
        nmapPath: nmapPath,
        arguments: Array(command.dropFirst()),
        workDirectory: workDirectory,
        scanID: scanID
    )
}

// MARK: - Daemon

private final class DaemonState: @unchecked Sendable {
    private let lock = NSLock()
    private var activeProcesses: [String: Process] = [:]

    func addActive(_ process: Process, scanID: String?) -> String {
        let id = scanID?.isEmpty == false ? scanID! : UUID().uuidString
        lock.lock()
        activeProcesses[id] = process
        lock.unlock()
        return id
    }

    func removeActive(_ id: String) {
        lock.lock()
        activeProcesses.removeValue(forKey: id)
        lock.unlock()
    }

    func cancelActive(scanID: String?) {
        lock.lock()
        let processes: [Process]
        if let scanID, !scanID.isEmpty {
            processes = activeProcesses[scanID].map { [$0] } ?? []
        } else {
            processes = Array(activeProcesses.values)
        }
        lock.unlock()
        processes.forEach { $0.terminate() }
    }
}

private let daemonState = DaemonState()

private func runDaemon() {
    guard geteuid() == 0 else {
        fputs("daemon must run as root\n", stderr)
        exit(1)
    }

    writeInstallStamp()
    runXPCDaemon()
}

/// #237: record the installed helper's protocol version + binary hash so the app can
/// verify compatibility without reinstalling (which would trigger an admin prompt).
private func writeInstallStamp() {
    do {
        try writeHelperInstallStamp(
            binaryURL: URL(fileURLWithPath: CommandLine.arguments[0]),
            stampURL: URL(fileURLWithPath: "/Library/Application Support/NmapUI/helper-stamp.json")
        )
    } catch {
        fputs("Could not write helper install stamp: \(error.localizedDescription)\n", stderr)
    }
}

private final class XPCHelperService: NSObject, NmapPrivilegedServiceProtocol {
    private let clientUID: uid_t

    init(clientUID: uid_t) {
        self.clientUID = clientUID
    }

    func ping(withReply reply: @escaping (Data) -> Void) {
        reply(Data("pong:\(HelperConstants.protocolVersion)".utf8))
    }

    func run(request: Data, withReply reply: @escaping (Data) -> Void) {
        guard let request = try? JSONDecoder().decode(HelperRequest.self, from: request),
              request.cmd == "run", let run = request.run else {
            reply(encodeResponse(HelperResponse(ok: false, exitCode: 1, stdout: "", stderr: "invalid request", error: "invalid request")))
            return
        }
        do {
            let result = try executeNmap(run, clientUID: clientUID)
            reply(encodeResponse(HelperResponse(ok: result.exitCode == 0, exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr, error: result.exitCode == 0 ? nil : "nmap exited with status \(result.exitCode)")))
        } catch {
            reply(encodeResponse(HelperResponse(ok: false, exitCode: 1, stdout: "", stderr: error.localizedDescription, error: error.localizedDescription)))
        }
    }

    func cancel(request: Data, withReply reply: @escaping (Data) -> Void) {
        let scanID = (try? JSONDecoder().decode(HelperCancelRequest.self, from: request))?.scanID
        daemonState.cancelActive(scanID: scanID)
        reply(encodeResponse(HelperResponse(ok: true, exitCode: 0, stdout: "cancelled", stderr: "", error: nil)))
    }

    private func encodeResponse(_ response: HelperResponse) -> Data { (try? JSONEncoder().encode(response)) ?? Data() }
}

private final class XPCListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier != 0,
              isAuthorizedClient(connection.processIdentifier) else { return false }
        connection.exportedInterface = NSXPCInterface(with: NmapPrivilegedServiceProtocol.self)
        connection.exportedObject = XPCHelperService(clientUID: connection.effectiveUserIdentifier)
        connection.resume()
        return true
    }

    private func isAuthorizedClient(_ pid: pid_t) -> Bool {
        var guest: SecCode?
        let attributes: [CFString: Any] = [kSecGuestAttributePid: pid]
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &guest) == errSecSuccess,
              let guest else { return false }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode else { return false }
        guard SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess else { return false }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String else { return false }
        if identifier == HelperConstants.authorizedBundleIdentifier { return true }

        // SwiftPM and ad-hoc signatures can assign the executable a derived
        // identifier. The signed app bundle still carries the stable identity
        // written into Info.plist, so verify that identity as a second check.
        var codePath: CFURL?
        guard SecCodeCopyPath(staticCode, [], &codePath) == errSecSuccess,
              let codePath,
              let executableURL = codePath as URL?,
              let info = NSDictionary(contentsOf: executableURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Info.plist")),
              let bundleIdentifier = info["CFBundleIdentifier"] as? String else { return false }
        return bundleIdentifier == HelperConstants.authorizedBundleIdentifier
    }
}

private func runXPCDaemon() {
    // Ensure launchd termination also stops any elevated nmap child before the
    // helper exits during an upgrade or normal system shutdown.
    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)
    let terminationSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global(qos: .utility))
    terminationSource.setEventHandler {
        daemonState.cancelActive(scanID: nil)
        exit(0)
    }
    terminationSource.resume()

    let listener = NSXPCListener(machServiceName: HelperConstants.machServiceName)
    let delegate = XPCListenerDelegate()
    listener.delegate = delegate
    listener.resume()
    fputs("NmapUI privileged XPC helper listening on \(HelperConstants.machServiceName)\n", stderr)
    withExtendedLifetime(terminationSource) {
        RunLoop.current.run()
    }
}

// MARK: - Execute

private struct ExecuteResult {
    let exitCode: Int
    let stdout: String
    let stderr: String
}

private final class CapturedOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var standardOutput = Data()
    private var standardError = Data()

    func store(_ data: Data, isStandardError: Bool) {
        lock.lock()
        if isStandardError { standardError = data } else { standardOutput = data }
        lock.unlock()
    }

    func values() -> (Data, Data) {
        lock.lock()
        defer { lock.unlock() }
        return (standardOutput, standardError)
    }
}

private func executeNmap(_ request: HelperRunRequest, clientUID: uid_t) throws -> ExecuteResult {
    try validate(request, clientUID: clientUID)

    let process = Process()
    process.currentDirectoryURL = URL(fileURLWithPath: request.workDirectory, isDirectory: true)
    process.executableURL = URL(fileURLWithPath: request.nmapPath)
    process.arguments = request.arguments

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    let processID = daemonState.addActive(process, scanID: request.scanID)
    defer { daemonState.removeActive(processID) }

    try process.run()
    let outputGroup = DispatchGroup()
    let capturedOutput = CapturedOutput()
    for (handle, isStandardError) in [(stdoutPipe.fileHandleForReading, false), (stderrPipe.fileHandleForReading, true)] {
        outputGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            var captured = Data()
            while true {
                let chunk = handle.readData(ofLength: 32 * 1024)
                if chunk.isEmpty { break }
                if captured.count < HelperConstants.maxResponseBytes {
                    captured.append(chunk.prefix(HelperConstants.maxResponseBytes - captured.count))
                }
            }
            capturedOutput.store(captured, isStandardError: isStandardError)
            outputGroup.leave()
        }
    }
    let deadline = Date().addingTimeInterval(HelperConstants.maximumScanRuntime)
    var timedOut = false
    while process.isRunning {
        if Date() >= deadline {
            timedOut = true
            process.terminate()
            Thread.sleep(forTimeInterval: 0.25)
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            break
        }
        Thread.sleep(forTimeInterval: 0.1)
    }
    process.waitUntilExit()
    outputGroup.wait()

    if timedOut {
        throw HelperError.executionFailed("nmap exceeded the maximum scan runtime")
    }

    let (stdoutData, stderrData) = capturedOutput.values()
    let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
    let stderr = String(data: stderrData, encoding: .utf8) ?? ""

    return ExecuteResult(exitCode: Int(process.terminationStatus), stdout: stdout, stderr: stderr)
}

private func validate(_ request: HelperRunRequest, clientUID: uid_t) throws {
    let nmapPath = request.nmapPath
    guard nmapPath.hasPrefix("/"), !nmapPath.contains("..") else {
        throw HelperError.invalidRequest("nmap path must be absolute")
    }
    let base = URL(fileURLWithPath: nmapPath).lastPathComponent
    guard nmapPath == NmapPrivilegedHelperContract.privilegedNmapPath || base == "nmap" else {
        throw HelperError.invalidRequest("executable must be nmap")
    }
    guard FileManager.default.isExecutableFile(atPath: nmapPath) else {
        throw HelperError.invalidRequest("nmap is not executable at \(nmapPath)")
    }

    let executableAttributes = try FileManager.default.attributesOfItem(atPath: nmapPath)
    let executableOwner = (executableAttributes[.ownerAccountID] as? NSNumber)?.uint32Value
    let executableMode = (executableAttributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
    guard executableOwner == 0, executableMode & 0o022 == 0 else {
        throw HelperError.invalidRequest("privileged nmap must be root-owned and not group/world writable")
    }

    let work = request.workDirectory
    guard work.hasPrefix("/"), !work.contains("..") else {
        throw HelperError.invalidRequest("invalid work directory")
    }
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: work, isDirectory: &isDir), isDir.boolValue else {
        throw HelperError.invalidRequest("work directory does not exist")
    }
    guard let account = getpwuid(clientUID), let homeCString = account.pointee.pw_dir else {
        throw HelperError.invalidRequest("could not resolve client home directory")
    }
    let home = String(cString: homeCString)
    let allowedRoot = URL(fileURLWithPath: home)
        .appendingPathComponent("Library/Application Support/NmapUI/work/scans", isDirectory: true)
        .standardizedFileURL.resolvingSymlinksInPath()
    let resolvedWork = URL(fileURLWithPath: work, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
    guard resolvedWork.path.hasPrefix(allowedRoot.path + "/") else {
        throw HelperError.invalidRequest("work directory is outside the NmapUI scan root")
    }

    guard request.arguments.count <= HelperConstants.maxArgumentCount else {
        throw HelperError.invalidRequest("too many arguments")
    }
    for argument in request.arguments {
        guard argument.count <= HelperConstants.maxArgumentLength else {
            throw HelperError.invalidRequest("argument too long")
        }
        if argument.contains("\0") || argument.contains(";") || argument.contains("|") || argument.contains("&") || argument.contains("`") || argument.contains("$(") {
            throw HelperError.invalidRequest("argument contains forbidden characters")
        }
    }
    try validateNmapArguments(request.arguments)
}

private func validateNmapArguments(_ arguments: [String]) throws {
    let flagsWithValues: Set<String> = [
        "-p", "--host-timeout", "--script-timeout", "--max-retries", "--max-rtt-timeout",
        "--min-hostgroup", "--max-hostgroup", "--script", "--script-args", "--stylesheet",
        "-oX", "-oG", "-iL"
    ]
    let standaloneFlags: Set<String> = ["-sn", "-PR", "-sS", "-sV", "-O", "-sC", "-Pn", "-T2", "-T3", "-T4", "--open", "-p-"]
    let safeRelativeFiles: Set<String> = ["phase1_results.xml", "phase2_results.xml", "phase2_progress.gnmap", "targets.tmp", "nmap-modern.xsl"]
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if standaloneFlags.contains(argument) {
            index += 1
            continue
        }
        if NmapPrivilegedHelperContract.isAllowedScanTarget(argument) {
            index += 1
            continue
        }
        guard flagsWithValues.contains(argument), index + 1 < arguments.count else {
            throw HelperError.invalidRequest("unsupported privileged nmap argument: \(argument)")
        }
        let value = arguments[index + 1]
        switch argument {
        case "-oX", "-oG", "-iL", "--stylesheet":
            guard safeRelativeFiles.contains(value) else {
                throw HelperError.invalidRequest("unsafe privileged scan artifact path")
            }
        case "--script":
            let scriptURL = URL(fileURLWithPath: value).standardizedFileURL.resolvingSymlinksInPath()
            guard scriptURL.lastPathComponent == "vulners.nse",
                  let attributes = try? FileManager.default.attributesOfItem(atPath: scriptURL.path),
                  (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == 0,
                  ((attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0) & 0o022 == 0 else {
                throw HelperError.invalidRequest("privileged Vulners script must be root-owned and immutable")
            }
        default:
            break
        }
        index += 2
    }
}

// MARK: - Wire protocol

private struct HelperRunRequest: Codable {
    let nmapPath: String
    let arguments: [String]
    let workDirectory: String
    let scanID: String?
}

private struct HelperRequest: Codable {
    let cmd: String
    let run: HelperRunRequest?
    let scanID: String?
}

private struct HelperCancelRequest: Codable {
    let cmd: String
    let scanID: String?
}

private struct HelperResponse: Codable {
    let ok: Bool
    let exitCode: Int
    let stdout: String
    let stderr: String
    let error: String?
}

private enum HelperError: LocalizedError {
    case notRoot
    case invalidRequest(String)
    case executionFailed(String)

    var errorDescription: String? {
        switch self {
        case .notRoot:
            return "helper must run as root"
        case .invalidRequest(let message):
            return message
        case .executionFailed(let message):
            return message
        }
    }
}
