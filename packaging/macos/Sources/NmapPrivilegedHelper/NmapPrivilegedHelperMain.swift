import Darwin
import Foundation
import RuntimeContracts

/// Root-only helper that runs allowlisted nmap invocations for NmapUI.
///
/// Modes:
/// - `daemon`: listen on the Mach service and serve run/cancel/progress/ping
///   requests from clients that satisfy `HelperClientAuthorization`.
/// - `run --request-base64 B64`: one-shot elevated run (the app's interactive
///   fallback). B64 is a JSON `NmapPrivilegedRunRequest`; the reply is one
///   line of JSON `NmapPrivilegedRunResponse` on stdout.
///
/// In both modes the helper runs only the installed root-owned nmap, and
/// scan files live in a helper-owned directory (see `HelperScanRun.swift`).
@main
struct NmapPrivilegedHelperMain {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let mode = args.first else {
            fputs("usage: NmapPrivilegedHelper daemon | run --request-base64 <json>\n", stderr)
            exit(2)
        }

        switch mode {
        case "daemon":
            runDaemon()
        case "run":
            runOneShot(Array(args.dropFirst()))
        default:
            fputs("unknown mode: \(mode)\n", stderr)
            exit(2)
        }
    }
}

// MARK: - One-shot

private func runOneShot(_ args: [String]) -> Never {
    let response: NmapPrivilegedRunResponse
    do {
        guard geteuid() == 0 else { throw HelperError.notRoot }
        response = try executeNmap(try parseRunCLIArguments(args))
    } catch {
        response = .failure(error.localizedDescription)
    }
    let data = (try? JSONEncoder().encode(response)) ?? Data()
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(0)
}

func parseRunCLIArguments(_ args: [String]) throws -> NmapPrivilegedRunRequest {
    guard args.count == 2, args[0] == "--request-base64" else {
        throw HelperError.invalidRequest("usage: run --request-base64 <json>")
    }
    guard let data = Data(base64Encoded: args[1]),
          let request = try? JSONDecoder().decode(NmapPrivilegedRunRequest.self, from: data) else {
        throw HelperError.invalidRequest("invalid run request")
    }
    return request
}

// MARK: - Daemon

/// Scans in flight, keyed by client UID and scan ID so one user cannot
/// cancel or read another user's scan.
final class DaemonState: @unchecked Sendable {
    private struct ActiveScan {
        let process: Process
        let runDirectory: String
    }

    private let lock = NSLock()
    private var active: [String: ActiveScan] = [:]

    private static func key(_ uid: uid_t, _ scanID: String) -> String { "\(uid):\(scanID)" }

    func add(_ process: Process, runDirectory: String, scanID: String, uid: uid_t) {
        lock.lock()
        active[Self.key(uid, scanID)] = ActiveScan(process: process, runDirectory: runDirectory)
        lock.unlock()
    }

    func remove(scanID: String, uid: uid_t) {
        lock.lock()
        active.removeValue(forKey: Self.key(uid, scanID))
        lock.unlock()
    }

    func runDirectory(scanID: String, uid: uid_t) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return active[Self.key(uid, scanID)]?.runDirectory
    }

    /// Cancels one scan, every scan of `uid` when `scanID` is nil, or every
    /// scan when `uid` is nil (helper shutdown).
    func cancel(scanID: String?, uid: uid_t?) {
        lock.lock()
        let processes: [Process]
        if let uid, let scanID, !scanID.isEmpty {
            processes = active[Self.key(uid, scanID)].map { [$0.process] } ?? []
        } else if let uid {
            processes = active.filter { $0.key.hasPrefix("\(uid):") }.map(\.value.process)
        } else {
            processes = active.values.map(\.process)
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
            binaryURL: URL(fileURLWithPath: NmapPrivilegedHelperContract.helperInstallPath),
            stampURL: URL(fileURLWithPath: NmapPrivilegedHelperContract.helperStampPath)
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
        reply(Data("pong:\(NmapPrivilegedHelperContract.protocolVersion)".utf8))
    }

    func run(request: Data, withReply reply: @escaping (Data) -> Void) {
        guard let run = try? JSONDecoder().decode(NmapPrivilegedRunRequest.self, from: request) else {
            reply(encode(.failure("invalid request")))
            return
        }
        let scanID = run.scanID.flatMap { $0.isEmpty ? nil : $0 } ?? UUID().uuidString
        let uid = clientUID
        do {
            let response = try executeNmap(
                run,
                onStart: { process, runDirectory in
                    daemonState.add(process, runDirectory: runDirectory, scanID: scanID, uid: uid)
                },
                onFinish: { daemonState.remove(scanID: scanID, uid: uid) }
            )
            reply(encode(response))
        } catch {
            reply(encode(.failure(error.localizedDescription)))
        }
    }

    func cancel(request: Data, withReply reply: @escaping (Data) -> Void) {
        let scanID = (try? JSONDecoder().decode(NmapPrivilegedScanReference.self, from: request))?.scanID
        daemonState.cancel(scanID: scanID, uid: clientUID)
        reply(encode(NmapPrivilegedRunResponse(ok: true, exitCode: 0, stdout: "cancelled", stderr: "", error: nil)))
    }

    func progress(request: Data, withReply reply: @escaping (Data) -> Void) {
        guard let scanID = (try? JSONDecoder().decode(NmapPrivilegedScanReference.self, from: request))?.scanID,
              let runDirectory = daemonState.runDirectory(scanID: scanID, uid: clientUID) else {
            reply(Data())
            return
        }
        let path = runDirectory + "/" + NmapPrivilegedHelperContract.progressArtifactName
        reply(((try? readArtifact(path, limit: HelperLimits.maxProgressBytes)) ?? nil) ?? Data())
    }

    private func encode(_ response: NmapPrivilegedRunResponse) -> Data { (try? JSONEncoder().encode(response)) ?? Data() }
}

private final class XPCListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let requirement: SecRequirement?

    init(requirementText: String?) {
        requirement = requirementText.flatMap(HelperClientAuthorization.makeRequirement)
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let requirement else {
            fputs("Rejected XPC client pid \(connection.processIdentifier): helper has no signing team, so no client is trusted\n", stderr)
            return false
        }
        let decision = HelperClientAuthorization.evaluate(connection: connection, requirement: requirement)
        guard decision.accepted else {
            fputs("Rejected XPC client pid \(connection.processIdentifier): \(decision.reason)\n", stderr)
            return false
        }
        connection.exportedInterface = NSXPCInterface(with: NmapPrivilegedServiceProtocol.self)
        connection.exportedObject = XPCHelperService(clientUID: connection.effectiveUserIdentifier)
        connection.resume()
        return true
    }
}

private func runXPCDaemon() {
    // Ensure launchd termination also stops any elevated nmap child before the
    // helper exits during an upgrade or normal system shutdown.
    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)
    let terminationSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global(qos: .utility))
    terminationSource.setEventHandler {
        daemonState.cancel(scanID: nil, uid: nil)
        exit(0)
    }
    terminationSource.resume()

    let requirementText = HelperClientAuthorization.clientRequirementForRunningHelper()
    let listener = NSXPCListener(machServiceName: NmapPrivilegedHelperContract.machServiceName)
    if let requirementText {
        // The system re-checks this requirement, by audit token, on every message.
        listener.setConnectionCodeSigningRequirement(requirementText)
        fputs("Accepting XPC clients that satisfy: \(requirementText)\n", stderr)
    } else {
        fputs("Helper is not signed with a team identity; refusing all XPC clients\n", stderr)
    }
    let delegate = XPCListenerDelegate(requirementText: requirementText)
    listener.delegate = delegate
    listener.resume()
    fputs("NmapUI privileged XPC helper listening on \(NmapPrivilegedHelperContract.machServiceName)\n", stderr)
    withExtendedLifetime((terminationSource, delegate)) {
        RunLoop.current.run()
    }
}
