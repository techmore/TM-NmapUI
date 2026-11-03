import Darwin
import Foundation
import RuntimeContracts

/// Where the helper finds nmap and puts scan output. Production paths are
/// fixed root-owned locations; tests substitute temporary ones and turn off
/// the root-ownership checks (they cannot create root-owned files).
struct HelperRunEnvironment {
    var nmapPath = NmapPrivilegedHelperContract.privilegedNmapPath
    var dataDirectory = NmapPrivilegedHelperContract.privilegedNmapDataDirectory
    var openSSLModulesDirectory = NmapPrivilegedHelperContract.privilegedOpenSSLModulesDirectory
    var openSSLEnginesDirectory = NmapPrivilegedHelperContract.privilegedOpenSSLEnginesDirectory
    var runRoot = NmapPrivilegedHelperContract.helperRunRoot
    var enforceRootOwnership = true
    var maximumRuntime = NmapPrivilegedHelperContract.maximumScanRuntime

    static let production = HelperRunEnvironment()
}

enum HelperError: LocalizedError {
    case notRoot
    case invalidRequest(String)
    case installation(String)
    case executionFailed(String)

    var errorDescription: String? {
        switch self {
        case .notRoot: return "helper must run as root"
        case .invalidRequest(let message): return message
        case .installation(let message): return "privileged nmap installation is not safe to run: \(message)"
        case .executionFailed(let message): return message
        }
    }
}

enum HelperLimits {
    static let maxArgumentCount = 64
    static let maxArgumentLength = 4096
    static let maxStreamBytes = 2 * 1024 * 1024
    static let maxProgressBytes = 8 * 1024 * 1024
}

// MARK: - Argument validation

func validateNmapArguments(_ arguments: [String]) throws {
    guard arguments.count <= HelperLimits.maxArgumentCount else {
        throw HelperError.invalidRequest("too many arguments")
    }
    for argument in arguments {
        guard argument.count <= HelperLimits.maxArgumentLength else {
            throw HelperError.invalidRequest("argument too long")
        }
        if argument.contains("\0") || argument.contains(";") || argument.contains("|") || argument.contains("&") || argument.contains("`") || argument.contains("$(") {
            throw HelperError.invalidRequest("argument contains forbidden characters")
        }
    }
    let flagsWithValues: Set<String> = [
        "-p", "--host-timeout", "--script-timeout", "--max-retries", "--max-rtt-timeout",
        "--min-hostgroup", "--max-hostgroup", "--script", "--script-args", "--stylesheet",
        "-oX", "-oG"
    ]
    let standaloneFlags: Set<String> = ["-sn", "-PR", "-sS", "-sV", "-O", "-sC", "-Pn", "-T2", "-T3", "-T4", "--open", "-p-"]
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
            // -iL is rejected here too: targets travel in the request, never as a path.
            throw HelperError.invalidRequest("unsupported privileged nmap argument: \(argument)")
        }
        let value = arguments[index + 1]
        switch argument {
        case "-oX", "-oG":
            guard NmapPrivilegedHelperContract.artifactNames.contains(value) else {
                throw HelperError.invalidRequest("unsupported privileged scan output name")
            }
        case "--stylesheet":
            guard value == NmapPrivilegedHelperContract.stylesheetName else {
                throw HelperError.invalidRequest("unsupported stylesheet reference")
            }
        case "--script":
            // nmap reads --script as a comma list or expression, and a resolved
            // symlink can be swapped after the check. Accept only the fixed,
            // root-owned install path, so the checked path is the one nmap opens.
            guard value == NmapPrivilegedHelperContract.privilegedVulnersScriptPath,
                  NmapPrivilegedHelperContract.isRootOwnedImmutablePath(value) else {
                throw HelperError.invalidRequest("privileged Vulners script must be the root-owned install path")
            }
        case "--script-args":
            // Script arguments can name files (userdb=, passdb=, ...) that
            // scripts would read as root. Only Vulners' own tuning is allowed.
            guard NmapPrivilegedHelperContract.isAllowedScriptArguments(value) else {
                throw HelperError.invalidRequest("unsupported privileged script arguments")
            }
        default:
            break
        }
        index += 2
    }
}

// MARK: - Installation checks

/// Refuses an nmap that a non-root user could change: the binary, every
/// library it loads, its data directory (NSE Lua) and OpenSSL's plug-in
/// directories must all be root-owned and read-only.
func verifyPrivilegedInstallation(_ environment: HelperRunEnvironment) throws {
    guard FileManager.default.isExecutableFile(atPath: environment.nmapPath) else {
        throw HelperError.installation("nmap is not executable at \(environment.nmapPath)")
    }
    try verifyNmapDataDirectory(environment.dataDirectory, requireRootOwnership: environment.enforceRootOwnership)
    guard environment.enforceRootOwnership else { return }

    guard NmapPrivilegedHelperContract.isRootOwnedImmutablePath(environment.nmapPath) else {
        throw HelperError.installation("\(environment.nmapPath) must be root-owned and not group/world writable")
    }
    let problems = MachOLinkage.untrustedLinkage(ofExecutable: environment.nmapPath)
    guard problems.isEmpty else {
        throw HelperError.installation(problems.joined(separator: "; "))
    }
    for directory in [environment.openSSLModulesDirectory, environment.openSSLEnginesDirectory] {
        try verifyRootOwnedTree(directory)
    }
    let modules = (try? FileManager.default.contentsOfDirectory(atPath: environment.openSSLModulesDirectory)) ?? []
    for module in modules {
        let modulePath = environment.openSSLModulesDirectory + "/" + module
        let moduleProblems = MachOLinkage.untrustedLinkage(ofExecutable: modulePath)
        guard moduleProblems.isEmpty else {
            throw HelperError.installation(moduleProblems.joined(separator: "; "))
        }
    }
}

private let requiredNmapDataEntries = [
    "nmap-services", "nmap-protocols", "nmap-rpc", "nmap-service-probes", "nmap-os-db",
    "nmap-mac-prefixes", "nse_main.lua", "nselib", "scripts", "scripts/script.db"
]

/// nmap looks in --datadir first and then falls back to other locations
/// (its compiled-in Homebrew path, then the working directory) for any file
/// that is missing, so the copy must be complete as well as root-owned.
func verifyNmapDataDirectory(_ directory: String, requireRootOwnership: Bool) throws {
    for entry in requiredNmapDataEntries where access(directory + "/" + entry, F_OK) != 0 {
        throw HelperError.installation("nmap data directory \(directory) is missing \(entry)")
    }
    if requireRootOwnership {
        try verifyRootOwnedTree(directory)
    } else {
        try walkTree(directory) { _, _ in }
    }
}

/// Every entry must be a root-owned directory or regular file, not writable
/// by group or others, under a root-owned immutable path. Symlinks are refused.
func verifyRootOwnedTree(_ directory: String) throws {
    guard NmapPrivilegedHelperContract.isRootOwnedImmutablePath(directory) else {
        throw HelperError.installation("\(directory) must be root-owned and not group/world writable")
    }
    try walkTree(directory) { path, info in
        guard info.st_uid == 0, info.st_mode & 0o022 == 0 else {
            throw HelperError.installation("\(path) must be root-owned and not group/world writable")
        }
    }
}

private func walkTree(_ root: String, _ check: (String, stat) throws -> Void) throws {
    var pending = [root]
    var visited = 0
    while let path = pending.popLast() {
        visited += 1
        guard visited <= 20_000 else { throw HelperError.installation("\(root) has too many entries") }
        var info = stat()
        guard lstat(path, &info) == 0 else { throw HelperError.installation("cannot inspect \(path)") }
        let type = info.st_mode & S_IFMT
        guard type == S_IFDIR || type == S_IFREG else {
            throw HelperError.installation("\(path) is not a regular file or directory")
        }
        try check(path, info)
        if type == S_IFDIR {
            let children = try FileManager.default.contentsOfDirectory(atPath: path)
            pending.append(contentsOf: children.map { path + "/" + $0 })
        }
    }
}

// MARK: - Helper-owned scan directory

/// Creates a private per-scan directory. Its parent must be owned by the
/// helper's user (root in production), mode 0700, and in production sit on a
/// root-owned immutable path, so no client can plant or swap entries in it.
func makeRunDirectory(root: String, enforceRootOwnership: Bool) throws -> String {
    if mkdir(root, 0o700) != 0, errno != EEXIST {
        throw HelperError.executionFailed("cannot create \(root): \(String(cString: strerror(errno)))")
    }
    var info = stat()
    guard lstat(root, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
          info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
        throw HelperError.executionFailed("\(root) must be a private directory owned by the helper")
    }
    if enforceRootOwnership {
        guard NmapPrivilegedHelperContract.isRootOwnedImmutablePath(root) else {
            throw HelperError.executionFailed("\(root) must be on a root-owned path")
        }
    }
    var template = Array((root + "/run.XXXXXX").utf8CString)
    guard let created = template.withUnsafeMutableBufferPointer({ mkdtemp($0.baseAddress!) }) else {
        throw HelperError.executionFailed("cannot create a scan directory: \(String(cString: strerror(errno)))")
    }
    return String(cString: created)
}

/// Creates a new file that cannot already exist or be a symlink.
func createExclusiveFile(_ path: String, contents: Data = Data()) throws {
    let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard descriptor >= 0 else {
        throw HelperError.executionFailed("cannot create \(path): \(String(cString: strerror(errno)))")
    }
    defer { close(descriptor) }
    try contents.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            let written = write(descriptor, buffer.baseAddress! + offset, buffer.count - offset)
            guard written > 0 else { throw HelperError.executionFailed("cannot write \(path)") }
            offset += written
        }
    }
}

/// Reads a regular file without following a symlink. Returns nil if absent.
func readArtifact(_ path: String, limit: Int) throws -> Data? {
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard descriptor >= 0 else {
        if errno == ENOENT { return nil }
        throw HelperError.executionFailed("cannot read scan output \((path as NSString).lastPathComponent): \(String(cString: strerror(errno)))")
    }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
        throw HelperError.executionFailed("scan output \((path as NSString).lastPathComponent) is not a regular file")
    }
    guard info.st_size <= off_t(limit) else {
        throw HelperError.executionFailed("scan output \((path as NSString).lastPathComponent) exceeds \(limit) bytes")
    }
    var data = Data(count: Int(info.st_size))
    let count = data.withUnsafeMutableBytes { buffer -> Int in
        guard let base = buffer.baseAddress else { return 0 }
        var total = 0
        while total < buffer.count {
            let result = read(descriptor, base + total, buffer.count - total)
            if result <= 0 { break }
            total += result
        }
        return total
    }
    return data.prefix(count)
}

struct PreparedRun: Equatable {
    let arguments: [String]
    /// Requested artifact name → path inside the run directory.
    let outputs: [String: String]
}

/// Turns a validated request into nmap's argv: outputs and targets become
/// helper-created files in `runDirectory`, and --datadir is pinned.
func prepareRun(_ request: NmapPrivilegedRunRequest, runDirectory: String, dataDirectory: String) throws -> PreparedRun {
    try validateNmapArguments(request.arguments)
    guard request.targets.count <= NmapPrivilegedHelperContract.maximumTargetCount else {
        throw HelperError.invalidRequest("too many targets")
    }
    for target in request.targets where !NmapPrivilegedHelperContract.isAllowedScanTarget(target) {
        throw HelperError.invalidRequest("invalid scan target: \(target)")
    }

    var arguments = ["--datadir", dataDirectory]
    var outputs: [String: String] = [:]
    var index = 0
    while index < request.arguments.count {
        let argument = request.arguments[index]
        if argument == "-oX" || argument == "-oG" {
            let name = request.arguments[index + 1]
            guard outputs[name] == nil else { throw HelperError.invalidRequest("duplicate scan output \(name)") }
            let path = runDirectory + "/" + name
            try createExclusiveFile(path)
            outputs[name] = path
            arguments.append(contentsOf: [argument, path])
            index += 2
            continue
        }
        arguments.append(argument)
        index += 1
    }
    if !request.targets.isEmpty {
        let path = runDirectory + "/targets.txt"
        try createExclusiveFile(path, contents: Data((request.targets.joined(separator: "\n") + "\n").utf8))
        arguments.append(contentsOf: ["-iL", path])
    }
    return PreparedRun(arguments: arguments, outputs: outputs)
}

/// nmap and the libraries it loads read configuration and code locations
/// from the environment (OPENSSL_CONF can load modules, LUA_PATH and
/// LUA_CPATH add Lua search paths, NMAPDIR adds a data directory). Start the
/// child from nothing and point each at a root-owned location.
func childEnvironment(_ environment: HelperRunEnvironment) -> [String: String] {
    [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "LUA_PATH": environment.dataDirectory + "/nselib/?.lua",
        "LUA_CPATH": "",
        "OPENSSL_CONF": "/dev/null",
        "OPENSSL_MODULES": environment.openSSLModulesDirectory,
        "OPENSSL_ENGINES": environment.openSSLEnginesDirectory,
    ]
}

// MARK: - Execute

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

/// Runs one privileged scan and returns its output files' contents. The
/// client's work directory is never opened: everything happens in a fresh
/// helper-owned directory that is removed afterwards.
func executeNmap(
    _ request: NmapPrivilegedRunRequest,
    environment: HelperRunEnvironment = .production,
    onStart: (Process, String) -> Void = { _, _ in },
    onFinish: () -> Void = {}
) throws -> NmapPrivilegedRunResponse {
    try verifyPrivilegedInstallation(environment)
    try validateNmapArguments(request.arguments)

    let runDirectory = try makeRunDirectory(root: environment.runRoot, enforceRootOwnership: environment.enforceRootOwnership)
    defer { try? FileManager.default.removeItem(atPath: runDirectory) }
    let prepared = try prepareRun(request, runDirectory: runDirectory, dataDirectory: environment.dataDirectory)

    let process = Process()
    process.currentDirectoryURL = URL(fileURLWithPath: runDirectory, isDirectory: true)
    process.executableURL = URL(fileURLWithPath: environment.nmapPath)
    process.arguments = prepared.arguments
    process.environment = childEnvironment(environment)
    process.standardInput = FileHandle.nullDevice

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    try process.run()
    onStart(process, runDirectory)
    defer { onFinish() }

    let outputGroup = DispatchGroup()
    let capturedOutput = CapturedOutput()
    for (handle, isStandardError) in [(stdoutPipe.fileHandleForReading, false), (stderrPipe.fileHandleForReading, true)] {
        outputGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            var captured = Data()
            while true {
                let chunk = handle.readData(ofLength: 32 * 1024)
                if chunk.isEmpty { break }
                if captured.count < HelperLimits.maxStreamBytes {
                    captured.append(chunk.prefix(HelperLimits.maxStreamBytes - captured.count))
                }
            }
            capturedOutput.store(captured, isStandardError: isStandardError)
            outputGroup.leave()
        }
    }
    let deadline = Date().addingTimeInterval(environment.maximumRuntime)
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

    var artifacts: [String: Data] = [:]
    for (name, path) in prepared.outputs {
        if let data = try readArtifact(path, limit: NmapPrivilegedHelperContract.maximumArtifactBytes), !data.isEmpty {
            artifacts[name] = data
        }
    }

    let (stdoutData, stderrData) = capturedOutput.values()
    let exitCode = Int(process.terminationStatus)
    return NmapPrivilegedRunResponse(
        ok: exitCode == 0,
        exitCode: exitCode,
        stdout: String(decoding: stdoutData, as: UTF8.self),
        stderr: String(decoding: stderrData, as: UTF8.self),
        error: exitCode == 0 ? nil : "nmap exited with status \(exitCode)",
        artifacts: artifacts
    )
}
