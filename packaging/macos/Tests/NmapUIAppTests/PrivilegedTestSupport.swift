import Darwin
import Foundation

/// Shared fixtures for the privileged-helper tests. None of them need root:
/// the helper's root-ownership checks are exercised by showing that
/// user-owned files are refused.
enum PrivilegedTestSupport {
    static func makeTemporaryDirectory() throws -> URL {
        // realpath: /var/folders is reached through the /var symlink.
        let base = URL(fileURLWithPath: realpath(FileManager.default.temporaryDirectory.path))
        let directory = base.appendingPathComponent("nmapui-helper-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    static func realpath(_ path: String) -> String {
        guard let resolved = Darwin.realpath(path, nil) else { return path }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    struct Output {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    @discardableResult
    static func run(_ executable: String, _ arguments: [String], environment: [String: String]? = nil) throws -> Output {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let environment { process.environment = environment }
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let out = stdout.fileHandleForReading.readDataToEndOfFile()
        let err = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Output(
            status: process.terminationStatus,
            stdout: String(decoding: out, as: UTF8.self),
            stderr: String(decoding: err, as: UTF8.self)
        )
    }

    static func shell(_ script: String) throws -> Output {
        try run("/bin/sh", ["-c", script])
    }

    static var hasCompiler: Bool {
        (try? run("/usr/bin/xcrun", ["--find", "clang"]).status) == 0
    }

    /// Compiles C source with `xcrun clang`; `arguments` go before the output flag.
    static func compile(_ source: String, to output: URL, arguments: [String]) throws {
        let sourceURL = output.deletingLastPathComponent().appendingPathComponent(output.lastPathComponent + ".c")
        try source.write(to: sourceURL, atomically: true, encoding: .utf8)
        let result = try run("/usr/bin/xcrun", ["clang"] + arguments + ["-o", output.path, sourceURL.path])
        guard result.status == 0 else {
            throw NSError(domain: "compile", code: Int(result.status), userInfo: [NSLocalizedDescriptionKey: result.stderr])
        }
        try FileManager.default.removeItem(at: sourceURL)
    }

    /// The smallest nmap data directory the helper accepts.
    static func makeNmapDataDirectory(at directory: URL) throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(at: directory.appendingPathComponent("nselib"), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: directory.appendingPathComponent("scripts"), withIntermediateDirectories: true)
        for name in ["nmap-services", "nmap-protocols", "nmap-rpc", "nmap-service-probes", "nmap-os-db", "nmap-mac-prefixes", "nse_main.lua", "scripts/script.db"] {
            try Data("# fixture\n".utf8).write(to: directory.appendingPathComponent(name))
        }
    }

    static func homebrewNmap() -> String? {
        ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap"].first { FileManager.default.isExecutableFile(atPath: $0) }
    }
}
