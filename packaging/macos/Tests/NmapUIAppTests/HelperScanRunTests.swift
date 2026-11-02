import Darwin
import Foundation
import RuntimeContracts
import Testing
@testable import NmapPrivilegedHelper

@Suite("Privileged helper owns scan files")
struct HelperScanRunTests {
    private func request(_ arguments: [String], targets: [String] = []) -> NmapPrivilegedRunRequest {
        NmapPrivilegedRunRequest(arguments: arguments, targets: targets, scanID: UUID().uuidString)
    }

    @Test("outputs and targets become helper-created files in the run directory")
    func outputsAndTargetsAreHelperFiles() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let run = try makeRunDirectory(root: directory.appendingPathComponent("runs").path, enforceRootOwnership: false)

        let prepared = try prepareRun(
            request(["-sS", "-oX", "phase2_results.xml", "-oG", "phase2_progress.gnmap", "--stylesheet", "nmap-modern.xsl"], targets: ["10.0.0.1", "10.0.0.2"]),
            runDirectory: run,
            dataDirectory: "/data"
        )

        #expect(prepared.arguments == [
            "--datadir", "/data", "-sS",
            "-oX", run + "/phase2_results.xml",
            "-oG", run + "/phase2_progress.gnmap",
            "--stylesheet", "nmap-modern.xsl",
            "-iL", run + "/targets.txt",
        ])
        #expect(prepared.outputs == ["phase2_results.xml": run + "/phase2_results.xml", "phase2_progress.gnmap": run + "/phase2_progress.gnmap"])
        #expect(try String(contentsOfFile: run + "/targets.txt", encoding: .utf8) == "10.0.0.1\n10.0.0.2\n")
        for path in prepared.outputs.values + [run + "/targets.txt"] {
            var info = stat()
            #expect(lstat(path, &info) == 0)
            #expect(info.st_mode & S_IFMT == S_IFREG)
            #expect(info.st_mode & 0o777 == 0o600)
        }
        var runInfo = stat()
        #expect(lstat(run, &runInfo) == 0 && runInfo.st_mode & 0o777 == 0o700)
    }

    @Test("client-supplied paths and file-reading options are refused", arguments: [
        ["-sn", "-iL", "targets.tmp"],
        ["-sn", "-iL", "/etc/master.passwd"],
        ["-sn", "-oX", "/etc/sudoers.d/x"],
        ["-sn", "-oX", "../phase1_results.xml"],
        ["-sn", "-oX", "-"],
        ["-sn", "-oG", "targets.txt"],
        ["-sn", "--stylesheet", "/tmp/x.xsl"],
        ["-sS", "--script-args", "userdb=/etc/master.passwd"],
        ["-sS", "--script-args", "mincvss=0,threads=10,passdb=/etc/x"],
        ["-sn", "--datadir", "/tmp"],
        ["-sn", "--servicedb", "/tmp/x"],
        ["-sn", "--resume", "/tmp/x"],
    ])
    func clientPathsAreRefused(arguments: [String]) {
        #expect(throws: (any Error).self) { try validateNmapArguments(arguments + ["10.0.0.5"]) }
    }

    @Test("the app's own Vulners tuning is allowed")
    func vulnersTuningAllowed() throws {
        try validateNmapArguments(["-sS", "--script-args", "mincvss=0,threads=10", "10.0.0.5"])
        try validateNmapArguments(["-sS", "--script-args", "mincvss=0,threads=5", "-oX", "phase2_results.xml", "10.0.0.5"])
    }

    @Test("bad targets and duplicate outputs are refused")
    func badTargetsAndDuplicateOutputs() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        for targets in [["-iL"], ["/etc/passwd"], ["10.0.0.1;id"], ["--script=x"]] {
            let run = try makeRunDirectory(root: directory.path + "/runs", enforceRootOwnership: false)
            #expect(throws: (any Error).self) {
                try prepareRun(request(["-sn"], targets: targets), runDirectory: run, dataDirectory: "/data")
            }
        }
        let run = try makeRunDirectory(root: directory.path + "/runs", enforceRootOwnership: false)
        #expect(throws: (any Error).self) {
            try prepareRun(request(["-sn", "-oX", "phase1_results.xml", "-oX", "phase1_results.xml", "10.0.0.1"]), runDirectory: run, dataDirectory: "/data")
        }
    }

    @Test("a planted output symlink is never opened")
    func plantedSymlinkIsNotFollowed() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let victim = directory.appendingPathComponent("victim")
        try Data("original".utf8).write(to: victim)
        let run = directory.appendingPathComponent("run").path
        try FileManager.default.createDirectory(atPath: run, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: run + "/phase1_results.xml", withDestinationPath: victim.path)

        #expect(throws: (any Error).self) {
            try prepareRun(request(["-sn", "-oX", "phase1_results.xml", "10.0.0.1"]), runDirectory: run, dataDirectory: "/data")
        }
        #expect(throws: (any Error).self) { _ = try readArtifact(run + "/phase1_results.xml", limit: 1024) }
        #expect(try Data(contentsOf: victim) == Data("original".utf8))
    }

    @Test("artifact reads are regular-file only and size-capped")
    func artifactReads() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("out.xml").path
        try createExclusiveFile(file, contents: Data("<nmaprun/>".utf8))
        #expect(try readArtifact(file, limit: 1024) == Data("<nmaprun/>".utf8))
        #expect(try readArtifact(directory.appendingPathComponent("missing").path, limit: 1024) == nil)
        #expect(throws: (any Error).self) { _ = try readArtifact(file, limit: 4) }
        #expect(throws: (any Error).self) { _ = try readArtifact(directory.path, limit: 1024) }
        #expect(throws: (any Error).self) { try createExclusiveFile(file) }
    }

    @Test("the run root must be a private directory owned by the helper")
    func runRootMustBePrivate() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let open = directory.appendingPathComponent("open").path
        try FileManager.default.createDirectory(atPath: open, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        #expect(throws: (any Error).self) { _ = try makeRunDirectory(root: open, enforceRootOwnership: false) }

        let link = directory.appendingPathComponent("link").path
        let target = directory.appendingPathComponent("target").path
        try FileManager.default.createDirectory(atPath: target, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        #expect(throws: (any Error).self) { _ = try makeRunDirectory(root: link, enforceRootOwnership: false) }

        // In production the root must also sit on a root-owned path.
        let privateRoot = directory.appendingPathComponent("private").path
        #expect(throws: (any Error).self) { _ = try makeRunDirectory(root: privateRoot, enforceRootOwnership: true) }
    }

    @Test("nmap's environment is rebuilt from nothing")
    func childEnvironmentIsMinimal() {
        let environment = childEnvironment(.production)
        #expect(Set(environment.keys) == ["PATH", "LC_ALL", "LUA_PATH", "LUA_CPATH", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES"])
        #expect(environment["OPENSSL_CONF"] == "/dev/null")
        #expect(environment["OPENSSL_MODULES"] == NmapPrivilegedHelperContract.privilegedOpenSSLModulesDirectory)
        #expect(environment["LUA_PATH"] == NmapPrivilegedHelperContract.privilegedNmapDataDirectory + "/nselib/?.lua")
        #expect(environment["LUA_CPATH"] == "")
    }

    @Test("a scan runs in the helper's directory, with --datadir and a clean environment, and returns its output")
    func executeReturnsArtifacts() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let data = directory.appendingPathComponent("data")
        try PrivilegedTestSupport.makeNmapDataDirectory(at: data)
        let fakeNmap = directory.appendingPathComponent("nmap")
        try """
        #!/bin/sh
        out=""; prev=""
        for a in "$@"; do [ "$prev" = "-oX" ] && out="$a"; prev="$a"; done
        { echo "cwd=$(pwd)"; echo "args=$*"; echo "targets=$(cat "$(dirname "$out")/targets.txt" | tr '\\n' ' ')"; /usr/bin/env; } > "$out"
        echo scanned
        """.write(to: fakeNmap, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fakeNmap.path)
        let runRoot = directory.appendingPathComponent("runs").path
        var environment = HelperRunEnvironment()
        environment.nmapPath = fakeNmap.path
        environment.dataDirectory = data.path
        environment.runRoot = runRoot
        environment.enforceRootOwnership = false

        var startedIn: String?
        let response = try executeNmap(
            request(["-sS", "-oX", "phase2_results.xml"], targets: ["192.0.2.7"]),
            environment: environment,
            onStart: { _, run in startedIn = run }
        )

        #expect(response.ok)
        #expect(response.stdout == "scanned\n")
        let output = String(decoding: try #require(response.artifacts["phase2_results.xml"]), as: UTF8.self)
        let run = try #require(startedIn)
        #expect(output.contains("cwd=\(run)\n"))
        #expect(output.contains("args=--datadir \(data.path) -sS -oX \(run)/phase2_results.xml -iL \(run)/targets.txt\n"))
        #expect(output.contains("targets=192.0.2.7 "))
        #expect(output.contains("OPENSSL_CONF=/dev/null\n"))
        #expect(!output.contains("HOME="))
        #expect(!output.contains("DYLD_"))
        #expect(!output.contains("NMAPDIR="))
        // The run directory is removed afterwards.
        #expect(try FileManager.default.contentsOfDirectory(atPath: runRoot).isEmpty)
    }

    @Test("an incomplete or symlinked data directory is refused")
    func dataDirectoryChecks() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let data = directory.appendingPathComponent("data")
        try PrivilegedTestSupport.makeNmapDataDirectory(at: data)
        try verifyNmapDataDirectory(data.path, requireRootOwnership: false)
        // User-owned data (NSE Lua) is refused for the root helper.
        #expect(throws: (any Error).self) { try verifyNmapDataDirectory(data.path, requireRootOwnership: true) }

        try FileManager.default.createSymbolicLink(atPath: data.path + "/nselib/evil.lua", withDestinationPath: "/tmp/evil.lua")
        #expect(throws: (any Error).self) { try verifyNmapDataDirectory(data.path, requireRootOwnership: false) }
        try FileManager.default.removeItem(atPath: data.path + "/nselib/evil.lua")

        try FileManager.default.removeItem(atPath: data.path + "/nse_main.lua")
        #expect(throws: (any Error).self) { try verifyNmapDataDirectory(data.path, requireRootOwnership: false) }
    }

    @Test("a user-owned nmap is refused before anything runs")
    func userOwnedNmapIsRefused() throws {
        let directory = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var environment = HelperRunEnvironment()
        environment.nmapPath = directory.appendingPathComponent("nmap").path
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: environment.nmapPath)
        environment.dataDirectory = directory.appendingPathComponent("data").path
        try PrivilegedTestSupport.makeNmapDataDirectory(at: URL(fileURLWithPath: environment.dataDirectory))
        #expect(throws: (any Error).self) { try verifyPrivilegedInstallation(environment) }
    }

    @Test("the one-shot mode takes only an encoded request")
    func oneShotParsing() throws {
        let original = request(["-sn", "-oX", "phase1_results.xml", "10.0.0.1"])
        let encoded = try JSONEncoder().encode(original).base64EncodedString()
        #expect(try parseRunCLIArguments(["--request-base64", encoded]) == original)
        #expect(throws: (any Error).self) { try parseRunCLIArguments(["--work-dir", "/tmp", "--", "/tmp/nmap", "-sn"]) }
        #expect(throws: (any Error).self) { try parseRunCLIArguments(["--request-base64", "not base64"]) }
    }
}
