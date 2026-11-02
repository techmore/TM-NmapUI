import Darwin
import Foundation
import RuntimeContracts
import Testing
@testable import NmapUIApp

/// Builds a tiny program that links a user-owned library, the shape of
/// Homebrew's nmap, and checks that it is refused and that the installer
/// plan turns it into a self-contained copy.
@Suite("Root nmap library checks and self-contained install", .enabled(if: PrivilegedTestSupport.hasCompiler))
struct MachOLinkageTests {
    private struct Fixture {
        let root: URL
        let tool: URL
        let crypto: URL
        let legacy: URL
    }

    /// root/opt/lib/libcrypto.3.dylib, root/opt/lib/ossl-modules/legacy.dylib
    /// (links libcrypto), root/opt/bin/tool (links libcrypto by absolute path
    /// and libextra by @rpath), and root/opt/share/nmap.
    private func makeFixture() throws -> Fixture {
        let root = try PrivilegedTestSupport.makeTemporaryDirectory()
        let lib = root.appendingPathComponent("opt/lib")
        let modules = lib.appendingPathComponent("ossl-modules")
        let bin = root.appendingPathComponent("opt/bin")
        for directory in [modules, bin] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        let crypto = lib.appendingPathComponent("libcrypto.3.dylib")
        try PrivilegedTestSupport.compile("int crypto_value(void) { return 7; }", to: crypto, arguments: ["-dynamiclib", "-Wl,-headerpad_max_install_names", "-install_name", crypto.path])
        let extra = lib.appendingPathComponent("libextra.dylib")
        try PrivilegedTestSupport.compile("int extra_value(void) { return 5; }", to: extra, arguments: ["-dynamiclib", "-Wl,-headerpad_max_install_names", "-install_name", "@rpath/libextra.dylib"])
        let legacy = modules.appendingPathComponent("legacy.dylib")
        try PrivilegedTestSupport.compile("int crypto_value(void); int legacy_value(void) { return crypto_value(); }", to: legacy, arguments: ["-dynamiclib", "-Wl,-headerpad_max_install_names", "-L", lib.path, "-lcrypto.3"])
        let tool = bin.appendingPathComponent("tool")
        try PrivilegedTestSupport.compile(
            "#include <stdio.h>\nint crypto_value(void); int extra_value(void);\nint main(void) { printf(\"%d\\n\", crypto_value() + extra_value()); return 0; }",
            to: tool,
            arguments: ["-L", lib.path, "-lcrypto.3", "-lextra", "-Wl,-rpath,@loader_path/../lib", "-Wl,-headerpad_max_install_names"]
        )
        try PrivilegedTestSupport.makeNmapDataDirectory(at: root.appendingPathComponent("opt/share/nmap"))
        return Fixture(root: root, tool: tool, crypto: crypto, legacy: legacy)
    }

    @Test("load commands, rpaths and universal slices are parsed")
    func parsesLoadCommands() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let images = try MachOLinkage.parse(contentsOf: fixture.tool)
        let names = images.flatMap(\.libraries).map(\.installName)
        #expect(names.contains(fixture.crypto.path))
        #expect(names.contains("@rpath/libextra.dylib"))
        #expect(names.contains("/usr/lib/libSystem.B.dylib"))
        #expect(images.flatMap(\.rpaths) == ["@loader_path/../lib"])

        #expect(try MachOLinkage.parse(contentsOf: URL(fileURLWithPath: "/usr/bin/true")).count >= 1)
        #expect(throws: MachOLinkage.ParseError.self) { try MachOLinkage.parse(Data("#!/bin/sh\n".utf8)) }
        #expect(throws: (any Error).self) { try MachOLinkage.parse(Data([0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0])) }
    }

    @Test("@rpath and @loader_path resolve like dyld")
    func resolvesClosure() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let closure = MachOLinkage.closure(ofExecutable: fixture.tool.path)
        #expect(closure.problems.isEmpty)
        #expect(Set(closure.images) == [fixture.tool.path, fixture.crypto.path, fixture.crypto.deletingLastPathComponent().appendingPathComponent("libextra.dylib").path])
        #expect(closure.declaredRpaths[fixture.tool.path] == ["@loader_path/../lib"])
    }

    @Test("a program that links user-owned libraries is refused; system binaries are not")
    func userOwnedLibrariesAreRefused() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let problems = MachOLinkage.untrustedLinkage(ofExecutable: fixture.tool.path)
        #expect(problems.contains { $0.contains("libcrypto.3.dylib") })
        #expect(problems.contains { $0.contains("LC_RPATH") })
        #expect(MachOLinkage.untrustedLinkage(ofExecutable: "/usr/bin/true").isEmpty)
    }

    @Test("an unresolvable @rpath library is a problem, not a silent pass")
    func unresolvedRpathIsReported() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try FileManager.default.removeItem(at: fixture.crypto.deletingLastPathComponent().appendingPathComponent("libextra.dylib"))
        let closure = MachOLinkage.closure(ofExecutable: fixture.tool.path)
        #expect(closure.problems.contains { $0.contains("@rpath/libextra.dylib") })
    }

    @Test("Homebrew's nmap is refused as a root binary", .enabled(if: PrivilegedTestSupport.homebrewNmap() != nil))
    func homebrewNmapIsRefused() throws {
        let nmap = try #require(PrivilegedTestSupport.homebrewNmap())
        #expect(!MachOLinkage.untrustedLinkage(ofExecutable: nmap).isEmpty)
    }

    @Test("the install plan produces a self-contained copy with absolute library paths")
    func installPlanIsSelfContained() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let destination = fixture.root.appendingPathComponent("installed")
        var destinations = PrivilegedNmapInstallPlan.Destinations()
        destinations.nmap = destination.appendingPathComponent("nmap").path
        destinations.libraryDirectory = destination.appendingPathComponent("libs").path
        destinations.openSSLModulesDirectory = destination.appendingPathComponent("libs/ossl-modules").path
        destinations.openSSLEnginesDirectory = destination.appendingPathComponent("libs/engines").path
        destinations.dataDirectory = destination.appendingPathComponent("nmap-data").path
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)

        let plan = try PrivilegedNmapInstallPlan.make(nmapPath: fixture.tool.path, destinations: destinations, requireRootOwnedTools: false)
        #expect(plan.libraries.map(\.destination).sorted() == [
            destinations.libraryDirectory + "/libcrypto.3.dylib",
            destinations.libraryDirectory + "/libextra.dylib",
            destinations.openSSLModulesDirectory + "/legacy.dylib",
        ])
        let commands = plan.shellCommands(setOwnership: false)
        #expect(!commands.contains { $0.hasPrefix("chown") })
        #expect(plan.shellCommands().contains { $0.hasPrefix("chown -R root:wheel") })

        let result = try PrivilegedTestSupport.shell((["set -eu"] + commands).joined(separator: "\n"))
        #expect(result.status == 0, "install commands failed: \(result.stderr)")

        let inside: (String) -> Bool = { $0.hasPrefix(destination.path) }
        #expect(MachOLinkage.untrustedLinkage(ofExecutable: destinations.nmap, isTrusted: inside).isEmpty)
        #expect(MachOLinkage.untrustedLinkage(ofExecutable: destinations.openSSLModulesDirectory + "/legacy.dylib", isTrusted: inside).isEmpty)
        let installed = try MachOLinkage.parse(contentsOf: URL(fileURLWithPath: destinations.nmap))
        #expect(installed.allSatisfy { $0.rpaths.isEmpty })
        #expect(installed.flatMap(\.libraries).allSatisfy { $0.installName.hasPrefix("/usr/lib/") || $0.installName.hasPrefix(destinations.libraryDirectory + "/") })

        // The copy runs without the original libraries.
        try FileManager.default.removeItem(at: fixture.crypto.deletingLastPathComponent())
        let output = try PrivilegedTestSupport.run(destinations.nmap, [])
        #expect(output.status == 0)
        #expect(output.stdout == "12\n")
        #expect(FileManager.default.fileExists(atPath: destinations.dataDirectory + "/nse_main.lua"))
    }
}
