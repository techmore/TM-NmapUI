import Darwin
import Foundation
import RuntimeContracts
import Testing
@testable import NmapPrivilegedHelper
@testable import NmapUIApp

/// Installs the machine's Homebrew nmap with the real install plan into a
/// temporary directory (as the current user, without chown), then scans a
/// local listening socket through the helper's real execution path: its own
/// run directory, --datadir, and the rebuilt environment (OpenSSL config and
/// modules, Lua paths). Root-ownership checks are off because the copy is
/// user-owned; everything else is what the root helper does.
@Suite(
    "Self-contained nmap scans through the helper path",
    .enabled(if: PrivilegedTestSupport.homebrewNmap() != nil && PrivilegedNmapInstallPlan.defaultInstallNameTool() != nil)
)
struct PrivilegedNmapIntegrationTests {
    @Test("a scan with default scripts runs entirely from the installed copy")
    func scanRunsFromInstalledCopy() async throws {
        let nmap = try #require(PrivilegedTestSupport.homebrewNmap())
        let root = try PrivilegedTestSupport.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        var destinations = PrivilegedNmapInstallPlan.Destinations()
        destinations.nmap = root.appendingPathComponent("bin/nmap").path
        destinations.libraryDirectory = root.appendingPathComponent("libs").path
        destinations.openSSLModulesDirectory = root.appendingPathComponent("libs/ossl-modules").path
        destinations.openSSLEnginesDirectory = root.appendingPathComponent("libs/engines").path
        destinations.dataDirectory = root.appendingPathComponent("nmap-data").path
        try FileManager.default.createDirectory(at: root.appendingPathComponent("bin"), withIntermediateDirectories: true)

        let plan = try await PrivilegedTestSupport.offPool { [destinations] in
            try PrivilegedNmapInstallPlan.make(nmapPath: nmap, destinations: destinations, requireRootOwnedTools: false)
        }
        if let crypto = plan.libraries.first(where: { ($0.source as NSString).lastPathComponent.hasPrefix("libcrypto.") }),
           FileManager.default.fileExists(atPath: (crypto.source as NSString).deletingLastPathComponent + "/ossl-modules/legacy.dylib") {
            #expect(plan.libraries.contains { $0.destination == destinations.openSSLModulesDirectory + "/legacy.dylib" })
        }
        let install = try await PrivilegedTestSupport.shell((["set -eu"] + plan.shellCommands(setOwnership: false)).joined(separator: "\n"))
        #expect(install.status == 0, "install commands failed: \(install.stderr)")
        let inside: (String) -> Bool = { $0.hasPrefix(root.path) }
        #expect(MachOLinkage.untrustedLinkage(ofExecutable: destinations.nmap, isTrusted: inside) == [])
        for module in (try? FileManager.default.contentsOfDirectory(atPath: destinations.openSSLModulesDirectory)) ?? [] {
            #expect(MachOLinkage.untrustedLinkage(ofExecutable: destinations.openSSLModulesDirectory + "/" + module, isTrusted: inside) == [])
        }

        let (listener, port) = try listenOnLoopback()
        defer { close(listener) }

        var environment = HelperRunEnvironment()
        environment.nmapPath = destinations.nmap
        environment.dataDirectory = destinations.dataDirectory
        environment.openSSLModulesDirectory = destinations.openSSLModulesDirectory
        environment.openSSLEnginesDirectory = destinations.openSSLEnginesDirectory
        environment.runRoot = root.appendingPathComponent("runs").path
        environment.enforceRootOwnership = false
        environment.maximumRuntime = 120

        // Unprivileged nmap falls back to a connect scan; -sC loads NSE (and
        // with it OpenSSL's legacy provider) from the installed copy.
        let scan = NmapPrivilegedRunRequest(
                arguments: ["-Pn", "-sC", "-T4", "-p", String(port), "--open", "--stylesheet", "nmap-modern.xsl",
                            "-oX", "phase2_results.xml", "-oG", "phase2_progress.gnmap"],
                targets: ["127.0.0.1"],
                scanID: UUID().uuidString
            )
        let response = try await PrivilegedTestSupport.offPool { [environment] in
            try executeNmap(scan, environment: environment)
        }

        #expect(response.exitCode == 0, "nmap failed: \(response.stderr)")
        #expect(!response.stderr.contains("legacy provider failed to load"))
        #expect(!response.stderr.localizedCaseInsensitiveContains("unable to find"))
        let xml = String(decoding: try #require(response.artifacts["phase2_results.xml"]), as: UTF8.self)
        // nmap writes "--" as "-&#45;" in XML.
        #expect(xml.contains("-&#45;datadir \(destinations.dataDirectory) "))
        #expect(xml.contains("portid=\"\(port)\""))
        #expect(xml.contains("state=\"open\""))
        #expect(xml.contains("href=\"nmap-modern.xsl\""))
        let gnmap = String(decoding: try #require(response.artifacts["phase2_progress.gnmap"]), as: UTF8.self)
        #expect(gnmap.contains("\(port)/open/tcp"))
    }

    private func listenOnLoopback() throws -> (Int32, UInt16) {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw POSIXError(.EIO) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = 0
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { pointer -> Bool in
                bind(descriptor, pointer, length) == 0 && listen(descriptor, 16) == 0 && getsockname(descriptor, pointer, &length) == 0
            }
        }
        guard bound else {
            close(descriptor)
            throw POSIXError(.EADDRINUSE)
        }
        return (descriptor, UInt16(bigEndian: address.sin_port))
    }
}
