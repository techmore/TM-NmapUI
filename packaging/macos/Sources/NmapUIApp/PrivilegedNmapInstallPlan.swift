import Darwin
import Foundation
import RuntimeContracts

/// Plans a self-contained, root-owned copy of the user's nmap for the root helper.
///
/// Homebrew's nmap links libraries in user-owned directories, and its data
/// directory (NSE Lua) and OpenSSL's provider modules are user-owned too, so
/// running it as root would run code the user's other processes can change.
/// The installer copies nmap, every non-system library it loads, OpenSSL's
/// `legacy` provider (nmap loads it) and nmap's data directory into root-owned
/// locations, and rewrites install names to absolute paths in the library
/// directory. The root helper refuses to run anything else.
struct PrivilegedNmapInstallPlan: Equatable {
    struct Copy: Equatable {
        let source: String
        let destination: String
    }

    struct Destinations: Equatable {
        var nmap = NmapPrivilegedHelperContract.privilegedNmapPath
        var libraryDirectory = NmapPrivilegedHelperContract.privilegedNmapLibraryDirectory
        var openSSLModulesDirectory = NmapPrivilegedHelperContract.privilegedOpenSSLModulesDirectory
        var openSSLEnginesDirectory = NmapPrivilegedHelperContract.privilegedOpenSSLEnginesDirectory
        var dataDirectory = NmapPrivilegedHelperContract.privilegedNmapDataDirectory
    }

    enum PlanError: LocalizedError, Equatable {
        case unresolvable(String)
        case linkage(String)
        case missingData(String)
        case missingTool(String)

        var errorDescription: String? {
            switch self {
            case .unresolvable(let message), .linkage(let message), .missingData(let message), .missingTool(let message):
                return message
            }
        }
    }

    let destinations: Destinations
    let nmap: Copy
    let libraries: [Copy]
    let dataDirectory: Copy
    /// Destination Mach-O file → install-name changes (old → new).
    let changes: [String: [String: String]]
    /// Destination library → its new install name.
    let identifiers: [String: String]
    /// Destination Mach-O file → LC_RPATH entries to delete.
    let deletedRpaths: [String: [String]]
    let installNameTool: String?

    static func make(
        nmapPath: String,
        destinations: Destinations = Destinations(),
        installNameTool: String? = defaultInstallNameTool(),
        requireRootOwnedTools: Bool = true
    ) throws -> PrivilegedNmapInstallPlan {
        guard let nmapReal = MachOLinkage.realPath(nmapPath) else {
            throw PlanError.unresolvable("Cannot resolve nmap at \(nmapPath).")
        }
        let closure = MachOLinkage.closure(ofExecutable: nmapReal)
        guard closure.problems.isEmpty else {
            throw PlanError.linkage("Cannot copy nmap's libraries: \(closure.problems.joined(separator: "; "))")
        }

        // Real path of each copied image → its destination.
        var destinationFor: [String: String] = [nmapReal: destinations.nmap]
        var libraries: [Copy] = []
        var usedNames: Set<String> = []
        func addLibrary(_ real: String, into directory: String) throws {
            guard destinationFor[real] == nil else { return }
            let name = (real as NSString).lastPathComponent
            let destination = directory + "/" + name
            guard usedNames.insert(destination).inserted else {
                throw PlanError.linkage("Two of nmap's libraries are both named \(name).")
            }
            destinationFor[real] = destination
            libraries.append(Copy(source: real, destination: destination))
        }
        for image in closure.images.dropFirst() {
            try addLibrary(image, into: destinations.libraryDirectory)
        }

        var closures = [closure]
        // nmap asks OpenSSL 3 for its "legacy" provider, which OpenSSL loads
        // from its compiled-in (Homebrew, user-owned) modules directory unless
        // OPENSSL_MODULES points elsewhere. Copy it next to libcrypto's copy.
        for image in closure.images.dropFirst() where (image as NSString).lastPathComponent.hasPrefix("libcrypto.") {
            let legacy = (image as NSString).deletingLastPathComponent + "/ossl-modules/legacy.dylib"
            guard let legacyReal = MachOLinkage.realPath(legacy) else { continue }
            let moduleClosure = MachOLinkage.closure(ofExecutable: legacyReal)
            guard moduleClosure.problems.isEmpty else {
                throw PlanError.linkage("Cannot copy OpenSSL's legacy provider: \(moduleClosure.problems.joined(separator: "; "))")
            }
            try addLibrary(legacyReal, into: destinations.openSSLModulesDirectory)
            for dependency in moduleClosure.images.dropFirst() {
                try addLibrary(dependency, into: destinations.libraryDirectory)
            }
            closures.append(moduleClosure)
        }

        var changes: [String: [String: String]] = [:]
        var deletedRpaths: [String: [String]] = [:]
        for closure in closures {
            for reference in closure.references where !reference.isSystem {
                guard let path = reference.path,
                      let real = MachOLinkage.realPath(path),
                      let target = destinationFor[real],
                      let file = destinationFor[reference.referencedFrom] else { continue }
                if reference.installName != target {
                    changes[file, default: [:]][reference.installName] = target
                }
            }
            for (image, rpaths) in closure.declaredRpaths {
                if let file = destinationFor[image] { deletedRpaths[file] = rpaths }
            }
        }
        var identifiers: [String: String] = [:]
        for library in libraries where !library.destination.hasPrefix(destinations.openSSLModulesDirectory + "/") {
            identifiers[library.destination] = library.destination
        }

        let dataSource = (((nmapReal as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent as NSString)
            .appendingPathComponent("share/nmap")
        guard FileManager.default.fileExists(atPath: dataSource + "/nse_main.lua"),
              FileManager.default.fileExists(atPath: dataSource + "/nmap-services") else {
            throw PlanError.missingData("nmap's data directory was not found at \(dataSource).")
        }

        let needsRewrite = !libraries.isEmpty || !deletedRpaths.isEmpty
        if needsRewrite {
            guard let installNameTool else {
                throw PlanError.missingTool("Copying nmap's libraries needs install_name_tool from the Xcode Command Line Tools.")
            }
            if requireRootOwnedTools, !NmapPrivilegedHelperContract.isRootControlledPath(installNameTool) {
                throw PlanError.missingTool("install_name_tool at \(installNameTool) is not root-owned, so it cannot be run as root. Install the Command Line Tools with Apple's installer (xcode-select --install).")
            }
        }

        return PrivilegedNmapInstallPlan(
            destinations: destinations,
            nmap: Copy(source: nmapReal, destination: destinations.nmap),
            libraries: libraries,
            dataDirectory: Copy(source: dataSource, destination: destinations.dataDirectory),
            changes: changes,
            identifiers: identifiers,
            deletedRpaths: deletedRpaths,
            installNameTool: needsRewrite ? installNameTool : nil
        )
    }

    static func defaultInstallNameTool() -> String? {
        if let result = try? ExternalProcessRunner.run(
            executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["--find", "install_name_tool"],
            timeout: 20
        ), result.exitCode == 0 {
            let path = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if path.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        return nil
    }

    /// Shell lines for the root install script. `setOwnership: false` lets
    /// tests run the same steps as an ordinary user in a temporary directory.
    func shellCommands(setOwnership: Bool = true) -> [String] {
        let q = Self.shellQuoted
        let d = destinations
        var lines = [
            "rm -rf \(q(d.libraryDirectory)) \(q(d.dataDirectory))",
            "rm -f \(q(d.nmap))",
            "mkdir -p \(q(d.libraryDirectory)) \(q(d.openSSLModulesDirectory)) \(q(d.openSSLEnginesDirectory))",
            "cp -L \(q(nmap.source)) \(q(nmap.destination))",
        ]
        for library in libraries {
            lines.append("cp -L \(q(library.source)) \(q(library.destination))")
        }
        let machOFiles = [nmap.destination] + libraries.map(\.destination)
        if let installNameTool {
            for file in machOFiles {
                var arguments: [String] = []
                if let identifier = identifiers[file] { arguments += ["-id", identifier] }
                for (old, new) in (changes[file] ?? [:]).sorted(by: { $0.key < $1.key }) {
                    arguments += ["-change", old, new]
                }
                for rpath in deletedRpaths[file] ?? [] { arguments += ["-delete_rpath", rpath] }
                if !arguments.isEmpty {
                    lines.append(([installNameTool] + arguments + [file]).map(q).joined(separator: " "))
                }
            }
        }
        for file in machOFiles {
            // Rewriting load commands invalidates the signature; arm64 requires one.
            lines.append("/usr/bin/codesign --force --sign - \(q(file))")
        }
        lines.append("cp -RL \(q(dataDirectory.source)) \(q(dataDirectory.destination))")
        if setOwnership {
            lines.append("chown -R root:wheel \(q(d.libraryDirectory)) \(q(d.nmap)) \(q(d.dataDirectory))")
        }
        lines += [
            "find \(q(d.libraryDirectory)) \(q(d.dataDirectory)) -type d -exec chmod 755 {} +",
            "find \(q(d.libraryDirectory)) \(q(d.dataDirectory)) -type f -exec chmod 644 {} +",
            "chmod 755 \(q(d.nmap))",
        ]
        return lines
    }

    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
