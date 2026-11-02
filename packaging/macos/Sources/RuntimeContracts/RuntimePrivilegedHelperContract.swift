import Darwin
import Foundation

public enum NmapPrivilegedHelperContract {
    // Bump whenever the wire format or helper validation changes.
    public static let protocolVersion = 6
    public static let machServiceName = "com.techmore.nmapui.nmap-helper"
    public static let authorizedBundleIdentifier = "com.techmore.nmapui"
    public static let helperInstallPath = "/Library/PrivilegedHelperTools/com.techmore.nmapui.nmap-helper"
    /// Root-owned nmap that the helper runs. The helper never takes a path from the client.
    public static let privilegedNmapPath = "/Library/PrivilegedHelperTools/com.techmore.nmapui.nmap"
    /// Root-owned copies of the non-system libraries the installed nmap links.
    public static let privilegedNmapLibraryDirectory = "/Library/PrivilegedHelperTools/com.techmore.nmapui.nmap-libs"
    /// OpenSSL provider modules (nmap loads "legacy") and an always-empty engines directory.
    public static let privilegedOpenSSLModulesDirectory = privilegedNmapLibraryDirectory + "/ossl-modules"
    public static let privilegedOpenSSLEnginesDirectory = privilegedNmapLibraryDirectory + "/engines"
    public static let supportDirectory = "/Library/Application Support/NmapUI"
    /// Root-owned copy of nmap's data directory, passed as --datadir.
    public static let privilegedNmapDataDirectory = supportDirectory + "/nmap-data"
    /// The only NSE script the root helper will pass to nmap.
    public static let privilegedVulnersScriptPath = supportDirectory + "/nmap-vulners/vulners.nse"
    /// Root-only (0700) parent of the helper's per-scan output directories.
    public static let helperRunRoot = supportDirectory + "/helper-runs"
    public static let helperStampPath = supportDirectory + "/helper-stamp.json"
    public static let maximumScanRuntime: TimeInterval = 2 * 60 * 60
    public static let responseGracePeriod: TimeInterval = 30

    /// Output names a client may request with -oX / -oG. The helper maps them
    /// into its own directory and returns their contents.
    public static let artifactNames: Set<String> = ["phase1_results.xml", "phase2_results.xml", "phase2_progress.gnmap"]
    public static let progressArtifactName = "phase2_progress.gnmap"
    /// --stylesheet only writes this href into the XML; nmap never opens it.
    public static let stylesheetName = "nmap-modern.xsl"
    public static let maximumArtifactBytes = 64 * 1024 * 1024
    public static let maximumTargetCount = 65_536

    /// The client requirement when the helper is signed by `teamID`, or nil
    /// when there is no usable team (ad-hoc builds), in which case the helper
    /// accepts no XPC clients.
    public static func clientCodeSigningRequirement(teamID: String?) -> String? {
        guard let teamID, isValidTeamIdentifier(teamID) else { return nil }
        return "anchor apple generic and identifier \"\(authorizedBundleIdentifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// Apple team identifiers are ten upper-case letters or digits.
    public static func isValidTeamIdentifier(_ value: String) -> Bool {
        value.range(of: #"^[A-Z0-9]{10}$"#, options: .regularExpression) != nil
    }

    public static func isAllowedScriptArguments(_ value: String) -> Bool {
        value.range(of: #"^mincvss=[0-9]{1,2}(\.[0-9])?,threads=[0-9]{1,2}$"#, options: .regularExpression) != nil
    }

    public static func isAllowedScanTarget(_ target: String) -> Bool {
        guard !target.isEmpty,
              !target.hasPrefix("-"),
              !target.contains(where: { ";&|><`$\\\"'".contains($0) }) else { return false }

        let parts = target.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count <= 2 else { return false }
        if parts.count == 2 {
            guard let prefix = Int(parts[1]), prefix >= 0 else { return false }
            if isIPv4(parts[0]) { return prefix <= 32 }
            if isIPv6(parts[0]) { return prefix <= 128 }
            return false
        }
        return isIPv4(target) || isIPv6(target) || target.range(
            of: #"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"#,
            options: .regularExpression
        ) != nil
    }

    /// True when `path` is absolute and it and every parent directory are
    /// root-owned, not symlinks, and not writable by group or others. Such a
    /// path cannot be swapped by an unprivileged caller between check and use.
    public static func isRootOwnedImmutablePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains("//") else { return false }
        var current = path
        while true {
            var info = stat()
            guard lstat(current, &info) == 0,
                  (info.st_mode & S_IFMT) != S_IFLNK,
                  info.st_uid == 0,
                  info.st_mode & 0o022 == 0 else { return false }
            if current == "/" { return true }
            let parent = (current as NSString).deletingLastPathComponent
            current = parent.isEmpty ? "/" : parent
        }
    }

    /// Like `isRootOwnedImmutablePath`, but allows root-owned symlinks inside
    /// root-controlled directories (as in `/usr/lib` or `/var`), provided the
    /// resolved target is itself root-owned and read-only.
    public static func isRootControlledPath(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains("//") else { return false }
        var current = path
        while true {
            var info = stat()
            guard lstat(current, &info) == 0, info.st_uid == 0 else { return false }
            if (info.st_mode & S_IFMT) != S_IFLNK, info.st_mode & 0o022 != 0 { return false }
            if current == "/" { break }
            let parent = (current as NSString).deletingLastPathComponent
            current = parent.isEmpty ? "/" : parent
        }
        guard let real = MachOLinkage.realPath(path) else { return false }
        return isRootOwnedImmutablePath(real)
    }

    /// The app reinstalls the helper unless the root daemon's own stamp
    /// reports this protocol and the bundled helper's exact SHA-256.
    public static func helperStampMatches(_ stamp: Data, bundledSHA256: String) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: stamp) as? [String: Any],
              (object["protocolVersion"] as? Int) == protocolVersion,
              let recorded = object["binarySHA256"] as? String,
              recorded.count == 64 else { return false }
        return recorded.lowercased() == bundledSHA256.lowercased()
    }

    private static func isIPv4(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isIPv6(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }
}

// MARK: - Wire format (JSON inside XPC Data)

/// A privileged scan. The client never names files: `-oX`/`-oG` take names
/// from `artifactNames`, and hosts to scan go in `targets` (not `-iL`).
public struct NmapPrivilegedRunRequest: Codable, Equatable, Sendable {
    public let arguments: [String]
    public let targets: [String]
    public let scanID: String?

    public init(arguments: [String], targets: [String], scanID: String?) {
        self.arguments = arguments
        self.targets = targets
        self.scanID = scanID
    }
}

/// Identifies a running scan for `cancel` and `progress`.
public struct NmapPrivilegedScanReference: Codable, Equatable, Sendable {
    public let scanID: String?

    public init(scanID: String?) {
        self.scanID = scanID
    }
}

public struct NmapPrivilegedRunResponse: Codable, Equatable, Sendable {
    public let ok: Bool
    public let exitCode: Int
    public let stdout: String
    public let stderr: String
    public let error: String?
    /// Output files the scan produced, keyed by requested artifact name.
    public let artifacts: [String: Data]

    public init(ok: Bool, exitCode: Int, stdout: String, stderr: String, error: String?, artifacts: [String: Data] = [:]) {
        self.ok = ok
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.artifacts = artifacts
    }

    public static func failure(_ message: String) -> NmapPrivilegedRunResponse {
        NmapPrivilegedRunResponse(ok: false, exitCode: 1, stdout: "", stderr: message, error: message)
    }
}

@objc public protocol NmapPrivilegedServiceProtocol: NSObjectProtocol {
    func ping(withReply reply: @escaping (Data) -> Void)
    /// `request` is a JSON `NmapPrivilegedRunRequest`; the reply is a JSON `NmapPrivilegedRunResponse`.
    func run(request: Data, withReply reply: @escaping (Data) -> Void)
    /// `request` is a JSON `NmapPrivilegedScanReference`.
    func cancel(request: Data, withReply reply: @escaping (Data) -> Void)
    /// `request` is a JSON `NmapPrivilegedScanReference`; the reply is the
    /// scan's grepable progress output so far (possibly empty).
    func progress(request: Data, withReply reply: @escaping (Data) -> Void)
}
