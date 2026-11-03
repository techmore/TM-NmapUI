import Darwin
import Foundation

public enum NmapPrivilegedHelperContract {
    // Bump whenever helper validation changes, so installed helpers are replaced.
    public static let protocolVersion = 5
    public static let machServiceName = "com.techmore.nmapui.nmap-helper"
    public static let authorizedBundleIdentifier = "com.techmore.nmapui"
    public static let privilegedNmapPath = "/Library/PrivilegedHelperTools/com.techmore.nmapui.nmap"
    /// The only NSE script the root helper will pass to nmap.
    public static let privilegedVulnersScriptPath = "/Library/Application Support/NmapUI/nmap-vulners/vulners.nse"
    public static let maximumScanRuntime: TimeInterval = 2 * 60 * 60
    public static let responseGracePeriod: TimeInterval = 30

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

    private static func isIPv4(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isIPv6(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }
}

@objc public protocol NmapPrivilegedServiceProtocol: NSObjectProtocol {
    func ping(withReply reply: @escaping (Data) -> Void)
    func run(request: Data, withReply reply: @escaping (Data) -> Void)
    func cancel(request: Data, withReply reply: @escaping (Data) -> Void)
}
