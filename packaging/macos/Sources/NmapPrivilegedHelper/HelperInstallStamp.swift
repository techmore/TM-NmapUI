import CryptoKit
import Foundation
import RuntimeContracts

/// Keep stamp generation testable without starting or installing the root daemon.
/// The daemon supplies its fixed binary/stamp paths; no request or CLI accepts them.
func writeHelperInstallStamp(binaryURL: URL, stampURL: URL, installedAt: Date = Date()) throws {
    let binary = try Data(contentsOf: binaryURL)
    // SHA256.Digest is a byte sequence, not an Array that can be conditionally cast.
    let hash = SHA256.hash(data: binary).map { String(format: "%02x", $0) }.joined()
    let stamp: [String: Any] = [
        "protocolVersion": NmapPrivilegedHelperContract.protocolVersion,
        "binarySHA256": hash,
        "installedAt": ISO8601DateFormatter().string(from: installedAt),
    ]
    let data = try JSONSerialization.data(withJSONObject: stamp, options: [.prettyPrinted])
    let fm = FileManager.default
    try fm.createDirectory(at: stampURL.deletingLastPathComponent(), withIntermediateDirectories: true)
    try data.write(to: stampURL, options: .atomic)
    try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: stampURL.path)
}
