import Darwin
import Foundation

/// Cross-process single-flight lock shared by the UI and LaunchAgent scans.
/// The kernel releases the lock if a process terminates unexpectedly.
final class ScanRunLock: @unchecked Sendable {
    private let descriptor: Int32
    let runID: UUID

    private init(descriptor: Int32, runID: UUID) {
        self.descriptor = descriptor
        self.runID = runID
    }

    static func acquire(in dataDirectory: URL, runID: UUID = UUID(), recordMarker: Bool = true) -> ScanRunLock? {
        do {
            try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
        } catch {
            RuntimeDiagnosticsLogger.error("Could not create scan lock directory: \(error.localizedDescription)")
            return nil
        }

        let lockURL = dataDirectory.appendingPathComponent("active-scan.lock")
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { return nil }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            close(descriptor)
            return nil
        }

        if recordMarker {
            let marker = "\(runID.uuidString)\n".data(using: .utf8) ?? Data()
            ftruncate(descriptor, 0)
            _ = marker.withUnsafeBytes { write(descriptor, $0.baseAddress, marker.count) }
        }
        return ScanRunLock(descriptor: descriptor, runID: runID)
    }

    deinit {
        flock(descriptor, LOCK_UN)
        close(descriptor)
    }
}
