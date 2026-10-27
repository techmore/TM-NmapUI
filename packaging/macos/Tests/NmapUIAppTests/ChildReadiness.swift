import Darwin
import Foundation

enum ChildReadinessError: Error { case timeout, ended, oversized }

/// Reads a child's readiness line: everything up to and including the first
/// newline. A pipe read returns whatever bytes are present, so one `poll` plus
/// `availableData` can observe a line half-written (Python `-u` writes
/// `print`'s text and its newline separately). Runs off the MainActor.
func childReadinessLine(_ handle: FileHandle, timeout: TimeInterval) async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
            do { continuation.resume(returning: try readReadinessLine(handle, timeout: timeout)) }
            catch { continuation.resume(throwing: error) }
        }
    }
}

private func readReadinessLine(_ handle: FileHandle, timeout: TimeInterval) throws -> Data {
    let descriptor = handle.fileDescriptor
    let deadline = ProcessInfo.processInfo.systemUptime + timeout
    var data = Data()
    var chunk = [UInt8](repeating: 0, count: 512)
    while true {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw ChildReadinessError.timeout }
        var state = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        let result = poll(&state, 1, Int32(max(1, remaining * 1000)))
        if result < 0 && errno == EINTR { continue }
        guard result >= 0 else { throw ChildReadinessError.ended }
        if result == 0 { continue }
        let count = read(descriptor, &chunk, chunk.count)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw ChildReadinessError.ended }
        data.append(contentsOf: chunk.prefix(count))
        guard data.count <= 65_536 else { throw ChildReadinessError.oversized }
        if let newline = data.firstIndex(of: 10) { return data.prefix(through: newline) }
    }
}
