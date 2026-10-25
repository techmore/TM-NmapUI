import Combine
import Foundation

/// Deferred Legacy work rechecks the same source gate when it actually starts.
/// Cancellation preserves the running count until the operation has unwound.
@MainActor
final class LegacyTaskQueue: ObservableObject {
    @Published private(set) var runningCount = 0
    private var tasks: [UUID: Task<Void, Never>] = [:]
    private let allowsLegacy: () -> Bool
    init(allowsLegacy: @escaping () -> Bool) { self.allowsLegacy = allowsLegacy }

    func enqueue(_ operation: @escaping @MainActor () async -> Void) {
        let id = UUID()
        tasks[id] = Task { [weak self] in
            guard let self else { return }
            defer { tasks.removeValue(forKey: id) }
            guard !Task.isCancelled, allowsLegacy() else { return }
            runningCount += 1
            defer { runningCount -= 1 }
            await operation()
        }
    }
    func cancelAll() { for task in tasks.values { task.cancel() } }
}
