import Foundation
import RuntimeContracts
import Testing
@testable import NmapUIApp

@Suite("Auto-scan request effects", .serialized)
@MainActor
struct RuntimeAutoScanEffectTests {
    @Test("authorization and scheduler failures disable auto-scan", arguments: [true, false])
    func failurePreventsEnabledSchedule(authorizationFails: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = AppSessionState(eventRouter: RuntimeEventRecorder())
        let error = NSError(domain: "test-auto-scan", code: 1)
        var authorized = 0
        var scheduled = 0
        var presented = 0
        let services = RuntimeAutoScanServices(
            ensureHelperReady: {
                authorized += 1
                if authorizationFails { throw error }
            },
            sync: { _, _, _ in scheduled += 1; return .failure(error) },
            presentFailure: { _ in presented += 1 }
        )
        let dispatcher = RuntimeRequestDispatcher(sessionState: state, autoScanServices: services, allowsLegacy: { true })
        _ = dispatcher.dispatch(RuntimeClientRequestEnvelope(event: .enableAutoScan), dataDirectory: directory, version: "test")
        for _ in 0..<20 where state.runtimeAutoScanSnapshot.enabled { await Task.yield() }
        #expect(authorized == 1)
        #expect(scheduled == (authorizationFails ? 0 : 1))
        #expect(presented == (authorizationFails ? 1 : 0))
        #expect(!state.runtimeAutoScanSnapshot.enabled)
        #expect(state.scanFeedback.contains("Auto-scan could not be enabled"))
        let config = try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("config.json"))) as? [String: Any]
        #expect((config?["autoScan"] as? [String: Any])?["enabled"] as? Bool == false)
    }
}
