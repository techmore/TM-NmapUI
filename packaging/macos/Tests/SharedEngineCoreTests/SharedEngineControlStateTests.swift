import Foundation
import Testing
@testable import SharedEngineCore

struct SharedEngineControlStateTests {
    func job(_ status: String, id: UUID? = nil, kind: String = "scan", extra: String = "") throws -> SharedControlledJob {
        let idField = id.map { ",\"source_job_id\":\"\($0.uuidString)\"" } ?? ""
        return try JSONDecoder().decode(SharedControlledJob.self, from: Data("{\"job_type\":\"\(kind)\",\"status\":\"\(status)\"\(idField)\(extra)}".utf8))
    }
    func ready() throws -> SharedControlState {
        var state = SharedControlState(); state.connected()
        state.receive(try job("idle")); state.receive(try job("idle", kind: "report")); return state
    }
    @Test func requiresBothStatusSnapshots() throws {
        var state = SharedControlState(); state.connected(); state.receive(try job("idle"))
        #expect(throws: SharedControlError.synchronizing) { try state.validateStart(target: "127.0.0.1") }
        state.receive(try job("idle", kind: "report")); try state.validateStart(target: "127.0.0.1")
    }
    @Test func disconnectRevokesControlsAndNeverReplaysUncertainStart() throws {
        var state = try ready(); state.submittedStart(); state.disconnected()
        #expect(state.startOutcome == .uncertain)
        #expect(throws: SharedControlError.disconnected) { try state.validateStart(target: "127.0.0.1") }
        state.connected(); state.receive(try job("idle")); state.receive(try job("idle", kind: "report"))
        #expect(throws: SharedControlError.busy) { try state.validateStart(target: "127.0.0.1") }
        try state.acknowledgeUncertainStart(); try state.validateStart(target: "127.0.0.1")
    }
    @Test func unknownStatusBlocksStartAndControls() throws {
        var state = try ready(); let id = UUID(); state.receive(try job("server-new-state", id: id))
        #expect(state.jobs[.scan]?.status == .unknown("server-new-state"))
        #expect(throws: SharedControlError.busy) { try state.validateStart(target: "127.0.0.1") }
        #expect(throws: SharedControlError.staleJob) { try state.validateControl(.scan, observedID: id, action: "cancel_job") }
    }
    @Test func controlsRequireExactObservedSourceAndPauseFlags() throws {
        var state = try ready(); let id = UUID(); state.receive(try job("running", id: id, extra: ",\"pause_supported\":true"))
        try state.validateControl(.scan, observedID: id, action: "cancel_job")
        try state.validateControl(.scan, observedID: id, action: "pause_job")
        #expect(throws: SharedControlError.staleJob) { try state.validateControl(.scan, observedID: UUID(), action: "cancel_job") }
        #expect(throws: SharedControlError.unsupported) { try state.validateControl(.scan, observedID: id, action: "resume_job") }
        state.receive(try job("running", id: id, extra: ",\"paused\":true,\"pause_requested\":true"))
        try state.validateControl(.scan, observedID: id, action: "resume_job")
    }
    @Test func retiredRunsCannotReplaceNewRunOrCancelIt() throws {
        var state = try ready(); let old = UUID(), current = UUID()
        state.receive(try job("running", id: old)); state.receive(try job("completed", id: old)); state.receive(try job("idle"))
        state.receive(try job("running", id: current)); state.receive(try job("completed", id: old)); state.receive(try job("idle"))
        state.receive(try job("idle"))
        #expect(state.jobs[.scan]?.sourceJobID == current)
        #expect(state.jobs[.scan]?.status == .running)
        #expect(throws: SharedControlError.staleJob) { try state.validateControl(.scan, observedID: old, action: "cancel_job") }
    }

    @Test func terminalRunCannotRegressWhenConcurrentHandlerSnapshotArrivesLate() throws {
        var state = try ready(); let id = UUID()
        state.receive(try job("running", id: id)); state.receive(try job("cancelled", id: id))
        state.receive(try job("cancelling", id: id))
        #expect(state.jobs[.scan]?.status == .cancelled)
        state.receive(try job("idle")); state.receive(try job("running", id: id))
        #expect(state.jobs[.scan]?.status == .idle)
        #expect(state.latestCompletion[.scan]?.status == .cancelled)
    }
    @Test func oldCompletionCannotResolveUncertainNewStart() throws {
        var state = try ready(); let old = UUID()
        state.receive(try job("completed", id: old)); state.submittedStart(); state.disconnected()
        state.connected(); state.receive(try job("completed", id: old)); state.receive(try job("idle", kind: "report"))
        #expect(state.startOutcome == .uncertain)
        state.receive(try job("running", id: UUID()))
        #expect(state.startOutcome == .none)
    }
    @Test func unscopedControlErrorCannotResolvePendingStart() throws {
        var state = try ready(); state.submittedStart()
        state.receiveError("This scan is no longer active; refresh its status")
        state.receive(try job("idle")); state.receive(try job("idle", kind: "report"))
        #expect(state.startOutcome == .uncertain)
        #expect(throws: SharedControlError.busy) { try state.validateStart(target: "127.0.0.1") }
        state.receive(try job("running", id: UUID()))
        #expect(state.startOutcome == .none)
    }
    @Test func disconnectedSnapshotsIgnoredAndErrorsBounded() throws {
        var state = SharedControlState(); state.receive(try job("running", id: UUID()))
        #expect(state.jobs.isEmpty)
        state.receiveError(String(repeating: "x", count: 2000)); #expect(state.lastError?.count == 500)
    }
}
