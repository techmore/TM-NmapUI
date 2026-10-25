import Foundation

public enum SharedJobKind: String, Codable, CaseIterable, Sendable { case scan, report }

/// Unknown server states are retained verbatim and never treated as idle.
public enum SharedJobStatus: Equatable, Sendable {
    case idle, running, cancelling, completed, failed, cancelled, interrupted, unknown(String)
    public init(_ raw: String) {
        switch raw {
        case "idle": self = .idle
        case "running": self = .running
        case "cancelling": self = .cancelling
        case "completed": self = .completed
        case "failed": self = .failed
        case "cancelled": self = .cancelled
        case "interrupted": self = .interrupted
        default: self = .unknown(raw)
        }
    }
    public var isTerminal: Bool {
        switch self { case .idle, .completed, .failed, .cancelled, .interrupted: true; default: false }
    }
}

public struct SharedControlledJob: Decodable, Equatable, Sendable {
    public let jobType: SharedJobKind
    public let sourceJobID: UUID?
    public let rawStatus: String
    public var status: SharedJobStatus { SharedJobStatus(rawStatus) }
    public let paused: Bool?
    public let pauseRequested: Bool?
    public let pauseSupported: Bool?
    public let pauseMode: String?
    public let phase: String?
    public let progress: Double?
    public let message: String?
    public let details: Details?
    public var effectivePhase: String? { phase ?? details?.phase }
    public var effectiveProgress: Double? { progress ?? details?.progress }
    public var effectiveMessage: String? { message ?? details?.message ?? details?.error }
    public struct Details: Decodable, Equatable, Sendable {
        public let target: String?
        public let phase: String?
        public let progress: Double?
        public let message: String?
        public let error: String?
    }
    enum CodingKeys: String, CodingKey {
        case jobType = "job_type", sourceJobID = "source_job_id", rawStatus = "status"
        case paused, pauseRequested = "pause_requested", pauseSupported = "pause_supported", pauseMode = "pause_mode"
        case phase, progress, message, details
    }
}

public enum SharedControlError: Error, Equatable, Sendable {
    case disconnected, synchronizing, busy, staleJob, unsupported, invalidTarget, invalidResponse, http(Int)
}
public enum SharedControlConnection: Equatable, Sendable { case disconnected, authenticating, synchronizing, ready }
public enum SharedStartOutcome: Equatable, Sendable { case none, submitting, uncertain }

/// A connection epoch is enforced by the transport. Retired source IDs also
/// prevent buffered events from a previous run replacing a newer observed run.
public struct SharedControlState: Equatable, Sendable {
    public private(set) var connection: SharedControlConnection = .disconnected
    public private(set) var jobs: [SharedJobKind: SharedControlledJob] = [:]
    public private(set) var latestCompletion: [SharedJobKind: SharedControlledJob] = [:]
    public private(set) var startOutcome: SharedStartOutcome = .none
    public private(set) var lastError: String?
    private var synchronized: Set<SharedJobKind> = []
    private var retired: Set<UUID> = []
    private var submittedAfterSourceID: UUID?
    public init() {}
    public mutating func authenticating() { disconnected(); connection = .authenticating; lastError = nil }
    public mutating func connected() { connection = .synchronizing; synchronized.removeAll() }
    public mutating func disconnected() {
        connection = .disconnected; synchronized.removeAll()
        if startOutcome == .submitting { startOutcome = .uncertain }
    }
    public mutating func receive(_ job: SharedControlledJob) {
        guard connection == .synchronizing || connection == .ready else { return }
        if let id = job.sourceJobID, retired.contains(id) { return }
        // The control handler and workflow run concurrently: a cancellation
        // snapshot can arrive after the worker has already published terminal
        // status. A run UUID never becomes active again after completion.
        if let id = job.sourceJobID,
           let terminal = latestCompletion[job.jobType], terminal.sourceJobID == id,
           (job.status == .running || job.status == .cancelling) { return }
        if let old = jobs[job.jobType]?.sourceJobID ?? latestCompletion[job.jobType]?.sourceJobID,
           let new = job.sourceJobID, old != new { retired.insert(old) }
        // Idle snapshots without a source ID cannot erase the displayed outcome
        // of a completed run; keep it separately from current scanner capacity.
        if job.sourceJobID != nil, job.status.isTerminal { latestCompletion[job.jobType] = job }
        if job.sourceJobID == nil, let old = jobs[job.jobType], !old.status.isTerminal, connection == .ready { return }
        jobs[job.jobType] = job
        synchronized.insert(job.jobType)
        if synchronized.count == SharedJobKind.allCases.count { connection = .ready }
        if job.jobType == .scan, let id = job.sourceJobID, id != submittedAfterSourceID { startOutcome = .none }
    }
    public mutating func receiveError(_ message: String) { lastError = String(message.prefix(500)); if startOutcome == .submitting { startOutcome = .uncertain } }
    public func requireReady() throws {
        guard connection != .disconnected && connection != .authenticating else { throw SharedControlError.disconnected }
        guard connection == .ready else { throw SharedControlError.synchronizing }
    }
    public func validateStart(target: String) throws {
        try requireReady()
        guard !target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, target.utf8.count <= 1024 else { throw SharedControlError.invalidTarget }
        guard startOutcome == .none, jobs.values.allSatisfy({ $0.status.isTerminal }) else { throw SharedControlError.busy }
    }
    public mutating func submittedStart() {
        submittedAfterSourceID = jobs[.scan]?.sourceJobID ?? latestCompletion[.scan]?.sourceJobID
        startOutcome = .submitting; lastError = nil
    }
    /// Uncertain delivery is never retried. After reconciling, a user may explicitly dismiss it.
    public mutating func acknowledgeUncertainStart() throws { try requireReady(); if startOutcome == .uncertain { startOutcome = .none } }
    public func validateControl(_ kind: SharedJobKind, observedID: UUID, action: String) throws {
        try requireReady()
        guard let job = jobs[kind], job.sourceJobID == observedID, job.status == .running else { throw SharedControlError.staleJob }
        if action == "pause_job" { guard job.pauseSupported == true, job.paused != true, job.pauseRequested != true else { throw SharedControlError.unsupported } }
        if action == "resume_job" { guard job.paused == true || job.pauseRequested == true else { throw SharedControlError.unsupported } }
    }
}

extension SharedControlError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .disconnected: "Connect to the scanner before sending controls."
        case .synchronizing: "Wait for the scanner to refresh both job statuses."
        case .busy: "The scanner has an active or uncertain job. Refresh its status before starting another."
        case .staleJob: "This scan is no longer the observed active run. Refresh its status."
        case .unsupported: "This pause or resume action is unavailable in the current scanner state."
        case .invalidTarget: "Enter a nonempty scan target of at most 1024 bytes."
        case .invalidResponse: "The scanner returned an incompatible or oversized authentication response."
        case .http(401): "The scanner rejected these credentials."
        case .http(let code): "The scanner returned HTTP \(code)."
        }
    }
}
