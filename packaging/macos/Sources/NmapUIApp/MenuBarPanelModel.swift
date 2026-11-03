import Foundation

/// Everything the menu bar panel shows, derived from plain values so it can be
/// unit-tested without AppKit or a running scanner.
struct MenuBarPanelModel: Equatable {
    enum Source: Equatable { case shared, native, unselected }
    enum Tone: Equatable { case ready, scanning, paused, attention, idle }

    struct Profile: Equatable, Identifiable {
        let id: UUID?
        let name: String
    }

    struct RecentScan: Equatable, Identifiable {
        let id: String
        let target: String
        let when: String
        let summary: String
        let changes: String?
        let succeeded: Bool
        let reportPath: String?
    }

    struct Input: Equatable {
        var source: Source = .unselected
        var engineReady = false
        var engineStatus = ""
        var engineAddress: String?
        var networkCIDR: String?
        var scanning = false
        var paused = false
        var scanTarget: String?
        var phase: String?
        /// 0...1 or 0...100; normalised by the model.
        var progress: Double?
        var lastError: String?
        var canStart = false
        var canStop = false
        var canPause = false
        var canResume = false
        var defaultTarget = ""
        var profiles: [Profile] = []
        var selectedProfileID: UUID?
        var recent: [RecentScan] = []
        var driveEnabled = false
        var driveConfigured = false
    }

    let source: Source
    let tone: Tone
    let headline: String
    let detail: String
    let progress: Double?
    let target: String
    let networkLabel: String
    let canStart: Bool
    let canStop: Bool
    let canPause: Bool
    let canResume: Bool
    let profiles: [Profile]
    let selectedProfileID: UUID?
    let recent: [RecentScan]
    let syncLabel: String
    let syncHealthy: Bool

    static let maxRecent = 4

    init(_ input: Input) {
        source = input.source
        target = input.scanTarget?.nilIfBlank ?? input.defaultTarget
        networkLabel = input.networkCIDR?.nilIfBlank ?? ""
        canStart = input.source != .unselected && input.canStart && !input.scanning
        canStop = input.scanning && input.canStop
        canPause = input.scanning && !input.paused && input.canPause
        canResume = input.scanning && input.paused && input.canResume
        profiles = input.profiles
        selectedProfileID = input.selectedProfileID
        recent = Array(input.recent.prefix(Self.maxRecent))
        progress = Self.fraction(input.progress)

        switch input.source {
        case .unselected:
            tone = .idle
            headline = "Choose a scan engine"
            detail = "Open NmapUI to pick the shared scanner or the native engine."
        case .shared, .native:
            if input.scanning {
                tone = input.paused ? .paused : .scanning
                let target = input.scanTarget?.nilIfBlank ?? "network"
                headline = input.paused ? "Paused · \(target)" : "Scanning \(target)"
                detail = input.phase?.nilIfBlank ?? "Working…"
            } else if let error = input.lastError?.nilIfBlank {
                tone = .attention
                headline = input.engineReady ? "Last action failed" : "Scanner unavailable"
                detail = error
            } else if !input.engineReady {
                tone = .attention
                headline = input.source == .shared ? "Scanner not connected" : "Starting engine"
                detail = input.engineStatus.nilIfBlank ?? "Waiting for the scanner…"
            } else {
                tone = .ready
                headline = "Ready to scan"
                detail = input.recent.first.map { "Last scan \($0.when) · \($0.summary)" } ?? "No scans yet"
            }
        }

        switch input.source {
        case .shared:
            syncHealthy = input.engineReady
            syncLabel = input.engineReady
                ? "Shared scanner · \(input.engineAddress ?? "connected")"
                : "Shared scanner offline"
        case .native:
            syncHealthy = !input.driveEnabled || input.driveConfigured
            syncLabel = input.driveEnabled
                ? (input.driveConfigured ? "Reports upload to Google Drive" : "Google Drive needs sign-in")
                : "Reports stay on this Mac"
        case .unselected:
            syncHealthy = false
            syncLabel = "No engine selected"
        }
    }

    static func fraction(_ value: Double?) -> Double? {
        guard let value, value.isFinite, value >= 0 else { return nil }
        let normalised = value > 1 ? value / 100 : value
        return min(max(normalised, 0), 1)
    }

    /// "+2 new · 1 missing · +3 CVEs", or nil when nothing changed.
    static func changeSummary(newHosts: Int, missingHosts: Int, newVulnerabilities: Int) -> String? {
        var parts: [String] = []
        if newHosts > 0 { parts.append("+\(newHosts) new") }
        if missingHosts > 0 { parts.append("\(missingHosts) missing") }
        if newVulnerabilities > 0 { parts.append("+\(newVulnerabilities) CVE\(newVulnerabilities == 1 ? "" : "s")") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}

private extension String {
    var nilIfBlank: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
