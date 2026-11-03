import Foundation
import Testing
@testable import NmapUIApp

@Suite("Menu bar panel model")
struct MenuBarPanelModelTests {
    private func scan(_ n: Int) -> MenuBarPanelModel.RecentScan {
        .init(id: "\(n)", target: "10.0.\(n).0/24", when: "09:0\(n)", summary: "\(n) hosts", changes: nil, succeeded: true, reportPath: "r\(n)")
    }

    @Test("no engine selected: idle, no scan controls")
    func unselected() {
        let model = MenuBarPanelModel(.init(source: .unselected, canStart: true))
        #expect(model.tone == .idle)
        #expect(model.headline == "Choose a scan engine")
        #expect(!model.canStart && !model.canStop)
        #expect(!model.syncHealthy)
    }

    @Test("ready engine offers Scan now and summarises the last scan")
    func ready() {
        var input = MenuBarPanelModel.Input(source: .native, engineReady: true, networkCIDR: "192.168.1.0/24", canStart: true, defaultTarget: "192.168.1.0/24")
        input.recent = [scan(1), scan(2), scan(3), scan(4), scan(5)]
        let model = MenuBarPanelModel(input)
        #expect(model.tone == .ready)
        #expect(model.headline == "Ready to scan")
        #expect(model.detail == "Last scan 09:01 · 1 hosts")
        #expect(model.canStart)
        #expect(model.target == "192.168.1.0/24")
        #expect(model.recent.count == MenuBarPanelModel.maxRecent)
        #expect(model.recent.first?.id == "1")
    }

    @Test("running shared scan shows target, phase, percent progress and controls")
    func scanning() {
        let input = MenuBarPanelModel.Input(source: .shared, engineReady: true, scanning: true, scanTarget: "10.20.0.0/24",
                                            phase: "Service scan 3/22", progress: 42, canStart: true, canStop: true, canPause: true, canResume: true)
        let model = MenuBarPanelModel(input)
        #expect(model.tone == .scanning)
        #expect(model.headline == "Scanning 10.20.0.0/24")
        #expect(model.detail == "Service scan 3/22")
        #expect(model.progress == 0.42)
        #expect(!model.canStart, "Scan now is disabled while a scan runs")
        #expect(model.canStop && model.canPause && !model.canResume)
    }

    @Test("paused scan offers Resume, not Pause")
    func paused() {
        let model = MenuBarPanelModel(.init(source: .shared, engineReady: true, scanning: true, paused: true, scanTarget: "h",
                                            canStop: true, canPause: true, canResume: true))
        #expect(model.tone == .paused)
        #expect(model.headline == "Paused · h")
        #expect(model.canResume && !model.canPause)
    }

    @Test("disconnected or failed engine needs attention and explains why")
    func attention() {
        let offline = MenuBarPanelModel(.init(source: .shared, engineReady: false, engineStatus: "Attach a scanner"))
        #expect(offline.tone == .attention)
        #expect(offline.headline == "Scanner not connected")
        #expect(offline.detail == "Attach a scanner")
        #expect(!offline.syncHealthy)

        let failed = MenuBarPanelModel(.init(source: .shared, engineReady: true, lastError: "Target rejected"))
        #expect(failed.tone == .attention)
        #expect(failed.headline == "Last action failed")
        #expect(failed.detail == "Target rejected")
    }

    @Test("progress accepts fractions or percentages and rejects junk", arguments: [
        (Double?.none, Double?.none), (0.25, 0.25), (25, 0.25), (150, 1), (-1, nil), (Double.nan, nil),
    ])
    func progress(value: Double?, expected: Double?) {
        #expect(MenuBarPanelModel.fraction(value) == expected)
    }

    @Test("change summary lists only what changed")
    func changes() {
        #expect(MenuBarPanelModel.changeSummary(newHosts: 0, missingHosts: 0, newVulnerabilities: 0) == nil)
        #expect(MenuBarPanelModel.changeSummary(newHosts: 2, missingHosts: 1, newVulnerabilities: 1) == "+2 new · 1 missing · +1 CVE")
        #expect(MenuBarPanelModel.changeSummary(newHosts: 0, missingHosts: 0, newVulnerabilities: 3) == "+3 CVEs")
    }

    @Test("native upload status reflects Google Drive configuration")
    func sync() {
        #expect(MenuBarPanelModel(.init(source: .native, driveEnabled: false)).syncLabel == "Reports stay on this Mac")
        let unconfigured = MenuBarPanelModel(.init(source: .native, driveEnabled: true, driveConfigured: false))
        #expect(unconfigured.syncLabel == "Google Drive needs sign-in" && !unconfigured.syncHealthy)
        #expect(MenuBarPanelModel(.init(source: .native, driveEnabled: true, driveConfigured: true)).syncHealthy)
        #expect(MenuBarPanelModel(.init(source: .shared, engineReady: true, engineAddress: "http://127.0.0.1:9000")).syncLabel == "Shared scanner · http://127.0.0.1:9000")
    }

    @Test("panel timestamps show the time for today and pass unknown formats through")
    @MainActor
    func timestamps() {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        #expect(AppDelegate.panelTimestamp(formatter.string(from: Date()).replacingOccurrences(of: "T", with: " ")).count == 5)
        #expect(AppDelegate.panelTimestamp("not a date") == "not a date")
        #expect(AppDelegate.panelTimestamp(nil) == "")
    }
}
