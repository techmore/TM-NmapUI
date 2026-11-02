import AppKit
import SwiftUI
import Testing
@testable import NmapUIApp

/// Renders the panel to PNGs for visual review when NMAPUI_PANEL_SNAPSHOT_DIR
/// is set; otherwise only checks that it lays out at a sensible size.
@Suite("Menu bar panel rendering")
@MainActor
struct MenuBarPanelSnapshotTests {
    static func states() -> [(String, MenuBarPanelModel.Input)] {
        let recent: [MenuBarPanelModel.RecentScan] = [
            .init(id: "1", target: "192.168.50.0/24", when: "09:21", summary: "23 hosts · 24m 50s", changes: "+2 new · 1 missing", succeeded: true, reportPath: "a"),
            .init(id: "2", target: "192.168.50.0/24", when: "Nov 1", summary: "21 hosts · 22m 10s", changes: nil, succeeded: true, reportPath: "b"),
            .init(id: "3", target: "printer.lan", when: "Oct 31", summary: "1 host · 58s", changes: "+1 CVE", succeeded: false, reportPath: nil),
        ]
        let profiles: [MenuBarPanelModel.Profile] = [.init(id: UUID(), name: "Main office"), .init(id: UUID(), name: "Warehouse")]
        return [
            ("scanning", .init(source: .shared, engineReady: true, engineAddress: "http://127.0.0.1:9000", networkCIDR: "192.168.50.0/24",
                               scanning: true, scanTarget: "192.168.50.0/24", phase: "Service scan 8/22: 192.168.50.31", progress: 66,
                               canStop: true, canPause: true, defaultTarget: "192.168.50.0/24", recent: recent)),
            ("ready", .init(source: .native, engineReady: true, networkCIDR: "192.168.50.0/24", canStart: true,
                            defaultTarget: "192.168.50.0/24", profiles: profiles, selectedProfileID: profiles[0].id,
                            recent: recent, driveEnabled: true, driveConfigured: true)),
            ("offline", .init(source: .shared, engineReady: false, engineStatus: "The scanner could not be reached at 127.0.0.1:9000.",
                              defaultTarget: "192.168.50.0/24")),
        ]
    }

    @Test("panel renders at a menu-bar-friendly size in light and dark mode")
    func render() throws {
        let directory = ProcessInfo.processInfo.environment["NMAPUI_PANEL_SNAPSHOT_DIR"].map(URL.init(fileURLWithPath:))
        for (name, input) in Self.states() {
            for appearance in [NSAppearance.Name.aqua, .darkAqua] {
                let store = MenuBarPanelStore(model: MenuBarPanelModel(input))
                let host = NSHostingView(rootView: MenuBarPanelView(store: store))
                host.appearance = NSAppearance(named: appearance)
                let size = host.fittingSize
                #expect(size.width == 360)
                #expect(size.height > 150 && size.height < 640, "\(name) height \(size.height)")
                guard let directory else { continue }
                let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: .borderless, backing: .buffered, defer: false)
                window.appearance = NSAppearance(named: appearance)
                window.contentView = host
                host.frame = NSRect(origin: .zero, size: size)
                host.layoutSubtreeIfNeeded()
                host.display()
                let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
                host.cacheDisplay(in: host.bounds, to: rep)
                let png = try #require(rep.representation(using: .png, properties: [:]))
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try png.write(to: directory.appendingPathComponent("panel-\(name)-\(appearance == .aqua ? "light" : "dark").png"))
            }
        }
    }
}
