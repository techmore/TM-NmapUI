import AppKit
import SwiftUI

/// Actions the panel can ask the app to perform.
struct MenuBarPanelActions {
    var scanNow: (_ target: String, _ profileID: UUID?) -> Void = { _, _ in }
    var stop: () -> Void = {}
    var pause: () -> Void = {}
    var resume: () -> Void = {}
    var openReport: (String) -> Void = { _ in }
    var openApp: () -> Void = {}
    var openSettings: () -> Void = {}
    var quit: () -> Void = {}
    var close: () -> Void = {}
}

@MainActor
final class MenuBarPanelStore: ObservableObject {
    @Published var model: MenuBarPanelModel
    var actions = MenuBarPanelActions()

    init(model: MenuBarPanelModel = MenuBarPanelModel(.init())) { self.model = model }

    func update(_ input: MenuBarPanelModel.Input) {
        let next = MenuBarPanelModel(input)
        if next != model { model = next }
    }
}

/// Light/dark variants of the main window's olive palette for the panel.
enum PanelPalette {
    static let background = dynamic(light: NativePalette.olive50, dark: Color(red: 22 / 255, green: 23 / 255, blue: 15 / 255))
    static let card = dynamic(light: NativePalette.white, dark: Color(red: 34 / 255, green: 35 / 255, blue: 24 / 255))
    static let border = dynamic(light: NativePalette.olive200, dark: Color(red: 64 / 255, green: 66 / 255, blue: 44 / 255))
    static let primaryText = dynamic(light: NativePalette.olive950, dark: NativePalette.olive50)
    static let secondaryText = dynamic(light: NativePalette.olive600, dark: NativePalette.olive300)
    static let accent = dynamic(light: NativePalette.olive700, dark: NativePalette.olive200)
    static let accentText = dynamic(light: NativePalette.olive50, dark: NativePalette.olive950)
    static let track = dynamic(light: NativePalette.olive100, dark: Color(red: 52 / 255, green: 54 / 255, blue: 36 / 255))
    static let ok = dynamic(light: NativePalette.emerald700, dark: NativePalette.emerald500)
    static let warn = dynamic(light: NativePalette.amber700, dark: NativePalette.amber500)
    static let warnFill = dynamic(light: NativePalette.amber100, dark: Color(red: 70 / 255, green: 48 / 255, blue: 12 / 255))
    static let danger = NativePalette.red600

    static func tone(_ tone: MenuBarPanelModel.Tone) -> Color {
        switch tone {
        case .ready: ok
        case .scanning: accent
        case .paused, .attention: warn
        case .idle: secondaryText
        }
    }

    private static func dynamic(light: Color, dark: Color) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? NSColor(dark) : NSColor(light)
        })
    }
}

struct MenuBarPanelView: View {
    @ObservedObject var store: MenuBarPanelStore
    @State private var target = ""
    @State private var profileID: UUID?
    @State private var editedTarget = false
    @FocusState private var targetFocused: Bool

    private var model: MenuBarPanelModel { store.model }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            statusCard
            if model.source != .unselected { scanCard }
            if !model.recent.isEmpty { recentCard }
            syncRow
            footer
        }
        .padding(14)
        .frame(width: 360)
        .background(PanelPalette.background)
        .onAppear(perform: syncFields)
        .onChange(of: model.target) { _ in if !editedTarget { target = model.target } }
        .onChange(of: model.selectedProfileID) { _ in profileID = model.selectedProfileID }
        .onExitCommand { store.actions.close() }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "network")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(PanelPalette.accent)
                .accessibilityHidden(true)
            Text("NmapUI")
                .font(.system(size: 18, weight: .semibold, design: .serif))
                .italic()
                .foregroundStyle(PanelPalette.primaryText)
            Text(sourceLabel)
                .font(.caption2.weight(.bold))
                .foregroundStyle(PanelPalette.secondaryText)
                .padding(.horizontal, 7).padding(.vertical, 3)
                .background(PanelPalette.track)
                .clipShape(Capsule())
            Spacer()
            Button(action: store.actions.openSettings) {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(PanelPalette.secondaryText)
            .help("Settings")
            .accessibilityLabel("Settings")
        }
    }

    private var sourceLabel: String {
        switch model.source {
        case .shared: "SHARED"
        case .native: "NATIVE"
        case .unselected: "SETUP"
        }
    }

    private var statusCard: some View {
        PanelCard {
            HStack(alignment: .top, spacing: 10) {
                StatusDot(color: PanelPalette.tone(model.tone), pulsing: model.tone == .scanning)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.headline)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(PanelPalette.primaryText)
                        .lineLimit(1)
                    Text(model.detail)
                        .font(.caption)
                        .foregroundStyle(PanelPalette.secondaryText)
                        .lineLimit(2)
                    if !model.networkLabel.isEmpty, !model.headline.hasSuffix(model.networkLabel) {
                        Text(model.networkLabel)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(PanelPalette.secondaryText)
                    }
                }
                Spacer(minLength: 0)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(model.headline). \(model.detail)")

            if model.tone == .scanning || model.tone == .paused {
                ProgressBar(fraction: model.progress, color: PanelPalette.tone(model.tone))
                HStack(spacing: 8) {
                    if model.canPause { panelButton("Pause", icon: "pause.fill", action: store.actions.pause) }
                    if model.canResume { panelButton("Resume", icon: "play.fill", action: store.actions.resume) }
                    if model.canStop { panelButton("Stop", icon: "stop.fill", tint: PanelPalette.danger, action: store.actions.stop) }
                    Spacer()
                }
            }
        }
    }

    private var scanCard: some View {
        PanelCard {
            Text("Scan now")
                .font(.caption.weight(.bold))
                .foregroundStyle(PanelPalette.secondaryText)
            TextField("Target, e.g. 192.168.1.0/24", text: $target)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .focused($targetFocused)
                .onChange(of: target) { _ in editedTarget = target != model.target }
                .onSubmit(startScan)
                .accessibilityLabel("Scan target")
            if model.source == .native, !model.profiles.isEmpty {
                Picker("Profile", selection: $profileID) {
                    Text("Unassigned").tag(UUID?.none)
                    ForEach(model.profiles) { profile in
                        Text(profile.name).tag(profile.id)
                    }
                }
                .pickerStyle(.menu)
                .font(.caption)
                .accessibilityLabel("Client profile")
            }
            Button(action: startScan) {
                Label("Scan now", systemImage: "dot.radiowaves.left.and.right")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(OliveButtonStyle(fill: NativePalette.olive700, hoverFill: NativePalette.olive600, text: NativePalette.olive50))
            .disabled(!model.canStart || target.trimmingCharacters(in: .whitespaces).isEmpty)
            .keyboardShortcut(.defaultAction)
            .help(model.canStart ? "Start a discovery and service scan" : "A scan is running or the scanner is not ready")
        }
    }

    private var recentCard: some View {
        PanelCard {
            Text("Recent scans")
                .font(.caption.weight(.bold))
                .foregroundStyle(PanelPalette.secondaryText)
            ForEach(model.recent) { scan in
                Button { scan.reportPath.map(store.actions.openReport) } label: {
                    RecentRow(scan: scan)
                }
                .buttonStyle(.plain)
                .help(scan.reportPath == nil ? "No saved report for this scan" : "Open report")
                .accessibilityHint(scan.reportPath == nil ? "" : "Opens the report")
            }
        }
    }

    private var syncRow: some View {
        HStack(spacing: 6) {
            Image(systemName: model.syncHealthy ? "checkmark.icloud" : "exclamationmark.icloud")
                .foregroundStyle(model.syncHealthy ? PanelPalette.ok : PanelPalette.warn)
                .accessibilityHidden(true)
            Text(model.syncLabel)
                .font(.caption)
                .foregroundStyle(PanelPalette.secondaryText)
                .lineLimit(1)
            Spacer()
        }
        .padding(.horizontal, 4)
        .accessibilityElement(children: .combine)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Button(action: store.actions.openApp) { Label("Open NmapUI", systemImage: "macwindow") }
                .buttonStyle(OliveButtonStyle(fill: PanelPalette.track, hoverFill: NativePalette.olive200, text: PanelPalette.primaryText))
                .keyboardShortcut("o", modifiers: .command)
            Spacer()
            Button("Quit", action: store.actions.quit)
                .buttonStyle(.borderless)
                .foregroundStyle(PanelPalette.secondaryText)
                .keyboardShortcut("q", modifiers: .command)
        }
    }

    private func panelButton(_ title: String, icon: String, tint: Color = PanelPalette.accent, action: @escaping () -> Void) -> some View {
        Button(action: action) { Label(title, systemImage: icon).font(.caption.weight(.semibold)) }
            .buttonStyle(.bordered)
            .tint(tint)
            .controlSize(.small)
    }

    private func syncFields() {
        target = model.target
        profileID = model.selectedProfileID
        editedTarget = false
    }

    private func startScan() {
        let value = target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard model.canStart, !value.isEmpty else { return }
        store.actions.scanNow(value, profileID)
        editedTarget = false
    }
}

private struct PanelCard<Content: View>: View {
    @ViewBuilder let content: () -> Content
    var body: some View {
        VStack(alignment: .leading, spacing: 8) { content() }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(PanelPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(PanelPalette.border, lineWidth: 1))
    }
}

private struct StatusDot: View {
    let color: Color
    let pulsing: Bool
    @State private var expanded = false
    var body: some View {
        ZStack {
            if pulsing {
                Circle().stroke(color.opacity(0.3), lineWidth: 4).scaleEffect(expanded ? 1.8 : 1).opacity(expanded ? 0 : 1)
            }
            Circle().fill(color).frame(width: 9, height: 9)
        }
        .frame(width: 16, height: 16)
        .onAppear { if pulsing { withAnimation(.easeOut(duration: 1.1).repeatForever(autoreverses: false)) { expanded = true } } }
        .accessibilityHidden(true)
    }
}

private struct ProgressBar: View {
    let fraction: Double?
    let color: Color
    var body: some View {
        Group {
            if let fraction {
                GeometryReader { proxy in
                    ZStack(alignment: .leading) {
                        Capsule().fill(PanelPalette.track)
                        Capsule().fill(color).frame(width: max(6, proxy.size.width * fraction))
                    }
                }
                .frame(height: 6)
                .accessibilityElement()
                .accessibilityLabel("Scan progress")
                .accessibilityValue("\(Int((fraction * 100).rounded())) percent")
            } else {
                ProgressView().progressViewStyle(.linear).tint(color)
                    .accessibilityLabel("Scan in progress")
            }
        }
    }
}

private struct RecentRow: View {
    let scan: MenuBarPanelModel.RecentScan
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: scan.succeeded ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(scan.succeeded ? PanelPalette.ok : PanelPalette.warn)
                .font(.caption)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(scan.target)
                        .font(.system(.caption, design: .monospaced).weight(.semibold))
                        .foregroundStyle(PanelPalette.primaryText)
                        .lineLimit(1)
                    Spacer()
                    Text(scan.when).font(.caption2).foregroundStyle(PanelPalette.secondaryText)
                }
                HStack(spacing: 6) {
                    Text(scan.summary).font(.caption2).foregroundStyle(PanelPalette.secondaryText)
                    if let changes = scan.changes {
                        Text(changes)
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(PanelPalette.warn)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(PanelPalette.warnFill)
                            .clipShape(Capsule())
                    }
                }
            }
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(scan.target), \(scan.when), \(scan.summary)\(scan.changes.map { ", \($0)" } ?? "")")
    }
}
