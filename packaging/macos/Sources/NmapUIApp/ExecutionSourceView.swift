import AppKit
import SwiftUI

struct ExecutionRootView: View {
    let appDelegate: AppDelegate
    @ObservedObject var router: ApplicationExecutionRouter

    var body: some View {
        VStack(spacing: 0) {
            ExecutionSourceChoiceView(appDelegate: appDelegate, router: router)
            Divider()
            switch router.source {
            case .shared:
                ScrollView { SharedEngineLibraryView(model: router.sharedScanner).padding(24) }.disabled(router.restartPending)
            case .legacy:
                NativeShellView(sessionState: appDelegate.sessionState,
                    onQuickScan: { appDelegate.startQuickScanFromNativeShell() },
                    onStartScan: { appDelegate.startScanFromNativeShell(target: $0, scanKind: $1, vpnHelper: $2) },
                    onOpenReport: { appDelegate.openReportPath($0) },
                    onCreateCustomer: { appDelegate.createCustomer($0) },
                    onSelectCustomer: { appDelegate.selectCustomer($0) })
                    .disabled(router.restartPending)
            case .unselected:
                VStack(spacing: 16) {
                    Image(systemName: "network").font(.system(size: 48))
                    Text("Choose which engine owns scanning").font(.title)
                    Text("Shared scanner connects to the canonical Flask service already running on this Mac. It does not start a local scanner, helper, network fingerprint or native scheduler.")
                    Text("Legacy compatibility preserves this branch's local engine, archives and native schedule configuration. Schedules and customers are not automatically migrated.")
                        .foregroundStyle(.secondary)
                }.multilineTextAlignment(.center).frame(maxWidth: 680).padding(40)
                Spacer()
            }
        }.frame(minWidth: 1100, minHeight: 760)
    }
}

struct ExecutionSourceChoiceView: View {
    let appDelegate: AppDelegate
    @ObservedObject var router: ApplicationExecutionRouter
    @ObservedObject var legacyWork: LegacyTaskQueue
    @State private var confirmation: ExecutionSource?

    init(appDelegate: AppDelegate, router: ApplicationExecutionRouter) {
        self.appDelegate = appDelegate
        self.router = router
        self.legacyWork = appDelegate.legacyWorkQueue
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(router.source == .shared ? "Shared scanner · canonical engine" : router.source == .legacy ? "Legacy compatibility · separate local engine" : "Execution source not selected")
                    .font(.headline)
                Spacer()
                if router.source == .unselected {
                    Button("Use Shared scanner (recommended)") { _ = appDelegate.chooseExecutionSource(.shared) }.buttonStyle(.borderedProminent)
                    Button("Use Legacy compatibility") { confirmation = .legacy }
                } else if !router.restartPending {
                    Button(router.source == .legacy ? "Switch to Shared after restart…" : "Switch to Legacy after restart…") {
                        confirmation = router.source == .legacy ? .shared : .legacy
                    }
                } else {
                    Text("Restart required").foregroundStyle(.orange)
                    Button("Quit now") { NSApp.terminate(nil) }
                }
            }
            if legacyWork.runningCount > 0 {
                HStack {
                    Text("A Legacy authorization or download is active. Finish or cancel it before changing source.").font(.caption)
                    Button("Cancel pending Legacy actions") { appDelegate.cancelPendingLegacyActions() }
                }
            }
            if router.source == .legacy, router.existingLegacyInstallation {
                Text("Existing native installation detected. Its schedule configuration and archives are preserved; changing source requires an explicit choice.").font(.caption).foregroundStyle(.secondary)
            }
            if !router.notice.isEmpty { Text(router.notice).font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
        }.padding(16)
        .confirmationDialog("Change execution source?", isPresented: Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil } }), titleVisibility: .visible) {
            if let next = confirmation {
                Button(next == .shared ? "Use Shared after restart" : "Use Legacy compatibility") {
                    _ = appDelegate.chooseExecutionSource(next)
                    confirmation = nil
                }
            }
            Button("Cancel", role: .cancel) { confirmation = nil }
        } message: {
            Text("Shared mode prevents old native schedules from running until Legacy is restored or schedules are explicitly migrated. Existing configuration, customers and archives remain unchanged. Shared service jobs continue when you detach or quit; cancel them explicitly if needed. Legacy compatibility runs a separate engine and is not a migration. Active Legacy scans, authorizations and downloads must finish or be explicitly cancelled before changing source.")
        }
    }
}

struct ExecutionSettingsView: View {
    let appDelegate: AppDelegate
    @ObservedObject var router: ApplicationExecutionRouter
    var body: some View {
        if router.source == .legacy && !router.restartPending {
            PreferencesView(store: appDelegate.preferencesStore, sessionState: appDelegate.sessionState,
                onChooseFolder: { appDelegate.chooseDataDirectory() }, onRevealFolder: { appDelegate.openDataDirectory() },
                onSave: { appDelegate.savePreferences() }, onReset: { appDelegate.resetPreferences() },
                onConnectGoogleDrive: { appDelegate.connectGoogleDriveFromSettings() },
                onDisconnectGoogleDrive: { appDelegate.disconnectGoogleDriveFromSettings() },
                onSaveGoogleDriveSettings: { appDelegate.saveGoogleDriveSettingsFromNative(enabled: $0, folderID: $1) },
                onSaveGoogleDriveCredentials: { appDelegate.saveGoogleDriveCredentialsFromNative($0) })
        } else {
            VStack(alignment: .leading, spacing: 20) {
                ExecutionSourceChoiceView(appDelegate: appDelegate, router: router)
                Text("Shared scanner settings, credentials, customers and scheduling belong to the canonical service. Native compatibility preferences are unavailable in Shared mode. No native helper or schedule is installed by this window.")
                    .padding(16)
            }.frame(width: 700).padding()
        }
    }
}

struct ExecutionCommands: Commands {
    let appDelegate: AppDelegate
    @ObservedObject var router: ApplicationExecutionRouter
    @ObservedObject var model: SharedEngineLibraryModel
    var body: some Commands {
        CommandMenu("Scanner") {
            if router.source == .shared {
                Button("Start canonical discovery / scan") { appDelegate.sharedMenuAction(.start, observedID: nil) }
                    .keyboardShortcut("s", modifiers: [.command, .shift])
                    .disabled(!router.allowsShared || model.controlState.connection != .ready)
                if let job = model.controlState.jobs[.scan], let id = job.sourceJobID {
                    Button("Stop observed shared scan") { appDelegate.sharedMenuAction(.stop, observedID: id) }
                        .keyboardShortcut(".", modifiers: [.command])
                        .disabled(!router.allowsShared || job.status != .running)
                    Button("Pause observed shared scan") { appDelegate.sharedMenuAction(.pause, observedID: id) }
                        .disabled(!router.allowsShared || job.status != .running || job.paused == true || job.pauseRequested == true || job.pauseSupported != true)
                    Button("Resume observed shared scan") { appDelegate.sharedMenuAction(.resume, observedID: id) }
                        .disabled(!router.allowsShared || job.status != .running || (job.paused != true && job.pauseRequested != true))
                }
            } else if router.source == .legacy {
                Button("Start Legacy quick scan") { appDelegate.startQuickScanFromNativeShell() }
                    .keyboardShortcut("s", modifiers: [.command, .shift]).disabled(!router.allowsLegacy)
                Button("Stop Legacy scan") { appDelegate.stopSwiftManagedScan() }
                    .keyboardShortcut(".", modifiers: [.command]).disabled(!router.allowsLegacy)
            }
        }
    }
}
