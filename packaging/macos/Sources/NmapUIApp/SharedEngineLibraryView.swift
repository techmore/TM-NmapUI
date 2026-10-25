import AppKit
import Foundation
import SharedEngineCore
import SwiftUI

enum SharedControlIntent {
    case start(target: String, skipHostDiscovery: Bool)
    case cancel(SharedJobKind, UUID)
    case pause(SharedJobKind, UUID)
    case resume(SharedJobKind, UUID)
    case reconnect
    case acknowledgeUncertain
}

@MainActor
final class SharedEngineLibraryModel: ObservableObject {
    @Published var address = "http://127.0.0.1:9000"
    @Published var username = ""
    @Published var password = ""
    @Published var scanTarget = ""
    @Published var skipHostDiscovery = false
    @Published private(set) var controlState = SharedControlState()
    @Published private(set) var controlNotice = "Attach a scanner to enable canonical scan controls."
    var routeControl: ((SharedControlIntent) -> Void)?
    private var controls: SharedEngineSocketClient?
    private var controlTask: Task<Void, Never>?
    @Published private(set) var snapshot: SharedEngineSnapshot?
    @Published private(set) var connected = false
    @Published private(set) var busy = false
    @Published private(set) var notice = "Connect to a scanner already running on this Mac to review its saved scans and reports."
    @Published private(set) var downloadNotice = ""
    @Published private(set) var observedAddress = ""
    @Published private(set) var hasError = false
    private var client: SharedEngineClient?
    private var pollTask: Task<Void, Never>?
    private var operation: Task<Void, Never>?
    private(set) var generation = 0
    private let reportStore: SharedEngineReportStore
    private let openDocument: (URL) -> Bool
    private let revealDocument: (URL) -> Void

    init(openDocument: @escaping (URL) -> Bool = { NSWorkspace.shared.open($0) },
         revealDocument: @escaping (URL) -> Void = { NSWorkspace.shared.activateFileViewerSelecting([$0]) },
         reportStore: SharedEngineReportStore = SharedEngineReportStore()) {
        self.openDocument = openDocument
        self.revealDocument = revealDocument
        self.reportStore = reportStore
    }

    func attach() {
        stop()
        snapshot = nil
        hasError = false
        do {
            let endpoint = try SharedEngineEndpoint(address)
            let client = SharedEngineClient(endpoint: endpoint, username: username, password: password)
            let controls = SharedEngineSocketClient(endpoint: endpoint, username: username, password: password)
            self.controls = controls
            self.client = client
            // Credentials live only in the session client, not in preferences or logs.
            password = ""
            busy = true
            notice = "Checking scanner access…"
            let current = generation
            controls.onChange = { [weak self] next in
                guard let self, self.generation == current else { return }
                self.controlState = next
                if let error = next.lastError { self.controlNotice = error }
                else if next.connection == .ready { self.controlNotice = "Canonical scanner status is current." }
                else { self.controlNotice = "Scanner controls are authenticating or synchronizing. No commands are queued." }
            }
            operation = Task { [weak self] in
                guard let self else { return }
                await refresh(client, generation: current)
                guard !Task.isCancelled, generation == current, connected else { return }
                controlTask = Task { [weak self] in
                    do { try await controls.connect() }
                    catch {
                        guard let self, generation == current, !Task.isCancelled else { return }
                        controlNotice = (error as? SharedControlError)?.localizedDescription ?? "The control connection is unavailable. Saved reports remain readable; reconnect explicitly to refresh controls."
                    }
                }
                pollTask = Task { [weak self] in
                    while !Task.isCancelled {
                        do { try await Task.sleep(nanoseconds: 10_000_000_000) } catch { return }
                        guard let self, generation == current, connected else { return }
                        if !busy { await refresh(client, generation: current) }
                    }
                }
            }
        } catch {
            hasError = true
            notice = safeMessage(error)
        }
    }

    func refreshNow() {
        guard let client, connected, !busy else { return }
        busy = true
        let current = generation
        operation = Task { [weak self] in await self?.refresh(client, generation: current) }
    }

    private func refresh(_ client: SharedEngineClient, generation current: Int) async {
        guard !Task.isCancelled, generation == current else { return }
        busy = true
        defer { if generation == current { busy = false } }
        do {
            let next = try await client.snapshot()
            guard !Task.isCancelled, generation == current else { return }
            snapshot = next
            observedAddress = client.endpoint.url.absoluteString
            connected = true
            hasError = false
            notice = "Connected scanner \(next.version). \(next.localTrust ? "Trusted local access." : "Credentials accepted.")"
        } catch {
            guard !Task.isCancelled, generation == current else { return }
            connected = false
            hasError = true
            notice = safeMessage(error) + (snapshot == nil ? "" : " The saved observation below is out of date.")
            self.client = nil
            controls?.disconnect()
        }
    }

    func stop() {
        generation += 1
        operation?.cancel()
        controlTask?.cancel()
        controls?.onChange = nil
        controls?.disconnect()
        controls = nil
        controlTask = nil
        controlState.disconnected()
        controlNotice = "Detached. Scanner service jobs continue unless explicitly cancelled."
        pollTask?.cancel()
        operation = nil
        pollTask = nil
        client = nil
        connected = false
        busy = false
        hasError = false
        if snapshot != nil { notice = "Detached. The saved scanner observation is out of date. Connect again to refresh." }
    }

    func stop(ifGeneration expected: Int?) {
        guard expected == generation else { return }
        stop()
    }

    func send(_ intent: SharedControlIntent) {
        guard let routeControl else { controlNotice = "Choose Shared scanner as the application execution source before sending controls."; return }
        routeControl(intent)
    }

    /// Called only after the application execution router validates Shared mode.
    func performSharedControl(_ intent: SharedControlIntent) {
        guard let controls else { controlNotice = "Attach the scanner before sending controls."; return }
        do {
            switch intent {
            case .start(let target, let skip): try controls.startScan(target: target, skipHostDiscovery: skip)
            case .cancel(let kind, let id): try controls.cancel(kind, observedID: id)
            case .pause(let kind, let id): try controls.pause(kind, observedID: id)
            case .resume(let kind, let id): try controls.resume(kind, observedID: id)
            case .acknowledgeUncertain: try controls.acknowledgeUncertainStart()
            case .reconnect:
                controlTask?.cancel()
                controls.disconnect()
                let current = generation
                controlTask = Task { [weak self] in
                    do { try await controls.reconnect() }
                    catch {
                        guard let self, generation == current, !Task.isCancelled else { return }
                        controlNotice = (error as? SharedControlError)?.localizedDescription ?? "The scanner control connection could not be restored. No commands were replayed."
                    }
                }
            }
        } catch {
            controlNotice = (error as? SharedControlError)?.localizedDescription ?? "The scanner control request failed. No local scanner was started."
        }
    }

    func download(_ row: SharedEngineRow, format: SharedReportFormat) {
        guard let client, connected, !busy, row.has(format) else { return }
        busy = true
        downloadNotice = "Downloading \(format.rawValue.uppercased()) from the connected scanner…"
        let current = generation
        operation = Task { [weak self] in
            guard let self else { return }
            defer { if generation == current { busy = false } }
            do {
                let data = try await client.report(path: row.path, format: format)
                guard !Task.isCancelled, generation == current else { return }
                let file = try reportStore.save(data, format: format)
                if openDocument(file) {
                    downloadNotice = "Opened a private \(format.rawValue.uppercased()) copy in your document viewer."
                } else {
                    revealDocument(file)
                    downloadNotice = "Downloaded privately; choose a document viewer in Finder to open the report."
                }
            } catch {
                guard !Task.isCancelled, generation == current else { return }
                downloadNotice = safeMessage(error)
            }
        }
    }

    private func safeMessage(_ error: Error) -> String {
        (error as? SharedEngineError)?.localizedDescription ?? "The shared report could not be saved. Check temporary storage and try again."
    }
}

struct SharedEngineLibraryView: View {
    @ObservedObject var model: SharedEngineLibraryModel
    @State private var attachmentGeneration: Int?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            GroupBox(model.routeControl == nil ? "Shared scanner · review only" : "Shared scanner · canonical engine") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(model.routeControl == nil ? "Review this scanner's activity and saved reports. Native scans, the native archive and native schedules remain separate." : "Use the connected canonical engine for scanning and review its saved history and reports. Legacy archives and schedules remain separate until explicitly migrated.")
                        .font(.callout)
                    TextField("Scanner address", text: $model.address).textFieldStyle(.roundedBorder)
                        .disabled(model.connected || model.busy)
                    HStack {
                        TextField("Username (if required)", text: $model.username).textFieldStyle(.roundedBorder)
                        SecureField("Password (memory only)", text: $model.password).textFieldStyle(.roundedBorder)
                    }.disabled(model.connected || model.busy)
                    HStack {
                        Button("Attach / check access") { model.attach(); attachmentGeneration = model.generation }.disabled(model.connected || model.busy)
                        Button("Refresh") { model.refreshNow() }.disabled(!model.connected || model.busy)
                        Button("Detach") { model.stop() }.disabled(!model.connected && !model.busy)
                        if model.busy { ProgressView().controlSize(.small) }
                    }
                    Text(model.notice).font(.callout).textSelection(.enabled)
                        .foregroundStyle(model.hasError ? Color.orange : Color.primary)
                    Text(model.routeControl == nil ? "The password stays in memory until you detach. Use 127.0.0.1 or [::1] for a scanner on this Mac. Nothing connects until you choose Attach; no scanner is started." : "The password stays in memory until detach. Attach connects to an already running service on 127.0.0.1 or [::1]; it does not install or start a service. Scans require an explicit control.")
                        .font(.caption).foregroundStyle(.secondary)
                }.padding(8)
            }
            if model.routeControl != nil { canonicalControls }
            if let snapshot = model.snapshot {
                if !model.connected { Label("Disconnected · saved observation is out of date", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                Text("\(model.observedAddress) · last observed \(snapshot.observedAt.formatted(date: .abbreviated, time: .standard))").font(.caption).foregroundStyle(.secondary)
                GroupBox(model.routeControl == nil ? "Connected scanner activity" : "Saved scanner observation") {
                    VStack(alignment: .leading, spacing: 6) {
                        if model.routeControl == nil {
                            Text(snapshot.status.maintenanceActive ? "Scanner maintenance is active." : (snapshot.status.hasActiveJobs ? "Scanner has work in progress." : "No scans or reports are running."))
                            ForEach(Array(snapshot.status.activeJobs.enumerated()), id: \.offset) { _, job in
                                Text([job.jobType, job.status, job.details?.target].compactMap { $0 }.joined(separator: " · "))
                            }
                        } else {
                            Text("Saved records were fetched at \(snapshot.observedAt.formatted(date: .omitted, time: .standard)). The live controls above show current job status.")
                            if snapshot.status.maintenanceActive { Text("Maintenance was active at this HTTP refresh.") }
                        }
                        Text(model.routeControl == nil ? "Updates every 10 seconds while connected. This view does not start, stop or schedule scans." : "Saved history and reports refresh every 10 seconds. Scan controls use live canonical job status. Scheduling remains owned by the scanner service.").font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                rows(snapshot.reports, title: "Connected scanner reports", empty: "This scanner has no saved report files.")
                if !model.downloadNotice.isEmpty { Text(model.downloadNotice).font(.callout).textSelection(.enabled) }
                rows(snapshot.history, title: "Connected scanner history", empty: "This scanner has no saved scan history.")
            }
        }
        .onAppear { attachmentGeneration = model.generation }
        .onDisappear { model.stop(ifGeneration: attachmentGeneration) }
    }

    private var canonicalControls: some View {
        GroupBox("Canonical discovery / scan") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Uses the scanner service's configured discovery/scan workflow. Native Complete, Dragnet and VPN presets remain in Legacy compatibility; new report generation is not yet available in Shared native mode.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    TextField("Target (for example 127.0.0.1)", text: $model.scanTarget).textFieldStyle(.roundedBorder)
                    Button("Start discovery / scan") { model.send(.start(target: model.scanTarget, skipHostDiscovery: model.skipHostDiscovery)) }
                        .disabled(!canStart)
                }
                Toggle("Skip host discovery (scanner -Pn option)", isOn: $model.skipHostDiscovery)
                    .disabled(model.controlState.connection != .ready)
                Text(connectionLabel).font(.headline)
                Text(model.controlNotice).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                ForEach(SharedJobKind.allCases, id: \.self) { kind in
                    if let job = model.controlState.jobs[kind] {
                        VStack(alignment: .leading, spacing: 5) {
                            Text("\(kind.rawValue.capitalized) · \(job.rawStatus)\(job.paused == true ? " · paused" : job.pauseRequested == true ? " · pause requested" : "")")
                            if let target = job.details?.target { Text(target).textSelection(.enabled) }
                            if let message = job.effectiveMessage { Text(message).font(.caption).textSelection(.enabled) }
                            if let progress = job.effectiveProgress, progress.isFinite { ProgressView(value: min(100, max(0, progress)), total: 100) }
                            if let id = job.sourceJobID {
                                Text("Source run \(id.uuidString.lowercased())").font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                                HStack {
                                    Button("Stop \(kind.rawValue)") { model.send(.cancel(kind, id)) }.disabled(!canControl(kind, id, "cancel_job"))
                                    Button("Pause") { model.send(.pause(kind, id)) }.disabled(!canControl(kind, id, "pause_job"))
                                    Button("Resume") { model.send(.resume(kind, id)) }.disabled(!canControl(kind, id, "resume_job"))
                                }
                            }
                        }
                    }
                    if let completed = model.controlState.latestCompletion[kind] {
                        Text("Last observed \(kind.rawValue) outcome: \(completed.rawStatus)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if model.controlState.startOutcome == .submitting {
                    Text("Start was sent. Waiting for the scanner's source run identity.").foregroundStyle(.orange)
                }
                if model.controlState.startOutcome == .uncertain {
                    Text("Start delivery is uncertain. Nothing will be retried automatically. Review the refreshed scanner status before acknowledging.").foregroundStyle(.orange)
                    Button("Acknowledge uncertainty after reviewing current status") { model.send(.acknowledgeUncertain) }
                        .disabled(model.controlState.connection != .ready)
                }
                Button("Reconnect controls / refresh live status") { model.send(.reconnect) }
                    .disabled(!model.connected || model.controlState.connection == .authenticating || model.controlState.connection == .synchronizing)
                Text("Detach and Quit leave service jobs running. Only an explicit Stop for an observed source run requests cancellation.").font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var connectionLabel: String {
        switch model.controlState.connection {
        case .disconnected: "Controls disconnected · previous job state may be out of date"
        case .authenticating: "Authenticating controls"
        case .synchronizing: "Synchronizing both canonical job statuses"
        case .ready: "Current canonical job status"
        }
    }
    private var canStart: Bool {
        guard !model.busy, model.connected else { return false }
        do { try model.controlState.validateStart(target: model.scanTarget); return true } catch { return false }
    }
    private func canControl(_ kind: SharedJobKind, _ id: UUID, _ action: String) -> Bool {
        do { try model.controlState.validateControl(kind, observedID: id, action: action); return true } catch { return false }
    }

    private func rows(_ entries: [SharedEngineRow], title: String, empty: String) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 10) {
                if entries.isEmpty { Text(empty).foregroundStyle(.secondary) }
                ForEach(Array(entries.prefix(200))) { entry in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(entry.customerName ?? "Unassigned").font(.headline)
                            Text(entry.target ?? "No target recorded").textSelection(.enabled)
                            Spacer()
                            Text(entry.status ?? "Saved artifact").font(.caption)
                        }
                        Text(entry.timestamp ?? "Time not recorded").font(.caption).foregroundStyle(.secondary)
                        Text(entry.path).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                        if let count = entry.hostCount { Text("\(count) recorded \(count == 1 ? "host" : "hosts")").font(.caption) }
                        HStack {
                            ForEach(SharedReportFormat.allCases, id: \.self) { format in
                                if entry.has(format) {
                                    Button("Open \(format.rawValue.uppercased())") { model.download(entry, format: format) }
                                        .disabled(!model.connected || model.busy)
                                }
                            }
                            if !entry.isArtifact { Text("Saved scan run · no report artifact").font(.caption).foregroundStyle(.secondary) }
                        }
                        Divider()
                    }
                }
                if entries.count > 200 { Text("Showing 200 of \(entries.count) records. The remaining records are retained by the scanner.").font(.caption) }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
}
