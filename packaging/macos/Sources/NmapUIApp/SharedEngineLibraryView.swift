import AppKit
import Foundation
import SharedEngineCore
import SwiftUI

@MainActor
final class SharedEngineLibraryModel: ObservableObject {
    @Published var address = "http://127.0.0.1:9000"
    @Published var username = ""
    @Published var password = ""
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
            let client = SharedEngineClient(endpoint: try SharedEngineEndpoint(address), username: username, password: password)
            self.client = client
            // Credentials live only in the session client, not in preferences or logs.
            password = ""
            busy = true
            notice = "Checking scanner access…"
            let current = generation
            operation = Task { [weak self] in
                guard let self else { return }
                await refresh(client, generation: current)
                guard !Task.isCancelled, generation == current, connected else { return }
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
        }
    }

    func stop() {
        generation += 1
        operation?.cancel()
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
            GroupBox("Shared scanner · review only") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Review this scanner's activity and saved reports. Native scans, the native archive and native schedules remain separate.")
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
                    Text("The password stays in memory until you detach. Use 127.0.0.1 or [::1] for a scanner on this Mac. Nothing connects until you choose Attach; no scanner is started.")
                        .font(.caption).foregroundStyle(.secondary)
                }.padding(8)
            }
            if let snapshot = model.snapshot {
                if !model.connected { Label("Disconnected · saved observation is out of date", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                Text("\(model.observedAddress) · last observed \(snapshot.observedAt.formatted(date: .abbreviated, time: .standard))").font(.caption).foregroundStyle(.secondary)
                GroupBox("Connected scanner activity") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(snapshot.status.maintenanceActive ? "Scanner maintenance is active." : (snapshot.status.hasActiveJobs ? "Scanner has work in progress." : "No scans or reports are running."))
                        ForEach(Array(snapshot.status.activeJobs.enumerated()), id: \.offset) { _, job in
                            Text([job.jobType, job.status, job.details?.target].compactMap { $0 }.joined(separator: " · "))
                        }
                        Text("Updates every 10 seconds while connected. This view does not start, stop or schedule scans.").font(.caption).foregroundStyle(.secondary)
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
