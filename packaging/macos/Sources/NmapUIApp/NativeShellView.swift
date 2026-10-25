import Foundation
import SwiftUI
import WebKit
import AppKit
import RuntimeContracts

/// Native SwiftUI dashboard. The web bridge below is retained for report and
/// compatibility events, but scan controls do not depend on JavaScript.
struct NativeShellView: View {
    @ObservedObject var sessionState: AppSessionState
    @StateObject private var sharedEngineLibrary = SharedEngineLibraryModel()
    let onQuickScan: () -> Void
    let onStartScan: (String, String, Bool) -> Void
    let onOpenReport: (String) -> Void
    let onCreateCustomer: (String) -> Void
    let onSelectCustomer: (UUID?) -> Void
    @State private var target = ""
    @State private var scanKind = "quick"
    @State private var showingSettings = false
    @State private var selectedTab = "Dashboard"
    @State private var customerPrefix = "CSP"
    @State private var newCustomerName = ""
    @State private var vpnHelper = false
    @State private var targetFollowsCurrentNetwork = true
    @State private var lastNetworkCIDR: String?
    @FocusState private var targetFocused: Bool

    private let oliveBackground = NativePalette.page

    var body: some View {
        VStack(spacing: 0) {
            pinnedCommandDeck
            NativeDivider().padding(.horizontal, 28)
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                switch selectedTab {
                case "History": historySection
                case "Reports": reportsSection
                case "Customers": customersSection
                case "Logs": logsSection
                case "Settings": settingsSection
                case "Shared scanner": SharedEngineLibraryView(model: sharedEngineLibrary)
                default:
                    statsCard
                    if sessionState.runtimeScanSession.isScanning { scanProgressCard }
                    if let artifacts = sessionState.currentScanReportArtifacts {
                        dashboardReportActionsCard(artifacts)
                    }
                    hostResultsCard
                }
                }
                .padding(28)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(minWidth: 1100, minHeight: 760)
        .background(oliveBackground.ignoresSafeArea())
        .tint(NativePalette.olive600)
        .foregroundStyle(NativePalette.body)
        .background(WindowAppearanceConfigurator(backgroundColor: oliveBackground))
        .environment(\.colorScheme, .light)
        .preferredColorScheme(.light)
        .onAppear {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first?.makeKeyAndOrderFront(nil)
            updateTargetFromNetwork(sessionState.runtimeNetworkState?.cidr)
            customerPrefix = sessionState.runtimeCustomerProfileSnapshot.prefix
        }
        .onChange(of: sessionState.runtimeNetworkState?.cidr) { cidr in
            updateTargetFromNetwork(cidr)
        }
        .sheet(isPresented: $showingSettings) {
            if let appDelegate = NSApp.delegate as? AppDelegate {
                PreferencesView(
                    store: appDelegate.preferencesStore,
                    sessionState: appDelegate.sessionState,
                    onChooseFolder: { appDelegate.chooseDataDirectory() },
                    onRevealFolder: { appDelegate.openDataDirectory() },
                    onSave: { appDelegate.savePreferences() },
                    onReset: { appDelegate.resetPreferences() },
                    onConnectGoogleDrive: { appDelegate.connectGoogleDriveFromSettings() },
                    onDisconnectGoogleDrive: { appDelegate.disconnectGoogleDriveFromSettings() },
                    onSaveGoogleDriveSettings: { enabled, folderID in appDelegate.saveGoogleDriveSettingsFromNative(enabled: enabled, folderID: folderID) },
                    onSaveGoogleDriveCredentials: { json in appDelegate.saveGoogleDriveCredentialsFromNative(json) }
                )
            }
        }
    }

    private var pinnedCommandDeck: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            tabBar
            networkStatusBar
            capabilityStatusBar
            Text("Native scanner controls · review the connected scanner in the Shared scanner tab")
                .font(.caption).foregroundStyle(NativePalette.olive600)
            scanToolbar
        }
        .padding(.horizontal, 28)
        .padding(.top, 22)
        .padding(.bottom, 14)
        .background(NativePalette.page)
    }

    private var tabBar: some View {
        HStack(spacing: 6) {
            ForEach(["Dashboard", "History", "Reports", "Customers", "Logs", "Settings", "Shared scanner"], id: \.self) { tab in
                Button(tab) { selectedTab = tab }
                    .buttonStyle(OliveButtonStyle(
                        fill: selectedTab == tab ? NativePalette.olive600 : .clear,
                        hoverFill: selectedTab == tab ? NativePalette.olive700 : NativePalette.olive100,
                        text: selectedTab == tab ? .white : NativePalette.olive700
                    ))
            }
        }
        .padding(6)
        .background(NativePalette.white.opacity(0.85))
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(NativePalette.olive200, lineWidth: 1))
    }

    private var networkStatusBar: some View {
        let network = sessionState.runtimeNetworkState
        return VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 0) {
                NetworkFact(title: "Local IP", value: network?.localIP ?? "Collecting...", valueColor: NativePalette.olive950)
                statusDivider
                NetworkFact(title: "Subnet", value: network?.mask ?? "Collecting...", valueColor: NativePalette.olive950)
                statusDivider
                NetworkFact(title: "Network", value: network?.cidr ?? "Collecting...", valueColor: NativePalette.olive950)
                statusDivider
                NetworkFact(title: "Public IP", value: network?.publicIP ?? "Collecting...", valueColor: NativePalette.olive950)
                Spacer(minLength: 0)
            }
            HStack(spacing: 10) {
                Label("Topology", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(NativePalette.olive600)
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        if let hops = network?.tracerouteHops, !hops.isEmpty {
                            ForEach(Array(hops.enumerated()), id: \.element.hop) { index, hop in
                                if index > 0 { Text("→").foregroundStyle(NativePalette.olive300) }
                                Text("\(hop.hop): \(hop.ip)")
                                    .font(.system(.caption, design: .monospaced).weight(.semibold))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 5)
                                    .background(isPrivateHop(hop.ip) ? NativePalette.amber100 : NativePalette.emerald100)
                                    .foregroundStyle(isPrivateHop(hop.ip) ? NativePalette.amber700 : NativePalette.emerald700)
                                    .clipShape(Capsule())
                                    .overlay(Capsule().stroke(isPrivateHop(hop.ip) ? NativePalette.amber200 : NativePalette.emerald200, lineWidth: 1))
                            }
                        } else {
                            Text("Collecting topology...").font(.caption).foregroundStyle(NativePalette.olive400)
                        }
                    }
                }
                .frame(height: 28)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(NativePalette.olive50)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(NativePalette.olive300, lineWidth: 1))
    }

    private var statusDivider: some View {
        Rectangle().fill(NativePalette.olive200).frame(width: 1, height: 34).padding(.horizontal, 16)
    }

    private var capabilityStatusBar: some View {
        let capabilities = sessionState.runtimeCapabilities
        return HStack(spacing: 8) {
            Text("Capabilities").font(.caption.weight(.bold)).foregroundStyle(NativePalette.olive600)
            CapabilityBadge(label: "Vulners", available: capabilities?.vulnersAvailable ?? false)
            CapabilityBadge(label: "ARP", available: capabilities?.arpScanAvailable ?? false)
            CapabilityBadge(label: "GoWitness", available: capabilities?.gowitnessAvailable ?? false)
            CapabilityBadge(label: "Helper", available: capabilities?.privilegedHelperAvailable ?? false)
            Spacer()
        }
    }

    private var scanToolbar: some View {
        HStack(spacing: 10) {
            TextField("Target (CIDR, host, or IP)", text: scanTargetBinding)
                .textFieldStyle(.plain)
                .focused($targetFocused)
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .frame(width: 300)
                .background(targetFocused ? NativePalette.white : NativePalette.olive50)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(targetFocused ? NativePalette.olive500 : NativePalette.olive200, lineWidth: targetFocused ? 2 : 1))
            Button { start(kind: "quick") } label: { Label("Quick", systemImage: "dot.radiowaves.left.and.right") }
                .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
                .disabled(sessionState.runtimeScanSession.isScanning || target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            Button { start(kind: "complete") } label: { Label("Complete", systemImage: "shield.checkered") }
                .buttonStyle(OliveButtonStyle(fill: NativePalette.olive900, hoverFill: NativePalette.olive950, text: .white))
                .disabled(sessionState.runtimeScanSession.isScanning || target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            Button { start(kind: "dragnet") } label: { Label("Dragnet", systemImage: "antenna.radiowaves.left.and.right") }
                .buttonStyle(OliveButtonStyle(fill: NativePalette.amber700, hoverFill: NativePalette.amber800, text: .white))
                .disabled(sessionState.runtimeScanSession.isScanning || target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            Toggle("VPN Helper", isOn: $vpnHelper)
                .toggleStyle(OliveToggleStyle())
                .font(.caption.weight(.bold))
                .foregroundStyle(NativePalette.olive600)
            Spacer()
            Text(sessionState.runtimeCustomerProfile?.reportLabel ?? "Unassigned network")
                .font(.system(.caption, design: .monospaced).weight(.semibold))
                .foregroundStyle(NativePalette.olive700)
        }
    }

    private var header: some View {
        HStack {
            Image("techmore", bundle: .module)
                .resizable()
                .scaledToFit()
                .frame(width: 102, height: 36)
            VStack(alignment: .leading, spacing: 5) {
                Text("TM-NMAPUI").font(.system(size: 30, weight: .regular, design: .serif)).italic().foregroundStyle(NativePalette.olive950)
                Text("Version \(RuntimeIdentity.productVersion())")
                    .font(.caption.weight(.medium)).foregroundStyle(NativePalette.olive600)
            }
            Spacer()
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Text(context.date.formatted(date: .abbreviated, time: .shortened))
                    .font(.system(size: 18, weight: .regular, design: .serif))
                    .foregroundStyle(NativePalette.olive950)
            }
            Spacer()
            Button {
                let scansDirectory = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL()
                    .appendingPathComponent("scans", isDirectory: true)
                try? FileManager.default.createDirectory(at: scansDirectory, withIntermediateDirectories: true)
                NSWorkspace.shared.open(scansDirectory)
            } label: {
                Label("Open Scan Files", systemImage: "folder.badge.gearshape")
            }
            .buttonStyle(OliveButtonStyle(fill: NativePalette.olive100, hoverFill: NativePalette.olive200, text: NativePalette.olive700))
            VStack(alignment: .trailing, spacing: 5) {
                Text(sessionState.runtimeScanSession.isScanning ? sessionState.scanStageDescription : "Ready to scan")
                    .foregroundStyle(sessionState.runtimeScanSession.isScanning ? NativePalette.amber700 : NativePalette.olive600)
                    .font(.callout.weight(.semibold))
                    .lineLimit(2)
                    .frame(maxWidth: 430, alignment: .trailing)
                HStack(spacing: 6) {
                    Circle().fill(sessionState.runtimeIsReady ? NativePalette.emerald600 : NativePalette.amber600).frame(width: 8, height: 8)
                    Text(sessionState.runtimeIsReady ? "Native runtime ready" : sessionState.runtimeStatusText)
                        .font(.caption.weight(.semibold)).foregroundStyle(NativePalette.olive600)
                }
            }
        }
    }

    private var scanTargetBinding: Binding<String> {
        Binding(
            get: { target },
            set: { newValue in
                target = newValue
                targetFollowsCurrentNetwork = newValue == sessionState.runtimeNetworkState?.cidr
            }
        )
    }

    private func updateTargetFromNetwork(_ cidr: String?) {
        guard let cidr, cidr != "Unknown" else { return }
        if targetFollowsCurrentNetwork || target.isEmpty || target == "Unknown" || target == lastNetworkCIDR {
            target = cidr
            targetFollowsCurrentNetwork = true
        }
        lastNetworkCIDR = cidr
    }

    private var networkCard: some View {
        NativeCard("Network", background: NativePalette.olive50, border: NativePalette.olive300) {
            let network = sessionState.runtimeNetworkState
            let privateHopCount = network?.tracerouteHops.filter { hop in
                hop.ip.hasPrefix("10.") || hop.ip.hasPrefix("192.168.")
            }.count ?? 0
            let publicHopCount = (network?.tracerouteHops.count ?? 0) - privateHopCount
            HStack(spacing: 28) {
                NetworkFact(title: "Local IP", value: network?.localIP ?? "Collecting...", valueColor: NativePalette.olive950)
                NetworkFact(title: "Subnet mask", value: network?.mask ?? "Collecting...", valueColor: NativePalette.olive950)
                NetworkFact(title: "Network", value: network?.cidr ?? "Collecting...", valueColor: NativePalette.olive950)
                NetworkFact(title: "Public IP", value: network?.publicIP ?? "Collecting...", valueColor: NativePalette.olive950)
                Spacer()
            }
            NativeDivider()
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 22) {
                    NetworkMetric(title: "Hops", value: "\(network?.tracerouteHops.count ?? 0)", labelColor: NativePalette.olive400, color: NativePalette.olive900)
                    NetworkMetric(title: "Private", value: "\(privateHopCount)", labelColor: NativePalette.amber500, color: NativePalette.amber600)
                    NetworkMetric(title: "Public", value: "\(publicHopCount)", labelColor: NativePalette.emerald500, color: NativePalette.emerald600)
                    NetworkMetric(title: "Exit", value: network?.tracerouteHops.last?.ip ?? "--", labelColor: NativePalette.olive400, color: NativePalette.olive900)
                    Spacer()
                }
                NativeDivider()
                HStack {
                    Label("Topology", systemImage: "point.3.connected.trianglepath.dotted")
                        .foregroundStyle(NativePalette.olive600)
                    Spacer()
                if let hops = network?.tracerouteHops, !hops.isEmpty {
                    HStack(spacing: 6) {
                        ForEach(Array(hops.enumerated()), id: \.element.hop) { index, hop in
                            if index > 0 { Text("→").foregroundStyle(NativePalette.olive300) }
                            Text("\(hop.hop): \(hop.ip)")
                                .font(.system(.caption, design: .monospaced).weight(.semibold))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 5)
                                .background(isPrivateHop(hop.ip) ? NativePalette.amber100 : NativePalette.emerald100)
                                .foregroundStyle(isPrivateHop(hop.ip) ? NativePalette.amber700 : NativePalette.emerald700)
                                .clipShape(Capsule())
                                .overlay(Capsule().stroke(isPrivateHop(hop.ip) ? NativePalette.amber200 : NativePalette.emerald200, lineWidth: 1))
                        }
                    }
                } else {
                    Text("Collecting topology...")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(NativePalette.olive400)
                }
                }
            }
            .padding(16)
            .background(NativePalette.olive50)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(NativePalette.olive200, lineWidth: 1))
        }
    }

    private var scanCard: some View {
        NativeCard("Scan", background: NativePalette.olive50, border: NativePalette.olive200) {
            VStack(alignment: .leading, spacing: 14) {
                TextField("Target (CIDR, host, or IP)", text: $target)
                    .textFieldStyle(.plain)
                    .focused($targetFocused)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(targetFocused ? NativePalette.white : NativePalette.olive50)
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(targetFocused ? NativePalette.olive500 : NativePalette.olive100, lineWidth: 2))
                    .shadow(color: targetFocused ? NativePalette.olive500.opacity(0.14) : .clear, radius: 0, x: 0, y: 0)
                HStack {
                    Button { start(kind: "quick") } label: { Label("Quick Scan", systemImage: "dot.radiowaves.left.and.right") }
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
                    Button { start(kind: "complete") } label: { Label("Complete + PDF", systemImage: "shield.checkered") }
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive900, hoverFill: NativePalette.olive950, text: .white))
                    Button { start(kind: "dragnet") } label: { Label("Dragnet + PDF", systemImage: "antenna.radiowaves.left.and.right") }
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.amber700, hoverFill: NativePalette.amber800, text: .white))
                }
                .disabled(sessionState.runtimeScanSession.isScanning || target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Toggle("VPN Helper", isOn: $vpnHelper)
                    .toggleStyle(OliveToggleStyle())
                    .font(.caption.weight(.bold))
                    .foregroundStyle(NativePalette.olive500)
                HStack {
                    Label("Client profile", systemImage: "person.crop.rectangle")
                        .foregroundStyle(NativePalette.olive600)
                    Spacer()
                    Text(sessionState.runtimeCustomerProfile?.reportLabel ?? "Unassigned network")
                        .font(.system(.caption, design: .monospaced).weight(.semibold))
                        .foregroundStyle(NativePalette.olive900)
                }
                .padding(12)
                .background(NativePalette.olive100)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
        }
    }

    private var statsCard: some View {
        let stats = sessionState.latestScanStats
        return NativeCard("Live scan intelligence") {
            HStack(spacing: 18) {
                NativeMetric(title: "Hosts", value: "\(stats?.hostCount ?? 0)", icon: "network", accent: NativePalette.olive600)
                NativeMetric(title: "Open ports", value: "\(stats?.openPortCount ?? 0)", icon: "door.left.hand.open", accent: NativePalette.olive500)
                NativeMetric(title: "Critical CVEs", value: "\(stats?.criticalCVECount ?? 0)", icon: "exclamationmark.triangle", accent: NativePalette.amber700)
                NativeMetric(title: "Low CVEs", value: "\(stats?.lowCVECount ?? 0)", icon: "checkmark.shield", accent: NativePalette.emerald600)
                Spacer()
            }
            Text(sessionState.scanFeedback).font(.callout).foregroundStyle(NativePalette.olive700).padding(.top, 6)
        }
    }

    private func dashboardReportActionsCard(_ artifacts: CurrentScanReportArtifacts) -> some View {
        return NativeCard("Completed scan reports", background: NativePalette.olive50, border: NativePalette.olive300) {
            HStack(spacing: 12) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(NativePalette.emerald600)
                VStack(alignment: .leading, spacing: 3) {
                    Text(artifacts.name)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(NativePalette.olive950)
                    Text("This scan is complete. Open its deliverables directly from the Dashboard.")
                        .font(.caption)
                        .foregroundStyle(NativePalette.olive600)
                }
                Spacer()
                ReportArtifactButton(title: "HTML", icon: "doc.richtext", path: artifacts.htmlPath, accent: NativePalette.olive600, onOpen: onOpenReport)
                if let pdfPath = artifacts.pdfPath { ReportArtifactButton(title: "PDF", icon: "doc.fill", path: pdfPath, accent: NativePalette.red600, onOpen: onOpenReport) }
                ReportArtifactButton(title: "XML", icon: "chevron.left.forwardslash.chevron.right", path: artifacts.xmlPath, accent: NativePalette.amber700, onOpen: onOpenReport)
            }
        }
    }

    private var historySection: some View {
        NativeCard("Native archive · scan history") {
            Text("Review prior scans, compare network context, and reopen historical artifacts.")
                .font(.callout).foregroundStyle(NativePalette.olive600)
            if sessionState.runtimeDataSnapshot.history.isEmpty { Text("No archived scans yet.").foregroundStyle(NativePalette.olive600) }
            else { ForEach(Array(sessionState.runtimeDataSnapshot.history.prefix(12)), id: \.timestamp) { entry in HistoryRow(entry: entry, onOpenReport: onOpenReport) } }
        }
    }

    private var reportsSection: some View {
        NativeCard("Native archive · reports") {
            Text("Open archived scan reports without relying on transient scan notifications.")
                .font(.callout).foregroundStyle(NativePalette.olive600)
            if sessionState.runtimeDataSnapshot.reports.isEmpty { Text("Reports will appear here after a successful scan.").foregroundStyle(NativePalette.olive600) }
            else { ForEach(sessionState.runtimeDataSnapshot.reports, id: \.name) { report in ReportRow(report: report, onOpenReport: onOpenReport) } }
        }
    }

    private var customersSection: some View {
        NativeCard("Customer assignment") {
            Text("Reports require an explicit customer or one unambiguous WAN IP/CIDR match.")
                .font(.callout).foregroundStyle(NativePalette.olive600)
            HStack {
                TextField("New customer name", text: $newCustomerName).textFieldStyle(.roundedBorder)
                Button("Create and assign") {
                    onCreateCustomer(newCustomerName)
                    newCustomerName = ""
                }
                .disabled(newCustomerName.trimmingCharacters(in: .whitespacesAndNewlines).count < 2)
                .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
            }
            if sessionState.customerRegistry.customers.isEmpty {
                Text("No customers exist. Create one to assign this network before scanning.").foregroundStyle(NativePalette.amber700)
            } else {
                ForEach(sessionState.customerRegistry.customers) { customer in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(customer.name).font(.headline)
                            Text("WAN: \(customer.publicIPs.joined(separator: ", "))  |  CIDR: \(customer.cidrs.joined(separator: ", "))")
                                .font(.caption).foregroundStyle(NativePalette.olive600)
                        }
                        Spacer()
                        Button(customer.id == sessionState.customerRegistry.activeCustomerID ? "Assigned" : "Assign") {
                            onSelectCustomer(customer.id)
                        }
                        .buttonStyle(OliveButtonStyle(fill: customer.id == sessionState.customerRegistry.activeCustomerID ? NativePalette.emerald600 : NativePalette.olive100, hoverFill: NativePalette.olive600, text: customer.id == sessionState.customerRegistry.activeCustomerID ? .white : NativePalette.olive700))
                    }
                    .padding(10).background(NativePalette.olive50).clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
                Button("Use automatic matching") { onSelectCustomer(nil) }
                    .buttonStyle(OliveButtonStyle(fill: NativePalette.olive100, hoverFill: NativePalette.olive200, text: NativePalette.olive700))
            }
            if let profile = sessionState.runtimeCustomerProfile {
                VStack(alignment: .leading, spacing: 8) {
                    Text(profile.reportLabel).font(.title3.weight(.semibold))
                    Text("Public IP: \(profile.publicIP)  ·  Fingerprint: \(profile.fingerprint)")
                    Text("Folder: \(profile.folderName)").font(.system(.caption, design: .monospaced)).foregroundStyle(NativePalette.olive500)
                }
                .padding(14)
                .background(NativePalette.olive50)
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(NativePalette.olive200, lineWidth: 1))
            } else { Text("Customer profile is being derived from the current network.").foregroundStyle(NativePalette.olive600) }
        }
    }

    private var logsSection: some View {
        NativeCard("Runtime feedback") {
            Text("Inspect live scan, report, and runtime events from the native execution path.")
                .font(.callout).foregroundStyle(NativePalette.olive600)
            VStack(alignment: .leading, spacing: 10) {
                Label(sessionState.runtimeStatusText, systemImage: "waveform.path.ecg")
                    .foregroundStyle(NativePalette.olive600)
                Text(sessionState.scanFeedback).font(.system(.body, design: .monospaced)).foregroundStyle(NativePalette.olive100)
                Text("Detailed diagnostics are written to the NmapUI runtime log.").font(.caption).foregroundStyle(NativePalette.olive500)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(NativePalette.zinc950)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(NativePalette.zinc800, lineWidth: 1))
        }
    }

    private var settingsSection: some View {
        NativeCard("Settings") {
            Text("Manage native runtime preferences, report storage, launch behavior, and integrations.")
                .font(.callout).foregroundStyle(NativePalette.olive600)
            if let appDelegate = NSApp.delegate as? AppDelegate {
                let helperReady = sessionState.runtimeCapabilities?.privilegedHelperAvailable ?? false
                VStack(alignment: .leading, spacing: 10) {
                    SettingsSummaryRow(label: "Nmap", value: appDelegate.sessionState.runtimeToolchain?.nmapPath ?? "Not found")
                    SettingsSummaryRow(label: "Traceroute", value: appDelegate.sessionState.runtimeToolchain?.traceroutePath ?? "Not found")
                    SettingsSummaryRow(label: "GoWitness", value: appDelegate.sessionState.runtimeToolchain?.gowitnessPath ?? "Not installed")
                    if appDelegate.sessionState.runtimeToolchain?.gowitnessPath == nil {
                        Button("Install GoWitness \(GowitnessManager.version)") { appDelegate.installGowitness() }
                            .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
                    }
                    SettingsSummaryRow(label: "Privilege helper", value: helperReady ? "XPC ready" : "Needs authorization/update")
                    if !helperReady {
                        Button("Install / Repair scanner helper") {
                            appDelegate.installPrivilegeHelperFromSettings()
                        }
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
                    }
                    SettingsSummaryRow(label: "Data directory", value: RuntimeSettingsStore.currentDataDirectoryURL().path)
                    Button("Open full native preferences") { showingSettings = true }
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
                }
            }
        }
    }

    private var scanProgressCard: some View {
        NativeCard("Active scan") {
            HStack {
                PulsingIndicator(color: NativePalette.olive600)
                Text(sessionState.scanStageDescription)
                    .foregroundStyle(NativePalette.olive700)
                Spacer()
                Button("Stop") { NSApp.delegate.flatMap { $0 as? AppDelegate }?.stopSwiftManagedScan() }
                    .buttonStyle(OliveButtonStyle(fill: NativePalette.olive100, hoverFill: NativePalette.red50, text: NativePalette.olive600, hoverText: NativePalette.red600))
            }
        }
    }

    private var hostResultsCard: some View {
        NativeCard("Discovered assets") {
            if sessionState.latestHosts.isEmpty {
                Text("No hosts discovered yet. Start a Quick Scan to populate this section.").foregroundStyle(NativePalette.olive600)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("IP / Host").frame(width: 160, alignment: .leading)
                        Text("MAC / Vendor").frame(width: 165, alignment: .leading)
                        Text("OS / Latency").frame(width: 125, alignment: .leading)
                        Text("Port").frame(width: 64, alignment: .leading)
                        Text("Service").frame(width: 220, alignment: .leading)
                        Text("Screenshot").frame(width: 96, alignment: .leading)
                        Text("Vulnerabilities").frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .font(.caption.weight(.bold)).foregroundStyle(.white)
                    .padding(8).background(NativePalette.olive900)
                    ForEach(Array(sessionState.latestHosts.enumerated()), id: \.element.ip) { index, host in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(host.ip).font(.system(.body, design: .monospaced).weight(.semibold))
                                Text(host.hostname.isEmpty ? "Unknown host" : host.hostname).font(.caption).foregroundStyle(NativePalette.olive600)
                            }.frame(width: 160, alignment: .leading)
                            VStack(alignment: .leading) {
                                Text(host.mac.isEmpty ? "--" : host.mac).font(.system(.caption, design: .monospaced))
                                Text(host.vendor.isEmpty ? "Unknown vendor" : host.vendor).font(.caption).foregroundStyle(NativePalette.olive600)
                            }.frame(width: 165, alignment: .leading)
                            VStack(alignment: .leading) {
                                Text(host.os).font(.caption)
                                Text(host.latency).font(.system(.caption, design: .monospaced)).foregroundStyle(NativePalette.olive600)
                            }.frame(width: 125, alignment: .leading)
                            HostPortColumn(host: host).frame(width: 64, alignment: .leading)
                            HostServiceColumn(host: host).frame(width: 220, alignment: .leading)
                            ScreenshotColumn(hostIP: host.ip, screenshots: sessionState.latestScreenshotURLs, onOpen: onOpenReport)
                            HostVulnerabilityColumn(host: host).frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .padding(8)
                        .background(index.isMultiple(of: 2) ? NativePalette.white : NativePalette.olive50)
                        .overlay(alignment: .bottom) { NativeDivider() }
                    }
                }
            }
        }
    }

    private func start(kind: String) {
        scanKind = kind
        RuntimeDiagnosticsLogger.log("SwiftUI scan button pressed kind=\(kind) target=\(target)")
        onStartScan(target, kind, vpnHelper)
    }

    private func isPrivateHop(_ ip: String) -> Bool {
        ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("172.16.") || ip.hasPrefix("172.17.") || ip.hasPrefix("172.18.") || ip.hasPrefix("172.19.") || ip.hasPrefix("172.2") || ip.hasPrefix("172.30.") || ip.hasPrefix("172.31.")
    }
}

private struct CapabilityBadge: View {
    let label: String
    let available: Bool

    var body: some View {
        Label(label, systemImage: available ? "checkmark.circle.fill" : "exclamationmark.circle")
            .font(.caption.weight(.semibold))
            .foregroundStyle(available ? NativePalette.emerald700 : NativePalette.amber700)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(available ? NativePalette.emerald100 : NativePalette.amber100)
            .clipShape(Capsule())
    }
}

enum NativePalette {
    // Exact sRGB conversions of the HTML OKLCH palette and Tailwind accents.
    static let page = Color(red: 226 / 255, green: 226 / 255, blue: 217 / 255)
    static let body = Color(red: 12 / 255, green: 12 / 255, blue: 9 / 255)
    static let white = Color.white
    static let olive50 = Color(red: 242 / 255, green: 243 / 255, blue: 232 / 255)
    static let olive100 = Color(red: 226 / 255, green: 227 / 255, blue: 212 / 255)
    static let olive200 = Color(red: 206 / 255, green: 208 / 255, blue: 187 / 255)
    static let olive300 = Color(red: 175 / 255, green: 177 / 255, blue: 148 / 255)
    static let olive400 = Color(red: 136 / 255, green: 137 / 255, blue: 99 / 255)
    static let olive500 = Color(red: 101 / 255, green: 103 / 255, blue: 58 / 255)
    static let olive600 = Color(red: 79 / 255, green: 80 / 255, blue: 43 / 255)
    static let olive700 = Color(red: 60 / 255, green: 61 / 255, blue: 32 / 255)
    static let olive900 = Color(red: 27 / 255, green: 28 / 255, blue: 14 / 255)
    static let olive950 = Color(red: 14 / 255, green: 14 / 255, blue: 7 / 255)
    static let amber50 = Color(red: 255 / 255, green: 251 / 255, blue: 235 / 255)
    static let amber100 = Color(red: 254 / 255, green: 243 / 255, blue: 199 / 255)
    static let amber200 = Color(red: 253 / 255, green: 230 / 255, blue: 138 / 255)
    static let amber500 = Color(red: 245 / 255, green: 158 / 255, blue: 11 / 255)
    static let amber600 = Color(red: 217 / 255, green: 119 / 255, blue: 6 / 255)
    static let amber700 = Color(red: 180 / 255, green: 83 / 255, blue: 9 / 255)
    static let amber800 = Color(red: 146 / 255, green: 64 / 255, blue: 14 / 255)
    static let emerald50 = Color(red: 236 / 255, green: 253 / 255, blue: 245 / 255)
    static let emerald100 = Color(red: 209 / 255, green: 250 / 255, blue: 229 / 255)
    static let emerald200 = Color(red: 167 / 255, green: 243 / 255, blue: 208 / 255)
    static let emerald500 = Color(red: 16 / 255, green: 185 / 255, blue: 129 / 255)
    static let emerald600 = Color(red: 5 / 255, green: 150 / 255, blue: 105 / 255)
    static let emerald700 = Color(red: 4 / 255, green: 120 / 255, blue: 87 / 255)
    static let red50 = Color(red: 254 / 255, green: 242 / 255, blue: 242 / 255)
    static let red600 = Color(red: 220 / 255, green: 38 / 255, blue: 38 / 255)
    static let zinc800 = Color(red: 39 / 255, green: 39 / 255, blue: 42 / 255)
    static let zinc900 = Color(red: 24 / 255, green: 24 / 255, blue: 27 / 255)
    static let zinc950 = Color(red: 9 / 255, green: 9 / 255, blue: 11 / 255)
    static let zinc400 = Color(red: 161 / 255, green: 161 / 255, blue: 170 / 255)
}

private struct NativeDivider: View {
    var body: some View { Rectangle().fill(NativePalette.olive100).frame(height: 1).padding(.vertical, 8) }
}

struct OliveButtonStyle: ButtonStyle {
    let fill: Color
    let hoverFill: Color
    let text: Color
    var hoverText: Color? = nil

    func makeBody(configuration: Configuration) -> some View {
        OliveButtonBody(configuration: configuration, fill: fill, hoverFill: hoverFill, text: text, hoverText: hoverText)
    }
}

private struct OliveButtonBody: View {
    let configuration: ButtonStyleConfiguration
    let fill: Color
    let hoverFill: Color
    let text: Color
    let hoverText: Color?
    @Environment(\.isEnabled) private var isEnabled
    @State private var hovering = false

    var body: some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(isEnabled ? (hovering ? (hoverText ?? text) : text) : NativePalette.olive400)
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(isEnabled ? (hovering ? hoverFill : fill) : NativePalette.olive100)
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .onHover { hovering = $0 }
    }
}

struct OliveToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: 8) {
                RoundedRectangle(cornerRadius: 3, style: .continuous)
                    .fill(configuration.isOn ? NativePalette.olive600 : NativePalette.white)
                    .frame(width: 16, height: 16)
                    .overlay(RoundedRectangle(cornerRadius: 3, style: .continuous).stroke(NativePalette.olive300, lineWidth: 1))
                    .overlay { if configuration.isOn { Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundStyle(.white) } }
                configuration.label
            }
        }
        .buttonStyle(.plain)
    }
}

private struct PulsingIndicator: View {
    let color: Color
    @State private var pulsing = false
    var body: some View {
        ZStack {
            Circle().stroke(color.opacity(0.25), lineWidth: 5).scaleEffect(pulsing ? 1.7 : 1)
            Circle().fill(color).frame(width: 9, height: 9)
        }
        .frame(width: 18, height: 18)
        .onAppear { withAnimation(.easeOut(duration: 1).repeatForever(autoreverses: false)) { pulsing = true } }
    }
}

private struct SettingsSummaryRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack(alignment: .top) {
            Text(label).fontWeight(.semibold).foregroundStyle(NativePalette.olive600).frame(width: 130, alignment: .leading)
            Text(value).font(.system(.caption, design: .monospaced)).foregroundStyle(NativePalette.olive900)
            Spacer()
        }
        .padding(8)
        .background(NativePalette.olive50)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct NativeCard<Content: View>: View {
    let title: String
    let background: Color
    let border: Color
    @ViewBuilder let content: () -> Content

    init(_ title: String, background: Color = NativePalette.white, border: Color = NativePalette.olive200, @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.background = background
        self.border = border
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title)
                .font(.system(size: 19, weight: .semibold, design: .serif))
                .italic()
                .foregroundStyle(NativePalette.olive900)
            content()
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(background)
        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .stroke(border, lineWidth: 1)
        }
        .shadow(color: .black.opacity(0.05), radius: 8, y: 3)
    }
}

private struct WindowAppearanceConfigurator: NSViewRepresentable {
    let backgroundColor: Color

    func makeNSView(context: Context) -> NSView { NSView(frame: .zero) }

    func updateNSView(_ nsView: NSView, context: Context) {
        guard let window = nsView.window else { return }
        window.isOpaque = true
        window.alphaValue = 1
        window.backgroundColor = NSColor(backgroundColor)
        window.appearance = NSAppearance(named: .aqua)
        window.isMovableByWindowBackground = true
        window.contentView?.wantsLayer = true
        window.contentView?.layer?.backgroundColor = NSColor(backgroundColor).cgColor
    }
}

private struct NetworkFact: View {
    let title: String
    let value: String
    let valueColor: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title.uppercased()).font(.caption.weight(.bold)).foregroundStyle(NativePalette.olive500)
            Text(value).font(.system(.body, design: .monospaced).weight(.semibold)).foregroundStyle(valueColor)
        }
    }
}

private struct NativeMetric: View {
    let title: String
    let value: String
    let icon: String
    let accent: Color
    var body: some View {
        Label {
            VStack(alignment: .leading) {
                Text(value).font(.title2.weight(.bold)).foregroundStyle(accent)
                Text(title).font(.caption).foregroundStyle(NativePalette.olive600)
            }
        } icon: {
            Image(systemName: icon).foregroundStyle(accent)
        }
    }
}

private struct NetworkMetric: View {
    let title: String
    let value: String
    let labelColor: Color
    let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title.uppercased()).font(.caption2.weight(.bold)).foregroundStyle(labelColor)
            Text(value).font(.system(.body, design: .monospaced).weight(.semibold)).foregroundStyle(color)
        }
    }
}

private struct HistoryRow: View {
    let entry: RuntimeReportHistoryEntry
    let onOpenReport: (String) -> Void
    var body: some View {
        HStack {
            Text(entry.timestamp).font(.caption).foregroundStyle(NativePalette.olive500)
            Text(entry.target).font(.system(.body, design: .monospaced)).foregroundStyle(NativePalette.olive950)
            Spacer()
            Text("\(entry.hostCount) hosts · \(entry.duration)").foregroundStyle(NativePalette.olive600)
            if let comparison = entry.comparison, comparison.hasChanges {
                Text("+\(comparison.newHosts.count) hosts · +\(comparison.newVulnerabilities.count) CVEs")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(NativePalette.amber700)
            }
            Text(entry.status?.uppercased() ?? "UNKNOWN")
                .font(.caption2.weight(.bold))
                .foregroundStyle(entry.status == "success" ? NativePalette.emerald700 : NativePalette.amber700)
                .padding(.horizontal, 7).padding(.vertical, 4)
                .background(entry.status == "success" ? NativePalette.emerald50 : NativePalette.amber50)
                .clipShape(Capsule())
            if let reportURL = entry.reportUrl { ReportArtifactButton(title: "HTML", icon: "doc.richtext", path: reportURL, accent: NativePalette.olive600, onOpen: onOpenReport) }
            if let pdfURL = entry.pdfUrl { ReportArtifactButton(title: "PDF", icon: "doc.fill", path: pdfURL, accent: NativePalette.red600, onOpen: onOpenReport) }
        }
        .padding(8)
        .background(NativePalette.olive50)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct ReportRow: View {
    let report: RuntimeReportListEntry
    let onOpenReport: (String) -> Void
    var body: some View {
        HStack {
            Image(systemName: "doc.text").foregroundStyle(NativePalette.olive600)
            Text(report.name).foregroundStyle(NativePalette.olive950)
            Spacer()
            Text(report.date).foregroundStyle(NativePalette.olive600)
            if let url = report.url { ReportArtifactButton(title: "HTML", icon: "doc.richtext", path: url, accent: NativePalette.olive600, onOpen: onOpenReport) }
            if let pdfURL = report.pdfUrl { ReportArtifactButton(title: "PDF", icon: "doc.fill", path: pdfURL, accent: NativePalette.red600, onOpen: onOpenReport) }
            if let xmlURL = report.xmlUrl { ReportArtifactButton(title: "XML", icon: "chevron.left.forwardslash.chevron.right", path: xmlURL, accent: NativePalette.amber700, onOpen: onOpenReport) }
        }
        .padding(8)
        .background(NativePalette.olive50)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct ReportArtifactButton: View {
    let title: String
    let icon: String
    let path: String
    let accent: Color
    let onOpen: (String) -> Void

    var body: some View {
        Button {
            onOpen(path)
        } label: {
            Label(title, systemImage: icon)
        }
        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive50, hoverFill: NativePalette.olive100, text: accent))
        .help("Open \(title) report")
    }
}

private struct HostPortColumn: View {
    let host: RuntimeNmapXMLHostSummary

    var body: some View {
        let ports = host.ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        VStack(alignment: .leading, spacing: 3) {
            if ports.isEmpty { Text("--").foregroundStyle(NativePalette.olive400) }
            else { ForEach(ports, id: \.self) { Text($0).font(.system(.caption, design: .monospaced).weight(.semibold)) } }
        }
    }
}

private struct HostServiceColumn: View {
    let host: RuntimeNmapXMLHostSummary

    var body: some View {
        let services = host.version.split(separator: "|").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        VStack(alignment: .leading, spacing: 3) {
            if services.isEmpty { Text(host.ports.isEmpty ? "No open service" : "Service unknown").foregroundStyle(NativePalette.olive400) }
            else {
                ForEach(services, id: \.self) { service in
                    Text(service.split(separator: ":", maxSplits: 1).dropFirst().first.map(String.init) ?? String(service))
                        .font(.caption).foregroundStyle(NativePalette.olive700)
                }
            }
        }
    }
}

private struct ScreenshotColumn: View {
    let hostIP: String
    let screenshots: [URL]
    let onOpen: (String) -> Void

    var body: some View {
        let matching = screenshots.first {
            let name = $0.lastPathComponent
            return name.contains(hostIP) || name.contains(hostIP.replacingOccurrences(of: ".", with: "-"))
        }
        if let matching {
            Button {
                onOpen(matching.absoluteString)
            } label: {
                Label("Open", systemImage: "photo")
                    .font(.caption.weight(.semibold))
            }
            .buttonStyle(OliveButtonStyle(fill: NativePalette.olive50, hoverFill: NativePalette.olive100, text: NativePalette.olive600))
            .help("Open GoWitness screenshot for \(hostIP)")
            .frame(width: 96, alignment: .leading)
        } else {
            Text("--").foregroundStyle(NativePalette.olive400).frame(width: 96, alignment: .leading)
        }
    }
}

private struct HostVulnerabilityColumn: View {
    let host: RuntimeNmapXMLHostSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if !host.vulnerabilities.isEmpty {
                ForEach(Array(host.vulnerabilities.sorted { lhs, rhs in
                    lhs.score == rhs.score ? lhs.id < rhs.id : lhs.score > rhs.score
                }.enumerated()), id: \.offset) { _, finding in
                    HStack(spacing: 5) {
                        Text("\(finding.id) (\(finding.score, specifier: "%.1f"))")
                            .font(.system(.caption, design: .monospaced).weight(.semibold))
                        if finding.exploit {
                            Text("EXPLOIT")
                                .font(.system(size: 9, weight: .bold, design: .rounded))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 4)
                                .padding(.vertical, 2)
                                .background(NativePalette.red600)
                                .clipShape(Capsule())
                        }
                    }
                    .foregroundStyle(finding.score >= 7.0 ? NativePalette.red600 : NativePalette.amber700)
                    if let port = finding.port, !port.isEmpty {
                        let serviceLabel = finding.service.map { " · \($0)" } ?? ""
                        Text("Port \(port)\(serviceLabel)")
                            .font(.caption2)
                            .foregroundStyle(NativePalette.olive600)
                    }
                }
                if host.lowCVECount > 0 {
                    Text("+ \(host.lowCVECount) lower-severity finding(s)")
                        .font(.caption)
                        .foregroundStyle(NativePalette.amber700)
                }
            } else if host.highCVEs.isEmpty {
                Text(host.lowCVECount == 0 ? "None reported" : "\(host.lowCVECount) lower-severity finding(s)")
                    .font(.caption).foregroundStyle(host.lowCVECount == 0 ? NativePalette.emerald700 : NativePalette.amber700)
            } else {
                Text(host.highCVEs).font(.system(.caption, design: .monospaced)).foregroundStyle(NativePalette.red600)
                if host.lowCVECount > 0 { Text("+ \(host.lowCVECount) lower-severity finding(s)").font(.caption).foregroundStyle(NativePalette.amber700) }
            }
        }
    }
}

private struct NativeLoadingStrip: View {
    let preloadMessage: String
    let helperReady: Bool
    let runtimeStatus: String

    var body: some View {
        HStack(spacing: 12) {
            PulsingIndicator(color: NativePalette.olive600)
            VStack(alignment: .leading, spacing: 2) {
                Text(preloadMessage)
                    .font(.system(size: 12, weight: .medium))
                Text(helperReady ? "Privileged scanner helper ready" : "Scanner helper installs on first full scan (one admin prompt)")
                    .font(.system(size: 11))
                    .foregroundStyle(NativePalette.olive600)
            }
            Spacer()
            Text(runtimeStatus)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(NativePalette.olive700)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .background(NativePalette.olive50)
        .overlay(alignment: .bottom) {
            Rectangle().fill(NativePalette.olive200).frame(height: 1)
        }
    }
}

struct WebPortalView: NSViewRepresentable {
    let url: URL
    let refreshNonce: UUID

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let userContentController = WKUserContentController()
        userContentController.add(context.coordinator, name: "nmapuiRuntime")
        userContentController.add(context.coordinator, name: "nmapuiRequest")
        // Mark native runtime early so the page uses the socket shim instead of Socket.IO CDN.
        let bootstrap = WKUserScript(
            source: "window.__NMAPUI_NATIVE_RUNTIME__ = true;",
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        userContentController.addUserScript(bootstrap)
        configuration.userContentController = userContentController
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.setValue(false, forKey: "drawsBackground")
        webView.navigationDelegate = context.coordinator
        webView.allowsMagnification = true
        if #available(macOS 13.3, *) {
            webView.isInspectable = true
        }
        WebPortalViewCoordinatorBridge.shared.register(webView: webView)
        loadDashboard(in: webView)
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        if context.coordinator.lastRefreshNonce != refreshNonce {
            context.coordinator.lastRefreshNonce = refreshNonce
            loadDashboard(in: webView)
            return
        }
        if context.coordinator.didFinishFirstLoad == false || webView.url == nil {
            loadDashboard(in: webView)
            return
        }
        if webView.url != url {
            loadDashboard(in: webView)
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        var didFinishFirstLoad = false
        var lastRefreshNonce = UUID()

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            didFinishFirstLoad = true
            guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
            Task { @MainActor in
                appDelegate.emitCurrentRuntimeSnapshotToWebView()
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            didFinishFirstLoad = false
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
            switch message.name {
            case "nmapuiRuntime":
                guard let body = message.body as? [String: Any] else { return }
                guard let action = body["action"] as? String else { return }
                RuntimeDiagnosticsLogger.log("Received native runtime action=\(action)")
                let target = (body["target"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let vpnHelper = body["vpnHelper"] as? Bool ?? false
                let scanKind = body["scanKind"] as? String ?? "quick"

                Task { @MainActor in
                    switch action {
                    case "start_quick_scan", "start_complete_scan", "start_dragnet_scan":
                        appDelegate.startScanFromNativeShell(
                            target: target,
                            scanKind: scanKind,
                            vpnHelper: vpnHelper
                        )
                    case "stop_scan":
                        appDelegate.stopSwiftManagedScan()
                    default:
                        break
                    }
                }
            case "nmapuiRequest":
                guard let body = message.body as? [String: Any] else { return }
                guard let eventName = body["event"] as? String else { return }
                let payload = body["payload"] as? [String: Any] ?? [:]
                guard let requestEvent = RuntimeClientRequest(rawValue: eventName) else { return }
                let request = RuntimeClientRequestEnvelope(
                    event: requestEvent,
                    payload: payload.toRuntimeJSONValueMap()
                )

                Task { @MainActor in
                    switch requestEvent {
                    case .getPrivilegeHelperStatus:
                        appDelegate.emitPrivilegeHelperStatus()
                        return
                    case .installPrivilegeHelper:
                        appDelegate.installPrivilegeHelperFromSettings()
                        return
                    case .openReport:
                        let path = (payload["path"] as? String)
                            ?? (payload["url"] as? String)
                            ?? ""
                        if !path.isEmpty {
                            appDelegate.openReportPath(path)
                        }
                        return
                    case .connectGoogleDrive:
                        appDelegate.connectGoogleDriveFromSettings()
                        return
                    case .disconnectGoogleDrive:
                        appDelegate.disconnectGoogleDriveFromSettings()
                        return
                    case .saveAppSettings:
                        appDelegate.saveAppSettingsFromWeb(payload)
                        return
                    case .stopScan:
                        appDelegate.stopSwiftManagedScan()
                        return
                    default:
                        break
                    }

                    let dispatcher = RuntimeRequestDispatcher(sessionState: appDelegate.sessionState)
                    let result = dispatcher.dispatch(
                        request,
                        dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL(),
                        version: RuntimeIdentity.productVersion()
                    )
                    for event in result.events {
                        appDelegate.sessionState.eventRouter.emit(event)
                    }
                    if let scanRequest = dispatcher.scanCoordinatorRequest(from: request) {
                        appDelegate.startScanFromNativeShell(
                            target: scanRequest.target,
                            scanKind: {
                                switch scanRequest.scanKind {
                                case .complete: return "complete"
                                case .dragnet: return "dragnet"
                                case .quick: return "quick"
                                }
                            }(),
                            vpnHelper: scanRequest.vpnHelper
                        )
                    }
                }
            default:
                break
            }
        }

        @MainActor
        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
        ) {
            guard navigationAction.navigationType == .linkActivated,
                  let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }

            // Open report artifacts and external links outside the dashboard document.
            if url.isFileURL {
                NSWorkspace.shared.open(url)
                decisionHandler(.cancel)
                return
            }
            if url.path.hasPrefix("/reports/") || url.absoluteString.contains("/reports/") {
                if let appDelegate = NSApp.delegate as? AppDelegate {
                    appDelegate.openReportPath(url.path.hasPrefix("/reports/") ? url.path : url.absoluteString)
                }
                decisionHandler(.cancel)
                return
            }
            if ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
                NSWorkspace.shared.open(url)
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }
    }

    private func loadDashboard(in webView: WKWebView) {
        let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        if url.isFileURL {
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        } else {
            webView.load(request)
        }
        scheduleSnapshotEmission()
    }

    private func scheduleSnapshotEmission() {
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 750_000_000)
            WebPortalViewCoordinatorBridge.shared.installNativeScanHandlers()
            guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
            appDelegate.emitCurrentRuntimeSnapshotToWebView()
        }
    }
}

private extension Dictionary where Key == String, Value == Any {
    func toRuntimeJSONValueMap() -> [String: RuntimeJSONValue] {
        reduce(into: [:]) { result, entry in
            switch entry.value {
            case let value as String:
                result[entry.key] = .string(value)
            case let value as Bool:
                result[entry.key] = .bool(value)
            case let value as Int:
                result[entry.key] = .int(value)
            case let value as Double:
                result[entry.key] = .double(value)
            case let value as [String: Any]:
                result[entry.key] = .object(value.toRuntimeJSONValueMap())
            case let value as [Any]:
                result[entry.key] = .array(value.compactMap { item in
                    switch item {
                    case let nested as String: return .string(nested)
                    case let nested as Bool: return .bool(nested)
                    case let nested as Int: return .int(nested)
                    case let nested as Double: return .double(nested)
                    default: return nil
                    }
                })
            default:
                break
            }
        }
    }
}

@MainActor
final class WebPortalViewCoordinatorBridge {
    static let shared = WebPortalViewCoordinatorBridge()

    private weak var webView: WKWebView?

    func register(webView: WKWebView) {
        self.webView = webView
    }

    func emitRuntimeEvent(event: String, payloadJSON: String) {
        guard let webView else { return }
        let script = """
        (() => {
            const eventName = \(Self.jsStringLiteral(event));
            const envelope = \(payloadJSON);
            const payload = envelope && typeof envelope === 'object' && Object.prototype.hasOwnProperty.call(envelope, 'payload')
                ? envelope.payload
                : envelope;
            const socketPayload = eventName === 'initial_data' && payload?.network
                ? {
                    ...payload.network,
                    publicIP: payload.publicIP || payload.network.publicIP,
                    customerProfile: payload.customerProfile,
                    googleDrive: payload.googleDrive,
                    autoScan: payload.autoScan
                }
                : payload;
            if (window.__nmapuiHandleNativeRuntimeEvent) {
                window.__nmapuiHandleNativeRuntimeEvent(eventName, envelope);
            }
            if (window.socket && typeof window.socket.__receive === 'function') {
                window.socket.__receive(eventName, socketPayload || {});
            }
        })();
        """
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    func applyNetworkSnapshot(_ networkState: RuntimeNetworkState) {
        installNativeScanHandlers()
        guard let webView else { return }
        let hopsJSON = Self.hopsJSON(networkState.tracerouteHops)
        let script = """
        (() => {
            const setText = (id, value) => {
                const element = document.getElementById(id);
                if (element) element.textContent = value || '--';
            };
            const localIP = \(Self.jsStringLiteral(networkState.localIP));
            const mask = \(Self.jsStringLiteral(networkState.mask));
            const cidr = \(Self.jsStringLiteral(networkState.cidr));
            const publicIP = \(Self.jsStringLiteral(networkState.publicIP));
            const hops = \(hopsJSON);

            setText('local-ip-value', localIP);
            setText('subnet-mask-value', mask);
            setText('cidr-value', cidr);
            setText('public-ip-value', publicIP);

            const targetInput = document.getElementById('scan-target');
            if (targetInput && (!targetInput.value || targetInput.value === '192.168.1.0/24' || targetInput.value === 'Unknown')) {
                targetInput.value = cidr;
            }

            ['start-scan-btn', 'generate-report-btn', 'dragnet-scan-btn'].forEach(id => {
                const button = document.getElementById(id);
                if (!button) return;
                button.disabled = false;
                button.removeAttribute('disabled');
                button.classList.remove('opacity-50', 'opacity-90', 'ring-4', 'ring-white/50');
                button.querySelector('.scan-button-pulse')?.classList.add('hidden');
            });
            document.getElementById('quick-scan-indicator')?.classList.add('hidden');
            document.getElementById('deep-scan-indicator')?.classList.add('hidden');
            setText('scan-console-status', 'Ready to scan');

            const routePath = document.getElementById('route-path');
            if (routePath) {
                routePath.replaceChildren();
                const isPrivateIP = (ip) => {
                    const parts = String(ip).split('.').map(Number);
                    return parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
                };
                hops.forEach((hop, index) => {
                    if (index > 0) {
                        const arrow = document.createElement('span');
                        arrow.className = 'text-olive-300 mx-1';
                        arrow.textContent = '->';
                        routePath.appendChild(arrow);
                    }
                    const chip = document.createElement('span');
                    const privateHop = isPrivateIP(hop.ip);
                    chip.id = `hop-${hop.hop}`;
                    chip.className = `px-2 py-1 rounded-lg text-[10px] font-mono font-bold border ${privateHop ? 'bg-amber-100 text-amber-700 border-amber-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200'} shadow-sm`;
                    chip.textContent = `${hop.hop}: ${hop.ip}`;
                    routePath.appendChild(chip);
                });
                if (!hops.length) {
                    const empty = document.createElement('span');
                    empty.className = 'italic text-olive-400';
                    empty.textContent = 'Collecting topology...';
                    routePath.appendChild(empty);
                }
                const privateCount = hops.filter(hop => isPrivateIP(hop.ip)).length;
                setText('total-hops', String(hops.length));
                setText('private-hops', String(privateCount));
                setText('public-hops', String(Math.max(0, hops.length - privateCount)));
                setText('exit-ip', hops.length ? hops[hops.length - 1].ip : '--');
            }
            window.__nmapuiNetworkSnapshotApplied = { localIP, mask, cidr, publicIP, hopCount: hops.length };
        })();
        """
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    func installNativeScanHandlers() {
        guard let webView else { return }
        RuntimeDiagnosticsLogger.log("Installing native scan handlers")
        let script = """
        (() => {
            if (!window.webkit?.messageHandlers?.nmapuiRuntime?.postMessage) return;
            window.__nmapuiNativeScanHandlersInstalledAt = new Date().toISOString();
            window.__NMAPUI_NATIVE_RUNTIME__ = true;

            const targetValue = () => document.getElementById('scan-target')?.value?.trim() || '';
            const vpnHelperValue = () => !!document.getElementById('vpn-helper-toggle')?.checked;
            const postAction = (action, scanKind, options = {}) => {
                const target = targetValue();
                window.webkit.messageHandlers.nmapuiRuntime.postMessage({
                    action,
                    target,
                    usePn: !!options.usePn,
                    vpnHelper: !!options.vpnHelper,
                    scanKind
                });
                const status = document.getElementById('scan-console-status');
                if (status) status.textContent = `Starting ${scanKind} scan for ${target || 'current target'}...`;
            };
            const bind = (id, handler) => {
                const button = document.getElementById(id);
                if (!button || button.dataset.nmapuiBound === '1') return;
                button.dataset.nmapuiBound = '1';
                button.addEventListener('click', event => {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    handler();
                }, true);
            };

            bind('start-scan-btn', () => postAction('start_quick_scan', 'quick'));
            bind('generate-report-btn', () => postAction('start_complete_scan', 'complete', { vpnHelper: vpnHelperValue() }));
            bind('dragnet-scan-btn', () => postAction('start_dragnet_scan', 'dragnet', { vpnHelper: vpnHelperValue() }));
            bind('stop-scan-btn', () => {
                window.webkit.messageHandlers.nmapuiRuntime.postMessage({ action: 'stop_scan' });
            });
        })();
        """
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    private static func hopsJSON(_ hops: [RuntimeTracerouteHop]) -> String {
        let payload = hops.map { ["hop": $0.hop, "ip": $0.ip] as [String: Any] }
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else {
            return "[]"
        }
        return json
    }

    private static func jsStringLiteral(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'", with: "\\'")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
        return "'\(escaped)'"
    }
}
