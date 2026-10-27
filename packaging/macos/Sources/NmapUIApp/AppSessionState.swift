import Foundation
import SwiftUI
import RuntimeContracts

@MainActor
struct RuntimeBootstrapSnapshot {
    var runtimeIdentity: RuntimeIdentity?
    var runtimeCapabilities: RuntimeCapabilities?
    var runtimeToolchain: RuntimeToolchain?
    var runtimeNetworkState: RuntimeNetworkState?
    var runtimeCustomerProfile: RuntimeCustomerProfile?
    var runtimeScanSession: RuntimeScanSessionSnapshot

    static func empty() -> RuntimeBootstrapSnapshot {
        RuntimeBootstrapSnapshot(
            runtimeIdentity: nil,
            runtimeCapabilities: nil,
            runtimeToolchain: nil,
            runtimeNetworkState: nil,
            runtimeCustomerProfile: nil,
            runtimeScanSession: RuntimeScanSessionSnapshot(
                scanStartTime: nil,
                currentScanPhase: nil,
                currentTarget: nil,
                currentScanKind: nil
            )
        )
    }
}

@MainActor
struct RuntimeDataSnapshot {
    var history: [RuntimeReportHistoryEntry]
    var reports: [RuntimeReportListEntry]

    static func empty() -> RuntimeDataSnapshot {
        RuntimeDataSnapshot(history: [], reports: [])
    }
}

@MainActor
struct RuntimeAutoScanSnapshot {
    var enabled: Bool
    var recurrence: String
    var startTime: String
    var target: String
    var config: [String: RuntimeJSONValue]

    static func empty() -> RuntimeAutoScanSnapshot {
        RuntimeAutoScanSnapshot(
            enabled: false,
            recurrence: "daily",
            startTime: "01:00",
            target: "",
            config: [:]
        )
    }
}

@MainActor
struct RuntimeGoogleDriveSnapshot {
    var enabled: Bool
    var folderId: String
    var config: [String: RuntimeJSONValue]

    static func empty() -> RuntimeGoogleDriveSnapshot {
        RuntimeGoogleDriveSnapshot(enabled: false, folderId: "", config: [:])
    }
}

@MainActor
struct RuntimeCustomerProfileSnapshot {
    var prefix: String
    var profile: RuntimeCustomerProfile?

    static func empty() -> RuntimeCustomerProfileSnapshot {
        RuntimeCustomerProfileSnapshot(prefix: "CSP", profile: nil)
    }
}

@MainActor
struct RuntimeScanSessionSnapshot: Equatable {
    var scanStartTime: String?
    var currentScanPhase: Int?
    var currentTarget: String?
    var currentScanKind: String?

    var isScanning: Bool {
        guard let currentScanPhase else { return false }
        return currentScanPhase > 0
    }
}

@MainActor
struct CurrentScanReportArtifacts: Equatable {
    let name: String
    let htmlPath: String
    let pdfPath: String?
    let xmlPath: String
}

@MainActor
final class AppSessionState: ObservableObject {
    let eventRouter: RuntimeEventRouting
    private let lifecycleEventBridge: RuntimeLifecycleEventBridge

    @Published var runtimeIsReady = false
    @Published var runtimeStatusText = "Starting..."
    @Published var startupHint = "Preparing native shell..."
    @Published var preloadMessage = "Loading dashboard..."
    @Published var showLoadingStrip = true
    @Published var runtimeIdentity: RuntimeIdentity?
    @Published var runtimeCapabilities: RuntimeCapabilities?
    @Published var runtimeToolchain: RuntimeToolchain?
    @Published var runtimeNetworkState: RuntimeNetworkState?
    @Published var runtimeCustomerProfile: RuntimeCustomerProfile?
    @Published var runtimeScanSession = RuntimeScanSessionSnapshot(
        scanStartTime: nil,
        currentScanPhase: nil,
        currentTarget: nil,
        currentScanKind: nil
    )
    @Published var runtimeBootstrapSnapshot = RuntimeBootstrapSnapshot.empty()
    @Published var runtimeDataSnapshot = RuntimeDataSnapshot.empty()
    @Published var runtimeAutoScanSnapshot = RuntimeAutoScanSnapshot.empty()
    @Published var runtimeGoogleDriveSnapshot = RuntimeGoogleDriveSnapshot.empty()
    @Published var runtimeCustomerProfileSnapshot = RuntimeCustomerProfileSnapshot.empty()
    @Published var latestScanStats: RuntimeScanStats?
    @Published var scanFeedback = "Ready to scan"
    @Published var scanStageDescription = "Ready to scan"
    @Published var latestHosts: [RuntimeNmapXMLHostSummary] = []
    @Published var latestScreenshotURLs: [URL] = []
    @Published var customerRegistry = CustomerRegistry.empty
    @Published var customerResolution: CustomerResolution = .unassigned
    /// Deliberately transient: Dashboard actions belong only to the scan just completed.
    @Published var currentScanReportArtifacts: CurrentScanReportArtifacts?

    private let googleDriveStatusProvider: (URL) -> GoogleDriveService.Status

    init(
        googleDriveStatusProvider: @escaping (URL) -> GoogleDriveService.Status = { GoogleDriveService.status(dataDirectory: $0) },
        eventRouter: RuntimeEventRouting = RuntimeEventRouter(
            emitHandler: { message in
                let envelope = RuntimeEventEncoder.encode(message)
                if let payload = try? String(data: JSONEncoder().encode(envelope.payload), encoding: .utf8) {
                    WebPortalViewCoordinatorBridge.shared.emitRuntimeEvent(event: envelope.event, payloadJSON: payload)
                }
            }
        ),
        lifecycleEventBridge: RuntimeLifecycleEventBridge = RuntimeLifecycleEventBridge(
            transport: RuntimeJSONEventTransport(),
            eventPublisher: { event, payload in
                WebPortalViewCoordinatorBridge.shared.emitRuntimeEvent(event: event, payloadJSON: payload)
            }
        )
    ) {
        self.googleDriveStatusProvider = googleDriveStatusProvider
        self.eventRouter = eventRouter
        self.lifecycleEventBridge = lifecycleEventBridge
    }

    func updateScanSession(
        scanStartTime: String?,
        currentScanPhase: Int?,
        currentTarget: String?,
        currentScanKind: String?
    ) {
        runtimeScanSession = RuntimeScanSessionSnapshot(
            scanStartTime: scanStartTime,
            currentScanPhase: currentScanPhase,
            currentTarget: currentTarget,
            currentScanKind: currentScanKind
        )
        runtimeBootstrapSnapshot.runtimeScanSession = runtimeScanSession
    }

    func clearScanSession() {
        updateScanSession(
            scanStartTime: nil,
            currentScanPhase: nil,
            currentTarget: nil,
            currentScanKind: nil
        )
        scanStageDescription = "Ready to scan"
    }

    func updateScanStage(_ description: String) {
        scanStageDescription = description
    }

    func emitScanStopped() {
        eventRouter.emit(.scanStopped(RuntimeScanStoppedEnvelope()))
    }

    func updateBootstrapSnapshot(
        runtimeIdentity: RuntimeIdentity?,
        runtimeCapabilities: RuntimeCapabilities?,
        runtimeToolchain: RuntimeToolchain?,
        runtimeNetworkState: RuntimeNetworkState?,
        runtimeCustomerProfile: RuntimeCustomerProfile?
    ) {
        self.runtimeIdentity = runtimeIdentity
        self.runtimeCapabilities = runtimeCapabilities
        self.runtimeToolchain = runtimeToolchain
        self.runtimeNetworkState = runtimeNetworkState
        self.runtimeCustomerProfile = runtimeCustomerProfile
        runtimeBootstrapSnapshot = RuntimeBootstrapSnapshot(
            runtimeIdentity: runtimeIdentity,
            runtimeCapabilities: runtimeCapabilities,
            runtimeToolchain: runtimeToolchain,
            runtimeNetworkState: runtimeNetworkState,
            runtimeCustomerProfile: runtimeCustomerProfile,
            runtimeScanSession: runtimeScanSession
        )
    }

    func emitInitialData() {
        guard let bootstrap = runtimeInitialDataEnvelope() else { return }
        eventRouter.emit(.initialData(bootstrap))
    }

    func emitBootstrapState(version: String, hosts: [RuntimeNmapXMLHostSummary]) {
        guard let bootstrap = runtimeBootstrapStateEnvelope(version: version, hosts: hosts) else { return }
        if let initialData = bootstrap.initialData {
            eventRouter.emit(.initialData(initialData))
        }
        for hop in bootstrap.tracerouteHops {
            eventRouter.emitTracerouteHop(hop: hop.hop, ip: hop.ip)
        }
        if let syncState = bootstrap.syncState {
            eventRouter.emit(.syncState(syncState))
        }
    }

    func runtimeBootstrapStateEnvelope(version: String, hosts: [RuntimeNmapXMLHostSummary]) -> RuntimeBootstrapStateEnvelope? {
        guard let initialData = runtimeInitialDataEnvelope(),
              let runtimeNetworkState else {
            return nil
        }

        let syncState = RuntimeSyncStateEnvelope(
            version: version,
            hosts: hosts,
            isScanning: runtimeScanSession.isScanning,
            phase: runtimeScanSession.currentScanPhase,
            target: runtimeScanSession.currentTarget,
            startTime: runtimeScanSession.scanStartTime,
            scanKind: runtimeScanSession.currentScanKind,
            hops: runtimeNetworkState.tracerouteHops.map {
                .object([
                    "hop": .int($0.hop),
                    "ip": .string($0.ip)
                ])
            },
            customerProfile: runtimeCustomerProfileSnapshot.profile,
            autoScan: runtimeAutoScanSnapshot.config
        )

        return RuntimeBootstrapStateEnvelope(
            initialData: initialData,
            syncState: syncState,
            tracerouteHops: runtimeNetworkState.tracerouteHops.map {
                RuntimeTracerouteHopEnvelope(hop: $0.hop, ip: $0.ip)
            }
        )
    }

    func runtimeTransportSessionEnvelope(version: String, hosts: [RuntimeNmapXMLHostSummary]) -> RuntimeTransportSessionEnvelope {
        RuntimeTransportSessionEnvelope(
            bootstrapState: runtimeBootstrapStateEnvelope(version: version, hosts: hosts),
            history: runtimeHistoryDataEnvelope(),
            reports: runtimeReportsDataEnvelope(),
            customerProfile: runtimeCustomerProfile,
            googleDriveStatus: runtimeGoogleDriveStatusEnvelope(),
            autoScanConfig: runtimeAutoScanConfigEnvelope()
        )
    }

    func runtimeInitialDataEnvelope() -> RuntimeInitialDataEnvelope? {
        guard let runtimeNetworkState else { return nil }
        guard let runtimeCustomerProfile else { return nil }
        return RuntimeInitialDataEnvelope(
            network: RuntimeNetworkSnapshot(
                localIP: runtimeNetworkState.localIP,
                mask: runtimeNetworkState.mask,
                cidr: runtimeNetworkState.cidr,
                publicIP: runtimeNetworkState.publicIP
            ),
            publicIP: runtimeNetworkState.publicIP,
            customerProfile: runtimeCustomerProfile,
            googleDrive: runtimeGoogleDriveSnapshot.config,
            autoScan: runtimeAutoScanSnapshot.config
        )
    }

    func emitTracerouteHops() {
        guard let runtimeNetworkState else { return }
        for hop in runtimeNetworkState.tracerouteHops {
            eventRouter.emitTracerouteHop(hop: hop.hop, ip: hop.ip)
        }
    }

    func emitSyncState(version: String, hosts: [RuntimeNmapXMLHostSummary]) {
        eventRouter.emit(.syncState(RuntimeSyncStateEnvelope(
            version: version,
            hosts: hosts,
            isScanning: runtimeScanSession.isScanning,
            phase: runtimeScanSession.currentScanPhase,
            target: runtimeScanSession.currentTarget,
            startTime: runtimeScanSession.scanStartTime,
            scanKind: runtimeScanSession.currentScanKind,
            hops: (runtimeNetworkState?.tracerouteHops ?? []).map {
                .object([
                    "hop": .int($0.hop),
                    "ip": .string($0.ip)
                ])
            },
            customerProfile: runtimeCustomerProfileSnapshot.profile,
            autoScan: runtimeAutoScanSnapshot.config
        )))
    }

    func refreshDataSnapshot(from dataDirectory: URL) {
        runtimeDataSnapshot = RuntimeDataSnapshot(
            history: RuntimeMetadataStore.loadHistory(from: dataDirectory),
            reports: RuntimeMetadataStore.loadReportsSnapshot(
                reportsDirectory: dataDirectory.appendingPathComponent("reports_archive"),
                historyPath: dataDirectory.appendingPathComponent("history.json")
            ).reports
        )
    }

    func emitHistoryData() {
        if let history = runtimeHistoryDataEnvelope() {
            eventRouter.emit(.historyData(history))
        }
    }

    func emitReportsData() {
        if let reports = runtimeReportsDataEnvelope() {
            eventRouter.emit(.reportsData(reports))
        }
    }

    func emitReportsRefresh() {
        eventRouter.emit(.reportsRefresh(RuntimeReportsDataEnvelope(reports: runtimeDataSnapshot.reports)))
        _ = try? lifecycleEventBridge.encodeReportsRefresh()
    }

    func emitScanComplete(
        phase: Int,
        duration: String,
        hostCount: Int? = nil,
        openPortCount: Int? = nil,
        criticalCVECount: Int? = nil,
        lowCVECount: Int? = nil,
        screenshotCount: Int? = nil,
        status: String? = nil
    ) {
        eventRouter.emitScanComplete(
            phase: phase,
            duration: duration,
            hostCount: hostCount,
            openPortCount: openPortCount,
            criticalCVECount: criticalCVECount,
            lowCVECount: lowCVECount,
            screenshotCount: screenshotCount,
            status: status
        )
        _ = try? lifecycleEventBridge.encodeScanComplete(
            phase: phase,
            duration: duration,
            hostCount: hostCount,
            openPortCount: openPortCount,
            criticalCVECount: criticalCVECount,
            lowCVECount: lowCVECount,
            screenshotCount: screenshotCount,
            status: status
        )
    }

    func runtimeHistoryDataEnvelope() -> RuntimeHistoryDataEnvelope? {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let rewritten = runtimeDataSnapshot.history.map { entry in
            RuntimeReportHistoryEntry(
                timestamp: entry.timestamp,
                target: entry.target,
                duration: entry.duration,
                hostCount: entry.hostCount,
                scanKind: entry.scanKind,
                status: entry.status,
                error: entry.error,
                reportUrl: Self.nativeAccessibleURL(entry.reportUrl, dataDirectory: dataDirectory),
                pdfUrl: Self.nativeAccessibleURL(entry.pdfUrl, dataDirectory: dataDirectory),
                xmlUrl: Self.nativeAccessibleURL(entry.xmlUrl, dataDirectory: dataDirectory),
                customerProfile: entry.customerProfile,
                comparison: entry.comparison
            )
        }
        return RuntimeHistoryDataEnvelope(history: rewritten)
    }

    func runtimeReportsDataEnvelope() -> RuntimeReportsDataEnvelope? {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let rewritten = runtimeDataSnapshot.reports.map { entry in
            RuntimeReportListEntry(
                name: entry.name,
                folder: entry.folder,
                url: Self.nativeAccessibleURL(entry.url, dataDirectory: dataDirectory),
                pdfName: entry.pdfName,
                pdfUrl: Self.nativeAccessibleURL(entry.pdfUrl, dataDirectory: dataDirectory),
                xmlName: entry.xmlName,
                xmlUrl: Self.nativeAccessibleURL(entry.xmlUrl, dataDirectory: dataDirectory),
                driveHtmlUrl: entry.driveHtmlUrl,
                drivePdfUrl: entry.drivePdfUrl,
                date: entry.date,
                duration: entry.duration,
                hostCount: entry.hostCount,
                status: entry.status,
                error: entry.error
            )
        }
        return RuntimeReportsDataEnvelope(reports: rewritten)
    }

    private static func nativeAccessibleURL(_ path: String?, dataDirectory: URL) -> String? {
        guard let path, !path.isEmpty else { return path }
        if path.hasPrefix("file:") || path.hasPrefix("http://") || path.hasPrefix("https://") {
            return path
        }
        if let fileURL = ReportGenerator.resolveFileURL(forReportPath: path, dataDirectory: dataDirectory) {
            return fileURL.absoluteString
        }
        return path
    }

    func refreshAutoScanSnapshot(from dataDirectory: URL, fallbackTarget: String) {
        let configURL = dataDirectory.appendingPathComponent("config.json")
        let json = (try? Data(contentsOf: configURL)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let autoScan = (json?["autoScan"] as? [String: Any]) ?? [:]
        if autoScan.isEmpty {
            runtimeAutoScanSnapshot = RuntimeAutoScanSnapshot(
                enabled: false,
                recurrence: "daily",
                startTime: "01:00",
                target: fallbackTarget,
                config: [:]
            )
            return
        }
        let enabled = autoScan["enabled"] as? Bool ?? false
        let recurrence = autoScan["recurrence"] as? String ?? "daily"
        let startTime = autoScan["startTime"] as? String ?? "01:00"
        let target = autoScan["target"] as? String ?? fallbackTarget
        runtimeAutoScanSnapshot = RuntimeAutoScanSnapshot(
            enabled: enabled,
            recurrence: recurrence,
            startTime: startTime,
            target: target,
            config: enrichedAutoScanConfig(
                enabled: enabled,
                recurrence: recurrence,
                startTime: startTime,
                target: target
            )
        )
    }

    func emitAutoScanConfig() {
        if let autoScan = runtimeAutoScanConfigEnvelope() {
            eventRouter.emit(.autoScanConfig(autoScan))
        }
    }

    func runtimeAutoScanConfigEnvelope() -> RuntimeAutoScanConfigEnvelope? {
        RuntimeAutoScanConfigEnvelope(
            enabled: runtimeAutoScanSnapshot.enabled,
            schedule: runtimeAutoScanSnapshot.recurrence,
            scheduleLabel: runtimeAutoScanSnapshot.recurrence.capitalized,
            config: enrichedAutoScanConfig(
                enabled: runtimeAutoScanSnapshot.enabled,
                recurrence: runtimeAutoScanSnapshot.recurrence,
                startTime: runtimeAutoScanSnapshot.startTime,
                target: runtimeAutoScanSnapshot.target
            )
        )
    }

    func updateAutoScanConfig(
        enabled: Bool,
        recurrence: String,
        startTime: String,
        target: String,
        dataDirectory: URL
    ) {
        let normalizedRecurrence = ["hourly", "daily", "weekly", "monthly"].contains(recurrence) ? recurrence : "daily"
        let normalizedStartTime = startTime.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "01:00" : startTime
        let normalizedTarget = target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? (runtimeNetworkState?.cidr ?? "192.168.1.0/24") : target
        let config = enrichedAutoScanConfig(
            enabled: enabled,
            recurrence: normalizedRecurrence,
            startTime: normalizedStartTime,
            target: normalizedTarget
        )
        let snapshot = RuntimeAutoScanSnapshot(
            enabled: enabled,
            recurrence: normalizedRecurrence,
            startTime: normalizedStartTime,
            target: normalizedTarget,
            config: config
        )
        runtimeAutoScanSnapshot = snapshot
        if case .failure(let error) = RuntimeMetadataStore.persistConfigSection("autoScan", values: config, to: dataDirectory) {
            scanFeedback = "Could not save auto-scan settings: \(error.localizedDescription)"
        }
    }

    private func enrichedAutoScanConfig(
        enabled: Bool,
        recurrence: String,
        startTime: String,
        target: String
    ) -> [String: RuntimeJSONValue] {
        let next = AutoScanSchedule.nextRunDate(enabled: enabled, recurrence: recurrence, startTime: startTime)
        var config: [String: RuntimeJSONValue] = [
            "enabled": .bool(enabled),
            "recurrence": .string(recurrence),
            "startTime": .string(startTime),
            "target": .string(target)
        ]
        if let next {
            config["nextRunAt"] = .string(ISO8601DateFormatter().string(from: next))
            if let label = AutoScanSchedule.formattedNextRun(next) {
                config["nextRunLabel"] = .string(label)
            }
        }
        return config
    }

    func refreshGoogleDriveSnapshot(from dataDirectory: URL) {
        let configURL = dataDirectory.appendingPathComponent("config.json")
        let json = (try? Data(contentsOf: configURL)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let googleDrive = (json?["googleDrive"] as? [String: Any]) ?? [:]
        runtimeGoogleDriveSnapshot = RuntimeGoogleDriveSnapshot(
            enabled: googleDrive["enabled"] as? Bool ?? false,
            folderId: googleDrive["folderId"] as? String ?? "",
            config: googleDrive.toJSONValueMap()
        )
    }

    func emitGoogleDriveStatus() {
        if let googleDrive = runtimeGoogleDriveStatusEnvelope() {
            eventRouter.emit(.googleDriveStatus(googleDrive))
        }
    }

    func runtimeGoogleDriveStatusEnvelope() -> RuntimeGoogleDriveStatusEnvelope? {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let live = googleDriveStatusProvider(dataDirectory)
        var config = runtimeGoogleDriveSnapshot.config
        config["enabled"] = .bool(runtimeGoogleDriveSnapshot.enabled)
        config["folderId"] = .string(runtimeGoogleDriveSnapshot.folderId)
        config["configured"] = .bool(live.configured)
        config["connected"] = .bool(live.connected)
        // Keep a stable enabled/disabled status for the UI envelope; connection detail lives in config.
        let statusText = runtimeGoogleDriveSnapshot.enabled ? "Google Drive enabled" : "Google Drive disabled"
        return RuntimeGoogleDriveStatusEnvelope(
            success: live.success || !runtimeGoogleDriveSnapshot.enabled,
            status: statusText,
            config: config
        )
    }

    func updateGoogleDriveSettings(enabled: Bool, folderId: String, dataDirectory: URL) {
        let normalizedFolderId = folderId.trimmingCharacters(in: .whitespacesAndNewlines)
        let snapshot = RuntimeGoogleDriveSnapshot(
            enabled: enabled,
            folderId: normalizedFolderId,
            config: [
                "enabled": .bool(enabled),
                "folderId": .string(normalizedFolderId)
            ]
        )
        runtimeGoogleDriveSnapshot = snapshot
        if case .failure(let error) = RuntimeMetadataStore.persistConfigSection("googleDrive", values: snapshot.config, to: dataDirectory) {
            scanFeedback = "Could not save Google Drive settings: \(error.localizedDescription)"
        }
    }

    func emitGoogleDriveAuthURL(success: Bool, url: String?, status: String) {
        eventRouter.emitGoogleDriveAuthURL(success: success, url: url, status: status)
    }

    func refreshCustomerProfileSnapshot(from dataDirectory: URL, networkState: RuntimeNetworkState?) {
        let prefix = RuntimeMetadataStore.loadCustomerProfilePrefix(from: dataDirectory)
        customerRegistry = CustomerRegistry.load(from: dataDirectory)
        customerResolution = customerRegistry.resolvedCustomer(network: networkState)
        let customer: CustomerRecord?
        switch customerResolution { case .assigned(let record, _): customer = record; default: customer = nil }
        let profile = RuntimeCustomerProfile.current(prefix: customer?.reportPrefix ?? prefix, networkState: networkState, customer: customer)
        runtimeCustomerProfileSnapshot = RuntimeCustomerProfileSnapshot(prefix: prefix, profile: profile)
        runtimeCustomerProfile = profile
        runtimeBootstrapSnapshot.runtimeCustomerProfile = profile
    }

    func createCustomer(name: String, networkState: RuntimeNetworkState?, dataDirectory: URL) throws {
        let cleanedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanedName.count >= 2 else { throw CustomerRegistryError.invalidName }
        guard !customerRegistry.customers.contains(where: { $0.name.caseInsensitiveCompare(cleanedName) == .orderedSame }) else { throw CustomerRegistryError.duplicateName }
        guard !cleanedName.contains("/"), !cleanedName.contains("\\"), !cleanedName.contains(".."),
              cleanedName.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw CustomerRegistryError.invalidName
        }
        let record = CustomerRecord(name: cleanedName, reportPrefix: RuntimeReportNaming.sanitizeSegment(cleanedName.uppercased(), fallback: "CUSTOMER"), publicIPs: [networkState?.publicIP].compactMap { $0 }, cidrs: [networkState?.cidr].compactMap { $0 })
        customerRegistry.customers.append(record)
        customerRegistry.activeCustomerID = record.id
        try customerRegistry.persist(to: dataDirectory)
        refreshCustomerProfileSnapshot(from: dataDirectory, networkState: networkState)
    }

    func selectCustomer(_ id: UUID?, networkState: RuntimeNetworkState?, dataDirectory: URL) throws {
        guard id == nil || customerRegistry.customers.contains(where: { $0.id == id }) else { throw CustomerRegistryError.unknownCustomer }
        customerRegistry.activeCustomerID = id
        try customerRegistry.persist(to: dataDirectory)
        refreshCustomerProfileSnapshot(from: dataDirectory, networkState: networkState)
    }

    func updateCustomerProfilePrefix(_ prefix: String, networkState: RuntimeNetworkState?, dataDirectory: URL) {
        let normalizedPrefix = prefix.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "CSP" : prefix
        let profile = RuntimeCustomerProfile.current(prefix: normalizedPrefix, networkState: networkState)
        runtimeCustomerProfileSnapshot = RuntimeCustomerProfileSnapshot(prefix: normalizedPrefix, profile: profile)
        runtimeCustomerProfile = profile
        runtimeBootstrapSnapshot.runtimeCustomerProfile = profile
        persistCustomerProfilePrefix(normalizedPrefix, dataDirectory: dataDirectory)
    }

    func emitCustomerProfile() {
        guard let profile = runtimeCustomerProfileSnapshot.profile else { return }
        eventRouter.emit(.customerProfile(profile))
    }
}

enum CustomerRegistryError: LocalizedError { case invalidName, duplicateName, unknownCustomer
    var errorDescription: String? { switch self { case .invalidName: return "Customer name must contain at least two characters"; case .duplicateName: return "A customer with this name already exists"; case .unknownCustomer: return "The selected customer no longer exists" } }
}

private extension AppSessionState {
    func persistCustomerProfilePrefix(_ prefix: String, dataDirectory: URL) {
        if case .failure(let error) = RuntimeMetadataStore.persistConfigSection(
            "customerProfile",
            values: ["prefix": .string(prefix)],
            to: dataDirectory
        ) {
            scanFeedback = "Could not save customer settings: \(error.localizedDescription)"
        }
    }
}

private extension Dictionary where Key == String, Value == Any {
    func toJSONValueMap() -> [String: RuntimeJSONValue] {
        reduce(into: [:]) { result, element in
            if let value = RuntimeJSONValue(jsonValue: element.value) {
                result[element.key] = value
            }
        }
    }
}
