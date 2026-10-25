import GoogleDriveCore
import AppKit
import Foundation
import ServiceManagement
import SwiftUI
import RuntimeContracts

private extension String {
    var nilIfEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var activeScanCoordinator: ScanCoordinator?
    private var activeScanLock: ScanRunLock?
    private var scanGeneration: UInt64 = 0
    private let runtimeMenuPresenter = RuntimeMenuPresenter()
    private let runtimeAlertPresenter = RuntimeAlertPresenter()
    private let appCommandController = AppCommandController()
    private let appMenuBuilder = AppMenuBuilder()
    private let launchAtLoginController = LaunchAtLoginController()
    let sessionState = AppSessionState()
    let preferencesStore = PreferencesStore()
    private lazy var lifecycleController = RuntimeLifecycleController(sessionState: sessionState)
    /// Task handle for privilege-helper status refreshes (distinct from
    /// lifecycle capability polling, which now lives in RuntimeLifecycleController).
    private var helperStatusRefreshTask: Task<Void, Never>?
    private lazy var appTerminationController = AppTerminationController()

    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if ScheduledScanRunner.isScheduledScanInvocation {
            NSApp.setActivationPolicy(.prohibited)
            Task {
                await ScheduledScanRunner.runAndExit()
            }
            return
        }

        NSApp.setActivationPolicy(.regular)
        // App stays a normal user process. Privileged nmap runs via helper when needed.
        _ = PrivilegeElevationController.relaunchAsRootIfNeeded()
        RuntimeDiagnosticsLogger.log(
            "Application did finish launching as user euid=\(geteuid()) privileged helper probe deferred"
        )
        let fallbackIdentity = RuntimeIdentity.localFallback(version: RuntimeIdentity.productVersion())
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        RuntimeDiagnosticsLogger.configure(dataDirectory: dataDirectory)
        try? FileManager.default.createDirectory(
            at: RuntimeSettingsStore.currentRuntimeWorkDirectoryURL(),
            withIntermediateDirectories: true
        )
        Self.copyBundledStylesheetIfNeeded()
        RuntimeDiagnosticsLogger.log("Application did finish launching")
        let startupIdentity = RuntimeMetadataStore.loadIdentity(from: dataDirectory) ?? fallbackIdentity
        let toolchain = RuntimeMetadataStore.loadToolchain(from: dataDirectory) ?? RuntimeToolchain.current()
        let capabilities = RuntimeMetadataStore.loadCapabilities(from: dataDirectory) ?? RuntimeCapabilities(
            googleDriveHelperAvailable: toolchain.googleDriveHelperPath != nil,
            arpScanAvailable: ["/opt/homebrew/bin/arp-scan", "/usr/local/bin/arp-scan", "/usr/sbin/arp-scan"].contains(where: { FileManager.default.isExecutableFile(atPath: $0) }),
            vulnersAvailable: FileManager.default.fileExists(atPath: RuntimeVulners.scriptPath()),
            gowitnessAvailable: GowitnessManager.resolvedBinaryURL() != nil,
            privilegedHelperAvailable: false
        )
        let networkState = RuntimeMetadataStore.loadNetworkState(from: dataDirectory)
        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: startupIdentity,
            runtimeCapabilities: capabilities,
            runtimeToolchain: toolchain,
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: RuntimeMetadataStore.loadCustomerProfile(from: dataDirectory)
                ?? RuntimeCustomerProfile.current(
                    prefix: RuntimeMetadataStore.loadCustomerProfilePrefix(from: dataDirectory),
                    networkState: networkState
                )
        )
        sessionState.refreshDataSnapshot(from: dataDirectory)
        sessionState.refreshAutoScanSnapshot(from: dataDirectory, fallbackTarget: networkState?.cidr ?? "192.168.1.0/24")
        sessionState.refreshGoogleDriveSnapshot(from: dataDirectory)
        sessionState.refreshCustomerProfileSnapshot(from: dataDirectory, networkState: networkState)
        RuntimeMetadataStore.persistIdentity(startupIdentity, to: dataDirectory)
        RuntimeMetadataStore.persistCapabilities(capabilities, to: dataDirectory)
        RuntimeMetadataStore.persistToolchain(toolchain, to: dataDirectory)
        Task {
            let freshNetworkState = await RuntimeNetworkState.current()
            await MainActor.run {
                RuntimeDiagnosticsLogger.log("Network state resolved localIP=\(freshNetworkState.localIP) mask=\(freshNetworkState.mask) cidr=\(freshNetworkState.cidr) publicIP=\(freshNetworkState.publicIP) hops=\(freshNetworkState.tracerouteHops.count)")
                let refreshedCustomerProfile = RuntimeCustomerProfile.current(
                    prefix: RuntimeMetadataStore.loadCustomerProfilePrefix(from: dataDirectory),
                    networkState: freshNetworkState
                )
                self.sessionState.updateBootstrapSnapshot(
                    runtimeIdentity: self.sessionState.runtimeIdentity,
                    runtimeCapabilities: self.sessionState.runtimeCapabilities,
                    runtimeToolchain: self.sessionState.runtimeToolchain,
                    runtimeNetworkState: freshNetworkState,
                    runtimeCustomerProfile: refreshedCustomerProfile
                )
                self.sessionState.refreshAutoScanSnapshot(from: dataDirectory, fallbackTarget: freshNetworkState.cidr)
                self.sessionState.refreshCustomerProfileSnapshot(from: dataDirectory, networkState: freshNetworkState)
                self.sessionState.emitInitialData()
                self.sessionState.emitSyncState(
                    version: RuntimeIdentity.productVersion(),
                    hosts: []
                )
                self.sessionState.emitTracerouteHops()
                self.sessionState.emitAutoScanConfig()
                self.sessionState.emitCustomerProfile()
                self.emitCurrentRuntimeSnapshotToWebView()
            }
            RuntimeMetadataStore.persistNetworkState(freshNetworkState, to: dataDirectory)
            if let runtimeCustomerProfile = self.sessionState.runtimeCustomerProfile {
                RuntimeMetadataStore.persistCustomerProfile(runtimeCustomerProfile, to: dataDirectory)
            }
        }
        lifecycleController.onReadinessChange = { [weak self] in
            self?.syncRuntimeMenuState()
        }
        lifecycleController.onPrivilegeHelperStatusRefresh = { [weak self] in
            self?.emitPrivilegeHelperStatus()
        }
        lifecycleController.startStartupSequence(dataDirectory: dataDirectory)
        setupStatusItem()
        syncLaunchAtLoginState()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first?.makeKeyAndOrderFront(nil)
        }
        return true
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        guard let button = statusItem?.button else { return }
        button.imagePosition = .imageOnly
        button.toolTip = "NmapUI"

        let runtimeStatusItem = NSMenuItem(title: "Native: Starting...", action: nil, keyEquivalent: "")
        runtimeStatusItem.isEnabled = false

        let openItem = NSMenuItem(title: "Starting NmapUI...", action: #selector(openApp), keyEquivalent: "o")
        openItem.isEnabled = false

        let aboutItem = NSMenuItem(title: "About NmapUI", action: #selector(showAbout), keyEquivalent: "")

        let preferencesItem = NSMenuItem(title: "Preferences...", action: #selector(openPreferences), keyEquivalent: ",")

        let restartItem = NSMenuItem(title: "Refresh Native State", action: #selector(restartRuntime), keyEquivalent: "r")

        let dataDirectoryItem = NSMenuItem(title: "Open Data Folder", action: #selector(openDataDirectory), keyEquivalent: "")

        let loginItem = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin), keyEquivalent: "")

        let uninstallItem = NSMenuItem(title: "Uninstall NmapUI", action: #selector(uninstallApp), keyEquivalent: "")

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q")

        let menu = appMenuBuilder.buildMenu(
            target: self,
            onRuntimeStatusItem: runtimeStatusItem,
            onOpenItem: openItem,
            onAboutItem: aboutItem,
            onPreferencesItem: preferencesItem,
            onRestartItem: restartItem,
            onDataDirectoryItem: dataDirectoryItem,
            onLaunchAtLoginItem: loginItem,
            onUninstallItem: uninstallItem,
            onQuitItem: quitItem
        )
        statusItem?.menu = menu
        runtimeMenuPresenter.configureStatusItem(
            statusItem,
            runtimeStatusMenuItem: runtimeStatusItem,
            openAppMenuItem: openItem,
            openDataDirectoryMenuItem: dataDirectoryItem,
            restartRuntimeMenuItem: restartItem,
            launchAtLoginMenuItem: loginItem
        )
    }

    private func syncLaunchAtLoginState() {
        launchAtLoginController.syncLaunchAtLoginState(runtimeMenuPresenter)
    }

    @objc private func openApp() {
        appCommandController.openApp()
    }

    @objc private func openPreferences() {
        appCommandController.openPreferences()
    }

    @objc private func showAbout() {
        appCommandController.showAbout()
    }

    @objc func openDataDirectory() {
        appCommandController.openDataDirectory()
    }

    @objc private func restartRuntime() {
        refreshNativeStateAfterPreferenceChange()
    }

    @objc func savePreferences() {
        savePreferencesAndRefreshNativeState()
    }

    @objc func resetPreferences() {
        preferencesStore.resetToDefaults()
        refreshNativeStateAfterPreferenceChange()
    }

    @objc private func toggleLaunchAtLogin() {
        launchAtLoginController.toggleLaunchAtLogin()
        syncLaunchAtLoginState()
    }

    @objc private func uninstallApp() {
        appTerminationController.uninstallApp()
    }

    @objc private func quitApp() {
        appTerminationController.quitApp()
    }

    @objc func chooseDataDirectory() {
        chooseDataDirectoryForSwiftUI()
    }

    private func savePreferencesAndRefreshNativeState() {
        if preferencesStore.save() {
            refreshNativeStateAfterPreferenceChange()
        } else {
            runtimeAlertPresenter.presentPreferencesSaveFailureAlert()
        }
    }

    private func refreshNativeStateAfterPreferenceChange() {
        RuntimeDiagnosticsLogger.log("Native preferences saved; legacy runtime restart is not required")
        refreshRuntimeCapabilities()
        markNativeRuntimeReady()
    }

    func startQuickScanFromNativeShell() {
        let target = sessionState.runtimeNetworkState?.cidr
            ?? sessionState.runtimeAutoScanSnapshot.target.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            ?? "192.168.1.0/24"
        startScanFromNativeShell(target: target, scanKind: "quick", vpnHelper: false)
    }

    func startScanFromNativeShell(target: String, scanKind: String, vpnHelper: Bool) {
        guard !sessionState.runtimeScanSession.isScanning else {
            RuntimeDiagnosticsLogger.log("Ignoring duplicate native scan request while a scan is already active")
            return
        }
        let normalizedTarget = normalizedScanTarget(target)
        sessionState.refreshCustomerProfileSnapshot(from: RuntimeSettingsStore.currentDataDirectoryURL(), networkState: sessionState.runtimeNetworkState)
        switch sessionState.customerResolution {
        case .assigned:
            break
        case .unassigned:
            sessionState.scanFeedback = "Assign a customer before scanning so reports are filed correctly"
            return
        case .ambiguous(let customers):
            sessionState.scanFeedback = "Customer match is ambiguous: \(customers.map(\.name).joined(separator: ", "))"
            return
        }
        RuntimeDiagnosticsLogger.log("Native scan requested target=\(normalizedTarget) scanKind=\(scanKind) vpnHelper=\(vpnHelper)")
        sessionState.currentScanReportArtifacts = nil
        sessionState.latestScreenshotURLs = []
        sessionState.updateScanSession(
            scanStartTime: ISO8601DateFormatter().string(from: Date()),
            currentScanPhase: 1,
            currentTarget: normalizedTarget,
            currentScanKind: scanKind
        )
        sessionState.updateScanStage("Preparing \(scanKind) scan for \(normalizedTarget)")
        sessionState.scanFeedback = sessionState.scanStageDescription
        Task { [weak self] in
            guard let self else { return }
            _ = await self.startSwiftManagedScan(
                target: normalizedTarget,
                usePn: false,
                vpnHelper: vpnHelper,
                scanKind: scanKind
            )
        }
    }

    func startSwiftManagedScan(target: String, usePn: Bool, vpnHelper: Bool, scanKind: String) async -> ScanCoordinator.ScanResult {
        scanGeneration &+= 1
        let generation = scanGeneration
        let normalizedTarget = normalizedScanTarget(target)
        if !sessionState.runtimeScanSession.isScanning {
            sessionState.updateScanSession(
                scanStartTime: ISO8601DateFormatter().string(from: Date()),
                currentScanPhase: 1,
                currentTarget: normalizedTarget,
                currentScanKind: scanKind
            )
            sessionState.updateScanStage("Preparing \(scanKind) scan for \(normalizedTarget)")
            sessionState.scanFeedback = sessionState.scanStageDescription
        }
        defer {
            if scanGeneration == generation {
                sessionState.clearScanSession()
            }
        }
        do {
            _ = try ScanTargetValidator.validate(normalizedTarget)
        } catch {
            sessionState.scanFeedback = error.localizedDescription
            return ScanCoordinator.ScanResult(phase: .phase1, duration: "0.00", xmlPath: nil, summary: nil, completed: false, error: error.localizedDescription)
        }

        // Refresh network identity immediately before resolving the customer
        // and creating report artifacts. The app can stay open across a VPN or
        // VLAN transition.
        let freshNetworkState = await RuntimeNetworkState.current()
        guard generation == scanGeneration else {
            return ScanCoordinator.ScanResult(phase: .phase1, duration: "0.00", xmlPath: nil, summary: nil, completed: false, error: "Scan superseded")
        }
        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: sessionState.runtimeIdentity,
            runtimeCapabilities: sessionState.runtimeCapabilities,
            runtimeToolchain: sessionState.runtimeToolchain,
            runtimeNetworkState: freshNetworkState,
            runtimeCustomerProfile: sessionState.runtimeCustomerProfile
        )
        sessionState.refreshCustomerProfileSnapshot(from: RuntimeSettingsStore.currentDataDirectoryURL(), networkState: freshNetworkState)
        RuntimeMetadataStore.persistNetworkState(freshNetworkState, to: RuntimeSettingsStore.currentDataDirectoryURL())
        switch sessionState.customerResolution {
        case .assigned:
            break
        case .unassigned:
            let message = "Assign a customer before scanning so reports are filed correctly"
            sessionState.scanFeedback = message
            return ScanCoordinator.ScanResult(phase: .phase1, duration: "0.00", xmlPath: nil, summary: nil, completed: false, error: message)
        case .ambiguous(let customers):
            let message = "Customer match is ambiguous: \(customers.map(\.name).joined(separator: ", "))"
            sessionState.scanFeedback = message
            return ScanCoordinator.ScanResult(phase: .phase1, duration: "0.00", xmlPath: nil, summary: nil, completed: false, error: message)
        }
        guard let scanLock = ScanRunLock.acquire(in: RuntimeSettingsStore.currentDataDirectoryURL()) else {
            let message = "Another scan is already running. Wait for it to finish before starting a new scan."
            sessionState.scanFeedback = message
            return ScanCoordinator.ScanResult(phase: .phase1, duration: "0.00", xmlPath: nil, summary: nil, completed: false, error: message)
        }
        activeScanLock = scanLock
        var completionWarnings: [String] = []
        if scanKind != "quick", GowitnessManager.resolvedBinaryURL() == nil {
            sessionState.scanFeedback = "Installing required GoWitness screenshot capability..."
            do {
                _ = try await GowitnessManager.install()
                sessionState.runtimeToolchain = RuntimeToolchain.current()
                refreshRuntimeCapabilities()
            } catch {
                completionWarnings.append("GoWitness installation failed")
                sessionState.scanFeedback = "Degraded: GoWitness installation failed; screenshots will be unavailable (\(error.localizedDescription))"
                RuntimeDiagnosticsLogger.error("GoWitness unavailable for scan: \(error.localizedDescription)")
            }
        }
        RuntimeDiagnosticsLogger.log(
            "Starting scan target=\(normalizedTarget) scanKind=\(scanKind) usePn=\(usePn) vpnHelper=\(vpnHelper) euid=\(geteuid()) helperReady=\(PrivilegeHelperClient.isHelperReachable)"
        )
        let request = ScanCoordinator.ScanRequest(
            target: normalizedTarget,
            usePn: usePn || scanKind == "complete",
            vpnHelper: vpnHelper,
            scanKind: ScanCoordinator.ScanKind(scanKind),
            allowInteractivePrivilegePrompt: true
        )
        let coordinator = ScanCoordinator(workDirectory: RuntimeSettingsStore.newScanWorkDirectoryURL())
        activeScanCoordinator = coordinator
        defer {
            if activeScanCoordinator === coordinator {
                activeScanCoordinator = nil
            }
            if activeScanLock === scanLock {
                activeScanLock = nil
            }
        }
        let feedbackTask = Task { @MainActor in
            let startedAt = Date()
            while !Task.isCancelled && sessionState.runtimeScanSession.isScanning {
                let elapsed = String(format: "%.0fs", Date().timeIntervalSince(startedAt))
                sessionState.scanFeedback = "\(sessionState.scanStageDescription) · elapsed \(elapsed)"
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
        sessionState.eventRouter.emitScanLifecycle(
            phase: 1,
            target: normalizedTarget,
            startTime: sessionState.runtimeScanSession.scanStartTime,
            scanKind: scanKind
        )
        let result = await coordinator.runFullScan(
            request,
            onPhaseStarted: { [weak self] phase, description in
                guard let self else { return }
                guard self.scanGeneration == generation else { return }
                self.sessionState.updateScanSession(
                    scanStartTime: self.sessionState.runtimeScanSession.scanStartTime,
                    currentScanPhase: phase.rawValue,
                    currentTarget: normalizedTarget,
                    currentScanKind: scanKind
                )
                self.sessionState.updateScanStage(description)
                self.sessionState.eventRouter.emitScanLifecycle(
                    phase: phase.rawValue,
                    target: normalizedTarget,
                    startTime: self.sessionState.runtimeScanSession.scanStartTime,
                    scanKind: scanKind
                )
            },
            onPhaseCompleted: { [weak self] phaseResult in
                guard phaseResult.phase == .phase1, let summary = phaseResult.summary else { return }
                guard let self else { return }
                guard self.scanGeneration == generation else { return }
                self.sessionState.latestHosts = summary.hosts
                self.sessionState.latestScanStats = RuntimeScanStats.make(from: summary)
                self.sessionState.eventRouter.emitPhaseStats(phase: phaseResult.phase.rawValue, summary: summary)
                RuntimeDiagnosticsLogger.log("Published phase 1 discovery results hosts=\(summary.hostCount)")
            },
            onHostProgress: { [weak self] scannedHosts in
                guard let self else { return }
                guard self.scanGeneration == generation else { return }
                self.sessionState.latestHosts = self.mergedHosts(
                    discovered: self.sessionState.latestHosts,
                    scanned: scannedHosts
                )
                let openPorts = self.sessionState.latestHosts.reduce(0) {
                    $0 + $1.ports.split(separator: ",").filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.count
                }
                self.sessionState.latestScanStats = RuntimeScanStats(
                    hostCount: self.sessionState.latestHosts.count,
                    openPortCount: openPorts,
                    criticalCVECount: self.sessionState.latestScanStats?.criticalCVECount ?? 0,
                    lowCVECount: self.sessionState.latestScanStats?.lowCVECount ?? 0
                )
                RuntimeDiagnosticsLogger.log("Published phase 2 host progress hosts=\(scannedHosts.count) openPorts=\(openPorts)")
            }
        )
        guard scanGeneration == generation else {
            return ScanCoordinator.ScanResult(phase: result.phase, duration: result.duration, xmlPath: nil, summary: nil, completed: false, error: "Scan superseded")
        }
        feedbackTask.cancel()
        if let summary = result.summary {
            sessionState.latestHosts = mergedHosts(discovered: sessionState.latestHosts, scanned: summary.hosts)
            sessionState.latestScanStats = RuntimeScanStats(
                hostCount: sessionState.latestHosts.count,
                openPortCount: summary.openPortCount,
                criticalCVECount: summary.criticalCVECount,
                lowCVECount: summary.lowCVECount
            )
            sessionState.scanFeedback = "Phase \(result.phase.rawValue) complete: \(summary.hostCount) hosts, \(summary.openPortCount) open ports"
            RuntimeDiagnosticsLogger.log("Scan phase \(result.phase.rawValue) completed hosts=\(summary.hostCount) openPorts=\(summary.openPortCount)")
        } else {
            sessionState.scanFeedback = result.error ?? "Scan completed without results"
            RuntimeDiagnosticsLogger.log("Scan phase \(result.phase.rawValue) completed without summary error=\(result.error ?? "none")")
        }
        if let summary = result.summary {
            sessionState.eventRouter.emitPhaseStats(phase: result.phase.rawValue, summary: summary)
        }

        let shouldGenerateReport = result.completed
            && result.xmlPath != nil
            && result.phase != .phase1
        var reportGenerated = false
        if shouldGenerateReport, let xmlPath = result.xmlPath {
            if scanKind != "quick", GowitnessManager.resolvedBinaryURL() != nil {
                sessionState.scanFeedback = "Capturing HTTP/S screenshots with GoWitness..."
                do {
                    let workDirectory = coordinator.workDirectoryURL
                    let screenshots = try await Task.detached(priority: .utility) {
                        try GowitnessCapture.capture(nmapXML: xmlPath, workDirectory: workDirectory)
                    }.value
                    sessionState.latestScreenshotURLs = screenshots
                    RuntimeDiagnosticsLogger.log("GoWitness captured screenshots count=\(screenshots.count)")
                } catch {
                    completionWarnings.append("GoWitness capture failed")
                    sessionState.scanFeedback = "Degraded: scan completed but GoWitness capture failed (\(error.localizedDescription))"
                    RuntimeDiagnosticsLogger.error("GoWitness capture failed: \(error.localizedDescription)")
                }
            }
            let generatedReport = await generateAndPublishReport(
                xmlPath: xmlPath,
                target: normalizedTarget,
                duration: result.duration,
                hostCount: result.summary?.hostCount ?? 0,
                scanKind: scanKind,
                status: "success",
                error: nil
            )
            if generatedReport == nil {
                completionWarnings.append("Report generation failed")
            } else if scanKind == "complete", generatedReport?.pdfURL == nil {
                completionWarnings.append("PDF renderer unavailable; HTML/XML report saved")
            }
            reportGenerated = generatedReport != nil
        }

        if !reportGenerated {
            let profile = sessionState.runtimeCustomerProfile
                ?? RuntimeCustomerProfile.current(
                    prefix: sessionState.runtimeCustomerProfileSnapshot.prefix,
                    networkState: sessionState.runtimeNetworkState
                )
            let status: String
            let historyError: String?
            if result.completed {
                status = shouldGenerateReport ? "failed" : "success"
                historyError = shouldGenerateReport ? "Report generation failed" : nil
            } else if result.error == "Scan cancelled" {
                status = "cancelled"
                historyError = result.error
            } else {
                status = "failed"
                historyError = result.error ?? "Scan failed without a result"
            }
            ReportGenerator.recordHistoryOnly(
                dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL(),
                customerProfile: profile,
                target: normalizedTarget,
                duration: result.duration,
                hostCount: result.summary?.hostCount ?? 0,
                scanKind: scanKind,
                status: status,
                error: historyError
            )
        }

        sessionState.emitScanComplete(
            phase: result.phase.rawValue,
            duration: result.duration,
            hostCount: result.summary?.hostCount,
            openPortCount: result.summary?.openPortCount,
            criticalCVECount: result.summary?.criticalCVECount,
            lowCVECount: result.summary?.lowCVECount,
            screenshotCount: sessionState.latestScreenshotURLs.count,
            status: result.completed ? (completionWarnings.isEmpty ? "success" : "completedWithWarnings") : (result.error == "Scan cancelled" ? "cancelled" : "failed")
        )
        if result.completed {
            sessionState.scanFeedback = completionWarnings.isEmpty
                ? "Scan complete in \(result.duration)"
                : "Scan complete with warnings: \(completionWarnings.joined(separator: "; "))"
        }
        sessionState.emitSyncState(
            version: RuntimeIdentity.productVersion(),
            hosts: result.summary?.hosts ?? []
        )
        sessionState.refreshDataSnapshot(from: RuntimeSettingsStore.currentDataDirectoryURL())
        sessionState.emitHistoryData()
        sessionState.emitReportsData()
        emitPrivilegeHelperStatus()
        return result
    }

    func generateAndPublishReport(
        xmlPath: URL,
        target: String,
        duration: String,
        hostCount: Int,
        scanKind: String,
        status: String,
        error: String?
    ) async -> ReportGenerator.GeneratedReport? {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let profile = sessionState.runtimeCustomerProfile
            ?? RuntimeCustomerProfile.current(
                prefix: sessionState.runtimeCustomerProfileSnapshot.prefix,
                networkState: sessionState.runtimeNetworkState
            )
        do {
            let screenshotURLs = sessionState.latestScreenshotURLs
            let generated = try await Task.detached(priority: .utility) {
                try ReportGenerator.generate(
                    xmlSource: xmlPath,
                    dataDirectory: dataDirectory,
                    customerProfile: profile,
                    target: target,
                    duration: duration,
                    hostCount: hostCount,
                    scanKind: scanKind,
                    screenshotURLs: screenshotURLs,
                    status: status,
                    error: error
                )
            }.value
            RuntimeDiagnosticsLogger.log("Report generated html=\(generated.htmlURL.path) pdf=\(generated.pdfURL?.path ?? "none")")
            sessionState.currentScanReportArtifacts = CurrentScanReportArtifacts(
                name: generated.htmlURL.lastPathComponent,
                htmlPath: generated.fileReportURL,
                pdfPath: generated.filePdfURL,
                xmlPath: generated.fileXmlURL
            )
            openCompletedManualReportArtifacts(generated)
            sessionState.eventRouter.emitReportReady(
                reportUrl: generated.fileReportURL,
                pdfUrl: generated.filePdfURL,
                xmlUrl: generated.fileXmlURL,
                customerProfile: profile
            )
            sessionState.refreshDataSnapshot(from: dataDirectory)
            sessionState.emitReportsRefresh()
            sessionState.emitHistoryData()
            sessionState.emitReportsData()

            copyReportToDesktopIfEnabled(generated: generated, dataDirectory: dataDirectory)

            if sessionState.runtimeGoogleDriveSnapshot.enabled {
                await uploadReportToGoogleDriveIfEnabled(generated: generated, dataDirectory: dataDirectory)
            }
            return generated
        } catch {
            RuntimeDiagnosticsLogger.error("Report generation failed: \(error.localizedDescription)")
            sessionState.scanFeedback = "Scan finished, but report generation failed: \(error.localizedDescription)"
            return nil
        }
    }

    private func copyReportToDesktopIfEnabled(
        generated: ReportGenerator.GeneratedReport,
        dataDirectory: URL
    ) {
        let configURL = dataDirectory.appendingPathComponent("config.json")
        let json = (try? Data(contentsOf: configURL)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let reports = (json?["reports"] as? [String: Any]) ?? [:]
        let saveToDesktop = reports["saveToDesktop"] as? Bool ?? false
        guard saveToDesktop else { return }

        let desktop = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Desktop")
        let destinationRoot = desktop.appendingPathComponent("NmapUI Reports", isDirectory: true)
            .appendingPathComponent(generated.folderName, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: destinationRoot, withIntermediateDirectories: true)
            for source in [generated.htmlURL, generated.xmlURL, generated.pdfURL].compactMap({ $0 }) {
                let dest = destinationRoot.appendingPathComponent(source.lastPathComponent)
                if FileManager.default.fileExists(atPath: dest.path) {
                    try FileManager.default.removeItem(at: dest)
                }
                try FileManager.default.copyItem(at: source, to: dest)
            }
            RuntimeDiagnosticsLogger.log("Copied report artifacts to \(destinationRoot.path)")
        } catch {
            RuntimeDiagnosticsLogger.error("Desktop report copy failed: \(error.localizedDescription)")
        }
    }

    private func uploadReportToGoogleDriveIfEnabled(
        generated: ReportGenerator.GeneratedReport,
        dataDirectory: URL
    ) async {
        let status = GoogleDriveService.status(dataDirectory: dataDirectory)
        // An expired token can still refresh during upload; status remains network-free.
        guard status.success && status.configured else {
            RuntimeDiagnosticsLogger.log("Skipping Google Drive upload: credentials unavailable (\(status.status))")
            return
        }

        var files = [generated.htmlURL, generated.xmlURL]
        if let pdf = generated.pdfURL {
            files.append(pdf)
        }
        let result = GoogleDriveService.uploadReportArtifacts(
            files: files,
            dataDirectory: dataDirectory,
            folderId: sessionState.runtimeGoogleDriveSnapshot.folderId
        )
        RuntimeDiagnosticsLogger.log(
            "Google Drive upload success=\(result.success) status=\(result.status) error=\(result.error ?? "none")"
        )

        if result.success {
            let links = result.uploaded.compactMap { row -> RuntimeReportDriveFile? in
                guard let name = row["name"], let id = row["id"] else { return nil }
                return RuntimeReportDriveFile(name: name, webViewLink: row["webViewLink"] ?? "", id: id)
            }
            RuntimeMetadataStore.persistReportMetadata(
                RuntimeReportMetadata(
                    uploadedAt: ISO8601DateFormatter().string(from: Date()),
                    folderId: result.folderId ?? sessionState.runtimeGoogleDriveSnapshot.folderId.nilIfEmpty,
                    dayFolderId: nil,
                    links: links
                ),
                to: generated.htmlURL
            )
        }

        let payload: [String: Any] = [
            "success": result.success,
            "status": result.status,
            "error": result.error as Any,
            "uploadedCount": result.uploaded.count
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload),
           let json = String(data: data, encoding: .utf8) {
            WebPortalViewCoordinatorBridge.shared.emitRuntimeEvent(
                event: "google_drive_upload_complete",
                payloadJSON: json
            )
        }
        sessionState.emitGoogleDriveStatus()
    }

    func emitPrivilegeHelperStatus() {
        helperStatusRefreshTask?.cancel()
        helperStatusRefreshTask = Task { [weak self] in
            let result = await Task.detached(priority: .utility) {
                (RuntimeCapabilities.current(), PrivilegeHelperClient.isCurrentHelperReachable)
            }.value
            guard let self, !Task.isCancelled else { return }
            self.sessionState.runtimeCapabilities = result.0
            RuntimeMetadataStore.persistCapabilities(
                result.0,
                to: RuntimeSettingsStore.currentDataDirectoryURL()
            )
            let payload: [String: Any] = [
                "ready": result.1,
                "status": result.1 ? "Privileged scanner helper is ready" : "Helper not installed or outdated — full scans will prompt once for admin",
                "machServiceName": PrivilegeHelperClient.machServiceName,
                "protocolVersion": NmapPrivilegedHelperContract.protocolVersion,
                "installPath": PrivilegeHelperClient.helperInstallPath
            ]
            guard let data = try? JSONSerialization.data(withJSONObject: payload),
                  let json = String(data: data, encoding: .utf8) else { return }
            WebPortalViewCoordinatorBridge.shared.emitRuntimeEvent(event: "privilege_helper_status", payloadJSON: json)
        }
    }

    private func refreshRuntimeCapabilities() {
        lifecycleController.refreshCapabilities()
    }

    @MainActor
    func installPrivilegeHelperFromSettings() {
        Task {
            do {
                try await PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
                RuntimeDiagnosticsLogger.log("Privilege helper installed from Settings")
            } catch {
                PrivilegeElevationController.presentHelperInstallFailure(error)
            }
            emitPrivilegeHelperStatus()
        }
    }

    func openReportPath(_ path: String) {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let resolvedURL: URL?
        if path.hasPrefix("file:") {
            resolvedURL = URL(string: path)
        } else if let reportURL = ReportGenerator.resolveFileURL(forReportPath: path, dataDirectory: dataDirectory) {
            resolvedURL = reportURL
        } else if let remoteURL = URL(string: path), ["http", "https"].contains(remoteURL.scheme?.lowercased() ?? "") {
            resolvedURL = remoteURL
        } else {
            resolvedURL = nil
        }

        guard let resolvedURL else {
            RuntimeDiagnosticsLogger.error("Unable to resolve report artifact path=\(path)")
            sessionState.scanFeedback = "Could not locate this report file"
            return
        }
        guard !resolvedURL.isFileURL || FileManager.default.fileExists(atPath: resolvedURL.path) else {
            RuntimeDiagnosticsLogger.error("Report artifact is missing path=\(resolvedURL.path)")
            sessionState.scanFeedback = "Report file is missing: \(resolvedURL.lastPathComponent)"
            return
        }
        do {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            process.arguments = [resolvedURL.isFileURL ? resolvedURL.path : resolvedURL.absoluteString]
            try process.run()
            RuntimeDiagnosticsLogger.log("Opened report artifact via macOS open path=\(resolvedURL.path)")
        } catch {
            RuntimeDiagnosticsLogger.error("Could not launch report artifact path=\(resolvedURL.path) error=\(error.localizedDescription)")
            sessionState.scanFeedback = "macOS could not open \(resolvedURL.lastPathComponent)"
        }
    }

    private func openCompletedManualReportArtifacts(_ generated: ReportGenerator.GeneratedReport) {
        openReportPath(generated.fileReportURL)
        if let pdfURL = generated.filePdfURL {
            openReportPath(pdfURL)
        }
    }

    @MainActor
    func connectGoogleDriveFromSettings() {
        Task { @MainActor in
            await self.performGoogleDriveConnect()
        }
    }

    @MainActor
    func disconnectGoogleDriveFromSettings() {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let result = GoogleDriveService.disconnect(dataDirectory: dataDirectory)
        RuntimeDiagnosticsLogger.log("Google Drive disconnect success=\(result.success) status=\(result.status ?? "none")")
        sessionState.refreshGoogleDriveSnapshot(from: dataDirectory)
        sessionState.emitGoogleDriveStatus()
        let payload: [String: Any] = [
            "success": result.success,
            "status": result.status ?? (result.success ? "Google Drive disconnected" : (result.error ?? "Disconnect failed")),
            "error": result.error as Any
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload),
           let json = String(data: data, encoding: .utf8) {
            WebPortalViewCoordinatorBridge.shared.emitRuntimeEvent(event: "google_drive_status", payloadJSON: json)
        }
    }

    func saveGoogleDriveSettingsFromNative(enabled: Bool, folderID: String) {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        sessionState.updateGoogleDriveSettings(enabled: enabled, folderId: folderID, dataDirectory: dataDirectory)
        sessionState.emitGoogleDriveStatus()
        RuntimeDiagnosticsLogger.log("Native Google Drive settings saved enabled=\(enabled) folderConfigured=\(!folderID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)")
    }

    func saveGoogleDriveCredentialsFromNative(_ credentialsJSON: String) {
        let result = GoogleDriveService.saveCredentials(credentialsJSON, dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL())
        RuntimeDiagnosticsLogger.log("Google Drive OAuth credentials save success=\(result.success)")
        presentGoogleDriveMessage(result.status ?? result.error ?? "Could not save Google Drive credentials.", isError: !result.success)
        sessionState.emitGoogleDriveStatus()
    }

    func saveAppSettingsFromWeb(_ payload: [String: Any]) {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let saveReportsDesktop = payload["saveReportsDesktop"] as? Bool ?? false
        RuntimeMetadataStore.persistConfigSection(
            "reports",
            values: ["saveToDesktop": .bool(saveReportsDesktop)],
            to: dataDirectory
        )
        if let enabled = payload["googleDriveEnabled"] as? Bool {
            let folderId = payload["googleDriveFolder"] as? String ?? sessionState.runtimeGoogleDriveSnapshot.folderId
            sessionState.updateGoogleDriveSettings(enabled: enabled, folderId: folderId, dataDirectory: dataDirectory)
        }
        RuntimeDiagnosticsLogger.log("App settings saved saveReportsDesktop=\(saveReportsDesktop)")
        sessionState.emitGoogleDriveStatus()
    }

    private func performGoogleDriveConnect() async {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        do {
            let session = try GoogleDriveOAuthSession.start()
            let auth = GoogleDriveService.authURL(dataDirectory: dataDirectory, redirectURI: session.redirectURI)
            guard auth.success, let authURLString = auth.authURL, let authURL = try? DrivePolicy.browserAuthorizationURL(authURLString) else {
                session.cancel(with: .listenFailed)
                presentGoogleDriveMessage(auth.error ?? "Unable to start Google Drive authorization.", isError: true)
                return
            }

            guard let state = URLComponents(url: authURL, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "state" })?.value, !state.isEmpty else {
                session.cancel(with: .invalidCallback)
                presentGoogleDriveMessage("Invalid Google authorization state.", isError: true)
                return
            }
            session.expectState(state)
            presentGoogleDriveMessage("Google authorization opened. Complete sign-in in the browser window.", isError: false)
            guard NSWorkspace.shared.open(authURL) else {
                session.cancel(with: .listenFailed)
                presentGoogleDriveMessage("Could not open your browser for Google sign-in.", isError: true)
                return
            }

            let callback = try await session.waitForCallback(timeoutSeconds: 180)
            let exchange = GoogleDriveService.exchangeCode(
                code: callback.code,
                state: callback.state,
                dataDirectory: dataDirectory
            )
            sessionState.refreshGoogleDriveSnapshot(from: dataDirectory)
            sessionState.emitGoogleDriveStatus()
            if exchange.success {
                // Ensure sync stays enabled after a successful connect.
                sessionState.updateGoogleDriveSettings(
                    enabled: true,
                    folderId: sessionState.runtimeGoogleDriveSnapshot.folderId,
                    dataDirectory: dataDirectory
                )
                sessionState.emitGoogleDriveStatus()
                presentGoogleDriveMessage(exchange.status ?? "Google Drive connected", isError: false)
            } else {
                presentGoogleDriveMessage(exchange.error ?? "Failed to complete Google Drive authorization.", isError: true)
            }
        } catch {
            presentGoogleDriveMessage(error.localizedDescription, isError: true)
            sessionState.emitGoogleDriveStatus()
        }
    }

    private func presentGoogleDriveMessage(_ message: String, isError: Bool) {
        let payload: [String: Any] = [
            "success": !isError,
            "status": message,
            "error": isError ? message : NSNull()
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload),
           let json = String(data: data, encoding: .utf8) {
            WebPortalViewCoordinatorBridge.shared.emitRuntimeEvent(event: "google_drive_status", payloadJSON: json)
        }
    }

    func stopSwiftManagedScan() {
        RuntimeDiagnosticsLogger.log("Stop scan requested")
        scanGeneration &+= 1
        activeScanCoordinator?.cancel()
        sessionState.emitScanStopped()
        sessionState.clearScanSession()
        sessionState.emitSyncState(
            version: RuntimeIdentity.productVersion(),
            hosts: []
        )
    }

    private func normalizedScanTarget(_ target: String) -> String {
        target.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            ?? sessionState.runtimeNetworkState?.cidr
            ?? sessionState.runtimeAutoScanSnapshot.target.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            ?? "192.168.1.0/24"
    }

    private func mergedHosts(
        discovered: [RuntimeNmapXMLHostSummary],
        scanned: [RuntimeNmapXMLHostSummary]
    ) -> [RuntimeNmapXMLHostSummary] {
        var scansByIP = scanned.reduce(into: [String: RuntimeNmapXMLHostSummary]()) { result, host in
            // Grepable Nmap progress may report the same host more than once.
            // Keep the latest report rather than trapping on a duplicate key.
            result[host.ip] = host
        }
        var merged = discovered.map { host in
            guard let scannedHost = scansByIP.removeValue(forKey: host.ip) else { return host }
            return RuntimeNmapXMLHostSummary(
                ip: host.ip,
                mac: scannedHost.mac.isEmpty ? host.mac : scannedHost.mac,
                vendor: scannedHost.vendor.isEmpty ? host.vendor : scannedHost.vendor,
                hostname: scannedHost.hostname.isEmpty ? host.hostname : scannedHost.hostname,
                os: scannedHost.os.isEmpty ? host.os : scannedHost.os,
                latency: scannedHost.latency.isEmpty ? host.latency : scannedHost.latency,
                ports: scannedHost.ports,
                version: scannedHost.version,
                highCVEs: scannedHost.highCVEs,
                lowCVECount: scannedHost.lowCVECount,
                vulnerabilities: scannedHost.vulnerabilities
            )
        }
        merged.append(contentsOf: scansByIP.values.sorted { $0.ip < $1.ip })
        return merged
    }

    func emitCurrentRuntimeSnapshotToWebView() {
        RuntimeDiagnosticsLogger.log("Emitting current runtime snapshot to web dashboard")
        if let networkState = sessionState.runtimeNetworkState {
            WebPortalViewCoordinatorBridge.shared.applyNetworkSnapshot(networkState)
        }
        sessionState.emitInitialData()
        sessionState.emitSyncState(
            version: RuntimeIdentity.productVersion(),
            hosts: []
        )
        sessionState.emitTracerouteHops()
        sessionState.emitHistoryData()
        sessionState.emitReportsData()
        sessionState.emitAutoScanConfig()
        sessionState.emitGoogleDriveStatus()
        sessionState.emitCustomerProfile()
        emitPrivilegeHelperStatus()
    }

    func updateCustomerPrefix(_ prefix: String) {
        sessionState.updateCustomerProfilePrefix(
            prefix,
            networkState: sessionState.runtimeNetworkState,
            dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL()
        )
        sessionState.emitCustomerProfile()
        RuntimeDiagnosticsLogger.log("Customer profile prefix updated prefix=\(sessionState.runtimeCustomerProfileSnapshot.prefix)")
    }

    func createCustomer(_ name: String) {
        do {
            try sessionState.createCustomer(name: name, networkState: sessionState.runtimeNetworkState, dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL())
            sessionState.emitCustomerProfile()
            sessionState.scanFeedback = "Customer \(name) created and assigned"
        } catch { sessionState.scanFeedback = error.localizedDescription }
    }

    func selectCustomer(_ id: UUID?) {
        do {
            try sessionState.selectCustomer(id, networkState: sessionState.runtimeNetworkState, dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL())
            sessionState.emitCustomerProfile()
        } catch { sessionState.scanFeedback = error.localizedDescription }
    }

    func installGowitness() {
        Task { @MainActor in
            sessionState.scanFeedback = "Downloading GoWitness \(GowitnessManager.version)..."
            do {
                let binary = try await GowitnessManager.install()
                sessionState.runtimeToolchain = RuntimeToolchain.current()
                refreshRuntimeCapabilities()
                sessionState.scanFeedback = "GoWitness \(GowitnessManager.version) installed at \(binary.path)"
            } catch {
                sessionState.scanFeedback = error.localizedDescription
                RuntimeDiagnosticsLogger.error("GoWitness installation failed: \(error.localizedDescription)")
            }
        }
    }

    private func markNativeRuntimeReady() {
        lifecycleController.markReady()
        syncRuntimeMenuState()
    }

    private func syncRuntimeMenuState() {
        runtimeMenuPresenter.syncRuntimeMenuState(
            isReady: sessionState.runtimeIsReady,
            statusText: sessionState.runtimeStatusText
        )
    }

    private func chooseDataDirectoryForSwiftUI() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: preferencesStore.dataDirectoryPath)

        panel.begin { [weak self] response in
            guard response == .OK, let self, let url = panel.url else { return }
            self.preferencesStore.dataDirectoryPath = url.path
        }
    }

    private static func copyBundledStylesheetIfNeeded() {
        let workDir = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL()
        let destination = workDir.appendingPathComponent("nmap-modern.xsl")
        if FileManager.default.fileExists(atPath: destination.path) {
            return
        }
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("nmap-modern.xsl"),
            Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/nmap-modern.xsl"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("nmap-modern.xsl")
        ].compactMap { $0 }
        for source in candidates where FileManager.default.fileExists(atPath: source.path) {
            try? FileManager.default.copyItem(at: source, to: destination)
            return
        }
    }
}
