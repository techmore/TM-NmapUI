import Foundation
import RuntimeContracts

/// Headless entrypoint used by the LaunchAgent for unattended scheduled scans.
enum ScheduledScanRunner {
    static var isScheduledScanInvocation: Bool {
        CommandLine.arguments.contains("--scheduled-scan")
    }

    struct Admission: Sendable {
        let directory: URL
        let lock: ScanRunLock
    }
    static func admit(store: ExecutionSourceStore = .live) -> Admission? {
        guard store.resolve().source == .legacy else { return nil }
        let directory = store.legacyDataDirectory
        guard let lock = ScanRunLock.acquire(in: directory), store.resolve().source == .legacy else { return nil }
        return Admission(directory: directory, lock: lock)
    }

    static func runAndExit() async {
        // Admission precedes logging/configuration/network/helper access. The
        // retained real scan lock serializes this runner with source changes.
        guard let admission = admit() else {
            try? FileHandle.standardError.write(contentsOf: Data("Native scheduled scan did not run: choose Legacy compatibility, and wait for any active Legacy scan/source change. Schedule configuration is preserved.\n".utf8))
            exit(0)
        }
        let dataDirectory = admission.directory
        defer { _ = admission.lock }
        RuntimeDiagnosticsLogger.log("Scheduled scan invocation starting")
        RuntimeDiagnosticsLogger.configure(dataDirectory: dataDirectory)
        try? FileManager.default.createDirectory(
            at: dataDirectory.appendingPathComponent("logs", isDirectory: true),
            withIntermediateDirectories: true
        )
        try? FileManager.default.createDirectory(
            at: RuntimeSettingsStore.currentRuntimeWorkDirectoryURL(),
            withIntermediateDirectories: true
        )

        // Ensure nmap-modern.xsl is available in the work directory when bundled.
        copyStylesheetIfNeeded()

        let networkState = await RuntimeNetworkState.current()
        RuntimeMetadataStore.persistNetworkState(networkState, to: dataDirectory)
        let registry = CustomerRegistry.load(from: dataDirectory)
        let resolution = registry.resolvedCustomerForScheduledScan(network: networkState)
        let customer: CustomerRecord
        switch resolution {
        case .assigned(let record, _):
            customer = record
        case .unassigned:
            RuntimeDiagnosticsLogger.error("Scheduled scan aborted: no customer assignment matches the current network")
            exit(3)
        case .ambiguous(let customers):
            RuntimeDiagnosticsLogger.error("Scheduled scan aborted: ambiguous customer assignment matches=\(customers.map(\.name).joined(separator: ","))")
            exit(3)
        }

        let configURL = dataDirectory.appendingPathComponent("config.json")
        let json = (try? Data(contentsOf: configURL)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let autoScan = (json?["autoScan"] as? [String: Any]) ?? [:]
        let enabled = autoScan["enabled"] as? Bool ?? false
        guard enabled else {
            RuntimeDiagnosticsLogger.log("Scheduled scan skipped: auto-scan disabled")
            exit(0)
        }

        let target = (autoScan["target"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedTarget = target.flatMap { $0.isEmpty ? nil : $0 } ?? networkState.cidr
        let scanKind = "complete"

        do {
            _ = try ScanTargetValidator.validate(resolvedTarget)
        } catch {
            RuntimeDiagnosticsLogger.error("Scheduled scan aborted: \(error.localizedDescription)")
            exit(4)
        }

        guard PrivilegeHelperClient.isCurrentHelperReachable else {
            RuntimeDiagnosticsLogger.error("Scheduled scan aborted: privileged helper is not installed/running")
            exit(2)
        }

        let coordinator = ScanCoordinator(workDirectory: RuntimeSettingsStore.newScanWorkDirectoryURL())
        let request = ScanCoordinator.ScanRequest(
            target: resolvedTarget,
            usePn: true,
            vpnHelper: false,
            scanKind: ScanCoordinator.ScanKind(scanKind),
            allowInteractivePrivilegePrompt: false
        )
        let result = await coordinator.runFullScan(request)
        var postProcessingFailed = false
        var reportGenerated = false
        RuntimeDiagnosticsLogger.log(
            "Scheduled scan finished completed=\(result.completed) phase=\(result.phase.rawValue) duration=\(result.duration) error=\(result.error ?? "none")"
        )

        if result.completed, let xmlPath = result.xmlPath, result.phase != .phase1 {
            let networkState = await RuntimeNetworkState.current()
            let profile = RuntimeCustomerProfile.current(prefix: customer.reportPrefix, networkState: networkState, customer: customer)
            do {
                var screenshots: [URL] = []
                if GowitnessManager.resolvedBinaryURL() != nil {
                    do {
                        screenshots = try GowitnessCapture.capture(nmapXML: xmlPath, workDirectory: coordinator.workDirectoryURL)
                    } catch {
                        postProcessingFailed = true
                        RuntimeDiagnosticsLogger.error("Scheduled GoWitness capture failed: \(error.localizedDescription)")
                    }
                }
                let generated = try ReportGenerator.generate(
                    xmlSource: xmlPath,
                    dataDirectory: dataDirectory,
                    customerProfile: profile,
                    target: resolvedTarget,
                    duration: result.duration,
                    hostCount: result.summary?.hostCount ?? 0,
                    scanKind: scanKind,
                    screenshotURLs: screenshots,
                    status: "success",
                    error: nil
                )
                reportGenerated = true
                if generated.pdfURL == nil {
                    postProcessingFailed = true
                    RuntimeDiagnosticsLogger.error("Scheduled complete scan finished without a PDF renderer")
                }
                RuntimeDiagnosticsLogger.log("Scheduled scan report generated")
                let googleDrive = (json?["googleDrive"] as? [String: Any]) ?? [:]
                if googleDrive["enabled"] as? Bool == true {
                    let upload = GoogleDriveService.uploadReportArtifacts(
                        files: [generated.htmlURL, generated.xmlURL, generated.pdfURL].compactMap { $0 },
                        dataDirectory: dataDirectory,
                        folderId: googleDrive["folderId"] as? String
                    )
                    if !upload.success {
                        postProcessingFailed = true
                        RuntimeDiagnosticsLogger.error("Scheduled Google Drive upload failed: \(upload.error ?? upload.status)")
                    }
                }
                let reportBehavior = (json?["reportBehavior"] as? [String: Any]) ?? [:]
                if reportBehavior["autoOpenScheduledReports"] as? Bool == true {
                    openReportArtifact(generated.htmlURL)
                    if let pdfURL = generated.pdfURL { openReportArtifact(pdfURL) }
                }
            } catch {
                postProcessingFailed = true
                RuntimeDiagnosticsLogger.error("Scheduled report generation failed: \(error.localizedDescription)")
            }
        }

        if !reportGenerated {
            let status: String
            let historyError: String?
            if result.completed {
                status = result.phase == .phase1 ? "success" : "failed"
                historyError = result.phase == .phase1 ? nil : "Report generation failed"
            } else if result.error == "Scan cancelled" {
                status = "cancelled"
                historyError = result.error
            } else {
                status = "failed"
                historyError = result.error ?? "Scheduled scan failed without a result"
            }
            ReportGenerator.recordHistoryOnly(
                dataDirectory: dataDirectory,
                customerProfile: RuntimeCustomerProfile.current(prefix: customer.reportPrefix, networkState: networkState, customer: customer),
                target: resolvedTarget,
                duration: result.duration,
                hostCount: result.summary?.hostCount ?? 0,
                scanKind: scanKind,
                status: status,
                error: historyError
            )
        }

        exit(result.completed && !postProcessingFailed ? 0 : 1)
    }

    private static func copyStylesheetIfNeeded() {
        let workDir = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL()
        let destination = workDir.appendingPathComponent("nmap-modern.xsl")
        if FileManager.default.fileExists(atPath: destination.path) {
            return
        }
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("nmap-modern.xsl"),
            Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/nmap-modern.xsl")
        ].compactMap { $0 }
        for source in candidates where FileManager.default.fileExists(atPath: source.path) {
            try? FileManager.default.copyItem(at: source, to: destination)
            return
        }
    }

    private static func openReportArtifact(_ url: URL) {
        do {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            process.arguments = [url.path]
            try process.run()
            RuntimeDiagnosticsLogger.log("Opened scheduled report artifact path=\(url.path)")
        } catch {
            RuntimeDiagnosticsLogger.error("Could not open scheduled report artifact path=\(url.path) error=\(error.localizedDescription)")
        }
    }
}
