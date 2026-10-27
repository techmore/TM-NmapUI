import Foundation
import RuntimeContracts

@MainActor
protocol RuntimeRequestDispatching {
    func dispatch(
        _ request: RuntimeClientRequestEnvelope,
        dataDirectory: URL,
        version: String
    ) -> RuntimeRequestDispatchResult
}

/// Effects stay explicit so request-contract tests never authenticate or install services.
@MainActor
struct RuntimeAutoScanServices {
    var ensureHelperReady: () async throws -> Void
    var sync: (Bool, String, String) -> Result<Void, Error>
    var presentFailure: (Error) -> Void

    static var live: Self {
        Self(
            ensureHelperReady: { try await PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true) },
            sync: { AutoScanScheduler.sync(enabled: $0, recurrence: $1, startTime: $2) },
            presentFailure: { PrivilegeElevationController.presentHelperInstallFailure($0) }
        )
    }
}

@MainActor
final class RuntimeRequestDispatcher: RuntimeRequestDispatching {
    private let sessionState: AppSessionState
    private let autoScanServices: RuntimeAutoScanServices

    init(sessionState: AppSessionState, autoScanServices: RuntimeAutoScanServices = .live) {
        self.sessionState = sessionState
        self.autoScanServices = autoScanServices
    }

    func dispatch(
        _ request: RuntimeClientRequestEnvelope,
        dataDirectory: URL,
        version: String
    ) -> RuntimeRequestDispatchResult {
        switch request.event {
        case .getInitialData:
            return RuntimeRequestDispatchResult(events: initialDataMessages())
        case .startQuickScan, .startCompleteScan, .startDragnetScan:
            return RuntimeRequestDispatchResult(scanRequest: scanStartPayload(from: request))
        case .getHistory:
            if let history = sessionState.runtimeHistoryDataEnvelope() {
                return RuntimeRequestDispatchResult(events: [.historyData(history)])
            }
            return RuntimeRequestDispatchResult()
        case .getReports:
            if let reports = sessionState.runtimeReportsDataEnvelope() {
                return RuntimeRequestDispatchResult(events: [.reportsData(reports)])
            }
            return RuntimeRequestDispatchResult()
        case .getCustomerProfile:
            if let profile = sessionState.runtimeCustomerProfileSnapshot.profile {
                return RuntimeRequestDispatchResult(events: [.customerProfile(profile)])
            }
            return RuntimeRequestDispatchResult()
        case .getGoogleDriveStatus:
            sessionState.refreshGoogleDriveSnapshot(from: dataDirectory)
            if let googleDrive = sessionState.runtimeGoogleDriveStatusEnvelope() {
                return RuntimeRequestDispatchResult(events: [.googleDriveStatus(googleDrive)])
            }
            return RuntimeRequestDispatchResult()
        case .enableAutoScan:
            let recurrence = stringValue("recurrence", from: request.payload) ?? sessionState.runtimeAutoScanSnapshot.recurrence
            let startTime = stringValue("startTime", from: request.payload) ?? sessionState.runtimeAutoScanSnapshot.startTime
            let target = stringValue("target", from: request.payload) ?? sessionState.runtimeAutoScanSnapshot.target
            sessionState.updateAutoScanConfig(
                enabled: true,
                recurrence: recurrence,
                startTime: startTime,
                target: target,
                dataDirectory: dataDirectory
            )
            // Install privileged helper (interactive once) then schedule unattended runs.
            Task { @MainActor in
                do {
                    try await autoScanServices.ensureHelperReady()
                    switch autoScanServices.sync(true, recurrence, startTime) {
                    case .success:
                        break
                    case .failure(let error):
                        sessionState.updateAutoScanConfig(
                            enabled: false,
                            recurrence: recurrence,
                            startTime: startTime,
                            target: target,
                            dataDirectory: dataDirectory
                        )
                        sessionState.scanFeedback = "Auto-scan could not be enabled: \(error.localizedDescription)"
                        sessionState.emitAutoScanConfig()
                    }
                } catch {
                    autoScanServices.presentFailure(error)
                    sessionState.updateAutoScanConfig(
                        enabled: false,
                        recurrence: recurrence,
                        startTime: startTime,
                        target: target,
                        dataDirectory: dataDirectory
                    )
                    sessionState.scanFeedback = "Auto-scan could not be enabled: \(error.localizedDescription)"
                    sessionState.emitAutoScanConfig()
                }
            }
            if let autoScan = sessionState.runtimeAutoScanConfigEnvelope() {
                return RuntimeRequestDispatchResult(events: [.autoScanConfig(autoScan)])
            }
            return RuntimeRequestDispatchResult()
        case .disableAutoScan:
            sessionState.updateAutoScanConfig(
                enabled: false,
                recurrence: sessionState.runtimeAutoScanSnapshot.recurrence,
                startTime: sessionState.runtimeAutoScanSnapshot.startTime,
                target: sessionState.runtimeAutoScanSnapshot.target,
                dataDirectory: dataDirectory
            )
            _ = autoScanServices.sync(false, sessionState.runtimeAutoScanSnapshot.recurrence, sessionState.runtimeAutoScanSnapshot.startTime)
            if let autoScan = sessionState.runtimeAutoScanConfigEnvelope() {
                return RuntimeRequestDispatchResult(events: [.autoScanConfig(autoScan)])
            }
            return RuntimeRequestDispatchResult()
        case .saveGoogleDriveSettings:
            sessionState.updateGoogleDriveSettings(
                enabled: boolValue("enabled", from: request.payload) ?? sessionState.runtimeGoogleDriveSnapshot.enabled,
                folderId: stringValue("folderId", from: request.payload) ?? sessionState.runtimeGoogleDriveSnapshot.folderId,
                dataDirectory: dataDirectory
            )
            if let googleDrive = sessionState.runtimeGoogleDriveStatusEnvelope() {
                return RuntimeRequestDispatchResult(events: [.googleDriveStatus(googleDrive)])
            }
            return RuntimeRequestDispatchResult()
        case .setCustomerProfilePrefix:
            sessionState.updateCustomerProfilePrefix(
                stringValue("prefix", from: request.payload) ?? "CSP",
                networkState: sessionState.runtimeNetworkState,
                dataDirectory: dataDirectory
            )
            if let profile = sessionState.runtimeCustomerProfileSnapshot.profile {
                return RuntimeRequestDispatchResult(events: [.customerProfile(profile)])
            }
            return RuntimeRequestDispatchResult()
        case .stopScan:
            return RuntimeRequestDispatchResult(events: [.scanStopped(RuntimeScanStoppedEnvelope())])
        case .getPrivilegeHelperStatus, .installPrivilegeHelper, .openReport, .connectGoogleDrive, .disconnectGoogleDrive, .saveAppSettings:
            // Handled by the native shell bridge (AppDelegate) for interactive system actions.
            return RuntimeRequestDispatchResult()
        case .saveGoogleDriveCredentials:
            let credentials = googleDriveCredentialsPayload(from: request)
            let result = GoogleDriveService.saveCredentials(credentials.credentialsJson, dataDirectory: dataDirectory)
            sessionState.refreshGoogleDriveSnapshot(from: dataDirectory)
            if let googleDrive = sessionState.runtimeGoogleDriveStatusEnvelope() {
                return RuntimeRequestDispatchResult(events: [
                    .googleDriveStatus(RuntimeGoogleDriveStatusEnvelope(
                        success: result.success,
                        status: result.status ?? (result.success ? "Google Drive credentials saved" : (result.error ?? "Failed to save credentials")),
                        config: googleDrive.config
                    ))
                ])
            }
            return RuntimeRequestDispatchResult(events: [.googleDriveStatus(RuntimeGoogleDriveStatusEnvelope(
                success: result.success,
                status: result.status ?? result.error ?? "Google Drive credentials updated",
                config: ["enabled": .bool(sessionState.runtimeGoogleDriveSnapshot.enabled)]
            ))])
        }
    }

    func scanStartPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeScanStartPayload {
        RuntimeScanStartPayload(
            target: stringValue("target", from: request.payload) ?? "",
            customerProfilePrefix: stringValue("customerProfilePrefix", from: request.payload),
            vpnHelper: boolValue("vpnHelper", from: request.payload)
        )
    }

    func scanCoordinatorRequest(from request: RuntimeClientRequestEnvelope) -> ScanCoordinator.ScanRequest? {
        guard [.startQuickScan, .startCompleteScan, .startDragnetScan].contains(request.event) else {
            return nil
        }
        return scanStartPayload(from: request).makeScanCoordinatorRequest(event: request.event)
    }

    func autoScanPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeAutoScanRequestPayload {
        RuntimeAutoScanRequestPayload(
            recurrence: stringValue("recurrence", from: request.payload),
            startTime: stringValue("startTime", from: request.payload),
            target: stringValue("target", from: request.payload)
        )
    }

    func googleDriveSettingsPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeGoogleDriveSettingsPayload {
        RuntimeGoogleDriveSettingsPayload(
            enabled: boolValue("enabled", from: request.payload) ?? false,
            folderId: stringValue("folderId", from: request.payload)
        )
    }

    func customerProfilePrefixPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeCustomerProfilePrefixPayload {
        RuntimeCustomerProfilePrefixPayload(
            prefix: stringValue("prefix", from: request.payload) ?? "CSP"
        )
    }

    func googleDriveCredentialsPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeGoogleDriveCredentialsPayload {
        RuntimeGoogleDriveCredentialsPayload(
            credentialsJson: stringValue("credentialsJson", from: request.payload) ?? "{}"
        )
    }

    private func initialDataMessages() -> [RuntimeEventMessage] {
        guard let bootstrap = sessionState.runtimeInitialDataEnvelope() else { return [] }
        return [.initialData(bootstrap)]
    }

    private func stringValue(_ key: String, from payload: [String: RuntimeJSONValue]) -> String? {
        guard case .string(let value)? = payload[key] else { return nil }
        return value
    }

    private func boolValue(_ key: String, from payload: [String: RuntimeJSONValue]) -> Bool? {
        guard case .bool(let value)? = payload[key] else { return nil }
        return value
    }
}
