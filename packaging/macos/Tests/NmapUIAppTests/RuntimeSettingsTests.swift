import Foundation
import Darwin
import RuntimeContracts
import Testing
import RuntimeContracts
@testable import NmapUIApp

@Suite("Runtime Settings", .serialized)
struct RuntimeSettingsTests {
    @Test("compares host, port, and vulnerability changes deterministically")
    func comparesScanChanges() {
        let oldFinding = RuntimeVulnerabilityFinding(id: "CVE-2020-0001", score: 7.5, severity: "high", port: "443")
        let newFinding = RuntimeVulnerabilityFinding(id: "CVE-2024-0002", score: 9.8, severity: "critical", port: "8080")
        let oldHost = RuntimeNmapXMLHostSummary(ip: "192.168.1.10", mac: "", vendor: "", hostname: "", os: "", latency: "", ports: "80, 443", version: "", highCVEs: "", lowCVECount: 0, vulnerabilities: [oldFinding])
        let currentHost = RuntimeNmapXMLHostSummary(ip: "192.168.1.10", mac: "", vendor: "", hostname: "", os: "", latency: "", ports: "443, 8080", version: "", highCVEs: "", lowCVECount: 0, vulnerabilities: [newFinding])
        let comparison = RuntimeNmapXMLSummary(hosts: [currentHost]).comparison(to: RuntimeNmapXMLSummary(hosts: [oldHost]))
        #expect(comparison.newHosts.isEmpty)
        #expect(comparison.newPorts == ["8080"])
        #expect(comparison.removedPorts == ["80"])
        #expect(comparison.newVulnerabilities == ["CVE-2024-0002@8080"])
        #expect(comparison.resolvedVulnerabilities == ["CVE-2020-0001@443"])
    }

    @Test("preserves structured Vulners metadata from Nmap XML")
    func parsesStructuredVulnersMetadata() {
        let xml = """
        <nmaprun><host><address addr="192.168.1.10" addrtype="ipv4"/><ports><port portid="443" protocol="tcp"><state state="open"/><service name="https" product="nginx" version="1.24"/><script id="vulners"><table key="cpe:/a:nginx:nginx:1.24"><table><elem key="id">CVE-2024-1234</elem><elem key="cvss">9.8</elem><elem key="type">cve</elem><elem key="is_exploit">true</elem></table></table></script></port></ports></host></nmaprun>
        """
        let summary = RuntimeNmapXMLParser.parse(xml: xml)
        let finding = summary?.hosts.first?.vulnerabilities.first
        #expect(finding?.id == "CVE-2024-1234")
        #expect(finding?.score == 9.8)
        #expect(finding?.port == "443")
        #expect(finding?.service == "https")
        #expect(finding?.exploit == true)
        #expect(finding?.severity == "critical")
    }

    @Test("validates and bounds scan targets")
    func validatesScanTargets() throws {
        #expect(try ScanTargetValidator.validate("127.0.0.1") == "127.0.0.1")
        #expect(try ScanTargetValidator.validate("192.168.1.1, 192.168.1.2") == "192.168.1.1,192.168.1.2")
        #expect(throws: ScanTargetValidationError.self) {
            try ScanTargetValidator.validate("10.0.0.0/8")
        }
        #expect(throws: ScanTargetValidationError.self) {
            try ScanTargetValidator.validate("bad/999")
        }
        #expect(ScanTargetValidator.targetContains(localCIDR: "10.10.0.0/24", target: "10.0.0.0/8"))
    }

    @Test("complete scans apply Pn only to hosts selected by discovery")
    func completeScanUsesPnDiscoveredTargets() {
        let arguments = ScanCoordinator.completeScanArguments(usePn: true, vpnHelper: false)
        #expect(arguments.contains("-Pn"))
        #expect(arguments.contains("-iL"))
        #expect(arguments.contains("targets.tmp"))
    }

    @Test("complete discovery uses privileged ARP before deep scanning")
    func completeDiscoveryUsesARP() {
        let complete = ScanCoordinator.phase1Arguments(target: "192.168.1.0/24", privilegedARP: true)
        let quick = ScanCoordinator.phase1Arguments(target: "192.168.1.0/24", privilegedARP: false)
        #expect(complete.contains("-sn"))
        #expect(complete.contains("-PR"))
        #expect(complete.contains("192.168.1.0/24"))
        #expect(!quick.contains("-PR"))
    }

    @Test("scan lock prevents manual and scheduled overlap")
    func scanLockIsSingleFlight() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-lock-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = ScanRunLock.acquire(in: directory)
        #expect(first != nil)
        let second = ScanRunLock.acquire(in: directory)
        #expect(second == nil)
        _ = first
    }

    @Test("duplicate ARP rows use the last parsed identity")
    func duplicateARPRowsAreSafe() {
        let rows = ARPDiscovery.parse("""
        Interface: en0, type: EN10MB, MAC: 00:00:00:00:00:01
        10.0.0.10  aa:bb:cc:dd:ee:ff  Old Vendor
        10.0.0.10  aa:bb:cc:dd:ee:ff  New Vendor
        """)
        #expect(rows.count == 2)
        #expect(rows.last?.vendor == "New Vendor")
    }

    @Test("parses arp-scan identities while ignoring headers")
    func parsesARPScanIdentities() {
        let output = """
        Interface: en0, type: EN10MB, 192.168.1.0/24
        Starting arp-scan 1.10.0
        192.168.1.1  aa:bb:cc:dd:ee:ff  Router Vendor
        192.168.1.20  11:22:33:44:55:66  Device Vendor
        2 packets received by filter, 0 packets dropped by kernel
        """
        let identities = ARPDiscovery.parse(output)
        #expect(identities.count == 2)
        #expect(identities[0].ip == "192.168.1.1")
        #expect(identities[0].mac == "AA:BB:CC:DD:EE:FF")
        #expect(identities[1].vendor == "Device Vendor")
    }

    @Test("scheduled customer resolution ignores stale manual selection")
    func scheduledResolutionIgnoresManualSelection() {
        let stale = CustomerRecord(name: "Old Site", reportPrefix: "OLD", publicIPs: ["198.51.100.1"])
        let current = CustomerRecord(name: "Current Site", reportPrefix: "CURRENT", publicIPs: ["203.0.113.4"])
        let registry = CustomerRegistry(customers: [stale, current], activeCustomerID: stale.id)
        let network = RuntimeNetworkState(localIP: "10.10.0.20", mask: "255.255.255.0", cidr: "10.10.0.0/24", publicIP: "203.0.113.4", tracerouteHops: [])
        #expect(registry.resolvedCustomerForScheduledScan(network: network) == .assigned(current, source: .automatic))
    }

    @Test("customer matching accepts WAN and local subnet containment")
    func customerMatchingUsesContainment() {
        let customer = CustomerRecord(name: "Range Customer", reportPrefix: "RANGE", publicIPs: ["203.0.113.0/24"], cidrs: ["10.20.0.0/16"])
        let registry = CustomerRegistry(customers: [customer], activeCustomerID: nil)
        let network = RuntimeNetworkState(localIP: "10.20.44.8", mask: "255.255.0.0", cidr: "10.20.0.0/16", publicIP: "203.0.113.88", tracerouteHops: [])
        #expect(registry.resolvedCustomer(network: network) == .assigned(customer, source: .automatic))
        #expect(registry.resolvedCustomerForScheduledScan(network: network) == .assigned(customer, source: .automatic))
    }

    @Test("customer filesystem names are sanitized")
    @MainActor
    func customerFilesystemNamesAreSanitized() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = AppSessionState()
        #expect(throws: CustomerRegistryError.self) {
            try state.createCustomer(name: "../../Desktop", networkState: nil, dataDirectory: directory)
        }
    }

    @Test("history recovers the previous valid snapshot")
    func historyRecoversBackup() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = RuntimeReportHistoryEntry(timestamp: "2026-01-01T00:00:00Z", target: "10.0.0.0/24", duration: "1", hostCount: 1, scanKind: "quick", status: "success", error: nil, reportUrl: nil, pdfUrl: nil, xmlUrl: nil, customerProfile: nil)
        let second = RuntimeReportHistoryEntry(timestamp: "2026-01-02T00:00:00Z", target: "10.0.0.0/24", duration: "2", hostCount: 2, scanKind: "complete", status: "success", error: nil, reportUrl: nil, pdfUrl: nil, xmlUrl: nil, customerProfile: nil)
        RuntimeMetadataStore.persistHistory([first], to: directory)
        RuntimeMetadataStore.persistHistory([second, first], to: directory)
        try Data("{".utf8).write(to: directory.appendingPathComponent("history.json"), options: .atomic)
        #expect(RuntimeMetadataStore.loadHistory(from: directory) == [first])
    }

    @Test("history writes merge concurrent scan completions")
    func historyWritesMergeConcurrentCompletions() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        DispatchQueue.concurrentPerform(iterations: 8) { index in
            let entry = RuntimeReportHistoryEntry(
                timestamp: String(format: "2026-01-01T00:00:%02dZ", index),
                target: "10.0.0.\(index)",
                duration: "1",
                hostCount: 1,
                scanKind: "quick",
                status: "success",
                error: nil,
                reportUrl: nil,
                pdfUrl: nil,
                xmlUrl: nil,
                customerProfile: nil
            )
            RuntimeMetadataStore.persistHistory([entry], to: directory)
        }

        #expect(RuntimeMetadataStore.loadHistory(from: directory).count == 8)
    }

    @Test("corrupt configuration recovers from backup without dropping other sections")
    func corruptConfigurationUsesBackup() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("nmapui-config-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let configURL = directory.appendingPathComponent("config.json")
        let backupURL = configURL.appendingPathExtension("backup")
        let original = #"{"googleDrive":{"enabled":true,"folderId":"folder"}}"#.data(using: .utf8)!
        try original.write(to: backupURL)
        try Data("not-json".utf8).write(to: configURL)

        let result = RuntimeMetadataStore.persistConfigSection(
            "autoScan",
            values: ["enabled": .bool(false)],
            to: directory
        )
        if case .failure(let error) = result {
            Issue.record("Configuration persistence failed: \(error.localizedDescription)")
        }
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: configURL)) as? [String: Any]
        let drive = json?["googleDrive"] as? [String: Any]
        #expect(drive?["folderId"] as? String == "folder")
        #expect(json?["autoScan"] != nil)
    }

    @Test("records scan attempts that do not produce a report")
    func recordsHistoryWithoutReport() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let customer = RuntimeCustomerProfile(
            customerID: "customer-1",
            customerName: "Test Customer",
            prefix: "TEST",
            publicIP: "",
            fingerprint: "test",
            baseName: "TEST",
            reportLabel: "TEST",
            folderName: "TEST"
        )

        ReportGenerator.recordHistoryOnly(
            dataDirectory: directory,
            customerProfile: customer,
            target: "10.0.0.0/24",
            duration: "3.00",
            hostCount: 0,
            scanKind: "quick",
            status: "failed",
            error: "Nmap exited with status 1"
        )

        let entry = RuntimeMetadataStore.loadHistory(from: directory).first
        #expect(entry?.status == "failed")
        #expect(entry?.error == "Nmap exited with status 1")
        #expect(entry?.reportUrl == nil)
        #expect(entry?.customerProfile?.customerID == "customer-1")
    }

    @Test("external process runner drains large output without deadlocking")
    func externalProcessRunnerDrainsOutput() throws {
        let result = try ExternalProcessRunner.run(
            executable: URL(fileURLWithPath: "/usr/bin/yes"),
            arguments: ["nmapui"],
            timeout: 0.2,
            maxOutputBytes: 128 * 1024
        )
        #expect(result.timedOut)
        #expect(!result.stdout.isEmpty)
    }

    @Test("privileged helper response window outlives its scan ceiling")
    func privilegedHelperTimeoutContractHasCleanupGrace() {
        #expect(NmapPrivilegedHelperContract.protocolVersion == 4)
        #expect(NmapPrivilegedHelperContract.privilegedNmapPath.hasSuffix("/com.techmore.nmapui.nmap"))
        #expect(NmapPrivilegedHelperContract.isAllowedScanTarget("192.168.222.0/24"))
        #expect(NmapPrivilegedHelperContract.isAllowedScanTarget("scanner.example.com"))
        #expect(!NmapPrivilegedHelperContract.isAllowedScanTarget("192.168.1.0/99"))
        #expect(!NmapPrivilegedHelperContract.isAllowedScanTarget("127.0.0.1;id"))
        #expect(NmapPrivilegedHelperContract.maximumScanRuntime >= 60 * 60)
        #expect(NmapPrivilegedHelperContract.responseGracePeriod > 0)
    }

    @Test("local scans drain noisy stdout and stderr before parsing XML")
    func localScanDrainsNoisyOutput() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let fakeNmap = directory.appendingPathComponent("fake-nmap.sh")
        let script = """
        #!/bin/sh
        /usr/bin/head -c 262144 /dev/zero
        /usr/bin/head -c 262144 /dev/zero >&2
        printf '%s' '<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><status state="up"/></host></nmaprun>' > phase1_results.xml
        """
        try script.write(to: fakeNmap, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fakeNmap.path)

        let result = await ScanCoordinator(workDirectory: directory, nmapPath: fakeNmap.path).runPhase1(.init(
            target: "127.0.0.1",
            usePn: false,
            vpnHelper: false,
            scanKind: .quick,
            allowInteractivePrivilegePrompt: false
        ))

        #expect(result.completed)
        #expect(result.summary?.hosts.first?.ip == "127.0.0.1")
    }

    @Test("privileged helper plist registers the concrete Mach service")
    func helperPlistUsesConcreteMachService() {
        let plist = PrivilegeHelperClient.launchDaemonPlistContents()
        #expect(plist.contains("<key>com.techmore.nmapui.nmap-helper</key>"))
        #expect(plist.contains("<key>MachServices</key>"))
        #expect(!plist.contains("helper.sock"))
        #expect(!plist.contains("<key>(machServiceName)</key>"))
    }

    @Test("legacy Google Drive credential persistence remains owner-readable")
    func googleDriveCredentialPersistenceIsPrivate() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        RuntimeMetadataStore.persistGoogleDriveCredentials("{\"client_secret\":\"redacted\"}", to: directory)
        let file = directory.appendingPathComponent("runtime-google-drive-credentials.json")
        let permissions = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        #expect(permissions?.intValue == 0o600)
        #expect(RuntimeMetadataStore.loadGoogleDriveCredentials(from: directory) != nil)
    }

    @Test("report path resolver rejects traversal")
    func reportResolverRejectsTraversal() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("reports_archive"), withIntermediateDirectories: true)
        #expect(ReportGenerator.resolveFileURL(forReportPath: "/reports/../../etc/passwd", dataDirectory: directory) == nil)
    }

    @Test("persists customer registry and resolves exact network matches")
    func persistsCustomerRegistryAndResolvesExactNetworkMatches() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let customer = CustomerRecord(name: "Acme", reportPrefix: "ACME", publicIPs: ["203.0.113.4"], cidrs: ["10.10.0.0/24"])
        let registry = CustomerRegistry(customers: [customer], activeCustomerID: nil)
        try registry.persist(to: directory)
        let loaded = CustomerRegistry.load(from: directory)
        #expect(loaded == registry)
        let network = RuntimeNetworkState(localIP: "10.10.0.20", mask: "255.255.255.0", cidr: "10.10.0.0/24", publicIP: "203.0.113.4", tracerouteHops: [])
        #expect(loaded.resolvedCustomer(network: network) == .assigned(customer, source: .automatic))
    }

    @Test("requires an explicit customer when network matching is ambiguous")
    func requiresExplicitCustomerForAmbiguousCustomerMatch() {
        let first = CustomerRecord(name: "Acme East", reportPrefix: "ACME_E", publicIPs: ["203.0.113.4"])
        let second = CustomerRecord(name: "Acme West", reportPrefix: "ACME_W", publicIPs: ["203.0.113.4"])
        let registry = CustomerRegistry(customers: [first, second], activeCustomerID: nil)
        let network = RuntimeNetworkState(localIP: "10.10.0.20", mask: "255.255.255.0", cidr: "10.10.0.0/24", publicIP: "203.0.113.4", tracerouteHops: [])
        guard case .ambiguous(let matches) = registry.resolvedCustomer(network: network) else {
            Issue.record("Expected ambiguous match")
            return
        }
        #expect(matches.count == 2)
    }
    @Test("runs a native quick discovery scan through ScanCoordinator")
    func nativeQuickDiscoveryScanProducesHostSummary() async throws {
        let nmapPath = try #require(RuntimeToolchain.current().nmapPath, "Native integration tests require nmap")
        let workDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("nmapui-scan-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: workDirectory) }

        // Unprivileged -sn uses TCP discovery on default ports 80/443. A host
        // with neither responding can legitimately produce zero hosts. Supply a
        // real loopback listener and direct Nmap's discovery probe to its port.
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        #expect(listener >= 0)
        defer { close(listener) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        try #require(bound == 0)
        try #require(listen(listener, 4) == 0)
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) }
        }
        try #require(named == 0)
        let port = UInt16(bigEndian: address.sin_port)
        try FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: true)
        let probe = workDirectory.appendingPathComponent("nmap-loopback-probe")
        try "#!/bin/sh\nexec \(nmapPath) -PS\(port) \"$@\"\n".write(to: probe, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: probe.path)
        let coordinator = ScanCoordinator(workDirectory: workDirectory, nmapPath: probe.path)
        let result = await coordinator.runPhase1(.init(
            target: "127.0.0.1",
            usePn: false,
            vpnHelper: false,
            scanKind: .quick,
            allowInteractivePrivilegePrompt: false
        ))

        #expect(result.completed)
        #expect(result.xmlPath != nil)
        #expect(result.summary?.hosts.contains(where: { $0.ip == "127.0.0.1" }) == true)
    }

    @Test("allocates a unique writable work directory for every scan")
    func scanWorkDirectoriesAreUnique() {
        let first = RuntimeSettingsStore.newScanWorkDirectoryURL()
        let second = RuntimeSettingsStore.newScanWorkDirectoryURL()
        defer {
            try? FileManager.default.removeItem(at: first)
            try? FileManager.default.removeItem(at: second)
        }

        #expect(first != second)
        #expect(FileManager.default.fileExists(atPath: first.path))
        #expect(FileManager.default.fileExists(atPath: second.path))
    }

    @Test("quick scans perform an unprivileged common-port pass after discovery")
    func quickScanIncludesTCPPortDiscoveryArguments() {
        let arguments = ScanCoordinator.quickPortScanArguments(vpnHelper: false)

        #expect(arguments.contains("-sT"))
        #expect(arguments.contains("-sV"))
        #expect(arguments.contains("--version-light"))
        #expect(arguments.contains("--top-ports"))
        #expect(arguments.contains("100"))
        #expect(arguments.contains("--host-timeout"))
        #expect(arguments.contains("2m"))
        #expect(arguments.contains("--max-retries"))
        #expect(arguments.contains("--open"))
        #expect(arguments.contains("-iL"))
        #expect(!arguments.contains("-sn"))
        #expect(!arguments.contains("-sS"))
    }

    @Test("complete scans bound slow hosts and vulnerability scripts")
    func completeScanIncludesRuntimeLimits() {
        let arguments = ScanCoordinator.completeScanArguments(usePn: false, vpnHelper: false)

        #expect(arguments.contains("--host-timeout"))
        #expect(arguments.contains("4m"))
        #expect(arguments.contains("--script-timeout"))
        #expect(arguments.contains("45s"))
        #expect(arguments.contains("--max-retries"))
        #expect(arguments.contains("--max-rtt-timeout"))
        #expect(arguments.contains("--min-hostgroup"))
        #expect(arguments.contains("--max-hostgroup"))
    }

    @Test("coalesces repeated hosts from Nmap progress output")
    func grepableProgressCoalescesDuplicateHosts() {
        let hosts = RuntimeNmapGrepableParser.parse(text: """
        Host: 192.168.1.10 ()  Ports: 22/open/tcp//ssh///
        Host: 192.168.1.10 ()  Ports: 80/open/tcp//http///
        """)

        #expect(hosts.count == 1)
        #expect(hosts[0].ip == "192.168.1.10")
        #expect(hosts[0].ports == "80")
    }


    @Test("collects native network reference data")
    func nativeNetworkSnapshotCollectsReferenceData() async {
        let snapshot = await RuntimeNetworkState.current()
        #expect(!snapshot.localIP.isEmpty)
        #expect(!snapshot.mask.isEmpty)
        #expect(!snapshot.cidr.isEmpty)
        #expect(!snapshot.publicIP.isEmpty)
    }

    @Test("persists and loads the versioned runtime settings contract")
    func persistAndLoadRoundTrip() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let settings = RuntimeSettings(
            useDefaultRuntimeCommand: false,
            runtimeExecutable: "/opt/homebrew/bin/swift",
            runtimeArguments: "run NmapUI --foo bar",
            dataDirectoryPath: tempDirectory.path,
            launchAtLoginEnabled: true
        )

        RuntimeSettingsStore.persist(settings, to: tempDirectory)
        let loaded = RuntimeSettingsStore.load(from: tempDirectory)

        #expect(loaded != nil)
        #expect(loaded?.schemaVersion == RuntimeSettings.schemaVersion)
        #expect(loaded == settings)
    }

    @Test("loads legacy runtime settings without a schema version")
    func loadsLegacySettingsWithoutVersion() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let legacyPayload: [String: Any] = [
            "useDefaultRuntimeCommand": false,
            "runtimeExecutable": "/usr/bin/node",
            "runtimeArguments": "legacy-host",
            "dataDirectoryPath": tempDirectory.path,
            "launchAtLoginEnabled": false
        ]
        let data = try JSONSerialization.data(withJSONObject: legacyPayload, options: [.sortedKeys])
        try data.write(to: tempDirectory.appendingPathComponent("runtime-settings.json"), options: [.atomic])

        let loaded = RuntimeSettingsStore.load(from: tempDirectory)

        #expect(loaded != nil)
        #expect(loaded?.schemaVersion == RuntimeSettings.schemaVersion)
        #expect(loaded?.useDefaultRuntimeCommand == true)
        #expect(loaded?.runtimeExecutable == "/usr/bin/true")
        #expect(loaded?.runtimeArguments == "")
    }

    @Test("persisted settings omit the legacy runtime command blob")
    func persistedSettingsOmitLegacyRuntimeCommandBlob() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let settings = RuntimeSettings(
            useDefaultRuntimeCommand: true,
            runtimeExecutable: "/usr/bin/true",
            runtimeArguments: "",
            dataDirectoryPath: tempDirectory.path,
            launchAtLoginEnabled: false
        )

        RuntimeSettingsStore.persist(settings, to: tempDirectory)

        let fileURL = tempDirectory.appendingPathComponent("runtime-settings.json")
        let data = try Data(contentsOf: fileURL)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        #expect(json != nil)
        #expect(json?["schemaVersion"] as? Int == RuntimeSettings.schemaVersion)
        #expect(json?["useDefaultRuntimeCommand"] as? Bool == true)
        #expect(json?["runtimeExecutable"] as? String == "/usr/bin/true")
        #expect(json?["runtimeArguments"] as? String == "")
        #expect(json?["runtimeCommand"] == nil)
    }

    @Test("rejects malformed runtime settings files")
    func rejectsMalformedRuntimeSettingsFiles() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let malformed = Data("not-json".utf8)
        try malformed.write(to: tempDirectory.appendingPathComponent("runtime-settings.json"), options: [.atomic])

        let loaded = RuntimeSettingsStore.load(from: tempDirectory)
        #expect(loaded == nil)
    }

    @Test("bootstraps the structured runtime settings file when missing")
    func bootstrapsStructuredRuntimeSettingsFileWhenMissing() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let defaults = UserDefaults.standard
        let originalUseDefaultRuntimeCommand = defaults.object(forKey: PreferencesKeys.useDefaultRuntimeCommand)
        let originalRuntimeExecutable = defaults.string(forKey: PreferencesKeys.runtimeExecutable)
        let originalRuntimeArguments = defaults.string(forKey: PreferencesKeys.runtimeArguments)
        let originalDataDirectory = defaults.string(forKey: PreferencesKeys.dataDirectory)
        defer {
            if let originalUseDefaultRuntimeCommand {
                defaults.set(originalUseDefaultRuntimeCommand, forKey: PreferencesKeys.useDefaultRuntimeCommand)
            } else {
                defaults.removeObject(forKey: PreferencesKeys.useDefaultRuntimeCommand)
            }
            if let originalRuntimeExecutable {
                defaults.set(originalRuntimeExecutable, forKey: PreferencesKeys.runtimeExecutable)
            } else {
                defaults.removeObject(forKey: PreferencesKeys.runtimeExecutable)
            }
            if let originalRuntimeArguments {
                defaults.set(originalRuntimeArguments, forKey: PreferencesKeys.runtimeArguments)
            } else {
                defaults.removeObject(forKey: PreferencesKeys.runtimeArguments)
            }
            if let originalDataDirectory {
                defaults.set(originalDataDirectory, forKey: PreferencesKeys.dataDirectory)
            } else {
                defaults.removeObject(forKey: PreferencesKeys.dataDirectory)
            }
        }

        defaults.set(false, forKey: PreferencesKeys.useDefaultRuntimeCommand)
        defaults.set("/usr/bin/node", forKey: PreferencesKeys.runtimeExecutable)
        defaults.set("legacy-host --migrate", forKey: PreferencesKeys.runtimeArguments)
        defaults.set(tempDirectory.path, forKey: PreferencesKeys.dataDirectory)

        let loaded = RuntimeSettingsStore.current()

        #expect(loaded.useDefaultRuntimeCommand == true)
        #expect(loaded.runtimeExecutable == "/usr/bin/true")
        #expect(loaded.runtimeArguments == "")
        #expect(FileManager.default.fileExists(atPath: tempDirectory.appendingPathComponent("runtime-settings.json").path))
        #expect(RuntimeSettingsStore.load(from: tempDirectory) == loaded)
    }

    @Test("preferences-derived runtime preview reflects structured fields")
    @MainActor
    func preferencesDerivedRuntimePreviewReflectsStructuredFields() throws {
        let store = PreferencesStore()
        store.useDefaultRuntimeCommand = false
        store.runtimeExecutable = "/opt/homebrew/bin/swift"
        store.runtimeArguments = "swift run NmapUI --scan --verbose"

        #expect(store.runtimeCommandLaunchPreview == "Executable: /opt/homebrew/bin/swift | Arguments: swift run NmapUI --scan --verbose")
        #expect(store.hasUnsavedChanges)
    }

    @Test("preferences store reset restores the structured defaults snapshot")
    @MainActor
    func preferencesStoreResetRestoresStructuredDefaultsSnapshot() throws {
        let store = PreferencesStore()
        let originalUseDefaultRuntimeCommand = store.useDefaultRuntimeCommand
        let originalRuntimeExecutable = store.runtimeExecutable
        let originalRuntimeArguments = store.runtimeArguments
        let originalDataDirectoryPath = store.dataDirectoryPath
        let originalLaunchAtLoginEnabled = store.launchAtLoginEnabled

        store.useDefaultRuntimeCommand.toggle()
        store.runtimeExecutable = "/opt/homebrew/bin/node"
        store.runtimeArguments = "swift run NmapUI --reset-check"
        store.dataDirectoryPath = originalDataDirectoryPath + "-updated"
        store.launchAtLoginEnabled.toggle()

        #expect(store.hasUnsavedChanges)

        store.resetToDefaults()

        #expect(store.useDefaultRuntimeCommand == originalUseDefaultRuntimeCommand)
        #expect(store.runtimeExecutable == originalRuntimeExecutable)
        #expect(store.runtimeArguments == originalRuntimeArguments)
        #expect(store.dataDirectoryPath == originalDataDirectoryPath)
        #expect(store.launchAtLoginEnabled == originalLaunchAtLoginEnabled)
        #expect(!store.hasUnsavedChanges)
    }

    @Test("parses the runtime network snapshot helpers")
    func parsesTheRuntimeNetworkSnapshotHelpers() throws {
        let routeOutput = """
        route to: default
         interface: en0
        """
        let ifconfigOutput = """
        inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
        """

        #expect(RuntimeNetworkState.firstCapture(in: routeOutput, pattern: #"interface:\s+(\w+)"#) == "en0")
        #expect(RuntimeNetworkState.firstCapture(in: ifconfigOutput, pattern: #"inet\s+([0-9.]+)"#) == "192.168.1.23")
        #expect(getNetworkCidr(localIP: "192.168.1.23", maskHex: "ffffff00") == "192.168.1.0/24")
    }

    @MainActor
    @Test("keeps the runtime bootstrap snapshot in sync with network changes")
    func keepsTheRuntimeBootstrapSnapshotInSyncWithNetworkChanges() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let originalNetworkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )
        let refreshedNetworkState = RuntimeNetworkState(
            localIP: "10.0.0.8",
            mask: "255.255.255.0",
            cidr: "10.0.0.0/24",
            publicIP: "198.51.100.10",
            tracerouteHops: [
                RuntimeTracerouteHop(hop: 1, ip: "10.0.0.1")
            ]
        )
        let profile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: originalNetworkState)

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: originalNetworkState,
            runtimeCustomerProfile: profile
        )

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: sessionState.runtimeIdentity,
            runtimeCapabilities: sessionState.runtimeCapabilities,
            runtimeToolchain: sessionState.runtimeToolchain,
            runtimeNetworkState: refreshedNetworkState,
            runtimeCustomerProfile: RuntimeCustomerProfile.current(prefix: "CSP", networkState: refreshedNetworkState)
        )

        #expect(sessionState.runtimeBootstrapSnapshot.runtimeNetworkState?.cidr == "10.0.0.0/24")
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeNetworkState?.tracerouteHops.count == 1)
        #expect(sessionState.runtimeCustomerProfile?.publicIP == "198.51.100.10")
    }

    @Test("persists and loads the runtime toolchain snapshot")
    func persistsAndLoadsRuntimeToolchainSnapshot() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let toolchain = RuntimeToolchain(
            nmapPath: "/opt/homebrew/bin/nmap",
            traceroutePath: "/usr/sbin/traceroute",
            brewPath: "/opt/homebrew/bin/brew",
            gowitnessPath: "/opt/homebrew/bin/gowitness",
            googleDriveHelperPath: "/tmp/GoogleDriveHelper"
        )

        RuntimeMetadataStore.persistToolchain(toolchain, to: tempDirectory)
        let loaded = RuntimeMetadataStore.loadToolchain(from: tempDirectory)

        #expect(loaded != nil)
        #expect(loaded?.nmapPath == toolchain.nmapPath)
        #expect(loaded?.traceroutePath == toolchain.traceroutePath)
        #expect(loaded?.brewPath == toolchain.brewPath)
        #expect(loaded?.gowitnessPath == toolchain.gowitnessPath)
        #expect(loaded?.googleDriveHelperPath == toolchain.googleDriveHelperPath)
    }

    @Test("runtime toolchain lookup prefers environment overrides")
    func runtimeToolchainLookupPrefersEnvironmentOverrides() throws {
        let originalNmap = ProcessInfo.processInfo.environment["NMAP_PATH"]
        let originalBrew = ProcessInfo.processInfo.environment["BREW_PATH"]
        let originalHelper = ProcessInfo.processInfo.environment["NMAPUI_GOOGLE_DRIVE_HELPER"]

        defer {
            restoreEnvironmentValue(originalNmap, forKey: "NMAP_PATH")
            restoreEnvironmentValue(originalBrew, forKey: "BREW_PATH")
            restoreEnvironmentValue(originalHelper, forKey: "NMAPUI_GOOGLE_DRIVE_HELPER")
        }

        setenv("NMAP_PATH", "/bin/ls", 1)
        setenv("BREW_PATH", "/bin/ls", 1)
        setenv("NMAPUI_GOOGLE_DRIVE_HELPER", "/bin/ls", 1)

        let toolchain = RuntimeToolchain.current()

        #expect(toolchain.nmapPath == "/bin/ls")
        #expect(toolchain.brewPath == "/bin/ls")
        #expect(toolchain.googleDriveHelperPath == "/bin/ls")
    }

    @Test("persists and loads the runtime network snapshot")
    func persistsAndLoadsRuntimeNetworkSnapshot() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: [
                RuntimeTracerouteHop(hop: 1, ip: "192.168.1.1"),
                RuntimeTracerouteHop(hop: 2, ip: "203.0.113.1")
            ]
        )

        RuntimeMetadataStore.persistNetworkState(networkState, to: tempDirectory)
        let loaded = RuntimeMetadataStore.loadNetworkState(from: tempDirectory)

        #expect(loaded != nil)
        #expect(loaded?.localIP == networkState.localIP)
        #expect(loaded?.mask == networkState.mask)
        #expect(loaded?.cidr == networkState.cidr)
        #expect(loaded?.publicIP == networkState.publicIP)
        #expect(loaded?.tracerouteHops == networkState.tracerouteHops)
    }

    @Test("persists and loads the runtime customer profile snapshot")
    func persistsAndLoadsRuntimeCustomerProfileSnapshot() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: [RuntimeTracerouteHop(hop: 1, ip: "192.168.1.1")]
        )
        let profile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)

        RuntimeMetadataStore.persistCustomerProfile(profile, to: tempDirectory)
        let loaded = RuntimeMetadataStore.loadCustomerProfile(from: tempDirectory)

        #expect(loaded != nil)
        #expect(loaded == profile)
        #expect(loaded?.folderName.contains(profile.fingerprint) == true)
    }

    @Test("persists and loads report drive metadata")
    func persistsAndLoadsReportDriveMetadata() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let reportPath = tempDirectory.appendingPathComponent("report.html")
        let metadata = RuntimeReportMetadata(
            uploadedAt: "2026-06-27T09:00:00Z",
            folderId: "folder-123",
            dayFolderId: "day-456",
            links: [
                RuntimeReportDriveFile(name: "report.html", webViewLink: "https://example.com/html", id: "html-1"),
                RuntimeReportDriveFile(name: "report.pdf", webViewLink: "https://example.com/pdf", id: "pdf-1")
            ]
        )

        RuntimeMetadataStore.persistReportMetadata(metadata, to: reportPath)
        let loaded = RuntimeMetadataStore.loadReportMetadata(from: reportPath)

        #expect(loaded != nil)
        #expect(loaded == metadata)
    }

    @Test("parses a basic Nmap XML host summary")
    func parsesBasicNmapXMLHostSummary() throws {
        let xml = """
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
            <hostnames><hostname name="scanner.local"/></hostnames>
            <os><osmatch name="Linux 6.x"/></os>
            <times srtt="12345"/>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="9.0"/>
                <script id="vulners">
                  <table>
                    <table>
                      <elem key="id">CVE-2024-0001</elem>
                      <elem key="cvss">8.1</elem>
                    </table>
                  </table>
                </script>
              </port>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx" version="1.24"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """

        let summary = RuntimeNmapXMLParser.parse(xml: xml)

        #expect(summary != nil)
        #expect(summary?.hostCount == 1)
        #expect(summary?.openPortCount == 2)
        #expect(summary?.criticalCVECount == 1)
        #expect(summary?.lowCVECount == 0)
        #expect(summary?.hosts.first?.ip == "192.168.1.10")
        #expect(summary?.hosts.first?.mac == "AA:BB:CC:DD:EE:FF")
        #expect(summary?.hosts.first?.vendor == "Acme")
        #expect(summary?.hosts.first?.hostname == "scanner.local")
    }

    @Test("derives runtime scan stats from the XML summary")
    func derivesRuntimeScanStatsFromXMLSummary() throws {
        let xml = """
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
              </port>
              <port protocol="tcp" portid="80">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """

        let summary = RuntimeNmapXMLParser.parse(xml: xml)
        let stats = summary.map(RuntimeScanStats.make(from:))

        #expect(stats?.hostCount == 1)
        #expect(stats?.openPortCount == 2)
        #expect(stats?.criticalCVECount == 0)
        #expect(stats?.lowCVECount == 0)
    }

    @Test("persists and loads runtime history entries")
    func persistsAndLoadsRuntimeHistoryEntries() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let profile = RuntimeCustomerProfile.current(
            prefix: "CSP",
            networkState: RuntimeNetworkState(
                localIP: "192.168.1.23",
                mask: "255.255.255.0",
                cidr: "192.168.1.0/24",
                publicIP: "203.0.113.2",
                tracerouteHops: []
            )
        )
        let history = [
            RuntimeReportHistoryEntry(
                timestamp: "2026-06-27T09:00:00Z",
                target: "192.168.1.0/24",
                duration: "12.34",
                hostCount: 4,
                scanKind: "quick",
                status: nil,
                error: nil,
                reportUrl: "/reports/report.html",
                pdfUrl: "/reports/report.pdf",
                xmlUrl: "/reports/report.xml",
                customerProfile: profile
            )
        ]

        RuntimeMetadataStore.persistHistory(history, to: tempDirectory)
        let loaded = RuntimeMetadataStore.loadHistory(from: tempDirectory)

        #expect(loaded == history)
    }

    @Test("encodes the runtime report payload shape")
    func encodesTheRuntimeReportPayloadShape() throws {
        let profile = RuntimeCustomerProfile.current(
            prefix: "CSP",
            networkState: RuntimeNetworkState(
                localIP: "192.168.1.23",
                mask: "255.255.255.0",
                cidr: "192.168.1.0/24",
                publicIP: "203.0.113.2",
                tracerouteHops: []
            )
        )
        let payload = RuntimeReportPayload(
            url: "/reports/example.html",
            pdfUrl: "/reports/example.pdf",
            name: "example.html",
            pdfName: "example.pdf",
            xmlName: "example.xml",
            xmlUrl: "/reports/example.xml",
            customerProfile: profile,
            driveHtmlUrl: "https://example.com/html",
            drivePdfUrl: "https://example.com/pdf"
        )

        let data = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode(RuntimeReportPayload.self, from: data)

        #expect(decoded == payload)
    }

    @Test("formats runtime report naming helpers")
    func formatsRuntimeReportNamingHelpers() throws {
        var components = DateComponents()
        components.year = 2026
        components.month = 6
        components.day = 27
        components.hour = 9
        components.minute = 15
        components.second = 30
        components.timeZone = TimeZone(secondsFromGMT: 0)
        let date = Calendar(identifier: .gregorian).date(from: components) ?? Date(timeIntervalSince1970: 0)

        #expect(RuntimeReportNaming.sanitizeSegment("  hello world!  ", fallback: "fallback") == "hello_world")
        #expect(RuntimeReportNaming.sanitizeSegment(nil, fallback: "fallback") == "fallback")
        #expect(RuntimeReportNaming.formatTimestamp(date) == "2026_06_27_091530")
        #expect(RuntimeReportNaming.formatDriveDayFolder(date) == "2026-06-27")
        #expect(RuntimeReportNaming.formatDisplayTimestamp(date).contains("2026"))
    }

    @Test("encodes a runtime report list entry")
    func encodesRuntimeReportListEntry() throws {
        let date = Date(timeIntervalSince1970: 1_000)
        let entry = RuntimeReportListBuilder.makeEntry(
            name: "example.html",
            folder: "reports",
            url: "/reports/example.html",
            pdfName: "example.pdf",
            pdfUrl: "/reports/example.pdf",
            xmlName: "example.xml",
            xmlUrl: "/reports/example.xml",
            driveHtmlUrl: "https://example.com/html",
            drivePdfUrl: "https://example.com/pdf",
            date: date,
            duration: "12.34",
            hostCount: 4,
            status: nil,
            error: nil
        )

        let data = try JSONEncoder().encode(entry)
        let decoded = try JSONDecoder().decode(RuntimeReportListEntry.self, from: data)

        #expect(decoded == entry)
        #expect(decoded.date.contains("T"))
        #expect(decoded.date.contains("Z"))
    }

    @Test("encodes a runtime reports snapshot")
    func encodesRuntimeReportsSnapshot() throws {
        let entry = RuntimeReportListBuilder.makeEntry(
            name: "example.html",
            folder: "reports",
            url: "/reports/example.html",
            pdfName: "example.pdf",
            pdfUrl: "/reports/example.pdf",
            xmlName: "example.xml",
            xmlUrl: "/reports/example.xml",
            driveHtmlUrl: "https://example.com/html",
            drivePdfUrl: "https://example.com/pdf",
            date: Date(timeIntervalSince1970: 1_000),
            duration: "12.34",
            hostCount: 4
        )
        let snapshot = RuntimeReportsSnapshot.make(reports: [entry], generatedAt: Date(timeIntervalSince1970: 2_000))
        let data = try JSONEncoder().encode(snapshot)
        let decoded = try JSONDecoder().decode(RuntimeReportsSnapshot.self, from: data)

        #expect(decoded == snapshot)
        #expect(decoded.reports.count == 1)
    }

    @Test("encodes a runtime failed scan entry")
    func encodesRuntimeFailedScanEntry() throws {
        let entry = RuntimeFailedScanBuilder.makeEntry(
            timestamp: "2026-06-27T09:00:00Z",
            scanKind: "complete",
            folder: "reports",
            error: "boom",
            hostCount: 4,
            duration: "12.34"
        )

        let data = try JSONEncoder().encode(entry)
        let decoded = try JSONDecoder().decode(RuntimeFailedScanEntry.self, from: data)

        #expect(decoded == entry)
        #expect(decoded.status == "failed")
        #expect(decoded.scanLabel == "Complete+PDF")
    }

    @Test("encodes runtime event messages")
    func encodesRuntimeEventMessages() throws {
        let message = RuntimeEventMessage.phaseComplete(
            RuntimePhaseCompleteEnvelope(
                phase: 2,
                duration: "12.34",
                hostCount: 4,
                openPortCount: 9,
                criticalCVECount: 1,
                lowCVECount: 2,
                screenshotCount: 3,
                status: "complete"
            )
        )

        let data = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(RuntimeEventMessage.self, from: data)

        #expect(decoded == message)
    }

    @Test("wraps runtime events in a transport envelope")
    func wrapsRuntimeEventsInTransportEnvelope() throws {
        let message = RuntimeEventMessage.googleDriveStatus(
            RuntimeGoogleDriveStatusEnvelope(
                success: true,
                status: "Connected",
                config: ["enabled": .bool(true)]
            )
        )
        let envelope = RuntimeEventEncoder.encode(message)

        let data = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(RuntimeTransportEnvelope.self, from: data)

        #expect(envelope == decoded)
        #expect(decoded.event == "google_drive_status")
    }

    @Test("round-trips transport envelopes as json")
    func roundTripsTransportEnvelopesAsJSON() throws {
        let message = RuntimeEventMessage.scanLifecycle(
            RuntimeScanLifecycleEnvelope(
                phase: 1,
                target: "192.168.1.0/24",
                startTime: "2026-06-27T09:00:00Z",
                scanKind: "quick"
            )
        )

        let data = try RuntimeEventEncoder.encodeJSON(message)
        let decoded = try RuntimeEventEncoder.decodeJSON(data)

        #expect(decoded.event == "scan_started")
        #expect(decoded.payload == message)
    }

    @MainActor
    @Test("records transport payloads")
    func recordsTransportPayloads() throws {
        let transport = RuntimeEventTransportRecorder()
        let message = RuntimeEventMessage.phaseStats(
            RuntimePhaseStatsEnvelope(
                phase: 2,
                summary: RuntimeNmapXMLSummary(hosts: [])
            )
        )

        let data = try transport.send(message)
        let decoded = try RuntimeEventEncoder.decodeJSON(data)

        #expect(transport.sentMessages == [message])
        #expect(decoded.payload == message)
        #expect(decoded.event == "phase_stats")
    }

    @MainActor
    @Test("records routed runtime events")
    func recordsRoutedRuntimeEvents() throws {
        let recorder = RuntimeEventRecorder()
        recorder.emitScanLifecycle(phase: 1, target: "192.168.1.0/24", startTime: "2026-06-27T09:00:00Z", scanKind: "quick")
        recorder.emitTracerouteHop(hop: 1, ip: "192.168.1.1")

        #expect(recorder.messages.count == 2)
        #expect(recorder.messages.first == .scanLifecycle(RuntimeScanLifecycleEnvelope(
            phase: 1,
            target: "192.168.1.0/24",
            startTime: "2026-06-27T09:00:00Z",
            scanKind: "quick"
        )))
        #expect(recorder.messages.last == .tracerouteHop(RuntimeTracerouteHopEnvelope(hop: 1, ip: "192.168.1.1")))
    }

    @MainActor
    @Test("records the newly mapped router events")
    func recordsTheNewlyMappedRouterEvents() throws {
        let recorder = RuntimeEventRecorder()
        let profile = RuntimeCustomerProfile.current(
            prefix: "CSP",
            networkState: RuntimeNetworkState(
                localIP: "192.168.1.23",
                mask: "255.255.255.0",
                cidr: "192.168.1.0/24",
                publicIP: "203.0.113.2",
                tracerouteHops: []
            )
        )
        let history = RuntimeReportHistoryEntry(
            timestamp: "2026-06-27T09:00:00Z",
            target: "192.168.1.0/24",
            duration: "12.34",
            hostCount: 4,
            scanKind: "quick",
            status: "complete",
            error: nil,
            reportUrl: "/reports/example.html",
            pdfUrl: "/reports/example.pdf",
            xmlUrl: "/reports/example.xml",
            customerProfile: profile
        )
        let report = RuntimeReportListEntry(
            name: "example.html",
            folder: "reports",
            url: "/reports/example.html",
            pdfName: "example.pdf",
            pdfUrl: "/reports/example.pdf",
            xmlName: "example.xml",
            xmlUrl: "/reports/example.xml",
            driveHtmlUrl: "https://example.com/html",
            drivePdfUrl: "https://example.com/pdf",
            date: "2026-06-27T09:00:00Z",
            duration: "12.34",
            hostCount: 4,
            status: "complete",
            error: nil
        )

        recorder.emitHistoryData([history])
        recorder.emitReportsData([report])
        recorder.emitScanComplete(
            phase: 3,
            duration: "12.34",
            hostCount: 4,
            openPortCount: 8,
            criticalCVECount: 1,
            lowCVECount: 2,
            screenshotCount: 6,
            status: "complete"
        )
        recorder.emitReportsRefresh()
        recorder.emitAutoScanConfig(enabled: true, schedule: "daily", scheduleLabel: "Daily", config: ["enabled": .bool(true)])
        recorder.emitGoogleDriveAuthURL(success: true, url: "https://example.com/auth", status: "Auth URL ready")
        recorder.emitLogEntry(level: "info", message: "ready", timestamp: "2026-06-27T09:00:00Z")

        #expect(recorder.messages.count == 7)
        #expect(recorder.messages[0] == .historyData(RuntimeHistoryDataEnvelope(history: [history])))
        #expect(recorder.messages[1] == .reportsData(RuntimeReportsDataEnvelope(reports: [report])))
        #expect(recorder.messages[2] == .scanComplete(RuntimePhaseCompleteEnvelope(
            phase: 3,
            duration: "12.34",
            hostCount: 4,
            openPortCount: 8,
            criticalCVECount: 1,
            lowCVECount: 2,
            screenshotCount: 6,
            status: "complete"
        )))
        #expect(recorder.messages[3] == .reportsRefresh(RuntimeReportsDataEnvelope(reports: [])))
        #expect(recorder.messages[4] == .autoScanConfig(RuntimeAutoScanConfigEnvelope(
            enabled: true,
            schedule: "daily",
            scheduleLabel: "Daily",
            config: ["enabled": .bool(true)]
        )))
        #expect(recorder.messages[5] == .googleDriveAuthURL(RuntimeGoogleDriveAuthURLEnvelope(
            success: true,
            url: "https://example.com/auth",
            status: "Auth URL ready"
        )))
        #expect(recorder.messages[6] == .logEntry(RuntimeLogEntryEnvelope(
            level: "info",
            message: "ready",
            timestamp: "2026-06-27T09:00:00Z"
        )))
    }

    @MainActor
    @Test("encodes lifecycle bridge events through the native transport")
    func encodesLifecycleBridgeEventsThroughTheNativeTransport() throws {
        let transport = RuntimeEventTransportRecorder()
        let bridge = RuntimeLifecycleEventBridge(transport: transport)

        let reportsRefreshData = try bridge.encodeReportsRefresh()
        let scanCompleteData = try bridge.encodeScanComplete(
            phase: 3,
            duration: "12.34",
            hostCount: 4,
            openPortCount: 8,
            criticalCVECount: 1,
            lowCVECount: 2,
            screenshotCount: 6,
            status: "complete"
        )

        let reportsRefreshEnvelope = try RuntimeEventEncoder.decodeJSON(reportsRefreshData)
        let scanCompleteEnvelope = try RuntimeEventEncoder.decodeJSON(scanCompleteData)

        #expect(transport.sentMessages.count == 2)
        #expect(reportsRefreshEnvelope.event == "reports_refresh")
        #expect(scanCompleteEnvelope.event == "scan_complete")
        #expect(reportsRefreshEnvelope.payload == .reportsRefresh(RuntimeReportsDataEnvelope(reports: [])))
        #expect(scanCompleteEnvelope.payload == .scanComplete(RuntimePhaseCompleteEnvelope(
            phase: 3,
            duration: "12.34",
            hostCount: 4,
            openPortCount: 8,
            criticalCVECount: 1,
            lowCVECount: 2,
            screenshotCount: 6,
            status: "complete"
        )))
    }

    @MainActor
    @Test("tracks the runtime scan session snapshot")
    func tracksTheRuntimeScanSessionSnapshot() throws {
        var snapshot = RuntimeScanSessionSnapshot(
            scanStartTime: nil,
            currentScanPhase: nil,
            currentTarget: nil,
            currentScanKind: nil
        )

        #expect(snapshot.isScanning == false)

        snapshot.scanStartTime = "2026-06-27T09:00:00Z"
        snapshot.currentScanPhase = 1
        snapshot.currentTarget = "192.168.1.0/24"
        snapshot.currentScanKind = "quick"

        #expect(snapshot.isScanning)
        #expect(snapshot.currentScanPhase == 1)
        #expect(snapshot.currentTarget == "192.168.1.0/24")
        #expect(snapshot.currentScanKind == "quick")
    }

    @MainActor
    @Test("updates the app session scan state through helpers")
    func updatesTheAppSessionScanStateThroughHelpers() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        #expect(sessionState.runtimeScanSession.isScanning == false)

        sessionState.updateScanSession(
            scanStartTime: "2026-06-27T09:00:00Z",
            currentScanPhase: 2,
            currentTarget: "192.168.1.0/24",
            currentScanKind: "complete"
        )

        #expect(sessionState.runtimeScanSession.isScanning)
        #expect(sessionState.runtimeScanSession.currentScanPhase == 2)
        #expect(sessionState.runtimeScanSession.currentTarget == "192.168.1.0/24")
        #expect(sessionState.runtimeScanSession.currentScanKind == "complete")

        sessionState.clearScanSession()

        #expect(sessionState.runtimeScanSession.isScanning == false)
        #expect(sessionState.runtimeScanSession.currentTarget == nil)
    }

    @MainActor
    @Test("tracks the runtime bootstrap snapshot")
    func tracksTheRuntimeBootstrapSnapshot() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let identity = RuntimeIdentity.localFallback(version: "1.0.0")
        let capabilities = RuntimeCapabilities(googleDriveHelperAvailable: true)
        let toolchain = RuntimeToolchain(
            nmapPath: "/opt/homebrew/bin/nmap",
            traceroutePath: "/usr/sbin/traceroute",
            brewPath: "/opt/homebrew/bin/brew",
            gowitnessPath: "/opt/homebrew/bin/gowitness",
            googleDriveHelperPath: "/tmp/GoogleDriveHelper"
        )
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )
        let customerProfile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)

        sessionState.updateScanSession(
            scanStartTime: "2026-06-27T09:00:00Z",
            currentScanPhase: 1,
            currentTarget: "192.168.1.0/24",
            currentScanKind: "quick"
        )
        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: identity,
            runtimeCapabilities: capabilities,
            runtimeToolchain: toolchain,
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: customerProfile
        )

        #expect(sessionState.runtimeBootstrapSnapshot.runtimeIdentity?.name == identity.name)
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeIdentity?.version == identity.version)
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeCapabilities?.googleDriveHelperAvailable == capabilities.googleDriveHelperAvailable)
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeToolchain?.nmapPath == toolchain.nmapPath)
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeToolchain?.traceroutePath == toolchain.traceroutePath)
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeNetworkState?.cidr == networkState.cidr)
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeCustomerProfile?.fingerprint == customerProfile.fingerprint)
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeScanSession.currentTarget == "192.168.1.0/24")
        #expect(sessionState.runtimeBootstrapSnapshot.runtimeScanSession.isScanning)
    }

    @MainActor
    @Test("emits initial data from the bootstrap snapshot")
    func emitsInitialDataFromTheBootstrapSnapshot() throws {
        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(eventRouter: recorder)
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )
        let customerProfile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: customerProfile
        )

        sessionState.emitInitialData()

        #expect(recorder.messages.count == 1)
        if case .initialData(let payload) = recorder.messages[0] {
            #expect(payload.network.localIP == networkState.localIP)
            #expect(payload.publicIP == networkState.publicIP)
            #expect(payload.customerProfile.fingerprint == customerProfile.fingerprint)
            #expect(payload.googleDrive.isEmpty)
            #expect(payload.autoScan.isEmpty)
        } else {
            Issue.record("Expected initialData payload")
        }
    }

    @MainActor
    @Test("builds the initial data envelope from bootstrap state")
    func buildsTheInitialDataEnvelopeFromBootstrapState() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )
        let customerProfile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: customerProfile
        )
        sessionState.refreshAutoScanSnapshot(from: tempDirectory, fallbackTarget: networkState.cidr)
        sessionState.refreshGoogleDriveSnapshot(from: tempDirectory)

        let bootstrap = sessionState.runtimeInitialDataEnvelope()

        #expect(bootstrap?.publicIP == networkState.publicIP)
        #expect(bootstrap?.customerProfile.fingerprint == customerProfile.fingerprint)
        #expect(bootstrap?.googleDrive.isEmpty == true)
        #expect(bootstrap?.autoScan.isEmpty == true)
    }

    @MainActor
    @Test("emits traceroute hops from the bootstrap snapshot")
    func emitsTracerouteHopsFromTheBootstrapSnapshot() throws {
        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(eventRouter: recorder)
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: [
                RuntimeTracerouteHop(hop: 1, ip: "192.168.1.1"),
                RuntimeTracerouteHop(hop: 2, ip: "198.51.100.1")
            ]
        )

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: nil,
            runtimeCapabilities: nil,
            runtimeToolchain: nil,
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)
        )

        sessionState.emitTracerouteHops()

        #expect(recorder.messages.count == 2)
        if case .tracerouteHop(let first) = recorder.messages[0] {
            #expect(first.hop == 1)
            #expect(first.ip == "192.168.1.1")
        } else {
            Issue.record("Expected tracerouteHop payload")
        }
    }

    @MainActor
    @Test("emits the full bootstrap state from a single helper")
    func emitsTheFullBootstrapStateFromASingleHelper() throws {
        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(eventRouter: recorder)
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: [
                RuntimeTracerouteHop(hop: 1, ip: "192.168.1.1")
            ]
        )
        let customerProfile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)
        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: customerProfile
        )

        sessionState.emitBootstrapState(version: "1.0.0", hosts: [])

        #expect(recorder.messages.count == 3)
        #expect(recorder.messages[0].event == .initialData)
        #expect(recorder.messages[1].event == .tracerouteHop)
        #expect(recorder.messages[2].event == .syncState)
    }

    @MainActor
    @Test("builds the full bootstrap state envelope from native state")
    func buildsTheFullBootstrapStateEnvelopeFromNativeState() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: [
                RuntimeTracerouteHop(hop: 1, ip: "192.168.1.1")
            ]
        )
        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)
        )

        let bootstrap = sessionState.runtimeBootstrapStateEnvelope(version: "1.0.0", hosts: [])

        #expect(bootstrap?.initialData?.publicIP == "203.0.113.2")
        #expect(bootstrap?.syncState?.version == "1.0.0")
        #expect(bootstrap?.tracerouteHops.count == 1)
    }

    @MainActor
    @Test("builds native status envelopes from session state")
    func buildsNativeStatusEnvelopesFromSessionState() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)
        )

        sessionState.refreshAutoScanSnapshot(from: FileManager.default.temporaryDirectory, fallbackTarget: networkState.cidr)
        sessionState.refreshGoogleDriveSnapshot(from: FileManager.default.temporaryDirectory)

        #expect(sessionState.runtimeAutoScanConfigEnvelope() != nil)
        #expect(sessionState.runtimeGoogleDriveStatusEnvelope() != nil)
    }

    @MainActor
    @Test("builds native history and reports envelopes from session state")
    func buildsNativeHistoryAndReportsEnvelopesFromSessionState() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let historyEntry = RuntimeReportHistoryEntry(
            timestamp: "2026-06-27T09:00:00Z",
            target: "192.168.1.0/24",
            duration: "12.34",
            hostCount: 4,
            scanKind: "quick",
            status: nil,
            error: nil,
            reportUrl: "/reports/demo/example.html",
            pdfUrl: nil,
            xmlUrl: nil,
            customerProfile: nil
        )
        sessionState.runtimeDataSnapshot = RuntimeDataSnapshot(history: [historyEntry], reports: [])

        #expect(sessionState.runtimeHistoryDataEnvelope()?.history == [historyEntry])
        #expect(sessionState.runtimeReportsDataEnvelope()?.reports.isEmpty == true)
    }

    @MainActor
    @Test("builds the unified transport session envelope from native state")
    func buildsTheUnifiedTransportSessionEnvelopeFromNativeState() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: [
                RuntimeTracerouteHop(hop: 1, ip: "192.168.1.1")
            ]
        )
        let historyEntry = RuntimeReportHistoryEntry(
            timestamp: "2026-06-27T09:00:00Z",
            target: "192.168.1.0/24",
            duration: "12.34",
            hostCount: 4,
            scanKind: "quick",
            status: nil,
            error: nil,
            reportUrl: "/reports/demo/example.html",
            pdfUrl: nil,
            xmlUrl: nil,
            customerProfile: nil
        )

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)
        )
        sessionState.runtimeDataSnapshot = RuntimeDataSnapshot(history: [historyEntry], reports: [])
        sessionState.refreshAutoScanSnapshot(from: FileManager.default.temporaryDirectory, fallbackTarget: networkState.cidr)
        sessionState.refreshGoogleDriveSnapshot(from: FileManager.default.temporaryDirectory)

        let session = sessionState.runtimeTransportSessionEnvelope(version: "1.0.0", hosts: [])

        #expect(session.bootstrapState != nil)
        #expect(session.history?.history == [historyEntry])
        #expect(session.customerProfile?.prefix == "CSP")
        #expect(session.googleDriveStatus != nil)
        #expect(session.autoScanConfig != nil)
    }

    @MainActor
    @Test("refreshes and emits history and reports from metadata")
    func refreshesAndEmitsHistoryAndReportsFromMetadata() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let reportsDirectory = tempDirectory.appendingPathComponent("reports_archive")
        let reportFolder = reportsDirectory.appendingPathComponent("demo", isDirectory: true)
        try FileManager.default.createDirectory(at: reportFolder, withIntermediateDirectories: true)
        let reportPath = reportFolder.appendingPathComponent("example.html")
        try Data("<html/>".utf8).write(to: reportPath)

        let historyEntry = RuntimeReportHistoryEntry(
            timestamp: "2026-06-27T09:00:00Z",
            target: "192.168.1.0/24",
            duration: "12.34",
            hostCount: 4,
            scanKind: "quick",
            status: nil,
            error: nil,
            reportUrl: "/reports/demo/example.html",
            pdfUrl: nil,
            xmlUrl: nil,
            customerProfile: nil
        )
        RuntimeMetadataStore.persistHistory([historyEntry], to: tempDirectory)

        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(eventRouter: recorder)
        sessionState.refreshDataSnapshot(from: tempDirectory)
        sessionState.emitHistoryData()
        sessionState.emitReportsData()

        #expect(sessionState.runtimeDataSnapshot.history == [historyEntry])
        #expect(sessionState.runtimeDataSnapshot.reports.count == 1)
        #expect(recorder.messages.count == 2)
        if case .historyData(let historyPayload) = recorder.messages[0] {
            #expect(historyPayload.history == [historyEntry])
        } else {
            Issue.record("Expected historyData payload")
        }
        if case .reportsData(let reportsPayload) = recorder.messages[1] {
            #expect(reportsPayload.reports.count == 1)
            #expect(reportsPayload.reports[0].name == "example.html")
            #expect(reportsPayload.reports[0].folder == "demo")
        } else {
            Issue.record("Expected reportsData payload")
        }
    }

    @Test("converts json values from dictionary payloads")
    func convertsJSONValuesFromDictionaryPayloads() throws {
        let value = RuntimeJSONValue(jsonValue: [
            "enabled": true,
            "recurrence": "daily",
            "count": 3,
            "ratio": 1.5,
            "nested": ["label": "CSP"]
        ])

        if case .object(let object)? = value {
            #expect(object["enabled"] == .bool(true))
            #expect(object["recurrence"] == .string("daily"))
            #expect(object["count"] == .int(3))
            #expect(object["ratio"] == .double(1.5))
            if case .object(let nested)? = object["nested"] {
                #expect(nested["label"] == .string("CSP"))
            } else {
                Issue.record("Expected nested object value")
            }
        } else {
            Issue.record("Expected object runtime JSON value")
        }
    }

    @MainActor
    @Test("refreshes and emits auto scan config from metadata")
    func refreshesAndEmitsAutoScanConfigFromMetadata() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let configURL = tempDirectory.appendingPathComponent("config.json")
        let config: [String: Any] = [
            "autoScan": [
                "enabled": true,
                "recurrence": "weekly",
                "startTime": "02:30",
                "target": "192.168.1.0/24"
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
        try data.write(to: configURL)

        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(eventRouter: recorder)
        sessionState.refreshAutoScanSnapshot(from: tempDirectory, fallbackTarget: "10.0.0.0/24")
        sessionState.emitAutoScanConfig()

        #expect(sessionState.runtimeAutoScanSnapshot.enabled)
        #expect(sessionState.runtimeAutoScanSnapshot.recurrence == "weekly")
        #expect(sessionState.runtimeAutoScanSnapshot.startTime == "02:30")
        #expect(sessionState.runtimeAutoScanSnapshot.target == "192.168.1.0/24")
        #expect(recorder.messages.count == 1)
        if case .autoScanConfig(let payload) = recorder.messages[0] {
            #expect(payload.enabled)
            #expect(payload.schedule == "weekly")
            #expect(payload.scheduleLabel == "Weekly")
            #expect(payload.config["enabled"] == .bool(true))
            #expect(payload.config["recurrence"] == .string("weekly"))
        } else {
            Issue.record("Expected autoScanConfig payload")
        }
    }

    @MainActor
    @Test("refreshes and emits google drive status from metadata", arguments: [true, false])
    func refreshesAndEmitsGoogleDriveStatusFromMetadata(helperSuccess: Bool) throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let configURL = tempDirectory.appendingPathComponent("config.json")
        let config: [String: Any] = [
            "googleDrive": [
                "enabled": true,
                "folderId": "folder-123"
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
        try data.write(to: configURL)

        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(
            googleDriveStatusProvider: { _ in
                GoogleDriveService.Status(
                    success: helperSuccess,
                    status: helperSuccess ? "Connected" : "Credentials missing",
                    configured: helperSuccess,
                    connected: helperSuccess,
                    error: helperSuccess ? nil : "missing configuration"
                )
            },
            eventRouter: recorder
        )
        sessionState.refreshGoogleDriveSnapshot(from: tempDirectory)
        sessionState.emitGoogleDriveStatus()

        #expect(sessionState.runtimeGoogleDriveSnapshot.enabled)
        #expect(sessionState.runtimeGoogleDriveSnapshot.folderId == "folder-123")
        #expect(recorder.messages.count == 1)
        if case .googleDriveStatus(let payload) = recorder.messages[0] {
            #expect(payload.success == helperSuccess)
            #expect(payload.config["configured"] == .bool(helperSuccess))
            #expect(payload.config["connected"] == .bool(helperSuccess))
            #expect(payload.status == "Google Drive enabled")
            #expect(payload.config["enabled"] == .bool(true))
            #expect(payload.config["folderId"] == .string("folder-123"))
        } else {
            Issue.record("Expected googleDriveStatus payload")
        }
    }

    @MainActor
    @Test("updates and persists auto scan config through the session helper")
    func updatesAndPersistsAutoScanConfigThroughTheSessionHelper() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        sessionState.updateAutoScanConfig(
            enabled: true,
            recurrence: "weekly",
            startTime: "03:15",
            target: "10.0.0.0/24",
            dataDirectory: tempDirectory
        )

        let saved = try JSONSerialization.jsonObject(with: Data(contentsOf: tempDirectory.appendingPathComponent("config.json"))) as? [String: Any]
        let autoScan = saved?["autoScan"] as? [String: Any]

        #expect(sessionState.runtimeAutoScanSnapshot.enabled)
        #expect(sessionState.runtimeAutoScanSnapshot.recurrence == "weekly")
        #expect(sessionState.runtimeAutoScanSnapshot.startTime == "03:15")
        #expect(sessionState.runtimeAutoScanSnapshot.target == "10.0.0.0/24")
        #expect((autoScan?["enabled"] as? Bool) == true)
        #expect((autoScan?["recurrence"] as? String) == "weekly")
        #expect((autoScan?["startTime"] as? String) == "03:15")
        #expect((autoScan?["target"] as? String) == "10.0.0.0/24")
    }

    @MainActor
    @Test("updates and persists google drive settings through the session helper")
    func updatesAndPersistsGoogleDriveSettingsThroughTheSessionHelper() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        sessionState.updateGoogleDriveSettings(
            enabled: true,
            folderId: "folder-123",
            dataDirectory: tempDirectory
        )

        let saved = try JSONSerialization.jsonObject(with: Data(contentsOf: tempDirectory.appendingPathComponent("config.json"))) as? [String: Any]
        let googleDrive = saved?["googleDrive"] as? [String: Any]

        #expect(sessionState.runtimeGoogleDriveSnapshot.enabled)
        #expect(sessionState.runtimeGoogleDriveSnapshot.folderId == "folder-123")
        #expect((googleDrive?["enabled"] as? Bool) == true)
        #expect((googleDrive?["folderId"] as? String) == "folder-123")
    }

    @MainActor
    @Test("refreshes and emits customer profile from metadata")
    func refreshesAndEmitsCustomerProfileFromMetadata() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let configURL = tempDirectory.appendingPathComponent("config.json")
        let config: [String: Any] = [
            "customerProfile": [
                "prefix": "CUST"
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
        try data.write(to: configURL)

        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(eventRouter: recorder)
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )

        sessionState.refreshCustomerProfileSnapshot(from: tempDirectory, networkState: networkState)
        sessionState.emitCustomerProfile()

        #expect(sessionState.runtimeCustomerProfileSnapshot.prefix == "CUST")
        #expect(sessionState.runtimeCustomerProfile?.prefix == "CUST")
        #expect(recorder.messages.count == 1)
        if case .customerProfile(let profile) = recorder.messages[0] {
            #expect(profile.prefix == "CUST")
            #expect(profile.publicIP == "203.0.113.2")
        } else {
            Issue.record("Expected customerProfile payload")
        }
    }

    @MainActor
    @Test("emits sync state from the session snapshot")
    func emitsSyncStateFromTheSessionSnapshot() throws {
        let recorder = RuntimeEventRecorder()
        let sessionState = AppSessionState(eventRouter: recorder)
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: [RuntimeTracerouteHop(hop: 1, ip: "192.168.1.1")]
        )
        let customerProfile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)

        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: customerProfile
        )
        sessionState.refreshAutoScanSnapshot(from: FileManager.default.temporaryDirectory, fallbackTarget: "192.168.1.0/24")
        sessionState.runtimeNetworkState = networkState
        sessionState.runtimeCustomerProfileSnapshot = RuntimeCustomerProfileSnapshot(prefix: "CSP", profile: customerProfile)
        sessionState.runtimeScanSession = RuntimeScanSessionSnapshot(
            scanStartTime: "2026-06-27T09:00:00Z",
            currentScanPhase: 1,
            currentTarget: "192.168.1.0/24",
            currentScanKind: "quick"
        )

        sessionState.emitSyncState(version: "1.0.0", hosts: [])

        #expect(recorder.messages.count == 1)
        if case .syncState(let payload) = recorder.messages[0] {
            #expect(payload.version == "1.0.0")
            #expect(payload.isScanning)
            #expect(payload.phase == 1)
            #expect(payload.target == "192.168.1.0/24")
            #expect(payload.scanKind == "quick")
            #expect(payload.hops.count == 1)
            if case .object(let hop)? = payload.hops.first {
                #expect(hop["hop"] == .int(1))
                #expect(hop["ip"] == .string("192.168.1.1"))
            } else {
                Issue.record("Expected hop object")
            }
            #expect(payload.customerProfile?.prefix == "CSP")
        } else {
            Issue.record("Expected syncState payload")
        }
    }

    @Test("encodes scan stopped events")
    func encodesScanStoppedEvents() throws {
        let message = RuntimeEventMessage.scanStopped(RuntimeScanStoppedEnvelope())
        let data = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(RuntimeEventMessage.self, from: data)

        #expect(decoded == message)
    }

    @MainActor
    @Test("updates the customer profile prefix through the session helper")
    func updatesTheCustomerProfilePrefixThroughTheSessionHelper() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let configURL = tempDirectory.appendingPathComponent("config.json")
        let config: [String: Any] = [
            "customerProfile": [
                "prefix": "OLD"
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
        try data.write(to: configURL)

        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )

        sessionState.updateCustomerProfilePrefix("NEW", networkState: networkState, dataDirectory: tempDirectory)

        let saved = try JSONSerialization.jsonObject(with: Data(contentsOf: configURL)) as? [String: Any]
        let savedPrefix = ((saved?["customerProfile"] as? [String: Any])?["prefix"]) as? String

        #expect(sessionState.runtimeCustomerProfileSnapshot.prefix == "NEW")
        #expect(sessionState.runtimeCustomerProfile?.prefix == "NEW")
        #expect(savedPrefix == "NEW")
    }

    @Test("encodes runtime bootstrap and Google Drive event envelopes")
    func encodesRuntimeBootstrapAndGoogleDriveEventEnvelopes() throws {
        let network = RuntimeNetworkSnapshot(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2"
        )
        let profile = RuntimeCustomerProfile.current(
            prefix: "CSP",
            networkState: RuntimeNetworkState(
                localIP: "192.168.1.23",
                mask: "255.255.255.0",
                cidr: "192.168.1.0/24",
                publicIP: "203.0.113.2",
                tracerouteHops: []
            )
        )
        let initialData = RuntimeInitialDataEnvelope(
            network: network,
            publicIP: network.publicIP,
            customerProfile: profile,
            googleDrive: ["enabled": .bool(true)],
            autoScan: ["enabled": .bool(false)]
        )
        let driveStatus = RuntimeGoogleDriveStatusEnvelope(
            success: true,
            status: "Google Drive connected",
            config: ["enabled": .bool(true)]
        )

        let initialDataRoundTrip = try JSONDecoder().decode(RuntimeInitialDataEnvelope.self, from: JSONEncoder().encode(initialData))
        let driveStatusRoundTrip = try JSONDecoder().decode(RuntimeGoogleDriveStatusEnvelope.self, from: JSONEncoder().encode(driveStatus))

        #expect(initialDataRoundTrip == initialData)
        #expect(driveStatusRoundTrip == driveStatus)
        #expect(initialDataRoundTrip.network == network)
        #expect(driveStatusRoundTrip.success)
    }

    @Test("encodes remaining transport envelopes")
    func encodesRemainingTransportEnvelopes() throws {
        let profile = RuntimeCustomerProfile.current(
            prefix: "CSP",
            networkState: RuntimeNetworkState(
                localIP: "192.168.1.23",
                mask: "255.255.255.0",
                cidr: "192.168.1.0/24",
                publicIP: "203.0.113.2",
                tracerouteHops: []
            )
        )
        let history = RuntimeReportHistoryEntry(
            timestamp: "2026-06-27T09:00:00Z",
            target: "192.168.1.0/24",
            duration: "12.34",
            hostCount: 4,
            scanKind: "quick",
            status: "complete",
            error: nil,
            reportUrl: "/reports/example.html",
            pdfUrl: "/reports/example.pdf",
            xmlUrl: "/reports/example.xml",
            customerProfile: profile
        )
        let report = RuntimeReportListEntry(
            name: "example.html",
            folder: "reports",
            url: "/reports/example.html",
            pdfName: "example.pdf",
            pdfUrl: "/reports/example.pdf",
            xmlName: "example.xml",
            xmlUrl: "/reports/example.xml",
            driveHtmlUrl: "https://example.com/html",
            drivePdfUrl: "https://example.com/pdf",
            date: "2026-06-27T09:00:00Z",
            duration: "12.34",
            hostCount: 4,
            status: "complete",
            error: nil
        )

        let messages: [RuntimeEventMessage] = [
            .historyData(RuntimeHistoryDataEnvelope(history: [history])),
            .reportsData(RuntimeReportsDataEnvelope(reports: [report])),
            .autoScanConfig(RuntimeAutoScanConfigEnvelope(
                enabled: true,
                schedule: "daily",
                scheduleLabel: "Daily",
                config: ["enabled": .bool(true)]
            )),
            .googleDriveAuthURL(RuntimeGoogleDriveAuthURLEnvelope(
                success: true,
                url: "https://example.com/auth",
                status: "Auth URL ready"
            )),
            .logEntry(RuntimeLogEntryEnvelope(level: "info", message: "ready", timestamp: "2026-06-27T09:00:00Z"))
        ]

        for message in messages {
            let data = try RuntimeEventEncoder.encodeJSON(message)
            let decoded = try RuntimeEventEncoder.decodeJSON(data)
            #expect(decoded.payload == message)
            #expect(decoded.event == message.event.rawValue)
        }
    }

    @Test("encodes the typed client request contract")
    func encodesTheTypedClientRequestContract() throws {
        let envelope = RuntimeClientRequestEnvelope(
            event: .saveGoogleDriveCredentials,
            payload: [
                "credentialsJson": .string("{\"installed\":true}")
            ]
        )

        let data = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(RuntimeClientRequestEnvelope.self, from: data)

        #expect(decoded == envelope)
        #expect(decoded.event == .saveGoogleDriveCredentials)
        #expect(decoded.payload["credentialsJson"] == .string("{\"installed\":true}"))
    }

    @MainActor
    @Test("dispatches Swift-owned client requests")
    func dispatchesSwiftOwnedClientRequests() async throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let networkState = RuntimeNetworkState(
            localIP: "192.168.1.23",
            mask: "255.255.255.0",
            cidr: "192.168.1.0/24",
            publicIP: "203.0.113.2",
            tracerouteHops: []
        )
        let profile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)
        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: RuntimeIdentity.localFallback(version: "1.0.0"),
            runtimeCapabilities: RuntimeCapabilities(googleDriveHelperAvailable: true),
            runtimeToolchain: RuntimeToolchain(
                nmapPath: "/opt/homebrew/bin/nmap",
                traceroutePath: "/usr/sbin/traceroute",
                brewPath: "/opt/homebrew/bin/brew",
                gowitnessPath: "/opt/homebrew/bin/gowitness",
                googleDriveHelperPath: "/tmp/GoogleDriveHelper"
            ),
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: profile
        )
        sessionState.refreshDataSnapshot(from: tempDirectory)
        sessionState.refreshAutoScanSnapshot(from: tempDirectory, fallbackTarget: "192.168.1.0/24")
        sessionState.refreshGoogleDriveSnapshot(from: tempDirectory)
        sessionState.refreshCustomerProfileSnapshot(from: tempDirectory, networkState: networkState)
        sessionState.emitHistoryData()
        sessionState.emitReportsData()

        var serviceCalls: [String] = []
        let services = RuntimeAutoScanServices(
            ensureHelperReady: { serviceCalls.append("authorize") },
            sync: { enabled, recurrence, time in
                serviceCalls.append("schedule:\(enabled):\(recurrence):\(time)")
                return .success(())
            },
            presentFailure: { _ in Issue.record("Unexpected authorization failure") }
        )
        let dispatcher = RuntimeRequestDispatcher(sessionState: sessionState, autoScanServices: services, allowsLegacy: { true })

        let initial = dispatcher.dispatch(
            RuntimeClientRequestEnvelope(event: .getInitialData),
            dataDirectory: tempDirectory,
            version: "1.0.0"
        )
        #expect(initial.events.count == 1)
        if case .initialData(let payload) = initial.events[0] {
            #expect(payload.publicIP == "203.0.113.2")
            #expect(payload.customerProfile == profile)
        } else {
            Issue.record("Expected initialData payload")
        }

        let history = dispatcher.dispatch(
            RuntimeClientRequestEnvelope(event: .getHistory),
            dataDirectory: tempDirectory,
            version: "1.0.0"
        )
        #expect(history.events.count == 1)
        if case .historyData(let payload) = history.events[0] {
            #expect(payload.history == [])
        } else {
            Issue.record("Expected historyData payload")
        }

        let reports = dispatcher.dispatch(
            RuntimeClientRequestEnvelope(event: .getReports),
            dataDirectory: tempDirectory,
            version: "1.0.0"
        )
        #expect(reports.events.count == 1)
        if case .reportsData(let payload) = reports.events[0] {
            #expect(payload.reports == [])
        } else {
            Issue.record("Expected reportsData payload")
        }

        let enabled = dispatcher.dispatch(
            RuntimeClientRequestEnvelope(
                event: .enableAutoScan,
                payload: [
                    "recurrence": .string("weekly"),
                    "startTime": .string("02:30"),
                    "target": .string("10.0.0.0/24")
                ]
            ),
            dataDirectory: tempDirectory,
            version: "1.0.0"
        )
        #expect(enabled.events.count == 1)
        if case .autoScanConfig(let payload) = enabled.events[0] {
            #expect(payload.enabled)
            #expect(payload.schedule == "weekly")
        } else {
            Issue.record("Expected autoScanConfig payload")
        }

        for _ in 0..<20 where serviceCalls.count < 2 { await Task.yield() }
        #expect(serviceCalls == ["authorize", "schedule:true:weekly:02:30"])
        _ = dispatcher.dispatch(RuntimeClientRequestEnvelope(event: .disableAutoScan), dataDirectory: tempDirectory, version: "1.0.0")
        #expect(serviceCalls.last == "schedule:false:weekly:02:30")

        let prefix = dispatcher.dispatch(
            RuntimeClientRequestEnvelope(
                event: .setCustomerProfilePrefix,
                payload: ["prefix": .string("NEW")]
            ),
            dataDirectory: tempDirectory,
            version: "1.0.0"
        )
        #expect(prefix.events.count == 1)
        if case .customerProfile(let payload) = prefix.events[0] {
            #expect(payload.prefix == "NEW")
        } else {
            Issue.record("Expected customerProfile payload")
        }

        let stopped = dispatcher.dispatch(
            RuntimeClientRequestEnvelope(event: .stopScan),
            dataDirectory: tempDirectory,
            version: "1.0.0"
        )
        #expect(stopped.events.count == 1)
        if case .scanStopped = stopped.events[0] {
        } else {
            Issue.record("Expected scanStopped payload")
        }
    }

    @MainActor
    @Test("parses Swift-owned scan start requests")
    func parsesSwiftOwnedScanStartRequests() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let dispatcher = RuntimeRequestDispatcher(sessionState: sessionState, allowsLegacy: { true })

        let quick = dispatcher.scanStartPayload(from: RuntimeClientRequestEnvelope(
            event: .startQuickScan,
            payload: [
                "target": .string("192.168.1.0/24"),
                "customerProfilePrefix": .string("CSP")
            ]
        ))
        #expect(quick.target == "192.168.1.0/24")
        #expect(quick.customerProfilePrefix == "CSP")
        #expect(quick.vpnHelper == nil)

        let complete = dispatcher.scanStartPayload(from: RuntimeClientRequestEnvelope(
            event: .startCompleteScan,
            payload: [
                "target": .string("192.168.1.0/24"),
                "vpnHelper": .bool(true)
            ]
        ))
        #expect(complete.target == "192.168.1.0/24")
        #expect(complete.vpnHelper == true)

        let dragnet = dispatcher.scanStartPayload(from: RuntimeClientRequestEnvelope(
            event: .startDragnetScan,
            payload: [
                "target": .string("192.168.1.10,192.168.1.11")
            ]
        ))
        #expect(dragnet.target == "192.168.1.10,192.168.1.11")
        #expect(dragnet.vpnHelper == nil)
    }

    @MainActor
    @Test("parses Swift-owned settings and Google Drive request payloads")
    func parsesSwiftOwnedSettingsAndGoogleDriveRequestPayloads() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let dispatcher = RuntimeRequestDispatcher(sessionState: sessionState, allowsLegacy: { true })

        let autoScan = dispatcher.autoScanPayload(from: RuntimeClientRequestEnvelope(
            event: .enableAutoScan,
            payload: [
                "recurrence": .string("monthly"),
                "startTime": .string("03:15"),
                "target": .string("10.0.0.0/24")
            ]
        ))
        #expect(autoScan.recurrence == "monthly")
        #expect(autoScan.startTime == "03:15")
        #expect(autoScan.target == "10.0.0.0/24")

        let driveSettings = dispatcher.googleDriveSettingsPayload(from: RuntimeClientRequestEnvelope(
            event: .saveGoogleDriveSettings,
            payload: [
                "enabled": .bool(true),
                "folderId": .string("folder-123")
            ]
        ))
        #expect(driveSettings.enabled)
        #expect(driveSettings.folderId == "folder-123")

        let prefix = dispatcher.customerProfilePrefixPayload(from: RuntimeClientRequestEnvelope(
            event: .setCustomerProfilePrefix,
            payload: ["prefix": .string("NEW")]
        ))
        #expect(prefix.prefix == "NEW")

        let credentials = dispatcher.googleDriveCredentialsPayload(from: RuntimeClientRequestEnvelope(
            event: .saveGoogleDriveCredentials,
            payload: ["credentialsJson": .string("{\"installed\":true}")]
        ))
        #expect(credentials.credentialsJson.contains("\"installed\":true"))
    }

    @MainActor
    @Test("builds scan coordinator requests from typed scan payloads")
    func buildsScanCoordinatorRequestsFromTypedScanPayloads() throws {
        let sessionState = AppSessionState(eventRouter: RuntimeEventRecorder())
        let dispatcher = RuntimeRequestDispatcher(sessionState: sessionState, allowsLegacy: { true })

        let quick = dispatcher.scanCoordinatorRequest(from: RuntimeClientRequestEnvelope(
            event: .startQuickScan,
            payload: ["target": .string("192.168.1.0/24")]
        ))
        #expect(quick?.target == "192.168.1.0/24")
        #expect(quick?.usePn == false)
        #expect(quick?.vpnHelper == false)

        let complete = dispatcher.scanCoordinatorRequest(from: RuntimeClientRequestEnvelope(
            event: .startCompleteScan,
            payload: [
                "target": .string("192.168.1.0/24"),
                "vpnHelper": .bool(true)
            ]
        ))
        #expect(complete?.target == "192.168.1.0/24")
        #expect(complete?.usePn == true)
        #expect(complete?.vpnHelper == true)

        let dragnet = dispatcher.scanCoordinatorRequest(from: RuntimeClientRequestEnvelope(
            event: .startDragnetScan,
            payload: ["target": .string("192.168.1.10,192.168.1.11")]
        ))
        #expect(dragnet?.target == "192.168.1.10,192.168.1.11")
        #expect(dragnet?.scanKind == .dragnet)
    }

    private func restoreEnvironmentValue(_ value: String?, forKey key: String) {
        if let value {
            setenv(key, value, 1)
        } else {
            unsetenv(key)
        }
    }
}
