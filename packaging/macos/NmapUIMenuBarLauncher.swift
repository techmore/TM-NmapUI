import Cocoa
import Darwin

class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var runtimePort = 9000
    // The appliance daemon always uses this port; the wrapper attaches to it.
    let fixedRuntimePort = 9000
    var statusItem: NSStatusItem!
    var pythonProcess: Process?
    var statusPollTimer: Timer?
    var statusPollTask: URLSessionDataTask?
    var statusPollGeneration = UUID()
    var browserOpenGeneration: UUID?
    var browserOpenTask: URLSessionDataTask?
    var hadActiveJob = false
    var completedIndicatorUntil: Date?
    var lockFileURL: URL?
    var launchedWithPrivileges = false

    var appURL: URL {
        URL(string: "http://127.0.0.1:\(runtimePort)")!
    }

    var runtimeStatusURL: URL {
        URL(string: "http://127.0.0.1:\(runtimePort)/api/runtime/status")!
    }

    var runtimeReadinessURL: URL {
        appURL.appendingPathComponent("api/health/ready")
    }

    // Menu items that need dynamic state updates
    var openItem: NSMenuItem!
    var activityItem: NSMenuItem!
    var startItem: NSMenuItem!
    var stopItem: NSMenuItem!
    var restartItem: NSMenuItem!
    var isQuitting = false

    var resourcesPath: String? {
        (Bundle.main.bundlePath as NSString?)?.appendingPathComponent("Contents/Resources")
    }

    var runScriptPath: String? {
        guard let resourcesPath else { return nil }
        return (resourcesPath as NSString).appendingPathComponent("run.sh")
    }

    var runtimePIDFilePath: String? {
        guard let resourcesPath else { return nil }
        return (resourcesPath as NSString).appendingPathComponent("nmapui-runtime.pid")
    }

    var shutdownMarkerPath: String? {
        guard let resourcesPath else { return nil }
        return (resourcesPath as NSString).appendingPathComponent("nmapui-shutdown")
    }

    var isFlaskRunning: Bool {
        if let process = pythonProcess, process.isRunning {
            return true
        }
        // Either the launched child or the appliance daemon owns the port.
        return isLocalPortInUse(runtimePort)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if !acquireSingleInstanceLock() {
            NSApp.terminate(nil)
            return
        }
        setupStatusItem()
        startFlask()
    }

    func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        updateStatusIcon(state: .starting, detail: "Starting NmapUI")

        let menu = NSMenu()
        menu.delegate = self
        // These states are supplied explicitly; AppKit must not re-enable
        // controls for a daemon the wrapper does not own.
        menu.autoenablesItems = false

        activityItem = NSMenuItem(title: "Starting NmapUI", action: nil, keyEquivalent: "")
        activityItem.isEnabled = false
        menu.addItem(activityItem)
        menu.addItem(NSMenuItem.separator())

        openItem = NSMenuItem(title: "Open NmapUI", action: #selector(openNmapUI(_:)), keyEquivalent: "o")
        openItem.target = self
        menu.addItem(openItem)

        menu.addItem(NSMenuItem.separator())

        startItem = NSMenuItem(title: "Start Scanner", action: #selector(startNmapUI(_:)), keyEquivalent: "s")
        startItem.target = self
        menu.addItem(startItem)

        stopItem = NSMenuItem(title: "Stop Scanner", action: #selector(stopNmapUI(_:)), keyEquivalent: "")
        stopItem.target = self
        menu.addItem(stopItem)

        restartItem = NSMenuItem(title: "Restart Scanner", action: #selector(restartNmapUI(_:)), keyEquivalent: "r")
        restartItem.target = self
        menu.addItem(restartItem)

        menu.addItem(NSMenuItem.separator())

        // HIG: an item that opens a dialog ends in an ellipsis, a destructive
        // item gets no shortcut, and Quit is the last item.
        let uninstallItem = NSMenuItem(title: "Uninstall NmapUI\u{2026}", action: #selector(uninstallApp(_:)), keyEquivalent: "")
        uninstallItem.target = self
        menu.addItem(uninstallItem)

        let quitItem = NSMenuItem(title: "Quit NmapUI", action: #selector(quitApp(_:)), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu
    }

    // Update menu item enabled states each time the menu opens
    func menuWillOpen(_ menu: NSMenu) {
        let running = isFlaskRunning
        openItem.isEnabled = true          // always available; will start+wait if needed
        startItem.isEnabled = !running
        let ownsRuntime = pythonProcess?.isRunning == true
        stopItem.isEnabled = ownsRuntime
        restartItem.isEnabled = ownsRuntime || !running
        let managedDetail = running && !ownsRuntime ? "This scanner is managed by its service; this app only displays its status." : nil
        stopItem.toolTip = managedDetail
        restartItem.toolTip = managedDetail
    }

    // MARK: - Flask lifecycle

    func isLocalPortInUse(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { close(fd) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.stride)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        let convertResult = withUnsafeMutablePointer(to: &address.sin_addr) {
            inet_pton(AF_INET, "127.0.0.1", $0)
        }
        guard convertResult == 1 else { return true }

        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }
        return result == 0
    }

    func pickAvailableRuntimePort() -> Int? {
        let fixedPort = fixedRuntimePort
        if isLocalPortInUse(fixedPort) {
            return nil
        }
        return fixedPort
    }

    func startFlask() {
        // A listener may be the managed daemon, not our child. It still needs
        // the attachment/status-poll path below.
        guard pythonProcess?.isRunning != true else { return }
        isQuitting = false

        guard let resourcesPath, let runScriptPath else { return }

        // The appliance is normally owned by the NmapUI LaunchDaemon. If it
        // already holds the runtime port, attach to it instead of starting a
        // second server — and never request administrator privileges: the
        // appliance must run for months without any authentication prompt.
        if isLocalPortInUse(fixedRuntimePort) {
            runtimePort = fixedRuntimePort
            launchedWithPrivileges = false
            pythonProcess = nil
            startStatusPolling()
            updateStatusIcon(state: .starting, detail: "Reading managed scanner status")
            print("Attached to the NmapUI daemon already listening on port \(fixedRuntimePort)")
            return
        }

        guard FileManager.default.fileExists(atPath: runScriptPath) else {
            print("run.sh not found inside bundle — rebuild with build.sh")
            return
        }

        removeRuntimeMarkers()

        guard let selectedPort = pickAvailableRuntimePort() else {
            updateStatusIcon(state: .error, detail: "Port \(fixedRuntimePort) is already in use")
            return
        }
        runtimePort = selectedPort

        let allowedOrigins = "http://127.0.0.1:\(runtimePort),http://localhost:\(runtimePort)"
        startStatusPolling()
        updateStatusIcon(state: .starting, detail: "Starting NmapUI")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [runScriptPath]
        process.currentDirectoryURL = URL(fileURLWithPath: resourcesPath, isDirectory: true)
        var environment = ProcessInfo.processInfo.environment
        environment["NMAPUI_PORT"] = String(runtimePort)
        environment["NMAPUI_ALLOWED_ORIGINS"] = allowedOrigins
        process.environment = environment

        do {
            try process.run()
            pythonProcess = process
            launchedWithPrivileges = false
            updateStatusIcon(state: .starting, detail: "Starting NmapUI")
            print("NmapUI started with PID: \(process.processIdentifier)")
        } catch {
            print("Failed to start NmapUI: \(error)")
            updateStatusIcon(state: .error, detail: "Failed to start NmapUI")
        }
    }

    // Only signal the live child this wrapper launched and its descendants.
    // A listener on the same port is not evidence of process ownership.
    func stopFlask(wait: Bool = true) {
        browserOpenGeneration = nil
        browserOpenTask?.cancel()
        browserOpenTask = nil
        stopStatusPolling()
        if pythonProcess?.isRunning == true {
            writeShutdownMarker()
            // The bounded helper captures descendants before terminating the
            // parent, so an uncooperative child cannot strand the UI in wait.
            stopTrackedRuntimeProcesses(wait: wait)
            removeRuntimeMarkers()
        }
        pythonProcess = nil
        launchedWithPrivileges = false

        print("NmapUI stopped")
        updateStatusIcon(state: .idle, detail: "NmapUI stopped")
    }

    struct RuntimeReadiness: Decodable {
        let ready: Bool
    }

    static func isReadyResponse(data: Data?, response: URLResponse?) -> Bool {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let data, let payload = try? JSONDecoder().decode(RuntimeReadiness.self, from: data) else { return false }
        return payload.ready
    }

    // Poll actual application readiness. An unrelated HTTP listener or a timed
    // out startup must not open an arbitrary/broken page and claim readiness.
    func waitForFlaskThenOpen(timeout: TimeInterval = 15) {
        guard browserOpenGeneration == nil else { return }
        let generation = UUID()
        browserOpenGeneration = generation
        pollReadinessThenOpen(generation: generation, deadline: Date().addingTimeInterval(timeout))
    }

    func pollReadinessThenOpen(generation: UUID, deadline: Date) {
        guard browserOpenGeneration == generation, !isQuitting else { return }
        var request = URLRequest(url: runtimeReadinessURL)
        request.timeoutInterval = 1
        request.cachePolicy = .reloadIgnoringLocalCacheData
        browserOpenTask = URLSession.shared.dataTask(with: request) { [weak self] data, response, _ in
            DispatchQueue.main.async {
                guard let self, self.browserOpenGeneration == generation, !self.isQuitting else { return }
                self.browserOpenTask = nil
                if Self.isReadyResponse(data: data, response: response) {
                    self.browserOpenGeneration = nil
                    NSWorkspace.shared.open(self.appURL)
                } else if Date() >= deadline {
                    self.browserOpenGeneration = nil
                    self.updateStatusIcon(state: .error, detail: "Scanner is not ready; retry Open NmapUI")
                } else {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                        self?.pollReadinessThenOpen(generation: generation, deadline: deadline)
                    }
                }
            }
        }
        browserOpenTask?.resume()
    }

    // MARK: - Menu actions

    @objc func openNmapUI(_ sender: Any?) {
        if !isFlaskRunning { startFlask() }
        waitForFlaskThenOpen()
    }

    @objc func startNmapUI(_ sender: Any?) {
        startFlask()
    }

    @objc func stopNmapUI(_ sender: Any?) {
        stopFlask()
    }

    @objc func restartNmapUI(_ sender: Any?) {
        stopFlask()
        // Brief pause to let the OS release the port before restarting
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            self.startFlask()
        }
    }

    @objc func quitApp(_ sender: Any?) {
        isQuitting = true
        stopFlask(wait: true)
        NSApp.terminate(nil)
    }

    @objc func uninstallApp(_ sender: Any?) {
        let alert = NSAlert()
        alert.messageText = "Uninstall NmapUI"
        alert.informativeText = "Quit the app and move NmapUI.app to the Trash to uninstall."
        alert.addButton(withTitle: "OK")
        alert.alertStyle = .informational
        alert.runModal()
    }

    func applicationWillTerminate(_ notification: Notification) {
        isQuitting = true
        stopFlask(wait: true)
        releaseSingleInstanceLock()
        statusItem = nil
    }

    enum ActivityIndicatorState {
        case idle
        case starting
        case active(jobTypes: [String])
        case paused
        case recentActivity
        case error
    }

    struct RuntimeStatus: Decodable {
        struct ActiveJob: Decodable {
            struct Details: Decodable {
                let message: String?
            }
            let sid: String?
            let job_type: String?
            let status: String?
            let details: Details?
            let paused: Bool?
            let pause_requested: Bool?
        }

        let has_active_jobs: Bool
        let active_job_types: [String]
        let active_jobs: [ActiveJob]
    }

    func startStatusPolling() {
        stopStatusPolling()
        statusPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.pollRuntimeStatus()
        }
        if let timer = statusPollTimer {
            RunLoop.main.add(timer, forMode: .common)
        }
        pollRuntimeStatus()
    }

    func stopStatusPolling() {
        statusPollTimer?.invalidate()
        statusPollTimer = nil
        statusPollGeneration = UUID()
        statusPollTask?.cancel()
        statusPollTask = nil
        hadActiveJob = false
        completedIndicatorUntil = nil
    }

    func pollRuntimeStatus() {
        if isQuitting {
            return
        }
        // A stalled response cannot accumulate parallel requests or later
        // overwrite a newer lifecycle/polling generation.
        guard statusPollTask == nil else { return }
        guard isFlaskRunning else {
            updateStatusIcon(state: .idle, detail: "NmapUI stopped")
            return
        }

        var request = URLRequest(url: runtimeStatusURL)
        request.timeoutInterval = 1.5
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let environment = ProcessInfo.processInfo.environment
        if let username = environment["NMAPUI_USERNAME"], !username.isEmpty,
           let password = environment["NMAPUI_PASSWORD"], !password.isEmpty {
            let credentials = Data("\(username):\(password)".utf8).base64EncodedString()
            request.setValue("Basic \(credentials)", forHTTPHeaderField: "Authorization")
        }
        let generation = statusPollGeneration

        statusPollTask = URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self, self.statusPollGeneration == generation, !self.isQuitting else { return }
                self.statusPollTask = nil
                if let _ = error {
                    self.updateStatusIcon(state: .starting, detail: "Waiting for local server")
                    return
                }

                guard
                    let http = response as? HTTPURLResponse,
                    http.statusCode == 200,
                    let data = data,
                    let runtimeStatus = try? JSONDecoder().decode(RuntimeStatus.self, from: data)
                else {
                    let statusCode = (response as? HTTPURLResponse)?.statusCode
                    self.updateStatusIcon(state: .error, detail: statusCode == 401 ? "Scanner status requires credentials; open NmapUI" : "Unable to read runtime status")
                    return
                }

                let now = Date()
                if runtimeStatus.has_active_jobs {
                    self.hadActiveJob = true
                    self.completedIndicatorUntil = nil
                    let allPaused = !runtimeStatus.active_jobs.isEmpty && runtimeStatus.active_jobs.allSatisfy { $0.paused == true }
                    self.updateStatusIcon(
                        state: allPaused ? .paused : .active(jobTypes: runtimeStatus.active_job_types),
                        detail: self.activityDetail(from: runtimeStatus)
                    )
                    return
                }

                if self.hadActiveJob {
                    self.hadActiveJob = false
                    self.completedIndicatorUntil = now.addingTimeInterval(20)
                }

                if let completedUntil = self.completedIndicatorUntil, completedUntil > now {
                    // Disappearance from active_jobs does not establish success:
                    // cancelled and failed jobs become inactive too.
                    self.updateStatusIcon(state: .recentActivity, detail: "Recent scan or report ended; review results")
                } else {
                    self.completedIndicatorUntil = nil
                    self.updateStatusIcon(state: .idle, detail: "NmapUI idle")
                }
            }
        }
        statusPollTask?.resume()
    }

    func activityDetail(from runtimeStatus: RuntimeStatus) -> String {
        if let job = runtimeStatus.active_jobs.first,
           job.paused == true {
            return "Scan paused; resume or cancel in NmapUI"
        }
        if let job = runtimeStatus.active_jobs.first,
           job.pause_requested == true {
            return "Pausing scan at the next checkpoint"
        }
        if let job = runtimeStatus.active_jobs.first,
           let message = job.details?.message,
           !message.isEmpty {
            return message
        }

        if runtimeStatus.active_job_types.isEmpty {
            return "Active work in progress"
        }

        return runtimeStatus.active_job_types
            .map { $0.capitalized }
            .joined(separator: " + ") + " in progress"
    }

    func updateStatusIcon(state: ActivityIndicatorState, detail: String) {
        guard let button = statusItem?.button else { return }
        activityItem?.title = String(detail.prefix(100))
        activityItem?.toolTip = detail

        let symbolName: String
        let accessibility: String

        switch state {
        case .idle:
            symbolName = "network"
            accessibility = "NmapUI idle"
        case .starting:
            symbolName = "hourglass"
            accessibility = "NmapUI starting"
        case .active(let jobTypes):
            symbolName = "dot.radiowaves.left.and.right"
            accessibility = "NmapUI active: " + (jobTypes.isEmpty ? "job running" : jobTypes.joined(separator: ", "))
        case .recentActivity:
            symbolName = "clock"
            accessibility = "NmapUI recent activity ended"
        case .paused:
            symbolName = "pause.circle"
            accessibility = "NmapUI scan paused"
        case .error:
            symbolName = "exclamationmark.triangle.fill"
            accessibility = "NmapUI status unavailable"
        }

        button.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: accessibility)
        button.toolTip = detail
        button.setAccessibilityLabel(accessibility + ". " + detail)
    }

    // MARK: - Privileged start/stop
    //
    // Privileged administration is owned by the NmapUI LaunchDaemon
    // (packaging/macos/install-daemon.sh). The wrapper deliberately no longer
    // starts the server with `administrator privileges`: that raised a GUI
    // password prompt on every launch, which is incompatible with an appliance
    // that must run unattended for months.

    func appleScriptEscaped(_ value: String) -> String {
        var escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
        escaped = escaped.replacingOccurrences(of: "\"", with: "\\\"")
        escaped = escaped.replacingOccurrences(of: "\n", with: "; ")
        return "\"\(escaped)\""
    }

    func shellEscaped(_ value: String) -> String {
        if value.isEmpty {
            return "''"
        }
        return "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    func writeShutdownMarker() {
        guard let shutdownMarkerPath else { return }
        FileManager.default.createFile(atPath: shutdownMarkerPath, contents: Data(), attributes: nil)
    }

    func removeRuntimeMarkers() {
        guard let runtimePIDFilePath, let shutdownMarkerPath else { return }
        try? FileManager.default.removeItem(atPath: runtimePIDFilePath)
        try? FileManager.default.removeItem(atPath: shutdownMarkerPath)
    }

    func stopRuntimeShellCommand(wait: Bool) -> String {
        let runtimePIDFilePathValue = runtimePIDFilePath ?? ""
        let shutdownMarkerPathValue = shutdownMarkerPath ?? ""
        // Do not trust a PID file, a command substring, or the runtime port to
        // establish ownership. Process.isRunning refers to our actual child.
        let targetPID = pythonProcess?.isRunning == true ? pythonProcess!.processIdentifier : 0
        return """
        PID_FILE=\(shellEscaped(runtimePIDFilePathValue))
        SHUTDOWN_MARKER=\(shellEscaped(shutdownMarkerPathValue))
        ROOT_PID=\(targetPID)
        PIDS=()
        STARTS=()
        collect_tree() {
          local target_pid="$1"
          local freeze="${2:-false}"
          local identity
          identity="$(/bin/ps -p "$target_pid" -o lstart= 2>/dev/null)"
          [[ -n "$identity" ]] || return
          # Freeze parents before enumerating children so they cannot replace a
          # terminated child between our final snapshot and forced shutdown.
          if [[ "$freeze" == true ]]; then
            /bin/kill -STOP "$target_pid" 2>/dev/null || return
          fi
          local child_pid
          while IFS= read -r child_pid; do
            [[ -z "$child_pid" ]] && continue
            collect_tree "$child_pid" "$freeze"
          done < <(/usr/bin/pgrep -P "$target_pid" 2>/dev/null || true)
          PIDS+=("$target_pid")
          STARTS+=("$identity")
        }
        same_process() {
          local index="$1"
          local current
          current="$(/bin/ps -p "${PIDS[$index]}" -o lstart= 2>/dev/null)"
          [[ -n "$current" && "$current" == "${STARTS[$index]}" ]]
        }
        if [[ "$ROOT_PID" -gt 1 ]]; then
          collect_tree "$ROOT_PID"
          for index in "${!PIDS[@]}"; do
            if same_process "$index"; then
              /bin/kill -CONT "${PIDS[$index]}" 2>/dev/null || true
              /bin/kill -TERM "${PIDS[$index]}" 2>/dev/null || true
            fi
          done
          # Even a child that ignores TERM gets only this bounded grace period.
          /bin/sleep 2
          # Include children born during TERM handling. Walk the original list
          # parent-first, retaining any original children already reparented.
          # Each recursive snapshot stops the parent before inspecting children.
          initial_count="${#PIDS[@]}"
          for ((index=initial_count-1; index>=0; index--)); do
            if same_process "$index"; then
              collect_tree "${PIDS[$index]}" true
            fi
          done
          for index in "${!PIDS[@]}"; do
            if same_process "$index"; then
              /bin/kill -KILL "${PIDS[$index]}" 2>/dev/null || true
            fi
          done
          if [[ -n "$PID_FILE" && -n "$SHUTDOWN_MARKER" ]]; then
            /bin/rm -f "$PID_FILE" "$SHUTDOWN_MARKER"
          fi
        fi
        """
    }

    func stopTrackedRuntimeProcesses(wait: Bool) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-lc", stopRuntimeShellCommand(wait: wait)]
        do {
            try process.run()
            if wait {
                process.waitUntilExit()
            }
        } catch {
            print("Failed to stop tracked runtime processes: \(error)")
        }
    }

    // MARK: - Single instance lock

    func acquireSingleInstanceLock() -> Bool {
        let fileManager = FileManager.default
        let lockDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("NmapUI", isDirectory: true)
        guard let lockDirectory else { return true }

        do {
            try fileManager.createDirectory(at: lockDirectory, withIntermediateDirectories: true)
        } catch {
            print("Unable to create lock directory: \(error)")
            return true
        }

        let lockFile = lockDirectory.appendingPathComponent("nmapui.lock")
        lockFileURL = lockFile

        if let contents = try? String(contentsOf: lockFile).trimmingCharacters(in: .whitespacesAndNewlines),
           let pid = Int32(contents),
           pid > 0,
           pid != getpid(),
           kill(pid, 0) == 0 {
            let alert = NSAlert()
            alert.messageText = "NmapUI already running"
            alert.informativeText = "Another instance of NmapUI is already running. Use the existing menu bar icon."
            alert.addButton(withTitle: "OK")
            alert.alertStyle = .warning
            alert.runModal()
            return false
        }

        do {
            try "\(getpid())".write(to: lockFile, atomically: true, encoding: .utf8)
        } catch {
            print("Unable to write lock file: \(error)")
        }

        return true
    }

    func releaseSingleInstanceLock() {
        guard let lockFileURL else { return }
        try? FileManager.default.removeItem(at: lockFileURL)
    }
}

func main() {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
}

main()
