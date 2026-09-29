import Cocoa
import Darwin

class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var runtimePort = 9000
    // The appliance daemon always uses this port; the wrapper attaches to it.
    let fixedRuntimePort = 9000
    var statusItem: NSStatusItem!
    var pythonProcess: Process?
    var statusPollTimer: Timer?
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

    // Menu items that need dynamic state updates
    var openItem: NSMenuItem!
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

        openItem = NSMenuItem(title: "Open NmapUI", action: #selector(openNmapUI(_:)), keyEquivalent: "o")
        openItem.target = self
        menu.addItem(openItem)

        menu.addItem(NSMenuItem.separator())

        startItem = NSMenuItem(title: "Start Flask", action: #selector(startNmapUI(_:)), keyEquivalent: "s")
        startItem.target = self
        menu.addItem(startItem)

        stopItem = NSMenuItem(title: "Stop Flask", action: #selector(stopNmapUI(_:)), keyEquivalent: "")
        stopItem.target = self
        menu.addItem(stopItem)

        restartItem = NSMenuItem(title: "Restart Flask", action: #selector(restartNmapUI(_:)), keyEquivalent: "r")
        restartItem.target = self
        menu.addItem(restartItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quitApp(_:)), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        let uninstallItem = NSMenuItem(title: "Uninstall", action: #selector(uninstallApp(_:)), keyEquivalent: "u")
        uninstallItem.target = self
        menu.addItem(uninstallItem)

        statusItem.menu = menu
    }

    // Update menu item enabled states each time the menu opens
    func menuWillOpen(_ menu: NSMenu) {
        let running = isFlaskRunning
        openItem.isEnabled = true          // always available; will start+wait if needed
        startItem.isEnabled = !running
        stopItem.isEnabled = running
        restartItem.isEnabled = true
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
        guard !isFlaskRunning else { return }
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
            updateStatusIcon(state: .active(jobTypes: []), detail: "Managed by NmapUI daemon")
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

    // Kill the tracked process and any stray app.py processes (e.g. from a
    // previous run or if pythonProcess is stale after a crash/restart).
    func stopFlask(wait: Bool = true) {
        writeShutdownMarker()
        stopStatusPolling()
        let ownedProcess = pythonProcess
        if let process = ownedProcess, process.isRunning {
            process.terminate()
            if wait { process.waitUntilExit() }
        }
        pythonProcess = nil
        launchedWithPrivileges = false

        // Only stop processes this app started. A daemon-managed server is
        // owned by launchd and must be left alone.
        if ownedProcess != nil {
            stopTrackedRuntimeProcesses(wait: wait)
        }
        removeRuntimeMarkers()

        print("NmapUI stopped")
        updateStatusIcon(state: .idle, detail: "NmapUI stopped")
    }

    // Poll the selected localhost port until Flask responds (or timeout), then open browser
    func waitForFlaskThenOpen(timeout: TimeInterval = 15) {
        DispatchQueue.global(qos: .userInitiated).async {
            let deadline = Date().addingTimeInterval(timeout)
            var ready = false
            while Date() < deadline {
                var request = URLRequest(url: self.appURL)
                request.timeoutInterval = 1
                let sema = DispatchSemaphore(value: 0)
                URLSession.shared.dataTask(with: request) { _, response, _ in
                    if let http = response as? HTTPURLResponse, http.statusCode < 500 {
                        ready = true
                    }
                    sema.signal()
                }.resume()
                sema.wait()
                if ready { break }
                Thread.sleep(forTimeInterval: 0.5)
            }
            DispatchQueue.main.async {
                NSWorkspace.shared.open(self.appURL)
            }
        }
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
        case completed
        case error
    }

    struct RuntimeStatus: Decodable {
        struct ActiveJob: Decodable {
            let sid: String?
            let job_type: String?
            let status: String?
            let details: [String: String]?
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
        hadActiveJob = false
        completedIndicatorUntil = nil
    }

    func pollRuntimeStatus() {
        if isQuitting {
            return
        }
        guard isFlaskRunning else {
            updateStatusIcon(state: .idle, detail: "NmapUI stopped")
            return
        }

        var request = URLRequest(url: runtimeStatusURL)
        request.timeoutInterval = 1.5

        URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
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
                    self.updateStatusIcon(state: .error, detail: "Unable to read runtime status")
                    return
                }

                let now = Date()
                if runtimeStatus.has_active_jobs {
                    self.hadActiveJob = true
                    self.completedIndicatorUntil = nil
                    self.updateStatusIcon(
                        state: .active(jobTypes: runtimeStatus.active_job_types),
                        detail: self.activityDetail(from: runtimeStatus)
                    )
                    return
                }

                if self.hadActiveJob {
                    self.hadActiveJob = false
                    self.completedIndicatorUntil = now.addingTimeInterval(20)
                }

                if let completedUntil = self.completedIndicatorUntil, completedUntil > now {
                    self.updateStatusIcon(state: .completed, detail: "Recent scan or report completed")
                } else {
                    self.completedIndicatorUntil = nil
                    self.updateStatusIcon(state: .idle, detail: "NmapUI idle")
                }
            }
        }.resume()
    }

    func activityDetail(from runtimeStatus: RuntimeStatus) -> String {
        if let job = runtimeStatus.active_jobs.first,
           let message = job.details?["message"],
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
        guard let button = statusItem.button else { return }

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
        case .completed:
            symbolName = "checkmark.circle.fill"
            accessibility = "NmapUI recent activity completed"
        case .error:
            symbolName = "exclamationmark.triangle.fill"
            accessibility = "NmapUI status unavailable"
        }

        button.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: accessibility)
        button.toolTip = detail
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
        let resourcesPathValue = resourcesPath ?? ""
        let runScriptPathValue = runScriptPath ?? ""
        let runtimePIDFilePathValue = runtimePIDFilePath ?? ""
        let shutdownMarkerPathValue = shutdownMarkerPath ?? ""
        let runtimePortValue = String(runtimePort)
        let waitFlag = wait ? "1" : "0"
        return """
        RESOURCES_PATH=\(shellEscaped(resourcesPathValue))
        RUN_SCRIPT_PATH=\(shellEscaped(runScriptPathValue))
        PID_FILE=\(shellEscaped(runtimePIDFilePathValue))
        SHUTDOWN_MARKER=\(shellEscaped(shutdownMarkerPathValue))
        RUNTIME_PORT=\(shellEscaped(runtimePortValue))
        WAIT_FLAG=\(waitFlag)
        kill_tree() {
          local target_pid="$1"
          if [[ -z "$target_pid" ]]; then
            return
          fi
          local child_pid
          while IFS= read -r child_pid; do
            [[ -z "$child_pid" ]] && continue
            kill_tree "$child_pid"
          done < <(/usr/bin/pgrep -P "$target_pid" 2>/dev/null || true)
          /bin/kill -TERM "$target_pid" 2>/dev/null || true
        }
        force_kill_tree() {
          local target_pid="$1"
          if [[ -z "$target_pid" ]]; then
            return
          fi
          local child_pid
          while IFS= read -r child_pid; do
            [[ -z "$child_pid" ]] && continue
            force_kill_tree "$child_pid"
          done < <(/usr/bin/pgrep -P "$target_pid" 2>/dev/null || true)
          /bin/kill -KILL "$target_pid" 2>/dev/null || true
        }
        if [[ -n "$SHUTDOWN_MARKER" ]]; then
          /usr/bin/touch "$SHUTDOWN_MARKER" 2>/dev/null || true
        fi
        if [[ -f "$PID_FILE" ]]; then
          TARGET_PID="$(/bin/cat "$PID_FILE" 2>/dev/null | /usr/bin/tr -cd '0-9')"
          if [[ -n "$TARGET_PID" ]]; then
            kill_tree "$TARGET_PID"
            if [[ "$WAIT_FLAG" == "1" ]]; then
              /bin/sleep 2
              force_kill_tree "$TARGET_PID"
            fi
          fi
        fi
        if [[ -n "$RUNTIME_PORT" ]]; then
          while IFS= read -r listener_pid; do
            [[ -z "$listener_pid" ]] && continue
            kill_tree "$listener_pid"
            if [[ "$WAIT_FLAG" == "1" ]]; then
              /bin/sleep 1
              force_kill_tree "$listener_pid"
            fi
          done < <(/usr/sbin/lsof -tiTCP:"$RUNTIME_PORT" -sTCP:LISTEN 2>/dev/null || true)
        fi
        /usr/bin/pkill -TERM -f "$RUN_SCRIPT_PATH" 2>/dev/null || true
        /usr/bin/pkill -TERM -f "$RESOURCES_PATH/app.py" 2>/dev/null || true
        /usr/bin/pkill -TERM -f "$RESOURCES_PATH/.venv/bin/python3" 2>/dev/null || true
        if [[ "$WAIT_FLAG" == "1" ]]; then
          /bin/sleep 1
          /usr/bin/pkill -KILL -f "$RUN_SCRIPT_PATH" 2>/dev/null || true
          /usr/bin/pkill -KILL -f "$RESOURCES_PATH/app.py" 2>/dev/null || true
          /usr/bin/pkill -KILL -f "$RESOURCES_PATH/.venv/bin/python3" 2>/dev/null || true
        fi
        /bin/rm -f "$PID_FILE" "$SHUTDOWN_MARKER"
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
