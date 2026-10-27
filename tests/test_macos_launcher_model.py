"""Compile and exercise the supported native launcher's non-UI state model."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("swiftc"), reason="Requires macOS Swift compiler")
def test_native_launcher_decodes_runtime_metadata_and_attaches_to_managed_service(tmp_path):
    source = (ROOT / "packaging/macos/NmapUIMenuBarLauncher.swift").read_text()
    source = source.rsplit("\nmain()", 1)[0]
    source += r'''

// A real server emits mixed-type job details. Unknown details must not make
// the entire native status decoder fail.
let mixed = #"{"has_active_jobs":true,"active_job_types":["scan"],"active_jobs":[{"sid":"tab","job_type":"scan","status":"running","details":{"message":"Scanning authorized targets","host_count":12,"attempted":true,"nested":{"remaining":3}}}]}"#
let decoded = try JSONDecoder().decode(AppDelegate.RuntimeStatus.self, from: Data(mixed.utf8))
let model = AppDelegate()
precondition(model.activityDetail(from: decoded) == "Scanning authorized targets")

let paused = #"{"has_active_jobs":true,"active_job_types":["scan"],"active_jobs":[{"paused":true,"pause_requested":true,"details":{"host_count":12}}]}"#
let pausedStatus = try JSONDecoder().decode(AppDelegate.RuntimeStatus.self, from: Data(paused.utf8))
precondition(model.activityDetail(from: pausedStatus) == "Scan paused; resume or cancel in NmapUI")

let pausing = #"{"has_active_jobs":true,"active_job_types":["scan"],"active_jobs":[{"paused":false,"pause_requested":true}]}"#
let pausingStatus = try JSONDecoder().decode(AppDelegate.RuntimeStatus.self, from: Data(pausing.utf8))
precondition(model.activityDetail(from: pausingStatus) == "Pausing scan at the next checkpoint")

class ManagedServiceProbe: AppDelegate {
    var startedPolling = false
    var displayedDetail = ""
    override func isLocalPortInUse(_ port: Int) -> Bool { true }
    override func startStatusPolling() { startedPolling = true }
    override func updateStatusIcon(state: ActivityIndicatorState, detail: String) { displayedDetail = detail }
}
let managed = ManagedServiceProbe()
managed.startFlask()
precondition(managed.startedPolling, "An existing daemon must start native status polling")
precondition(managed.pythonProcess == nil, "Attaching must not launch a second scanner")
precondition(managed.displayedDetail == "Reading managed scanner status")

let response = HTTPURLResponse(url: model.runtimeReadinessURL, statusCode: 200, httpVersion: nil, headerFields: nil)!
precondition(AppDelegate.isReadyResponse(data: Data(#"{"ready":true}"#.utf8), response: response))
precondition(!AppDelegate.isReadyResponse(data: Data(#"{"ready":false}"#.utf8), response: response))
precondition(!AppDelegate.isReadyResponse(data: Data("<html>Different local app</html>".utf8), response: response))

class ShutdownProbe: AppDelegate {
    let directory: String
    init(directory: String) {
        self.directory = directory
        super.init()
    }
    override var resourcesPath: String? { directory }
}

// Exercise the emitted cleanup helper against real children. The marker is
// deliberately stale and points to an unrelated process; it must be ignored.
let shutdown = ShutdownProbe(directory: CommandLine.arguments[1])
let owned = Process()
owned.executableURL = URL(fileURLWithPath: "/bin/bash")
let descendantsPath = (shutdown.directory as NSString).appendingPathComponent("descendants")
owned.arguments = ["-c", "trap ':' TERM; while :; do /bin/sleep 60 & echo $! >> \"$1\"; wait $!; done", "owned-runtime", descendantsPath]
try owned.run()
shutdown.pythonProcess = owned
let unrelated = Process()
unrelated.executableURL = URL(fileURLWithPath: "/bin/sleep")
unrelated.arguments = ["60"]
try unrelated.run()
try String(unrelated.processIdentifier).write(toFile: shutdown.runtimePIDFilePath!, atomically: true, encoding: .utf8)
Thread.sleep(forTimeInterval: 0.2)
let started = Date()
shutdown.stopFlask(wait: true)
Thread.sleep(forTimeInterval: 0.1)
let ownedStopped = !owned.isRunning
let unrelatedSurvived = unrelated.isRunning
let descendantPIDs = try String(contentsOfFile: descendantsPath).split(separator: "\n").compactMap { Int32($0) }
let survivingDescendants = descendantPIDs.filter { kill($0, 0) == 0 }
// Always clean up a failed regression without hiding the survivor assertion.
for pid in survivingDescendants { kill(pid, SIGKILL) }
if owned.isRunning { kill(owned.processIdentifier, SIGKILL) }
if unrelated.isRunning { unrelated.terminate() }
owned.waitUntilExit()
unrelated.waitUntilExit()
precondition(ownedStopped, "An owned child ignoring TERM must be stopped")
precondition(unrelatedSurvived, "An unrelated PID in a stale marker must survive")
precondition(descendantPIDs.count >= 2, "TERM handling must launch a replacement descendant during the grace period")
precondition(survivingDescendants.isEmpty, "Every owned descendant must be stopped, including replacements after TERM")
precondition(Date().timeIntervalSince(started) < 6, "Cleanup must be bounded")
print("Native status and managed attachment checks passed")
'''
    harness = tmp_path / "main.swift"
    harness.write_text(source)
    binary = tmp_path / "launcher-model-test"
    compiled = subprocess.run(
        ["swiftc", "-module-cache-path", str(tmp_path / "module-cache"), str(harness), "-o", str(binary)],
        capture_output=True, text=True, timeout=90,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    checked = subprocess.run([str(binary), str(tmp_path)], capture_output=True, text=True, timeout=15)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert "Native status and managed attachment checks passed" in checked.stdout
