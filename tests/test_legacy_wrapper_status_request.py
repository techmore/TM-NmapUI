"""Compile the actual legacy launcher and exercise only its request factory."""

import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform != "darwin", reason="Requires the macOS Cocoa SDK")
def test_production_legacy_status_request_preserves_unicode_basic_and_disables_cache(tmp_path):
    compiler = shutil.which("swiftc")
    assert compiler, "The macOS launcher requires swiftc"
    source = (ROOT / "packaging/macos/NmapUIMenuBarLauncher.swift").read_text()
    assert source.endswith("main()\n")
    # Remove only the app entrypoint invocation. The entire unchanged production
    # launcher still compiles, but no NSApplication, service or browser is started.
    source = source.removesuffix("main()\n") + r'''
let fixtureURL = URL(string: "http://127.0.0.1:12345/api/runtime/status")!
let request = makeRuntimeStatusRequest(url: fixtureURL, environment: [
    "NMAPUI_USERNAME": "scanner-雪", "NMAPUI_PASSWORD": "private-contraseña-🔐"
])
precondition(request.url == fixtureURL)
precondition(request.timeoutInterval == 1.5)
precondition(request.cachePolicy == .reloadIgnoringLocalCacheData)
for environment: [String: String] in [[:], ["NMAPUI_USERNAME": "scanner"],
    ["NMAPUI_USERNAME": "", "NMAPUI_PASSWORD": "password"],
    ["NMAPUI_USERNAME": "scanner", "NMAPUI_PASSWORD": " \t"]] {
    precondition(makeRuntimeStatusRequest(url: fixtureURL, environment: environment).value(forHTTPHeaderField: "Authorization") == nil)
}
let encoded = try JSONSerialization.data(withJSONObject: ["authorization": request.value(forHTTPHeaderField: "Authorization")!])
print(String(data: encoded, encoding: .utf8)!)
'''
    harness = tmp_path / "StatusRequest.swift"
    binary = tmp_path / "status-request"
    harness.write_text(source)
    subprocess.run([compiler, str(harness), "-o", str(binary)], check=True, capture_output=True, text=True, timeout=60)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=10)
    authorization = json.loads(result.stdout)["authorization"]
    assert authorization == "Basic " + base64.b64encode("scanner-雪:private-contraseña-🔐".encode()).decode()
