import os
import base64
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
APP_BUNDLE = ROOT / "NmapUI.app"
RUN_SCRIPT = APP_BUNDLE / "Contents" / "Resources" / "run.sh"


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_url(url, *, timeout=60, headers=None):
    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        try:
            with urlopen(Request(url, headers=headers or {}), timeout=5) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception as error:  # pragma: no cover - exercised only in smoke mode
            last_error = error
            time.sleep(1)

    raise AssertionError(f"Timed out waiting for {url}: {last_error}")


@pytest.mark.skipif(sys.platform != "darwin", reason="packaged-app smoke test is macOS-only")
def test_build_script_output_launches_and_serves_health(tmp_path):
    if os.environ.get("NMAPUI_RUN_PACKAGED_SMOKE") != "1":
        pytest.skip("Set NMAPUI_RUN_PACKAGED_SMOKE=1 to run packaged-app smoke coverage")

    missing = [tool for tool in ("swiftc", "xcrun", "codesign") if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"Missing macOS packaging tools: {', '.join(missing)}")

    port = _find_free_port()
    env = os.environ.copy()
    env["NMAPUI_SKIP_OPEN"] = "1"
    env["NMAPUI_PORT"] = str(port)
    env["NMAPUI_APPLICATIONS_DIR"] = str(tmp_path / "Applications")
    env["NMAPUI_DATA_DIR"] = str(tmp_path / "data")
    env["NMAPUI_LOG_DIR"] = str(tmp_path / "logs")
    env["NMAPUI_USERNAME"] = "smoke-test"
    env["NMAPUI_PASSWORD"] = "isolated-smoke-test-password"
    env["NMAPUI_TRUST_LOCAL_UI"] = "false"
    authorization = base64.b64encode(
        f"{env['NMAPUI_USERNAME']}:{env['NMAPUI_PASSWORD']}".encode()
    ).decode()

    subprocess.run(
        ["bash", "build.sh"],
        cwd=ROOT,
        env=env,
        check=True,
        timeout=1800,
    )

    assert APP_BUNDLE.exists()
    assert RUN_SCRIPT.exists()

    process = subprocess.Popen(
        [str(RUN_SCRIPT)],
        cwd=RUN_SCRIPT.parent,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        health_body = _wait_for_url(f"http://127.0.0.1:{port}/api/health/live", timeout=90)
        index_body = _wait_for_url(
            f"http://127.0.0.1:{port}/", timeout=30,
            headers={"Authorization": f"Basic {authorization}"},
        )

        assert "ok" in health_body.lower()
        assert "Dashboard" in index_body
        assert "Reports" in index_body
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover - exercised only in smoke mode
            process.kill()
            process.wait(timeout=5)
