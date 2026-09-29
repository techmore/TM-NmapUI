"""Opt-in smoke test for the supervised single-worker Socket.IO server."""

import os
from pathlib import Path
import runpy
import signal
import socket
import subprocess
import sys
import time

import pytest
import requests
import socketio

from nmapui.runtime_db import create_runtime_state_store


ROOT = Path(__file__).resolve().parents[1]


def test_production_entrypoint_rejects_corrupt_session_key(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "session.key").write_bytes(b"short")
    env = {
        **os.environ,
        "NMAPUI_DATA_DIR": str(data_dir),
        "NMAPUI_LOG_DIR": str(tmp_path / "logs"),
        "NMAPUI_SKIP_LEGACY_MIGRATION": "1",
        "NMAPUI_STARTUP_TRACEROUTE": "false",
    }

    result = subprocess.run(
        [sys.executable, "-c", "import nmapui.wsgi"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
    )

    assert result.returncode != 0
    assert "Private file is too short" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="Privileged Nmap smoke requires POSIX")
def test_root_nmap_syn_scan_is_available_on_loopback():
    if os.environ.get("NMAPUI_RUN_PRIVILEGED_SCAN_SMOKE") != "1":
        pytest.skip("Set NMAPUI_RUN_PRIVILEGED_SCAN_SMOKE=1 to run the root scanner smoke test")
    assert os.geteuid() == 0, "Run this smoke test as root on the isolated Ubuntu CI runner"

    result = subprocess.run(
        [
            "nmap", "-n", "-Pn", "-sS", "-p", "1",
            "--host-timeout", "10s", "127.0.0.1",
        ],
        capture_output=True, text=True, timeout=15, check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert "Nmap done:" in result.stdout
    assert "1 IP address" in result.stdout


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _assert_authenticated_browser_flow(base_url, username, password):
    from playwright.sync_api import sync_playwright

    def wait_for_socket_connection(page):
        page.locator("#scan-target").wait_for(state="visible", timeout=20_000)
        page.evaluate(
            """() => new Promise((resolve, reject) => {
                const socket = window.socket;
                if (!socket) {
                    reject(new Error('Socket.IO client was not initialized'));
                    return;
                }
                if (socket.connected) {
                    resolve(true);
                    return;
                }
                const timeout = window.setTimeout(
                    () => reject(new Error('Socket.IO did not connect in time')),
                    20_000
                );
                socket.once('connect', () => {
                    window.clearTimeout(timeout);
                    resolve(true);
                });
            })"""
        )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.goto(f"{base_url}/", wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_url("**/login", timeout=20_000)
            assert page.get_by_role("heading", name="NmapUI").is_visible()
            page.locator("#username").fill(username)
            page.locator("#password").fill(password)
            with page.expect_response(
                lambda response: response.url.split("?", 1)[0] == f"{base_url}/login"
                and response.request.method == "POST"
            ) as login_response:
                page.get_by_role("button", name="Sign in").click()
            assert login_response.value.status == 302, (
                f"Login returned HTTP {login_response.value.status}: "
                f"{login_response.value.text()}"
            )
            page.wait_for_url(f"{base_url}/", wait_until="domcontentloaded", timeout=20_000)
            wait_for_socket_connection(page)
            session_status = page.evaluate(
                """async () => {
                    const response = await fetch('/api/session/status');
                    return { status: response.status, body: await response.json() };
                }"""
            )
            assert session_status == {
                "status": 200,
                "body": {
                    "authenticated": True,
                    "username": username,
                    "local_trust": False,
                    "auth_configured": True,
                },
            }

            page.reload(wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_url(f"{base_url}/", wait_until="domcontentloaded", timeout=20_000)
            wait_for_socket_connection(page)
            reloaded_status = page.evaluate(
                """async () => {
                    const response = await fetch('/api/session/status');
                    return { status: response.status, body: await response.json() };
                }"""
            )
            assert reloaded_status == session_status
        finally:
            browser.close()


def test_gunicorn_readiness_stays_degraded_when_recovery_write_fails(tmp_path):
    if os.environ.get("NMAPUI_RUN_PRODUCTION_SMOKE") != "1":
        pytest.skip("Set NMAPUI_RUN_PRODUCTION_SMOKE=1 to run the production server smoke test")

    runtime_root = ROOT
    runtime_python = sys.executable
    if os.environ.get("NMAPUI_RUN_STAGED_SMOKE") == "1":
        stage_runtime = runpy.run_path(str(ROOT / "packaging" / "stage_runtime.py"))["stage_runtime"]
        runtime_root = stage_runtime(ROOT, tmp_path / "release")
        runtime_python = str(runtime_root / ".venv" / "bin" / "python")

    data_dir = tmp_path / "data"
    store = create_runtime_state_store(data_dir / "runtime.sqlite3")
    store.upsert_job(
        job_id="interrupted-job", owner_sid="sid", job_type="scan",
        status="running", payload={"target": "127.0.0.1"},
    )
    with store.connect() as conn:
        conn.execute(
            "CREATE TRIGGER refuse_recovery BEFORE UPDATE ON jobs "
            "BEGIN SELECT RAISE(ABORT, 'injected recovery failure'); END"
        )

    port = _free_port()
    env = {
        **os.environ,
        "NMAPUI_DATA_DIR": str(data_dir),
        "NMAPUI_LOG_DIR": str(tmp_path / "logs"),
        "NMAPUI_SKIP_LEGACY_MIGRATION": "1",
        "NMAPUI_HOST": "127.0.0.1",
        "NMAPUI_PORT": str(port),
        "NMAPUI_STARTUP_TRACEROUTE": "false",
        "NMAPUI_TRUST_LOCAL_UI": "true",
        "NMAPUI_USERNAME": "smoke",
        "NMAPUI_PASSWORD": "smoke-secret-password",
    }
    log_path = tmp_path / "recovery-gunicorn.log"
    with log_path.open("w+") as log_file:
        process = subprocess.Popen(
            [
                runtime_python, "-m", "gunicorn",
                "--bind", f"127.0.0.1:{port}",
                "--workers", "1", "--threads", "10", "--timeout", "180",
                "nmapui.wsgi:application",
            ],
            cwd=runtime_root, env=env, stdout=log_file, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail(f"Gunicorn exited early:\n{log_path.read_text()}")
                try:
                    response = requests.get(
                        f"http://127.0.0.1:{port}/api/health/ready", timeout=2
                    )
                    body = response.json()
                    if body.get("startup", {}).get("startup_complete"):
                        break
                except (requests.RequestException, ValueError):
                    pass
                time.sleep(0.25)
            else:
                pytest.fail(f"Gunicorn did not complete startup:\n{log_path.read_text()}")

            assert response.status_code == 503
            assert body["ready"] is False
            assert body["startup"]["recovery"] == {
                "ok": False, "failed_jobs": 1, "listing_error": None,
            }
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def test_gunicorn_worker_serves_authenticated_browser_and_websocket(tmp_path):
    if os.environ.get("NMAPUI_RUN_PRODUCTION_SMOKE") != "1":
        pytest.skip("Set NMAPUI_RUN_PRODUCTION_SMOKE=1 to run the production server smoke test")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    runtime_root = ROOT
    runtime_python = sys.executable
    if os.environ.get("NMAPUI_RUN_STAGED_SMOKE") == "1":
        stage_runtime = runpy.run_path(str(ROOT / "packaging" / "stage_runtime.py"))["stage_runtime"]
        runtime_root = stage_runtime(ROOT, tmp_path / "release")
        runtime_python = str(runtime_root / ".venv" / "bin" / "python")
    env = {
        **os.environ,
        "NMAPUI_DATA_DIR": str(tmp_path / "data"),
        "NMAPUI_LOG_DIR": str(tmp_path / "logs"),
        "NMAPUI_HOST": "127.0.0.1",
        "NMAPUI_PORT": str(port),
        "NMAPUI_STARTUP_TRACEROUTE": "false",
        "NMAPUI_TRUST_LOCAL_UI": "false",
        "NMAPUI_USERNAME": "smoke",
        "NMAPUI_PASSWORD": "smoke-secret-password",
    }
    log_path = tmp_path / "gunicorn.log"
    with log_path.open("w+") as log_file:
        process = subprocess.Popen(
            [
                runtime_python, "-m", "gunicorn",
                "--bind", f"127.0.0.1:{port}",
                "--workers", "1", "--threads", "10", "--timeout", "180",
                "nmapui.wsgi:application",
            ],
            cwd=runtime_root,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        client = None
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    response = requests.get(f"{base_url}/api/health/ready", timeout=2)
                    if response.status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.25)
            else:
                pytest.fail(f"Gunicorn did not become ready:\n{log_path.read_text()}")

            if process.poll() is not None:
                pytest.fail(f"Gunicorn exited early:\n{log_path.read_text()}")
            assert response.json()["ready"] is True
            assert response.json()["auto_scan_thread_alive"] is True
            assert response.json()["startup"]["traceroute_initialized"] is False
            assert response.json()["startup"]["recovery"]["ok"] is True
            session_key = tmp_path / "data" / "session.key"
            assert session_key.stat().st_mode & 0o777 == 0o600
            if runtime_root != ROOT:
                assert response.json()["release_id"] == (runtime_root / "release_id").read_text().strip()
                checker = ROOT / "packaging" / "check_release_ready.py"
                result = subprocess.run(
                    [sys.executable, str(checker), "--release", str(runtime_root), "--port", str(port)],
                    capture_output=True, text=True, timeout=10,
                )
                assert result.returncode == 0, result.stderr

                wrong_release = tmp_path / "wrong-release"
                wrong_release.mkdir()
                (wrong_release / "release_id").write_text("0" * 32 + "\n", encoding="ascii")
                result = subprocess.run(
                    [sys.executable, str(checker), "--release", str(wrong_release), "--port", str(port)],
                    capture_output=True, text=True, timeout=10,
                )
                assert result.returncode == 1

            browser = requests.Session()
            assert browser.get(f"{base_url}/api/session/status", timeout=3).status_code == 401
            assert browser.get(f"{base_url}/api/socket-token", timeout=3).status_code == 401

            login = browser.post(
                f"{base_url}/login",
                data={"username": "smoke", "password": "smoke-secret-password"},
                allow_redirects=False,
                timeout=3,
            )
            assert login.status_code == 302
            assert browser.cookies
            session_status = browser.get(f"{base_url}/api/session/status", timeout=3)
            assert session_status.status_code == 200
            assert session_status.json() == {
                "authenticated": True,
                "username": "smoke",
                "local_trust": False,
                "auth_configured": True,
            }

            token = browser.get(f"{base_url}/api/socket-token", timeout=3).json()["token"]
            cookie_header = "; ".join(
                f"{name}={value}" for name, value in browser.cookies.get_dict().items()
            )
            client = socketio.Client(handle_sigint=False, reconnection=False)
            client.connect(
                base_url,
                headers={"Cookie": cookie_header},
                auth={"token": token},
                transports=["websocket"],
                wait_timeout=10,
            )
            assert client.connected
            if os.environ.get("NMAPUI_RUN_BROWSER_AUTH_SMOKE") == "1":
                _assert_authenticated_browser_flow(
                    base_url,
                    "smoke",
                    "smoke-secret-password",
                )
        finally:
            if client is not None and client.connected:
                client.disconnect()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def test_installed_service_requires_session_and_accepts_websocket():
    base_url = os.environ.get("NMAPUI_TEST_INSTALLED_SERVICE_URL")
    username = os.environ.get("NMAPUI_TEST_INSTALLED_SERVICE_USERNAME")
    password = os.environ.get("NMAPUI_TEST_INSTALLED_SERVICE_PASSWORD")
    if not all((base_url, username, password)):
        pytest.skip("Set installed-service URL and throwaway credentials to run this check")

    _assert_authenticated_browser_flow(base_url, username, password)


@pytest.mark.skipif(os.name != "posix", reason="Scan process groups require POSIX")
def test_gunicorn_shutdown_reaps_stubborn_scan_child(tmp_path):
    if os.environ.get("NMAPUI_RUN_PRODUCTION_SMOKE") != "1":
        pytest.skip("Set NMAPUI_RUN_PRODUCTION_SMOKE=1 to run the production server smoke test")

    runtime_root = ROOT
    runtime_python = sys.executable
    if os.environ.get("NMAPUI_RUN_STAGED_SMOKE") == "1":
        stage_runtime = runpy.run_path(str(ROOT / "packaging" / "stage_runtime.py"))["stage_runtime"]
        runtime_root = stage_runtime(ROOT, tmp_path / "release")
        runtime_python = str(runtime_root / ".venv" / "bin" / "python")

    ticks = tmp_path / "scan-ticks.txt"
    child_pid_path = tmp_path / "scan-child.pid"
    child_code = (
        "import signal,sys,time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "path=Path(sys.argv[1])\n"
        "index=0\n"
        "while True:\n"
        " path.write_text(str(index)); index+=1; time.sleep(0.05)\n"
    )
    config = tmp_path / "gunicorn-reaper.py"
    config.write_text(
        "def post_worker_init(worker):\n"
        "    import app, subprocess, sys\n"
        "    from pathlib import Path\n"
        f"    child = subprocess.Popen([sys.executable, '-c', {child_code!r}, {str(ticks)!r}], start_new_session=True)\n"
        "    child._nmapui_process_group = True\n"
        "    app.job_registry.attach_process('smoke-sid', 'scan', child)\n"
        f"    Path({str(child_pid_path)!r}).write_text(str(child.pid))\n",
        encoding="utf-8",
    )
    port = _free_port()
    env = {
        **os.environ,
        "NMAPUI_DATA_DIR": str(tmp_path / "data"),
        "NMAPUI_LOG_DIR": str(tmp_path / "logs"),
        "NMAPUI_SKIP_LEGACY_MIGRATION": "1",
        "NMAPUI_HOST": "127.0.0.1",
        "NMAPUI_PORT": str(port),
        "NMAPUI_STARTUP_TRACEROUTE": "false",
        "NMAPUI_TRUST_LOCAL_UI": "true",
        "NMAPUI_USERNAME": "smoke",
        "NMAPUI_PASSWORD": "smoke-secret-password",
    }
    log_path = tmp_path / "gunicorn-reaper.log"
    child_pid = None
    with log_path.open("w+") as log_file:
        process = subprocess.Popen(
            [
                runtime_python, "-m", "gunicorn", "-c", str(config),
                "--bind", f"127.0.0.1:{port}",
                "--workers", "1", "--threads", "10", "--timeout", "180",
                "nmapui.wsgi:application",
            ],
            cwd=runtime_root, env=env, stdout=log_file, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail(f"Gunicorn exited early:\n{log_path.read_text()}")
                if child_pid_path.exists() and ticks.exists():
                    child_pid = int(child_pid_path.read_text())
                    break
                time.sleep(0.1)
            assert child_pid is not None, f"Worker did not start its scan child:\n{log_path.read_text()}"

            first_tick = ticks.read_text()
            deadline = time.monotonic() + 3
            while ticks.read_text() == first_tick and time.monotonic() < deadline:
                time.sleep(0.05)
            assert ticks.read_text() != first_tick, "Scan child did not make progress"

            process.terminate()
            process.wait(timeout=15)
            last_tick = ticks.read_text()
            time.sleep(0.2)
            assert ticks.read_text() == last_tick, f"Scan child survived Gunicorn shutdown:\n{log_path.read_text()}"
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
