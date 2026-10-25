import os
import json
import plistlib
import runpy
import base64
from contextlib import closing
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
APP_BUNDLE = ROOT / "NmapUI.app"
RUN_SCRIPT = APP_BUNDLE / "Contents" / "Resources" / "run.sh"


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_url(url, *, timeout=60, headers=None, process=None):
    deadline = time.monotonic() + timeout
    last_error = None

    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise AssertionError(f"Packaged process exited with status {process.returncode} while waiting for {url}")
        try:
            with urlopen(Request(url, headers=headers or {}), timeout=5) as response:
                return response.read().decode("utf-8", errors="replace")
        except HTTPError as error:
            last_error = f"{error}: {error.read(2048).decode('utf-8', errors='replace')}"
        except Exception as error:  # pragma: no cover - exercised only in smoke mode
            last_error = error
        time.sleep(0.25)

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
    # Startup/browser smoke must work without public network availability.
    for flag in ("NMAPUI_STARTUP_TRACEROUTE", "NMAPUI_ENABLE_NETWORK_FINGERPRINT",
                 "NMAPUI_ENABLE_UPDATE_CHECK", "NMAPUI_ENABLE_VULNERS"):
        env[flag] = "false"
    env["NMAPUI_HOST"] = "127.0.0.1"
    env["NMAPUI_PORT"] = str(port)
    env["NMAPUI_APPLICATIONS_DIR"] = str(tmp_path / "Applications")
    env["NMAPUI_DATA_DIR"] = str(tmp_path / "data")
    env["NMAPUI_LOG_DIR"] = str(tmp_path / "logs")
    env["NMAPUI_USERNAME"] = "smöké-test"
    env["NMAPUI_PASSWORD"] = "isolated-smoke-test-pässword"
    env["NMAPUI_TRUST_LOCAL_UI"] = "false"
    env["NMAPUI_SKIP_LEGACY_MIGRATION"] = "1"
    env["NMAPUI_SKIP_EMBEDDED_DRIVE_CREDENTIALS"] = "1"
    migration_source = tmp_path / "source-runtime.sqlite3"
    with closing(sqlite3.connect(migration_source)) as source_conn:
        source_conn.execute("PRAGMA journal_mode=WAL")
        source_conn.execute("PRAGMA wal_autocheckpoint=0")
        source_conn.execute("CREATE TABLE migration_smoke (value TEXT NOT NULL)")
        source_conn.execute("INSERT INTO migration_smoke VALUES ('committed-in-wal')")
        source_conn.commit()
        assert Path(f"{migration_source}-wal").is_file()
        env["NMAPUI_MIGRATE_DB"] = "1"
        env["NMAPUI_MIGRATE_DB_FROM"] = str(migration_source)
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

        with closing(sqlite3.connect(Path(env["NMAPUI_DATA_DIR"]) / "runtime.sqlite3")) as installed_conn:
            assert installed_conn.execute("SELECT value FROM migration_smoke").fetchone() == (
                "committed-in-wal",
            )

    assert APP_BUNDLE.exists()
    assert RUN_SCRIPT.exists()
    bundled_resources = APP_BUNDLE / "Contents" / "Resources"
    raw_version, short_version, build_version = runpy.run_path(
        str(ROOT / "packaging/macos/bundle_version.py")
    )["bundle_versions"]((ROOT / "VERSION").read_text())
    with (APP_BUNDLE / "Contents/Info.plist").open("rb") as plist_file:
        bundle_metadata = plistlib.load(plist_file)
    assert bundle_metadata["CFBundleShortVersionString"] == short_version
    assert bundle_metadata["CFBundleVersion"] == build_version
    assert (bundled_resources / "VERSION").read_text().strip() == raw_version
    bundled_web_report_xsl = (bundled_resources / "nmap-modern.xsl").read_text(encoding="utf-8")
    bundled_pdf_report_xsl = (bundled_resources / "nmap-pdf-olive-legacy.xsl").read_text(
        encoding="utf-8"
    )
    assert 'id="vuln-critical-count"' in bundled_web_report_xsl
    assert 'id="vuln-critical-count"' in bundled_pdf_report_xsl
    assert "No findings do not prove a host is free of vulnerabilities." in bundled_web_report_xsl
    assert "No findings do not prove a host is free of vulnerabilities." in bundled_pdf_report_xsl
    assert not (bundled_resources / "nmap-vulners" / "vulners_enterprise.nse").exists()
    assert (bundled_resources / "static" / "vendor" / "fonts.css").is_file()
    assert (bundled_resources / "static" / "vendor" / "fonts" / "files").is_dir()

    # Do not leave PIPE buffers undrained while polling health: verbose startup
    # or request logs can fill them and stall an otherwise responsive server.
    launch_log_path = tmp_path / "packaged-launch.log"
    launch_log = launch_log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [str(RUN_SCRIPT)],
        cwd=RUN_SCRIPT.parent,
        env=env,
        stdout=launch_log,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        started = time.monotonic()
        health_body = _wait_for_url(f"http://127.0.0.1:{port}/api/health/live", timeout=90, process=process)
        readiness = json.loads(_wait_for_url(f"http://127.0.0.1:{port}/api/health/ready", timeout=30, process=process))
        elapsed = time.monotonic() - started
        print(f"Packaged runtime reached readiness after {elapsed:.2f}s on loopback port {port}")
        assert readiness["ready"] is True
        assert readiness["startup"]["startup_complete"] is True
        assert readiness["startup"]["dependencies_ok"] is True
        assert readiness["startup"]["traceroute_initialized"] is False
        assert readiness["auto_scan_thread_alive"] is True
        status_url = f"http://127.0.0.1:{port}/api/runtime/status"
        with pytest.raises(HTTPError) as denied:
            urlopen(status_url, timeout=5)
        assert denied.value.code == 401
        with urlopen(Request(status_url, headers={"Authorization": f"Basic {authorization}"}), timeout=5) as response:
            assert response.headers["Cache-Control"] == "no-store"
            assert json.load(response)["has_active_jobs"] is False
        launch_log.flush()
        startup_log = launch_log_path.read_text(encoding="utf-8", errors="replace")
        assert "Skipping public traceroute during service startup" in startup_log
        assert "Running traceroute:" not in startup_log
        index_body = _wait_for_url(
            f"http://127.0.0.1:{port}/", timeout=30,
            headers={"Authorization": f"Basic {authorization}"},
        )
        tailwind_body = _wait_for_url(f"http://127.0.0.1:{port}/static/css/tailwind.css")
        socket_body = _wait_for_url(f"http://127.0.0.1:{port}/static/vendor/socket.io.min.js")
        lucide_body = _wait_for_url(f"http://127.0.0.1:{port}/static/vendor/lucide.min.js")
        fonts_body = _wait_for_url(f"http://127.0.0.1:{port}/static/vendor/fonts.css")
        inter_font_body = _wait_for_url(
            f"http://127.0.0.1:{port}/static/vendor/fonts/files/inter-latin-opsz-normal.woff2"
        )
        report_runtime_body = _wait_for_url(
            f"http://127.0.0.1:{port}/static/js/report_runtime.js"
        )

        assert "ok" in health_body.lower()
        assert "Dashboard" in index_body
        assert "Reports" in index_body
        assert "/static/css/tailwind.css" in index_body
        assert "/static/vendor/socket.io.min.js" in index_body
        assert "/static/vendor/lucide.min.js" in index_body
        assert "/static/vendor/fonts.css" in index_body
        assert len(tailwind_body) > 25_000
        assert "EIO=4" in socket_body
        assert "lucide" in lucide_body.lower()
        assert "font-family: 'Inter'" in fonts_body
        assert "font-family: 'Instrument Serif'" in fonts_body
        assert len(inter_font_body) > 10_000
        assert "spreadsheetSafeText" in report_runtime_body
        assert "csvValue(cell.textContent)" in report_runtime_body
        assert "csvValue(cell.textContent.trim())" not in report_runtime_body
    except Exception as error:
        launch_log.flush()
        diagnostics = launch_log_path.read_text(encoding="utf-8", errors="replace")[-12_000:]
        raise AssertionError(
            f"Packaged smoke failed (process status {process.poll()}): {error}\n{diagnostics}"
        ) from error
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover - exercised only in smoke mode
            process.kill()
            process.wait(timeout=5)
        launch_log.close()


@pytest.mark.parametrize("operator_setting,expected", [(None, "false"), ("true", "true"), ("false", "false")])
def test_packaged_entrypoint_defaults_startup_traceroute_off_and_preserves_operator_choice(tmp_path, operator_setting, expected):
    source = (ROOT / "build.sh").read_text()
    script = source.split('cat > "$APP_NAME/Contents/Resources/run.sh" << \'EOF\'\n', 1)[1].split('\nEOF', 1)[0]
    (tmp_path / ".venv/bin").mkdir(parents=True)
    (tmp_path / ".venv/bin/activate").write_text("")
    (tmp_path / "run.sh").write_text(script)
    (tmp_path / "app.py").write_text('import os; print(os.environ["NMAPUI_STARTUP_TRACEROUTE"])')
    env = {**os.environ, "NMAPUI_DATA_DIR": str(tmp_path / "data"), "NMAPUI_LOG_DIR": str(tmp_path / "logs"),
           "NMAPUI_USERNAME": "test", "NMAPUI_PASSWORD": "isolated-test"}
    env.pop("NMAPUI_STARTUP_TRACEROUTE", None)
    if operator_setting is not None:
        env["NMAPUI_STARTUP_TRACEROUTE"] = operator_setting
    result = subprocess.run(["bash", str(tmp_path / "run.sh")], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


def test_packaged_health_wait_reports_exited_child_without_waiting_for_deadline():
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(7)"])
    child.wait(timeout=5)
    with pytest.raises(AssertionError, match="exited with status 7"):
        _wait_for_url("http://127.0.0.1:1/api/health/live", timeout=90, process=child)
