import os
import base64
from contextlib import closing
from pathlib import Path
import shutil
import socket
import sqlite3
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
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover - exercised only in smoke mode
            process.kill()
            process.wait(timeout=5)
