import importlib
import os
from pathlib import Path
import shutil
import socket
import threading
import time
import uuid
from urllib.request import urlopen

import pytest

from persistence import remove_scan_metadata_index_entry, upsert_scan_metadata_index_entry


ROOT = Path(__file__).resolve().parents[1]


def _require_browser_regression_enabled():
    if os.environ.get("NMAPUI_RUN_BROWSER_REGRESSION") != "1":
        pytest.skip("Set NMAPUI_RUN_BROWSER_REGRESSION=1 to run browser regression coverage")


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_url(url, *, timeout=60):
    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        try:
            with urlopen(url, timeout=5) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception as error:  # pragma: no cover - only exercised in gated mode
            last_error = error
            time.sleep(1)

    raise AssertionError(f"Timed out waiting for {url}: {last_error}")


def _get_browser(playwright):
    try:
        return playwright.chromium.launch(headless=True)
    except Exception as error:  # pragma: no cover - only exercised in gated mode
        pytest.fail(f"Browser regression coverage was enabled but Chromium could not launch: {error}")


def _connect_socket(browser_server):
    # Flask-SocketIO's in-process test_client replaces the server's packet
    # senders globally, breaking the real browser connections under test.
    import socketio

    client = socketio.Client(handle_sigint=False, reconnection=False, request_timeout=5)
    client.connect(browser_server["base_url"], transports=["polling"])
    return client


def _get_socket_sid(client):
    return client.get_sid("/")


@pytest.fixture(scope="session")
def browser_server(tmp_path_factory):
    _require_browser_regression_enabled()

    os.environ.setdefault("NMAPUI_TRUST_LOCAL_UI", "true")
    os.environ.setdefault("NMAPUI_ALLOW_UNSAFE_WERKZEUG", "true")
    os.environ.setdefault("NMAPUI_DEBUG", "false")
    os.environ.setdefault("NMAPUI_USERNAME", "scanner")
    os.environ.setdefault("NMAPUI_PASSWORD", "secret-pass")
    # The network Socket.IO client and Playwright pages do not carry the loopback
    # token; disable socket auth for browser regressions.
    os.environ.setdefault("NMAPUI_SOCKET_AUTH_DISABLED", "true")

    port = _find_free_port()
    # The app builds its explicit origin allowlist at import time. Use that
    # same port for the test server rather than binding a different one later.
    os.environ["NMAPUI_PORT"] = str(port)
    data_dir = tmp_path_factory.mktemp("browser-runtime")
    os.environ["NMAPUI_DATA_DIR"] = str(data_dir)
    app_module = importlib.import_module("app")

    server_thread = threading.Thread(
        target=lambda: app_module.socketio.run(
            app_module.app,
            host="127.0.0.1",
            port=port,
            debug=False,
            allow_unsafe_werkzeug=True,
        ),
        daemon=True,
    )
    server_thread.start()

    _wait_for_url(f"http://127.0.0.1:{port}/api/health/live", timeout=90)

    yield {
        "app_module": app_module,
        "base_url": f"http://127.0.0.1:{port}",
        "scans_dir": data_dir / "scans",
    }


@pytest.fixture
def playwright_browser():
    _require_browser_regression_enabled()
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = _get_browser(playwright)
        try:
            yield browser
        finally:
            browser.close()


@pytest.fixture
def scan_fixture(browser_server):
    scans_dir = browser_server["scans_dir"]
    fixture_id = uuid.uuid4().hex[:8]
    customer_name = f"Browser Regression {fixture_id}"
    customer_root = scans_dir / customer_name
    primary_dir = customer_root / "2026-03-14" / "scan_120000_198.51.100.0_24"
    baseline_dir = customer_root / "2026-03-13" / "scan_110000_198.51.100.0_24"

    for scan_dir, timestamp, diff_summary in (
        (
            primary_dir,
            "2026-03-14T12:00:00",
            {
                "has_changes": True,
                "baseline_timestamp": "2026-03-13T11:00:00",
                "added_hosts": ["198.51.100.12"],
                "removed_hosts": [],
                "changed_hosts": ["198.51.100.10"],
                "new_ports": ["198.51.100.10:443"],
                "removed_ports": [],
                "new_vulnerabilities": ["CVE-2026-0001"],
                "removed_vulnerabilities": [],
            },
        ),
        (
            baseline_dir,
            "2026-03-13T11:00:00",
            None,
        ),
    ):
        scan_dir.mkdir(parents=True, exist_ok=True)
        metadata = {
            "customer_name": customer_name,
            "customer_id": f"browser-{fixture_id}",
            "target": "198.51.100.0/24",
            "timestamp": timestamp,
            "date": timestamp[:10],
            "time": timestamp[11:19],
            "status": "completed",
            "completed_successfully": True,
            "diff_summary": diff_summary,
            "asset_snapshot": (
                [{"ip": "198.51.100.10", "ports": "80,443"},
                 {"ip": "198.51.100.12", "ports": "22"}]
                if diff_summary else [{"ip": "198.51.100.10", "ports": "80"}]
            ),
        }
        (scan_dir / "metadata.json").write_text(__import__("json").dumps(metadata, indent=2))
        (scan_dir / "scan_web.html").write_text(
            f"<html><body><h1>{customer_name} Report</h1><p>Browser fixture report body</p></body></html>"
        )
        (scan_dir / "scan_report.pdf").write_bytes(b"%PDF-1.4\n% browser fixture\n")
        (scan_dir / "scan.xml").write_text("<nmaprun></nmaprun>")
        upsert_scan_metadata_index_entry(scans_dir, scan_dir, metadata)
        # Mirror into the runtime sqlite store: /api/runtime/reports reads only from
        # the store, so JSON-index-only writes are invisible to the running server.
        import sys as _sys
        runtime_store = getattr(_sys.modules.get("app"), "runtime_store", None)
        if runtime_store is not None:
            rel = str(scan_dir.relative_to(scans_dir))
            runtime_store.upsert_report_artifact(
                scan_path=rel,
                customer_id=str(metadata.get("customer_id", "") or ""),
                target=str(metadata.get("target", "") or ""),
                html_path=str(scan_dir / "scan_web.html"),
                pdf_path=str(scan_dir / "scan_report.pdf") if (scan_dir / "scan_report.pdf").exists() else None,
                xml_path=str(scan_dir / "scan.xml"),
                payload=metadata,
            )

    try:
        yield {
            "customer_name": customer_name,
            "report_title": f"{customer_name} Report",
        }
    finally:
        for scan_dir in (primary_dir, baseline_dir):
            if runtime_store is not None:
                runtime_store.delete_report_artifact(str(scan_dir.relative_to(scans_dir)))
            if scan_dir.exists():
                remove_scan_metadata_index_entry(scans_dir, scan_dir)
        if customer_root.exists():
            shutil.rmtree(customer_root, ignore_errors=True)


def test_reports_tab_renders_saved_report_and_view_action(browser_server, playwright_browser, scan_fixture):
    context = playwright_browser.new_context()
    page = context.new_page()

    page.goto(browser_server["base_url"], wait_until="domcontentloaded")
    page.locator("#tab-reports-btn").click()

    page.locator("#reports-tab-list").get_by_text(scan_fixture["customer_name"]).first.wait_for()
    view_link = page.locator("#reports-tab-list").get_by_role("link", name="View Report").first

    with context.expect_page() as popup_info:
        view_link.click()

    report_page = popup_info.value
    report_page.wait_for_load_state("networkidle")
    assert scan_fixture["report_title"] in report_page.content()

    report_page.close()
    context.close()


def test_history_tab_renders_diff_summary(browser_server, playwright_browser, scan_fixture):
    context = playwright_browser.new_context()
    page = context.new_page()

    page.goto(browser_server["base_url"], wait_until="domcontentloaded")
    page.locator("#tab-history-btn").click()
    page.locator("#history-focus-all-btn").click()

    history_list = page.locator("#history-tab-list")
    fixture_card = history_list.locator("article").filter(
        has=page.locator("h3", has_text=scan_fixture["customer_name"])
    ).first
    fixture_card.wait_for()
    fixture_card.get_by_text("Changes since previous scan").wait_for()
    fixture_card.get_by_text("1 new host(s)").wait_for()
    fixture_card.get_by_text("1 changed host(s)").wait_for()

    context.close()


def test_history_tab_compares_selected_scan_pair(browser_server, playwright_browser, scan_fixture):
    context = playwright_browser.new_context()
    page = context.new_page()

    page.goto(browser_server["base_url"], wait_until="domcontentloaded")
    page.locator("#tab-history-btn").click()
    page.locator("#history-focus-all-btn").click()

    history_cards = page.locator("#history-tab-list article").filter(
        has=page.locator("h3", has_text=scan_fixture["customer_name"])
    )
    # History is newest first: compare the current scan against the older base.
    history_cards.nth(1).get_by_role("button", name="Select Base").click()
    history_cards.first.get_by_role("button", name="Compare to Base").click()

    page.locator("#history-compare-panel").wait_for()
    page.locator("#history-compare-summary").get_by_text("new host(s)").wait_for()
    page.locator("#history-compare-details").get_by_text("198.51.100.12").wait_for()
    page.locator("#history-compare-details").get_by_text("198.51.100.10").wait_for()

    context.close()


def test_second_tab_replays_active_report_state(browser_server, playwright_browser):
    app_module = browser_server["app_module"]
    owner_client = _connect_socket(browser_server)
    owner_sid = _get_socket_sid(owner_client)

    app_module.set_current_customer_state(
        {"id": "browser-live", "name": "Browser Live Customer", "confidence": 1.0},
        sid=owner_sid,
    )
    app_module.set_network_key_state(
        {
            "target": "1.1.1.1",
            "total_hops": 1,
            "private_hops": [],
            "public_hops": [{"ip": "1.1.1.1", "is_private": False}],
            "exit_ip": "1.1.1.1",
            "hops": [{"ip": "1.1.1.1", "is_private": False}],
        },
        sid=owner_sid,
    )
    app_module.set_last_scan_target_state(value="198.51.100.0/24", sid=owner_sid)
    app_module.job_registry.start(
        owner_sid,
        "report",
        {"message": "Generating report...", "target": "198.51.100.0/24"},
    )
    app_module.broadcaster.start_job(owner_sid, job_type="report")
    app_module.broadcaster.record(
        owner_sid,
        "scan_feedback",
        {"message": "Generating report...", "target": "198.51.100.0/24"},
        job_type="report",
    )

    browser = playwright_browser
    context = browser.new_context()
    first_page = context.new_page()
    second_page = context.new_page()

    try:
        for page in (first_page, second_page):
            page.goto(browser_server["base_url"], wait_until="domcontentloaded")
            page.locator("#scan-target").wait_for()
            page.wait_for_function("() => window.socket && window.socket.connected")
            page.wait_for_function(
                "() => document.getElementById('scan-target').value === '198.51.100.0/24'"
            )
            page.wait_for_function(
                "() => document.getElementById('report-status-text').textContent.includes('Generating report')"
            )
            page.wait_for_function(
                "() => document.getElementById('generate-report-btn').classList.contains('card-pulsing')"
            )
            page.wait_for_function(
                "() => !document.getElementById('start-scan-btn').classList.contains('ring-4')"
            )
    finally:
        app_module.broadcaster.end_job(owner_sid, job_type="report")
        app_module.job_registry.complete(owner_sid, "report", status="completed")
        owner_client.disconnect()
        context.close()


def test_second_tab_replays_active_scan_state(browser_server, playwright_browser):
    app_module = browser_server["app_module"]
    owner_client = _connect_socket(browser_server)
    owner_sid = _get_socket_sid(owner_client)

    app_module.set_current_customer_state(
        {"id": "browser-scan", "name": "Browser Scan Customer", "confidence": 1.0},
        sid=owner_sid,
    )
    app_module.set_network_key_state(
        {
            "target": "1.1.1.1",
            "total_hops": 1,
            "private_hops": [],
            "public_hops": [{"ip": "1.1.1.1", "is_private": False}],
            "exit_ip": "1.1.1.1",
            "hops": [{"ip": "1.1.1.1", "is_private": False}],
        },
        sid=owner_sid,
    )
    app_module.set_last_scan_target_state(value="198.51.100.0/24", sid=owner_sid)
    app_module.job_registry.start(
        owner_sid,
        "scan",
        {"message": "Running quick scan on 198.51.100.0/24", "target": "198.51.100.0/24"},
    )
    app_module.broadcaster.start_job(owner_sid, job_type="scan")
    app_module.broadcaster.record(
        owner_sid,
        "scan_feedback",
        "Running quick scan on 198.51.100.0/24",
        job_type="scan",
    )

    browser = playwright_browser
    context = browser.new_context()
    first_page = context.new_page()
    second_page = context.new_page()

    try:
        for page in (first_page, second_page):
            page.goto(browser_server["base_url"], wait_until="domcontentloaded")
            page.locator("#scan-target").wait_for()
            page.wait_for_function("() => window.socket && window.socket.connected")
            page.wait_for_function(
                "() => document.getElementById('scan-target').value === '198.51.100.0/24'"
            )
            page.wait_for_function(
                "() => document.getElementById('report-status-text').textContent.includes('Running quick scan')"
            )
            page.wait_for_function(
                "() => document.getElementById('report-status-text').textContent.includes('Running quick scan on 198.51.100.0/24')"
            )
            page.wait_for_function(
                "() => document.getElementById('start-scan-btn').classList.contains('ring-4')"
            )
            page.wait_for_function(
                "() => !document.getElementById('generate-report-btn').classList.contains('card-pulsing')"
            )
    finally:
        app_module.broadcaster.end_job(owner_sid, job_type="scan")
        app_module.job_registry.complete(owner_sid, "scan", status="completed")
        owner_client.disconnect()
        context.close()


def test_existing_open_tabs_receive_live_report_state(browser_server, playwright_browser):
    app_module = browser_server["app_module"]
    browser = playwright_browser
    context = browser.new_context()
    first_page = context.new_page()
    second_page = context.new_page()

    try:
        for page in (first_page, second_page):
            page.goto(browser_server["base_url"], wait_until="domcontentloaded")
            page.locator("#scan-target").wait_for()
            page.wait_for_function("() => window.socket && window.socket.connected")

        owner_client = _connect_socket(browser_server)
        owner_sid = _get_socket_sid(owner_client)
        try:
            app_module.set_last_scan_target_state(value="198.51.100.0/24", sid=owner_sid)
            app_module.job_registry.start(
                owner_sid,
                "report",
                {
                    "message": "Generating report...",
                    "target": "198.51.100.0/24",
                    "chunked": False,
                },
            )
            app_module.broadcaster.start_job(owner_sid, job_type="report")
            app_module.emit_job_status(owner_sid, "report")
            for subscriber_sid in app_module.broadcaster.get_subscribers(
                owner_sid,
                job_type="report",
            ):
                app_module.emit_to_client(
                    subscriber_sid,
                    "scan_feedback",
                    {
                        "message": "Generating report...",
                        "target": "198.51.100.0/24",
                    },
                )

            for page in (first_page, second_page):
                page.wait_for_function(
                    "() => document.getElementById('generate-report-btn').classList.contains('card-pulsing')"
                )
                page.wait_for_function(
                    "() => !document.getElementById('start-scan-btn').classList.contains('ring-4')"
                )
                page.wait_for_function(
                    "() => document.getElementById('report-status-text').textContent.includes('Generating report')"
                )
        finally:
            app_module.broadcaster.end_job(owner_sid, job_type="report")
            app_module.job_registry.complete(owner_sid, "report", status="completed")
            owner_client.disconnect()
    finally:
        context.close()


def test_existing_open_tabs_receive_live_scan_state(browser_server, playwright_browser):
    app_module = browser_server["app_module"]
    browser = playwright_browser
    context = browser.new_context()
    first_page = context.new_page()
    second_page = context.new_page()

    try:
        for page in (first_page, second_page):
            page.goto(browser_server["base_url"], wait_until="domcontentloaded")
            page.locator("#scan-target").wait_for()
            page.wait_for_function("() => window.socket && window.socket.connected")

        owner_client = _connect_socket(browser_server)
        owner_sid = _get_socket_sid(owner_client)
        try:
            app_module.set_last_scan_target_state(value="198.51.100.0/24", sid=owner_sid)
            app_module.job_registry.start(
                owner_sid,
                "scan",
                {
                    "message": "Running quick scan on 198.51.100.0/24",
                    "target": "198.51.100.0/24",
                },
            )
            app_module.broadcaster.start_job(owner_sid, job_type="scan")
            app_module.emit_job_status(owner_sid, "scan")
            for subscriber_sid in app_module.broadcaster.get_subscribers(
                owner_sid,
                job_type="scan",
            ):
                app_module.emit_to_client(
                    subscriber_sid,
                    "scan_feedback",
                    "Running quick scan on 198.51.100.0/24",
                )

            for page in (first_page, second_page):
                page.wait_for_function(
                    "() => document.getElementById('start-scan-btn').classList.contains('ring-4')"
                )
                page.wait_for_function(
                    "() => !document.getElementById('generate-report-btn').classList.contains('card-pulsing')"
                )
                page.wait_for_function(
                    "() => document.getElementById('report-status-text').textContent.includes('Running quick scan on 198.51.100.0/24')"
                )
        finally:
            app_module.broadcaster.end_job(owner_sid, job_type="scan")
            app_module.job_registry.complete(owner_sid, "scan", status="completed")
            owner_client.disconnect()
    finally:
        context.close()
