import importlib
import json
import os
from pathlib import Path
import shutil
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import quote
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
    os.environ["NMAPUI_ENABLE_NETWORK_FINGERPRINT"] = "false"
    os.environ["NMAPUI_ENABLE_UPDATE_CHECK"] = "false"
    os.environ["NMAPUI_ENABLE_VULNERS"] = "false"
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

    # Opening the UI requests a network key. Keep the browser regression
    # isolated from the host network and its customer scan history.
    from nmapui.client_state import DEFAULT_NETWORK_KEY

    original_traceroute = app_module.run_traceroute_runtime
    original_requests_get = app_module.requests.get
    allowed_external_lookups = []
    unexpected_lookups = []
    allowed_urls = {
        "https://api.github.com/repos/techmore/TM-NmapUI/releases/latest",
        "https://api.ipify.org",
    }

    class ResponseStub:
        text = "203.0.113.10"

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "tag_name": app_module.get_app_version(),
                "html_url": "https://github.com/techmore/TM-NmapUI/releases/latest",
                "body": "",
                "assets": [],
            }

    def isolated_requests_get(url, *args, **kwargs):
        if url not in allowed_urls:
            unexpected_lookups.append(url)
            raise RuntimeError(f"Unexpected external request in browser test: {url}")
        allowed_external_lookups.append(url)
        return ResponseStub()

    def test_traceroute(*, target, sid=None, deps):
        key = {
            **DEFAULT_NETWORK_KEY,
            "target": target,
            "total_hops": 1,
            "hops": [{"ip": target, "is_private": False}],
            "public_hops": [{"ip": target, "is_private": False}],
            "exit_ip": target,
        }
        app_module.set_network_key_state(key, sid=sid)
        return key

    app_module.run_traceroute_runtime = test_traceroute
    app_module.requests.get = isolated_requests_get

    try:
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
            "external_lookups": allowed_external_lookups,
        }
        assert not unexpected_lookups, f"Unexpected external test requests: {unexpected_lookups}"
        assert not allowed_external_lookups, (
            "managed-service opt-outs should keep browser connections from "
            f"requesting external enrichment services: {allowed_external_lookups}"
        )
    finally:
        app_module.run_traceroute_runtime = original_traceroute
        app_module.requests.get = original_requests_get


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
            "primary_dir": primary_dir,
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


def test_quick_start_shows_tool_versions_as_unchecked_not_missing(
    browser_server, playwright_browser
):
    context = playwright_browser.new_context()
    page = context.new_page()

    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.wait_for_function(
            """() => document.getElementById('settings-nmap-version').textContent === 'Nmap: Not checked'
            && document.getElementById('settings-vulners-version').textContent === 'Vulners: Not checked'
            && document.getElementById('settings-arpscan-version').textContent === 'ARP-Scan: Not checked'"""
        )
    finally:
        context.close()


def test_remote_sync_secret_is_not_persisted_in_browser_storage(
    browser_server, playwright_browser
):
    context = playwright_browser.new_context()
    page = context.new_page()
    secret = "browser-regression-remote-sync-secret"
    legacy_settings = json.dumps(
        {
            "scanOnlyMode": False,
            "excludedTargets": "",
            "remoteSyncApiKey": secret,
        }
    )
    page.add_init_script(
        f"localStorage.setItem('gemini-nmap-settings', {json.dumps(legacy_settings)});"
    )
    settings_posts = []
    page.on(
        "request",
        lambda request: settings_posts.append(json.loads(request.post_data))
        if request.method == "POST" and request.url.endswith("/api/settings")
        else None,
    )

    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.locator("#tab-settings-btn").click()
        page.get_by_text("Settings loaded from the local runtime.", exact=True).wait_for()

        assert page.locator("#settings-remote-sync-api-key").input_value() == ""
        stored = page.evaluate(
            "() => JSON.parse(localStorage.getItem('gemini-nmap-settings') || '{}')"
        )
        assert "remoteSyncApiKey" not in stored
        assert secret not in json.dumps(stored)

        page.locator("#settings-remote-sync-api-key").fill(secret)
        page.locator("#save-settings-btn").click()
        page.get_by_text("Settings saved to the local runtime and this browser.", exact=True).wait_for()
        assert settings_posts[-1]["sync"]["remote_sync"]["api_key"] == secret
        assert page.locator("#settings-remote-sync-api-key").input_value() == ""
        stored = page.evaluate(
            "() => JSON.parse(localStorage.getItem('gemini-nmap-settings') || '{}')"
        )
        assert "remoteSyncApiKey" not in stored
        assert secret not in json.dumps(stored)

        settings_doc = page.evaluate(
            "async () => (await fetch('/api/settings')).json()"
        )
        remote_sync = settings_doc["sync"]["remote_sync"]
        assert remote_sync["api_key"] == ""
        assert remote_sync["api_key_configured"] is True

        secret_path = browser_server["app_module"].REMOTE_SYNC_SECRET_FILE
        key_path = browser_server["app_module"].REMOTE_SYNC_SECRET_KEY_FILE
        from nmapui.settings import load_remote_sync_secret

        assert secret not in secret_path.read_text(encoding="utf-8")
        assert load_remote_sync_secret(
            secret_path=secret_path,
            key_path=key_path,
        ) == secret

        page.reload(wait_until="domcontentloaded")
        page.locator("#tab-settings-btn").click()
        page.get_by_text(
            "A key is stored encrypted on this scanner. Leave this field blank to keep it, or enter a replacement.",
            exact=True,
        ).wait_for()
        assert page.locator("#settings-remote-sync-api-key").input_value() == ""
    finally:
        context.close()


def test_browser_security_policy_blocks_inline_scripts_and_delegates_actions(
    browser_server, playwright_browser
):
    browser = playwright_browser
    context = browser.new_context()
    page = context.new_page()
    csp_violations = []

    def capture_csp_violations(message):
        if "content security policy" in message.text.lower():
            csp_violations.append(message.text)

    page.on("console", capture_csp_violations)
    font_requests = []
    page.on(
        "request",
        lambda request: font_requests.append(request.url)
        if "fonts.googleapis.com" in request.url or "fonts.gstatic.com" in request.url
        else None,
    )

    try:
        response = page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        assert response is not None
        policy = response.headers.get("content-security-policy", "")
        script_policy = next(
            directive for directive in policy.split(";") if directive.strip().startswith("script-src ")
        )
        assert "'unsafe-inline'" not in script_policy
        assert "base-uri 'self'" in policy
        assert "object-src 'none'" in policy
        assert "form-action 'self'" in policy
        assert "frame-ancestors 'none'" in policy
        assert "fonts.googleapis.com" not in policy
        assert "fonts.gstatic.com" not in policy
        assert page.evaluate(
            """() => Array.from(document.scripts).every((script) =>
                new URL(script.src, window.location.href).origin === window.location.origin
            )"""
        )

        page.locator("#scan-target").wait_for()
        for font in ('16px Inter', '16px "Instrument Serif"'):
            # FontFaceSet.ready can resolve before a later layout requests a
            # swap font. Explicitly load the Latin face and require a real face.
            assert page.evaluate(
                """async (font) => {
                    const faces = await document.fonts.load(font, 'Network Scanner');
                    return faces.length > 0 && faces.every(face => face.status === 'loaded')
                        && document.fonts.check(font, 'Network Scanner');
                }""", font,
            )
        assert page.locator('link[href="/static/vendor/fonts.css"]').count() == 1
        assert page.evaluate("typeof window.lucide?.createIcons === 'function'")
        assert page.locator("script:not([src])").count() == 0
        assert page.locator("[onclick], [onchange], [oninput], [onsubmit]").count() == 0
        assert page.locator("[data-action]").count() > 0

        log_panel = page.locator("#log-panel")
        assert "hidden" in log_panel.get_attribute("class")
        assert log_panel.evaluate("element => getComputedStyle(element).display") == "none"
        update_modal = page.locator("#update-modal")
        assert update_modal.evaluate("element => getComputedStyle(element).display") == "none"
        page.locator("#log-panel-toggle-btn").click()
        assert "hidden" not in log_panel.get_attribute("class")
        page.locator("#log-panel-toggle-btn").click()
        assert "hidden" in log_panel.get_attribute("class")
        assert not csp_violations
        assert font_requests == []
    finally:
        context.close()


def test_stop_scan_button_cancels_active_job_and_returns_controls_to_idle(
    browser_server, playwright_browser
):
    app_module = browser_server["app_module"]
    context = playwright_browser.new_context()
    page = context.new_page()
    sid = None

    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.locator("#stop-scan-btn").wait_for()
        page.wait_for_function("() => window.socket && window.socket.connected")
        sid = page.evaluate("window.socket.id")
        assert app_module.job_registry.start(sid, "scan", {"target": "127.0.0.1"})
        app_module.emit_job_status(sid, "scan")
        page.wait_for_function(
            "() => document.getElementById('start-scan-btn').classList.contains('ring-4')"
        )
        page.evaluate(
            "window.__scanCancelled = null; "
            "window.socket.once('job_cancelled', message => "
            "{ window.__scanCancelled = message; })"
        )

        page.locator("#stop-scan-btn").click()
        page.wait_for_function("() => window.__scanCancelled !== null", timeout=5_000)
        cancellation = page.evaluate("window.__scanCancelled")

        assert cancellation == {"job_type": "scan", "message": "Cancelling scan job..."}
        assert app_module.job_registry.get(sid, "scan")["status"] == "cancelling"

        # Model the worker's final cancelled status; no Nmap process is started
        # by this UI-to-handler regression.
        app_module.job_registry.complete(sid, "scan", status="cancelled")
        app_module.emit_job_status(sid, "scan")
        page.wait_for_function(
            "() => !document.getElementById('start-scan-btn').classList.contains('ring-4')"
        )
        assert page.locator("#start-scan-btn").is_enabled()
    finally:
        if sid and app_module.job_registry.get(sid, "scan"):
            app_module.job_registry.complete(sid, "scan", status="cancelled")
        context.close()


def test_stop_report_button_cancels_active_job_and_returns_controls_to_idle(
    browser_server, playwright_browser
):
    app_module = browser_server["app_module"]
    context = playwright_browser.new_context()
    page = context.new_page()
    sid = None

    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.locator("#stop-report-btn").wait_for(state="attached")
        page.wait_for_function("() => window.socket && window.socket.connected")
        page.wait_for_function(
            "() => window.socket.listeners('job_status').length >= 2"
        )
        sid = page.evaluate("window.socket.id")
        assert app_module.job_registry.start(
            sid, "report", {"target": "127.0.0.1", "chunked": False}
        )
        app_module.emit_job_status(sid, "report")
        page.wait_for_function(
            "() => !document.getElementById('stop-report-btn').classList.contains('hidden')"
        )
        page.evaluate(
            "window.__reportCancelled = null; "
            "window.socket.once('job_cancelled', message => "
            "{ window.__reportCancelled = message; })"
        )

        page.locator("#stop-report-btn").click()
        page.wait_for_function("() => window.__reportCancelled !== null", timeout=5_000)

        assert page.evaluate("window.__reportCancelled") == {
            "job_type": "report",
            "message": "Cancelling report job...",
        }
        assert app_module.job_registry.get(sid, "report")["status"] == "cancelling"

        # Model the worker's final cancelled status; no report or Nmap job is
        # started by this UI-to-handler regression.
        app_module.job_registry.complete(sid, "report", status="cancelled")
        app_module.emit_job_status(sid, "report")
        page.wait_for_function(
            "() => document.getElementById('stop-report-btn').classList.contains('hidden')"
        )
        assert not page.locator("#generate-report-btn").evaluate(
            "element => element.classList.contains('card-pulsing')"
        )
    finally:
        if sid and app_module.job_registry.get(sid, "report"):
            app_module.job_registry.complete(sid, "report", status="cancelled")
        context.close()


def test_generated_report_uses_hash_csp_embedded_css_and_safe_runtime(
    browser_server, playwright_browser, scan_fixture
):
    from nmapui.reporting import convert_xml_to_html

    scan_dir = scan_fixture["primary_dir"]
    xml_path = scan_dir / "scan.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun version="7.94" startstr="today" args="nmap -sV 192.0.2.1">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <host><status state="up" reason="syn-ack"/><address addr="192.0.2.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames><ports>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="  =1+1"/>
        <script id="http-title"><elem key="title">&lt;img src=x onerror=window.__reportXss=true&gt;</elem></script>
      </port>
    </ports>
  </host>
  <runstats><finished time="1" timestr="today" summary="Nmap done"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
""",
        encoding="utf-8",
    )
    assert convert_xml_to_html(
        xml_path,
        scan_dir / "scan_web.html",
        stylesheet=ROOT / "nmap-modern.xsl",
        get_app_version=lambda: "browser-test",
    )

    relative_scan_path = str(scan_dir.relative_to(browser_server["scans_dir"]))
    report_url = (
        f"{browser_server['base_url']}/api/runtime/reports/"
        f"{quote(relative_scan_path, safe='/')}/html"
    )
    context = playwright_browser.new_context(accept_downloads=True)
    page = context.new_page()
    csp_violations = []
    page.on(
        "console",
        lambda message: csp_violations.append(message.text)
        if "content security policy" in message.text.lower()
        else None,
    )
    try:
        response = page.goto(report_url, wait_until="load")
        assert response is not None and response.status == 200
        policy = response.headers.get("content-security-policy", "")
        script_policy = next(
            directive for directive in policy.split(";") if directive.strip().startswith("script-src ")
        )
        assert "'sha256-" in script_policy
        assert "'unsafe-inline'" not in script_policy
        assert "sandbox allow-scripts" in policy

        state = page.evaluate(
            """() => ({
                scriptCount: document.scripts.length,
                onlyEmbeddedRuntime: document.scripts.length === 1
                    && document.scripts[0].id === 'nmapui-report-runtime'
                    && !document.scripts[0].src,
                headingFontSize: getComputedStyle(document.querySelector('#scannedhosts h2')).fontSize,
                jquery: typeof window.jQuery,
                tailwindRuntime: typeof window.tailwind,
                injectedElements: document.querySelectorAll('img[onerror], svg[onload]').length,
                payloadAsText: document.body.textContent.includes('<img src=x onerror=window.__reportXss=true>'),
                hostContentInitiallyVisible: !document.getElementById('content-192-0-2-1').hidden,
            })"""
        )
        assert state["onlyEmbeddedRuntime"]
        assert state["headingFontSize"] == "30px"
        assert state["jquery"] == "undefined"
        assert state["tailwindRuntime"] == "undefined"
        assert state["injectedElements"] == 0
        assert state["payloadAsText"]
        assert state["hostContentInitiallyVisible"]
        assert page.evaluate("window.__reportXss") is None

        page.locator(".report-table-controls input").nth(1).fill("not-present")
        assert page.locator("#table-services tbody tr:visible").count() == 0
        page.locator(".report-table-controls input").nth(1).fill("nginx")
        assert page.locator("#table-services tbody tr:visible").count() == 1
        with page.expect_download() as download_info:
            page.locator(".report-table-controls").nth(1).get_by_role(
                "button", name="Download CSV"
            ).click()
        csv_download = download_info.value
        assert csv_download.suggested_filename == "table-services.csv"
        csv_text = Path(csv_download.path()).read_text(encoding="utf-8")
        assert "nginx" in csv_text
        assert '"\'  =1+1"' in csv_text
        page.locator("#keyword-input").fill("nginx")
        page.locator("#highlight-button").click()
        assert page.locator("#table-services mark.report-keyword").count() > 0
        page.locator("[data-collapse-target='content-192-0-2-1']").click()
        assert page.locator("#content-192-0-2-1").evaluate("element => element.hidden")

        legacy_response = page.goto(
            f"{browser_server['base_url']}/api/scans/"
            f"{quote(relative_scan_path, safe='/')}/html",
            wait_until="load",
        )
        assert legacy_response is not None and legacy_response.status == 200
        assert legacy_response.headers.get("content-security-policy") == policy
        assert not csp_violations
    finally:
        context.close()


def test_archive_button_opens_and_closes_scan_history(browser_server, playwright_browser):
    browser = playwright_browser
    context = browser.new_context()
    page = context.new_page()

    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.locator("#scan-target").wait_for()
        page.wait_for_function("() => window.socket && window.socket.connected")
        page.wait_for_function(
            "() => document.getElementById('view-history-btn')?.dataset.historyWired === 'true'"
        )

        history_modal = page.locator("#history-modal")
        page.locator("#view-history-btn").click()
        page.get_by_role("heading", name="Scan History").wait_for(state="visible")
        assert "hidden" not in history_modal.get_attribute("class")

        page.get_by_role("button", name="Close scan history dialog").click()
        assert "hidden" in history_modal.get_attribute("class")
    finally:
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


def test_history_target_is_rendered_as_text_not_html(
    browser_server, playwright_browser, scan_fixture
):
    app_module = browser_server["app_module"]
    scan_dir = scan_fixture["primary_dir"]
    metadata_path = scan_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    attack = '<img src=x onerror="window.__nmapuiHistoryXss = true">'
    metadata["target"] = attack
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    upsert_scan_metadata_index_entry(browser_server["scans_dir"], scan_dir, metadata)
    app_module.runtime_store.upsert_report_artifact(
        scan_path=str(scan_dir.relative_to(browser_server["scans_dir"])),
        customer_id=str(metadata["customer_id"]),
        target=attack,
        html_path=str(scan_dir / "scan_web.html"),
        pdf_path=str(scan_dir / "scan_report.pdf"),
        xml_path=str(scan_dir / "scan.xml"),
        payload=metadata,
    )

    context = playwright_browser.new_context()
    page = context.new_page()
    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.locator("#tab-history-btn").click()
        page.locator("#history-focus-all-btn").click()
        card = page.locator("#history-tab-list article").filter(
            has=page.locator("h3", has_text=scan_fixture["customer_name"])
        ).first
        target = card.locator("p").filter(has_text="Target:").first
        target.get_by_text(attack, exact=False).wait_for()
        assert target.locator("img").count() == 0
        assert page.evaluate("window.__nmapuiHistoryXss") is None
    finally:
        context.close()


def test_socket_history_duration_is_rendered_as_text_not_html(
    browser_server, playwright_browser
):
    browser = playwright_browser
    context = browser.new_context()
    page = context.new_page()
    attack = '<img src=x onerror="window.__nmapuiDurationXss = true">'

    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.locator("#scan-target").wait_for()
        page.wait_for_function(
            "() => window.socket && window.socket.connected && window.socket.listeners('history_data').length && window.socket.listeners('reports_data').length"
        )
        page.evaluate(
            """(duration) => {
                window.__nmapuiDurationXss = false;
                const payload = [{
                    timestamp: new Date().toISOString(),
                    duration,
                    status: 'completed',
                    target: '192.0.2.10',
                    hostCount: 1,
                    customerProfile: { baseName: 'Security Test', folderName: 'security-test' },
                    reportUrl: '',
                    pdfUrl: ''
                }];
                window.socket.listeners('history_data').forEach((handler) => handler(payload));
                window.socket.listeners('reports_data').forEach((handler) => handler([{
                    date: new Date().toISOString(),
                    duration,
                    folder: 'security-test',
                    name: 'Failed report security test',
                    status: 'failed',
                    url: '',
                    pdfUrl: '',
                    xmlUrl: '',
                    driveHtmlUrl: '',
                    drivePdfUrl: ''
                }]));
            }""",
            attack,
        )

        assert page.locator("#history-tab-list img").count() == 0
        assert page.locator("#reports-tab-list img").count() == 0
        assert attack in page.locator("#history-tab-list").text_content()
        assert attack in page.locator("#reports-tab-list").text_content()
        assert page.evaluate("window.__nmapuiDurationXss") is False
    finally:
        context.close()


def test_deep_scan_results_reject_javascript_cve_urls(browser_server, playwright_browser):
    context = playwright_browser.new_context()
    page = context.new_page()
    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        result = page.evaluate(
            """() => {
                const ip = '198.51.100.44';
                const row = document.createElement('tr');
                for (const column of ['status', 'ip', 'mac', 'vendor', 'hostname', 'open_ports', 'version', 'cves']) {
                    const cell = document.createElement('td');
                    cell.dataset.column = column;
                    if (column === 'ip') cell.textContent = ip;
                    row.appendChild(cell);
                }
                document.querySelector('#discovery-table tbody').appendChild(row);
                window.discoveryRowsByIp = new Map([[ip, row]]);
                window.currentHosts = { [ip]: { ip } };
                window.__nmapuiDeepScanXss = false;
                window.updateRowWithResults({
                    ip,
                    ports: [{ port: 80, service: '<img src=x onerror=window.__nmapuiDeepScanXss=true>' }],
                    cves: [{
                        id: 'CVE-2026-0001',
                        score: 9.8,
                        url: 'javascript:window.__nmapuiDeepScanXss=true'
                    }]
                });
                return {
                    versionText: row.querySelector('[data-column="version"]').textContent,
                    versionImages: row.querySelectorAll('[data-column="version"] img').length,
                    cveAnchors: row.querySelectorAll('[data-column="cves"] a').length,
                    cveText: row.querySelector('[data-column="cves"]').textContent,
                    executed: window.__nmapuiDeepScanXss
                };
            }"""
        )
        assert result["versionText"] == '<img src=x onerror=window.__nmapuiDeepScanXss=true>'
        assert result["versionImages"] == 0
        assert result["cveAnchors"] == 0
        assert "CVE-2026-0001" in result["cveText"]
        assert result["executed"] is False
    finally:
        context.close()


def test_foreign_browser_origin_cannot_fetch_loopback_socket_token(
    browser_server, playwright_browser
):
    context = playwright_browser.new_context()
    page = context.new_page()
    attacker_origin = "http://localhost.evil.example"
    socket_token_url = f"{browser_server['base_url']}/api/socket-token"
    api_statuses = []
    failed_api_requests = []

    page.on(
        "response",
        lambda response: api_statuses.append(response.status)
        if response.url == socket_token_url
        else None,
    )
    page.on(
        "requestfailed",
        lambda request: failed_api_requests.append(request.failure)
        if request.url == socket_token_url
        else None,
    )

    try:
        # Chromium may block public-origin-to-loopback access before Flask sees
        # it. If the request reaches the service, its origin guard must reject
        # it with 401; either way, an untrusted page must never get a token.
        page.route(
            f"{attacker_origin}/**",
            lambda route: route.fulfill(
                status=200,
                content_type="text/html",
                body="<html><body>untrusted origin</body></html>",
            ),
        )
        page.goto(attacker_origin, wait_until="domcontentloaded")

        fetch_result = page.evaluate(
            """async url => {
                try {
                    const response = await fetch(url, { credentials: 'include' });
                    return { status: response.status };
                } catch (error) {
                    return { blocked: true, error: String(error) };
                }
            }""",
            socket_token_url,
        )

        assert fetch_result.get("status") != 200
        assert not api_statuses or api_statuses == [401]
        assert api_statuses or failed_api_requests
    finally:
        context.close()


def test_same_site_form_cannot_mutate_an_authenticated_session(
    browser_server, playwright_browser, monkeypatch
):
    from flask import Flask, jsonify
    from nmapui import auth, session
    from werkzeug.serving import make_server

    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.setenv("NMAPUI_COOKIE_SECURE", "false")
    monkeypatch.delenv("NMAPUI_ALLOWED_ORIGINS", raising=False)
    mutations = []

    @auth.require_auth
    def isolated_disconnect():
        mutations.append("disconnect")
        return jsonify({"success": True})

    app = browser_server["app_module"].app
    monkeypatch.setitem(app.view_functions, "google_drive_disconnect_route", isolated_disconnect)
    base_url = browser_server["base_url"]
    target = f"{base_url}/api/settings/google-drive/disconnect"
    attacker_app = Flask("csrf-regression")

    @attacker_app.route("/")
    def attacker_form():
        return (f'<iframe name="result"></iframe><form method="POST" '
                f'action="{target}" target="result"><button>Submit</button></form>')

    attacker_server = make_server("127.0.0.1", 0, attacker_app)
    attacker_thread = threading.Thread(target=attacker_server.serve_forever, daemon=True)
    attacker_thread.start()
    attacker_origin = f"http://127.0.0.1:{attacker_server.server_port}"
    context = playwright_browser.new_context()
    context.add_cookies([{
        "name": session.SESSION_COOKIE,
        "value": session.issue_token(auth._session_signing_secret(), "scanner"),
        "url": base_url,
        "sameSite": "Lax",
        "httpOnly": True,
    }])
    page = context.new_page()
    try:
        page.goto(base_url, wait_until="domcontentloaded")
        status = page.evaluate(
            "async url => (await fetch(url, {method: 'POST'})).status", target
        )
        assert status == 200
        assert mutations == ["disconnect"]

        page.goto(attacker_origin, wait_until="domcontentloaded")
        with page.expect_response(target) as submitted:
            page.get_by_role("button", name="Submit").click()
        response = submitted.value
        headers = response.request.all_headers()
        assert headers["origin"] == attacker_origin
        assert headers["sec-fetch-site"] == "same-site"
        assert session.SESSION_COOKIE in headers.get("cookie", "")
        assert response.status == 403
        assert mutations == ["disconnect"]
    finally:
        context.close()
        attacker_server.shutdown()
        attacker_server.server_close()
        attacker_thread.join(timeout=5)


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


def test_completed_scan_job_status_updates_last_duration(browser_server, playwright_browser):
    app_module = browser_server["app_module"]
    browser = playwright_browser
    context = browser.new_context()
    page = context.new_page()
    owner_client = None

    try:
        page.goto(browser_server["base_url"], wait_until="domcontentloaded")
        page.locator("#scan-target").wait_for()
        page.wait_for_function("() => window.socket && window.socket.connected")

        owner_client = _connect_socket(browser_server)
        owner_sid = _get_socket_sid(owner_client)
        started_at = (datetime.now() - timedelta(seconds=10)).isoformat()
        assert app_module.job_registry.start(owner_sid, "scan", {"target": "127.0.0.1"})
        app_module.job_registry.update(owner_sid, "scan", started_at=started_at)
        app_module.broadcaster.start_job(owner_sid, job_type="scan")
        app_module.emit_job_status(owner_sid, "scan")

        page.wait_for_function(
            "() => document.getElementById('start-scan-btn').classList.contains('ring-4')"
        )
        app_module.job_registry.complete(owner_sid, "scan", status="completed")
        app_module.emit_job_status(owner_sid, "scan")

        page.wait_for_function(
            "() => !document.getElementById('last-scan-duration').classList.contains('hidden')"
        )
        duration_text = page.locator("#last-scan-time-val").text_content().strip()
        assert duration_text.endswith("s")
        assert 9 <= float(duration_text[:-1]) <= 11
        assert page.locator("#start-scan-btn").is_enabled()
    finally:
        if owner_client is not None:
            owner_sid = _get_socket_sid(owner_client)
            app_module.broadcaster.end_job(owner_sid, job_type="scan")
            app_module.job_registry.complete(owner_sid, "scan", status="completed")
            owner_client.disconnect()
        context.close()
