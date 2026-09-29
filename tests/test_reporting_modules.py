from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import shutil
import sys
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import nmapui.reporting as reporting
from nmapui.reporting import (
    _allow_report_pdf_resource,
    build_report_diff_summary,
    convert_html_to_pdf,
    convert_xml_to_html,
    extract_scan_statistics,
    find_latest_saved_scan_for_pdf,
    find_previous_scan_metadata,
    generate_pdf_from_saved_task,
    get_most_recent_scan_xml,
    inject_diff_summary_into_report_html,
    mark_scan_failure,
    merge_nmap_xml_files,
    parse_scan_xml_for_assets,
    parse_vulners_script,
    report_content_security_policy,
    render_report_diff_summary_html,
    save_scan_metadata,
    summarize_asset_differences,
)
from nmapui.workflows import cleanup_chunk_artifacts

def _recent_iso(days_ago, hour, minute=0):
    dt = datetime.now() - timedelta(days=days_ago)
    return dt.replace(hour=hour, minute=minute, second=0, microsecond=0).isoformat()

_RECENT_TS_1 = _recent_iso(2, 1)
_RECENT_TS_2 = _recent_iso(1, 2)
_RECENT_TS_3 = _recent_iso(1, 3)

ROOT = Path(__file__).resolve().parents[1]


def test_pdf_resource_policy_blocks_script_and_out_of_tree_requests(tmp_path):
    report_root = tmp_path / "scan"
    report_root.mkdir()
    report = report_root / "scan.html"
    local_css = report_root / "report.css"
    outside_file = tmp_path / "secret.txt"

    assert _allow_report_pdf_resource(report.as_uri(), "document", report_root)
    assert _allow_report_pdf_resource(local_css.as_uri(), "stylesheet", report_root)
    assert not _allow_report_pdf_resource(outside_file.as_uri(), "image", report_root)
    assert not _allow_report_pdf_resource(
        "https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css",
        "stylesheet",
        report_root,
    )
    assert not _allow_report_pdf_resource(
        "https://fonts.gstatic.com/example.woff2", "font", report_root
    )
    assert not _allow_report_pdf_resource(
        "https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js",
        "script",
        report_root,
    )
    assert not _allow_report_pdf_resource(
        "https://example.invalid/report.css", "stylesheet", report_root
    )
    assert not _allow_report_pdf_resource(
        "http://cdn.datatables.net/report.css", "stylesheet", report_root
    )
    assert _allow_report_pdf_resource(
        "data:image/png;base64,AA==", "image", report_root
    )


@pytest.mark.skipif(
    os.environ.get("NMAPUI_RUN_BROWSER_REGRESSION") != "1",
    reason="Set NMAPUI_RUN_BROWSER_REGRESSION=1 to run browser-backed PDF security coverage",
)
def test_pdf_renderer_blocks_external_scripts(tmp_path):
    requests = []

    class ScriptHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"document.body.textContent = 'REMOTE_SCRIPT_RAN';")

        def log_message(self, _format, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), ScriptHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    html_path = tmp_path / "scan.html"
    pdf_path = tmp_path / "scan.pdf"
    html_path.write_text(
        "<html><body>Local report"
        f"<script src='http://127.0.0.1:{server.server_port}/payload.js'></script>"
        "<script>document.body.textContent = 'INLINE_SCRIPT_RAN';</script>"
        "</body></html>",
        encoding="utf-8",
    )

    try:
        assert convert_html_to_pdf(html_path, pdf_path)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert pdf_path.is_file()
    assert pdf_path.read_bytes().startswith(b"%PDF-")
    assert requests == []


def test_wkhtmltopdf_fallback_disables_javascript_and_local_files(tmp_path, monkeypatch):
    commands = []
    html_path = tmp_path / "scan.html"
    html_path.write_text("<html><body>Local report</body></html>", encoding="utf-8")

    def capture_run(command, **_kwargs):
        commands.append(command)

    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    monkeypatch.setattr(
        reporting.shutil,
        "which",
        lambda name: "/usr/bin/wkhtmltopdf" if name == "wkhtmltopdf" else None,
    )
    monkeypatch.setattr(reporting.subprocess, "run", capture_run)

    assert convert_html_to_pdf(html_path, tmp_path / "scan.pdf")
    assert len(commands) == 1
    assert "--disable-javascript" in commands[0]
    assert "--disable-local-file-access" in commands[0]
    assert "--enable-local-file-access" not in commands[0]


def test_pdf_converter_fails_closed_when_supported_renderers_are_unavailable(tmp_path, monkeypatch):
    html_path = tmp_path / "scan.html"
    html_path.write_text("<html><body>Local report</body></html>", encoding="utf-8")
    subprocess_calls = []

    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    monkeypatch.setattr(reporting.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        reporting.subprocess,
        "run",
        lambda *args, **kwargs: subprocess_calls.append((args, kwargs)),
    )

    assert not convert_html_to_pdf(html_path, tmp_path / "scan.pdf")
    assert subprocess_calls == []


def test_cleanup_chunk_artifacts_removes_intermediates_but_keeps_merge(tmp_path):
    merged = tmp_path / "scan.xml"
    merged.write_text("merged", encoding="utf-8")
    chunk_xml = tmp_path / "scan_chunk_0.xml"
    chunk_xml.write_text("chunk", encoding="utf-8")
    chunk_xml.with_suffix(".nmap").write_text("normal", encoding="utf-8")
    chunk_xml.with_suffix(".gnmap").write_text("grepable", encoding="utf-8")

    cleanup_chunk_artifacts([chunk_xml], merged_xml_path=merged)

    assert merged.exists()
    assert not chunk_xml.exists()
    assert not chunk_xml.with_suffix(".nmap").exists()
    assert not chunk_xml.with_suffix(".gnmap").exists()


def test_parse_vulners_script_extracts_vulnerability_fields():
    script = ET.fromstring(
        """
        <script id="vulners">
          <table key="cpe:/a:test:demo">
            <elem key="id">CVE-2026-0001</elem>
            <elem key="type">cve</elem>
            <elem key="cvss">7.5</elem>
            <elem key="is_exploit">false</elem>
          </table>
        </script>
        """
    )

    vulns = parse_vulners_script(script, "443", "https")

    assert vulns[0]["cve_id"] == "CVE-2026-0001"
    assert vulns[0]["url"] == "https://vulners.com/cve/CVE-2026-0001"


def test_extract_scan_statistics_counts_ports_and_cves(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        """
        <nmaprun>
          <host>
            <ports>
              <port portid="22">
                <state state="open"/>
                <script id="vulners">
                  <table><elem key="id">CVE-2026-0001</elem></table>
                </script>
              </port>
            </ports>
          </host>
          <runstats>
            <hosts up="1" down="0" total="1"/>
            <finished elapsed="12.5"/>
          </runstats>
        </nmaprun>
        """
    )

    stats = extract_scan_statistics(xml_path)

    assert stats["hosts_up"] == 1
    assert stats["total_ports_found"] == 1
    assert stats["total_cves"] == 1


def test_parse_scan_xml_for_assets_extracts_asset_data(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
            <hostnames><hostname name="router.local"/></hostnames>
            <ports>
              <port portid="80">
                <state state="open"/>
                <service name="http"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )

    assets = parse_scan_xml_for_assets(xml_path)

    assert assets[0]["ip"] == "192.168.1.10"
    assert assets[0]["hostname"] == "router.local"
    assert assets[0]["vendor"] == "Acme"
    assert assets[0]["ports"] == "80 (http)"


def test_save_scan_metadata_persists_customer_id(tmp_path):
    scan_dir = tmp_path / "data" / "scans" / "Acme" / "2026-03-14" / "scan_010000_target"
    scan_dir.mkdir(parents=True)

    save_scan_metadata(
        scan_dir,
        "Acme Customer",
        "192.168.1.0/24",
        {"xml": scan_dir / "scan.xml"},
        network_key={"target": "192.168.1.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=3),
        end_time=datetime.now(),
    )

    metadata = json.loads((scan_dir / "metadata.json").read_text())
    index = json.loads((tmp_path / "data" / "scans" / ".scan_metadata_index.json").read_text())

    assert metadata["customer_id"] == "cust-123"
    assert metadata["customer_name"] == "Acme Customer"
    assert index["entries"][0]["path"] == "Acme/2026-03-14/scan_010000_target"
    assert index["entries"][0]["metadata"]["customer_id"] == "cust-123"


def test_save_scan_metadata_persists_report_artifact_record(tmp_path):
    scan_dir = tmp_path / "data" / "scans" / "Acme" / "2026-03-14" / "scan_010000_target"
    scan_dir.mkdir(parents=True)
    runtime_calls = []

    class RuntimeStoreStub:
        def upsert_report_artifact(self, **kwargs):
            runtime_calls.append(kwargs)

    save_scan_metadata(
        scan_dir,
        "Acme Customer",
        "192.168.1.0/24",
        {
            "xml": scan_dir / "scan.xml",
            "web_html": scan_dir / "scan_web.html",
            "pdf": scan_dir / "scan_report.pdf",
        },
        network_key={"target": "192.168.1.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=3),
        end_time=datetime.now(),
        runtime_store=RuntimeStoreStub(),
    )

    assert runtime_calls[0]["scan_path"] == "Acme/2026-03-14/scan_010000_target"
    assert runtime_calls[0]["customer_id"] == "cust-123"
    assert runtime_calls[0]["target"] == "192.168.1.0/24"
    assert runtime_calls[0]["html_path"].endswith("scan_web.html")
    assert runtime_calls[0]["pdf_path"].endswith("scan_report.pdf")
    assert runtime_calls[0]["payload"]["downloads"]["pdf"].endswith(".pdf")
    assert runtime_calls[0]["payload"]["downloads"]["xml"].endswith(".xml")


def test_save_scan_metadata_persists_asset_snapshot_and_diff_summary_to_report_artifact(tmp_path):
    scans_root = tmp_path / "data" / "scans"
    older = scans_root / "Acme" / "2026-03-13" / "scan_010000_target"
    newer = scans_root / "Acme" / "2026-03-14" / "scan_020000_target"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    runtime_calls = []

    class RuntimeStoreStub:
        def upsert_report_artifact(self, **kwargs):
            runtime_calls.append(kwargs)

    (older / "scan.xml").write_text(
        """
        <nmaprun>
          <host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/></host>
        </nmaprun>
        """
    )
    (newer / "scan.xml").write_text(
        """
        <nmaprun>
          <host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/></host>
          <host><status state="up"/><address addr="10.0.0.20" addrtype="ipv4"/></host>
        </nmaprun>
        """
    )

    save_scan_metadata(
        older,
        "Acme Customer",
        "10.0.0.0/24",
        {"xml": older / "scan.xml"},
        network_key={"target": "10.0.0.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=4),
        end_time=datetime.now() - timedelta(minutes=3),
        runtime_store=RuntimeStoreStub(),
    )
    save_scan_metadata(
        newer,
        "Acme Customer",
        "10.0.0.0/24",
        {"xml": newer / "scan.xml"},
        network_key={"target": "10.0.0.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=2),
        end_time=datetime.now(),
        runtime_store=RuntimeStoreStub(),
    )

    latest_payload = runtime_calls[-1]["payload"]
    assert latest_payload["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert latest_payload["asset_snapshot"][1]["ip"] == "10.0.0.20"


def test_save_scan_metadata_persists_diff_summary_for_followup_scan(tmp_path, monkeypatch):
    scans_root = tmp_path / "data" / "scans"
    older = scans_root / "Acme" / "2026-03-13" / "scan_010000_target"
    newer = scans_root / "Acme" / "2026-03-14" / "scan_020000_target"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    (older / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="10.0.0.10" addrtype="ipv4"/>
            <ports>
              <port portid="80"><state state="open"/><service name="http"/></port>
            </ports>
          </host>
        </nmaprun>
        """
    )
    (newer / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="10.0.0.10" addrtype="ipv4"/>
            <ports>
              <port portid="443"><state state="open"/><service name="https"/></port>
            </ports>
          </host>
          <host>
            <status state="up"/>
            <address addr="10.0.0.20" addrtype="ipv4"/>
          </host>
        </nmaprun>
        """
    )

    save_scan_metadata(
        older,
        "Acme Customer",
        "10.0.0.0/24",
        {"xml": older / "scan.xml"},
        network_key={"target": "10.0.0.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=4),
        end_time=datetime.now() - timedelta(minutes=3),
    )
    save_scan_metadata(
        newer,
        "Acme Customer",
        "10.0.0.0/24",
        {"xml": newer / "scan.xml"},
        network_key={"target": "10.0.0.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=2),
        end_time=datetime.now(),
    )

    newer_metadata = json.loads((newer / "metadata.json").read_text())
    index = json.loads((scans_root / ".scan_metadata_index.json").read_text())
    newer_entry = next(
        entry
        for entry in index["entries"]
        if entry["path"] == "Acme/2026-03-14/scan_020000_target"
    )

    assert newer_metadata["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert newer_metadata["diff_summary"]["added_hosts"] == ["10.0.0.20"]
    assert newer_metadata["diff_summary"]["new_ports"] == ["443 (https)"]
    assert newer_entry["metadata"]["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert newer_metadata["diff_summary_computed"] is True

    from nmapui import runtime_history
    from persistence import load_json_document, normalize_scan_metadata_document

    def unexpected_parse(_path):
        raise AssertionError("History should use the persisted diff result")

    monkeypatch.setattr(runtime_history, "parse_scan_xml_for_assets", unexpected_parse)
    history = runtime_history.build_history_rows(
        runtime_store=None,
        scans_dir=scans_root,
        load_json_document=load_json_document,
        normalize_scan_metadata_document=normalize_scan_metadata_document,
        logger=__import__("logging").getLogger(__name__),
    )
    assert len(history) == 2


def test_failed_diff_comparison_is_not_cached_as_complete(tmp_path, monkeypatch):
    from nmapui import reporting
    from persistence import upsert_scan_metadata_index_entry

    scans_root = tmp_path / "scans"
    older = scans_root / "older"
    newer = scans_root / "newer"
    for scan_dir, timestamp in ((older, "2026-03-13T01:00:00"), (newer, "2026-03-14T01:00:00")):
        scan_dir.mkdir(parents=True)
        (scan_dir / "scan.xml").write_text("<nmaprun/>", encoding="utf-8")
        metadata = {
            "path": scan_dir.name,
            "timestamp": timestamp,
            "customer_id": "cust-123",
            "target": "10.0.0.0/24",
        }
        (scan_dir / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        upsert_scan_metadata_index_entry(scans_root, scan_dir, metadata)

    def failed_parse(_path):
        raise ValueError("transient read failure")

    monkeypatch.setattr(reporting, "parse_scan_xml_for_assets", failed_parse)
    reporting.refresh_persisted_diff_summaries(scans_root, customer_id="cust-123", target="10.0.0.0/24")
    assert json.loads((newer / "metadata.json").read_text())["diff_summary_computed"] is False

    monkeypatch.setattr(reporting, "parse_scan_xml_for_assets", lambda _path: [])
    reporting.refresh_persisted_diff_summaries(scans_root, customer_id="cust-123", target="10.0.0.0/24")
    assert json.loads((newer / "metadata.json").read_text())["diff_summary_computed"] is True


def test_get_most_recent_scan_xml_prefers_customer_id_over_folder_name(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    renamed_customer_dir = scans_dir / "Renamed_Customer" / "2026-03-13" / "scan_010000_target"
    renamed_customer_dir.mkdir(parents=True)
    (renamed_customer_dir / "scan.xml").write_text("<nmaprun/>")
    (renamed_customer_dir / "metadata.json").write_text(
        f"""
        {{
          "customer_id": "cust-123",
          "customer_name": "Renamed Customer",
          "timestamp": "{_RECENT_TS_1}"
        }}
        """
    )

    xml_path, metadata = get_most_recent_scan_xml(
        "cust-123",
        customers=[{"id": "cust-123", "name": "Original Customer"}],
        scans_dir=scans_dir,
        sanitize_customer_dir_name=lambda value: value.replace(" ", "_"),
        max_days=30,
    )

    assert xml_path == renamed_customer_dir / "scan.xml"
    assert metadata["customer_id"] == "cust-123"


def test_get_most_recent_scan_xml_ignores_invalid_metadata_files(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    valid_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    invalid_dir = scans_dir / "Broken" / "2026-03-13" / "scan_020000_target"
    valid_dir.mkdir(parents=True)
    invalid_dir.mkdir(parents=True)

    (valid_dir / "scan.xml").write_text("<nmaprun/>")
    (valid_dir / "metadata.json").write_text(
        f"""
        {{
          "customer_id": "cust-123",
          "customer_name": "Acme Customer",
          "timestamp": "{_RECENT_TS_1}"
        }}
        """
    )
    (invalid_dir / "scan.xml").write_text("<nmaprun/>")
    (invalid_dir / "metadata.json").write_text("{not-json")

    xml_path, metadata = get_most_recent_scan_xml(
        "cust-123",
        customers=[{"id": "cust-123", "name": "Acme Customer"}],
        scans_dir=scans_dir,
        sanitize_customer_dir_name=lambda value: value.replace(" ", "_"),
        max_days=30,
    )

    assert xml_path == valid_dir / "scan.xml"
    assert metadata["customer_id"] == "cust-123"


def test_get_most_recent_scan_xml_prefers_runtime_artifacts(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    artifact_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "scan.xml").write_text("<nmaprun/>")

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            assert customer_id == "cust-123"
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_020000_target",
                    "xml_path": str(artifact_dir / "scan.xml"),
                    "payload": {
                        "customer_id": "cust-123",
                        "customer_name": "Acme Customer",
                        "timestamp": _RECENT_TS_2,
                    },
                }
            ]

    xml_path, metadata = get_most_recent_scan_xml(
        "cust-123",
        customers=[{"id": "cust-123", "name": "Acme Customer"}],
        scans_dir=scans_dir,
        sanitize_customer_dir_name=lambda value: value.replace(" ", "_"),
        max_days=30,
        runtime_store=RuntimeStoreStub(),
    )

    assert xml_path == artifact_dir / "scan.xml"
    assert metadata["customer_id"] == "cust-123"


def test_mark_scan_failure_persists_incomplete_artifact_metadata(tmp_path):
    scan_dir = tmp_path / "data" / "scans" / "Acme" / "2026-03-14" / "scan_010000_target"
    scan_dir.mkdir(parents=True)
    runtime_calls = []

    class RuntimeStoreStub:
        def upsert_report_artifact(self, **kwargs):
            runtime_calls.append(kwargs)

    mark_scan_failure(
        scan_dir,
        target="192.168.1.0/24",
        customer_name="Acme Customer",
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        error="Nmap scan failed on chunk 2",
        stage="scan_chunks",
        runtime_store=RuntimeStoreStub(),
    )

    metadata = json.loads((scan_dir / "metadata.json").read_text())
    index = json.loads((tmp_path / "data" / "scans" / ".scan_metadata_index.json").read_text())

    assert metadata["status"] == "failed"
    assert metadata["failure_stage"] == "scan_chunks"
    assert metadata["failure_error"] == "Nmap scan failed on chunk 2"
    assert metadata["completed_successfully"] is False
    assert metadata["customer_id"] == "cust-123"
    assert index["entries"][0]["metadata"]["status"] == "failed"
    assert index["entries"][0]["metadata"]["failure_stage"] == "scan_chunks"
    assert runtime_calls
    assert runtime_calls[0]["customer_id"] == "cust-123"
    assert runtime_calls[0]["payload"]["status"] == "failed"
    assert runtime_calls[0]["payload"]["failure_stage"] == "scan_chunks"
    assert runtime_calls[0]["payload"]["failure_error"] == "Nmap scan failed on chunk 2"
    assert runtime_calls[0]["payload"]["completed_successfully"] is False


def test_merge_nmap_xml_files_combines_hosts_and_updates_runstats(tmp_path, monkeypatch):
    first = tmp_path / "first.xml"
    second = tmp_path / "second.xml"
    merged = tmp_path / "merged.xml"

    first.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="nmap.xsl"?>
<nmaprun args="nmap 192.168.1.1">
  <host starttime="100" endtime="130">
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished summary="first" />
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
<!-- preserved trailer -->
"""
    )
    second.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun args="nmap 192.168.1.2">
  <host starttime="140" endtime="190">
    <status state="up"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished summary="second" />
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""
    )

    parse_calls = []
    original_parse = ET.parse

    def count_parse(path, *args, **kwargs):
        parse_calls.append(Path(path))
        return original_parse(path, *args, **kwargs)

    monkeypatch.setattr(reporting.ET, "parse", count_parse)
    merge_nmap_xml_files([first, second], merged)

    root = ET.fromstring(merged.read_text())
    hosts = root.findall("host")
    runstats = root.find("runstats")
    hosts_elem = runstats.find("hosts")

    assert len(hosts) == 2
    assert hosts_elem.get("up") == "2"
    assert hosts_elem.get("down") == "0"
    assert hosts_elem.get("total") == "2"
    assert parse_calls == [first, second]
    merged_text = merged.read_text()
    assert merged_text.startswith(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<?xml-stylesheet type="text/xsl" href="nmap.xsl"?>\n'
    )
    assert merged_text.endswith("</nmaprun>\n<!-- preserved trailer -->\n")


def test_merge_nmap_xml_files_preserves_previous_output_on_serialization_failure(
    tmp_path, monkeypatch
):
    source = tmp_path / "chunk.xml"
    output = tmp_path / "merged.xml"
    source.write_text(
        '<nmaprun args="nmap 192.0.2.1"><runstats><finished summary="fixture"/>'
        '<hosts up="0" down="0" total="0"/></runstats></nmaprun>',
        encoding="utf-8",
    )
    output.write_text("previous complete report", encoding="utf-8")

    def fail_after_partial_write(_tree, output_file, **_kwargs):
        output_file.write("<partial")
        raise OSError("injected XML serialization failure")

    monkeypatch.setattr(reporting.ET.ElementTree, "write", fail_after_partial_write)
    with pytest.raises(OSError, match="injected XML serialization failure"):
        merge_nmap_xml_files([source], output)

    assert output.read_text(encoding="utf-8") == "previous complete report"
    assert list(tmp_path.glob(".merged.xml.*.tmp")) == []


def test_find_latest_saved_scan_for_pdf_prefers_latest_matching_customer(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    older = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    newer = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    (older / "scan.xml").write_text("<nmaprun/>")
    (newer / "scan.xml").write_text("<nmaprun/>")
    (older / "metadata.json").write_text(
        f'{{\"target\":\"192.168.1.0/24\",\"customer_id\":\"cust-123\",\"timestamp\":\"{_RECENT_TS_1}\"}}'
    )
    (newer / "metadata.json").write_text(
        f'{{\"target\":\"192.168.1.0/24\",\"customer_id\":\"cust-123\",\"timestamp\":\"{_RECENT_TS_2}\"}}'
    )

    scan_dir, xml_path = find_latest_saved_scan_for_pdf(
        "192.168.1.0/24",
        scans_dir=scans_dir,
        load_json_document=lambda path, default: json.loads(path.read_text()),
        normalize_scan_metadata_document=lambda value: value,
        customer_id="cust-123",
        max_days=30,
    )

    assert scan_dir == newer
    assert xml_path == newer / "scan.xml"


def test_find_latest_saved_scan_for_pdf_prefers_runtime_artifacts(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    artifact_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "scan.xml").write_text("<nmaprun/>")

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            assert customer_id == "cust-123"
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_020000_target",
                    "xml_path": str(artifact_dir / "scan.xml"),
                    "payload": {
                        "target": "192.168.1.0/24",
                        "customer_id": "cust-123",
                        "timestamp": _RECENT_TS_2,
                    },
                }
            ]

    scan_dir, xml_path = find_latest_saved_scan_for_pdf(
        "192.168.1.0/24",
        scans_dir=scans_dir,
        load_json_document=lambda path, default: json.loads(path.read_text()),
        normalize_scan_metadata_document=lambda value: value,
        customer_id="cust-123",
        max_days=30,
        runtime_store=RuntimeStoreStub(),
    )

    assert scan_dir == artifact_dir
    assert xml_path == artifact_dir / "scan.xml"


def test_generate_pdf_from_saved_task_completes_report_job(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    previous_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    previous_dir.mkdir(parents=True)
    scan_dir.mkdir(parents=True)
    (previous_dir / "metadata.json").write_text(
        f'{{"path":"Acme/2026-03-13/scan_010000_target","customer_id":"cust-123","target":"192.168.1.0/24","timestamp":"2026-03-13T01:00:00"}}'
    )
    (previous_dir / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="80"><state state="open"/><service name="http"/></port></ports>
          </host>
        </nmaprun>
        """
    )
    xml_path = scan_dir / "scan.xml"
    xml_path.write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="443"><state state="open"/><service name="https"/></port></ports>
          </host>
        </nmaprun>
        """
    )
    (scan_dir / "metadata.json").write_text(
        f'{{"path":"Acme/2026-03-14/scan_020000_target","customer_id":"cust-123","target":"192.168.1.0/24","timestamp":"2026-03-14T02:00:00"}}'
    )
    observed = {"events": []}
    runtime_calls = []

    class JobRegistryStub:
        def start(self, sid, job_type, details):
            observed["started"] = (sid, job_type, details)
            return True

        def complete(self, sid, job_type, status="completed", details=None):
            observed["completed"] = (sid, job_type, status, details)

        def clear_if_disconnected(self, sid, job_type):
            observed["cleared"] = (sid, job_type)

    generate_pdf_from_saved_task(
        {
            "job_registry": JobRegistryStub(),
            "emit_job_status": lambda sid, job_type: observed.setdefault("status_calls", []).append((sid, job_type)),
            "emit_to_client": lambda sid, event, data=None: observed["events"].append((sid, event, data)),
            "get_client_state": lambda sid=None: {"current_customer": {"id": "cust-123"}},
            "find_latest_saved_scan_for_pdf": lambda target, **kwargs: (scan_dir, xml_path),
            "convert_xml_to_html": lambda xml_path, html_path, **kwargs: html_path.write_text(
                "<html><body><h1>Report</h1></body></html>",
                encoding="utf-8",
            ) or True,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "get_app_version": lambda: "v1.0.0",
            "logger": type("LoggerStub", (), {"exception": lambda self, *args, **kwargs: None})(),
            "runtime_store": type(
                "RuntimeStoreStub",
                (),
                {
                    "upsert_report_artifact": lambda self, **kwargs: runtime_calls.append(kwargs),
                    "append_log": lambda self, **kwargs: None,
                },
            )(),
            "scans_dir": scans_dir,
            "socketio_sleep": lambda value: None,
            "web_stylesheet": "web.xsl",
            "pdf_stylesheet": "pdf.xsl",
        },
        "sid-1",
        {"target": "192.168.1.0/24", "customer_name": "Acme Customer"},
    )

    assert observed["started"][1] == "report"
    assert observed["completed"][2] == "completed"
    assert observed["completed"][3]["mode"] == "pdf_only"
    assert observed["cleared"] == ("sid-1", "report")
    assert runtime_calls[0]["scan_path"] == "Acme/2026-03-14/scan_020000_target"
    assert runtime_calls[0]["customer_id"] == "cust-123"
    assert runtime_calls[0]["pdf_path"].endswith("scan_report.pdf")
    report_complete = next(event for event in observed["events"] if event[1] == "report_complete")
    assert report_complete[2]["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert 'id="scan-diff-summary"' in (scan_dir / "scan_web.html").read_text(encoding="utf-8")
    assert 'id="scan-diff-summary"' in (scan_dir / "scan_pdf.html").read_text(encoding="utf-8")


def test_find_previous_scan_metadata_matches_customer_and_target():
    current = {
        "path": "Acme/2026-03-14/scan_020000_target",
        "customer_id": "cust-123",
        "target": "192.168.1.0/24",
        "timestamp": "2026-03-14T02:00:00",
    }
    scans = [
        current,
        {
            "path": "Acme/2026-03-13/scan_010000_target",
            "customer_id": "cust-123",
            "target": "192.168.1.0/24",
            "timestamp": "2026-03-13T01:00:00",
        },
        {
            "path": "Other/2026-03-13/scan_010000_target",
            "customer_id": "cust-999",
            "target": "192.168.1.0/24",
            "timestamp": "2026-03-13T03:00:00",
        },
    ]

    previous = find_previous_scan_metadata(current, scans)

    assert previous["path"] == "Acme/2026-03-13/scan_010000_target"


def test_summarize_asset_differences_reports_added_removed_and_changed_hosts():
    previous_assets = [
        {
            "ip": "192.168.1.10",
            "hostname": "router.local",
            "ports": "22 (ssh), 80 (http)",
            "vulnerabilities": [{"cve_id": "CVE-2026-0001"}],
        },
        {
            "ip": "192.168.1.20",
            "hostname": "printer.local",
            "ports": "9100 (jetdirect)",
            "vulnerabilities": [],
        },
    ]
    current_assets = [
        {
            "ip": "192.168.1.10",
            "hostname": "router.local",
            "ports": "22 (ssh), 443 (https)",
            "vulnerabilities": [{"cve_id": "CVE-2026-0002"}],
        },
        {
            "ip": "192.168.1.30",
            "hostname": "camera.local",
            "ports": "554 (rtsp)",
            "vulnerabilities": [],
        },
    ]

    diff = summarize_asset_differences(current_assets, previous_assets)

    assert diff["has_changes"] is True
    assert diff["added_hosts"] == ["192.168.1.30"]
    assert diff["removed_hosts"] == ["192.168.1.20"]
    assert diff["new_ports"] == ["443 (https)", "554 (rtsp)"]
    assert "80 (http)" in diff["removed_ports"]
    assert diff["new_vulnerabilities"] == ["CVE-2026-0002"]
    assert diff["removed_vulnerabilities"] == ["CVE-2026-0001"]
    assert diff["changed_hosts"][0]["host"] == "192.168.1.10"


def test_build_report_diff_summary_uses_previous_matching_scan(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    previous_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    current_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    previous_dir.mkdir(parents=True)
    current_dir.mkdir(parents=True)

    (previous_dir / "metadata.json").write_text(
        f'{{"path":"Acme/2026-03-13/scan_010000_target","customer_id":"cust-123","target":"192.168.1.0/24","timestamp":"2026-03-13T01:00:00"}}'
    )
    (current_dir / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="443"><state state="open"/><service name="https"/></port></ports>
          </host>
        </nmaprun>
        """
    )
    (previous_dir / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="80"><state state="open"/><service name="http"/></port></ports>
          </host>
        </nmaprun>
        """
    )

    diff_summary = build_report_diff_summary(
        {
            "path": "Acme/2026-03-14/scan_020000_target",
            "customer_id": "cust-123",
            "target": "192.168.1.0/24",
            "timestamp": "2026-03-14T02:00:00",
        },
        current_dir / "scan.xml",
        scans_dir=scans_dir,
    )

    assert diff_summary["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert diff_summary["removed_ports"] == ["80 (http)"]
    assert diff_summary["new_ports"] == ["443 (https)"]


def test_inject_diff_summary_into_report_html_adds_summary_section(tmp_path):
    html_path = tmp_path / "scan_web.html"
    html_path.write_text("<html><body><h1>Report</h1></body></html>", encoding="utf-8")

    inject_diff_summary_into_report_html(
        html_path,
        {
            "has_changes": True,
            "baseline_timestamp": "2026-03-13T01:00:00",
            "added_hosts": ["192.168.1.20"],
            "removed_hosts": [],
            "changed_hosts": [{"host": "192.168.1.10"}],
            "new_ports": ["443 (https)"],
            "removed_ports": ["80 (http)"],
            "new_vulnerabilities": ["CVE-2026-0002"],
            "removed_vulnerabilities": [],
        },
    )

    html = html_path.read_text(encoding="utf-8")

    assert 'id="scan-diff-summary"' in html
    assert "Changes Since Previous Scan" in html
    assert "1 new host(s)" in html
    assert "1 changed host(s)" in html
    assert "1 new vulnerabilit" in html


def test_render_report_diff_summary_html_returns_empty_string_without_changes():
    assert render_report_diff_summary_html(None) == ""
    assert render_report_diff_summary_html({"has_changes": False}) == ""


def test_representative_report_fixture_renders_shared_landmarks_for_web_and_pdf(tmp_path):
    if shutil.which("xsltproc") is None:
        raise AssertionError("xsltproc is required for report stylesheet regression coverage")

    xml_path = tmp_path / "scan.xml"
    web_html_path = tmp_path / "scan_web.html"
    pdf_html_path = tmp_path / "scan_pdf.html"

    xml_path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS -T3 --top-ports 100 -oA /tmp/scan 192.168.1.0/24" startstr="Sat Mar 14 12:00:00 2026" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx &lt;img src=x onerror=alert(1)&gt;" version="1.25.0"/>
        <script id="http-title">
          <elem key="title">nginx/1.25.0</elem>
        </script>
        <script id="vulners" output="CVE-2026-0001 9.8 https://vulners.com/cve/CVE-2026-0001">
          <table key="cpe:/a:nginx:nginx:1.25.0">
            <table><elem key="id">CVE-2026-0001</elem><elem key="type">cve</elem><elem key="cvss">9.8</elem></table>
            <table><elem key="id">CVE-2026-0002</elem><elem key="type">cve</elem><elem key="cvss">7.5</elem></table>
            <table><elem key="id">CVE-2026-0003</elem><elem key="type">cve</elem><elem key="cvss">5.0</elem></table>
            <table><elem key="id">CVE-2026-0004</elem><elem key="type">cve</elem><elem key="cvss">3.1</elem></table>
          </table>
        </script>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="0" timestr="Sat Mar 14 12:01:00 2026" elapsed="60.00" summary="Nmap done"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
""",
        encoding="utf-8",
    )

    assert convert_xml_to_html(
        xml_path,
        web_html_path,
        stylesheet=ROOT / "nmap-modern.xsl",
        get_app_version=lambda: "test-version",
    )
    assert convert_xml_to_html(
        xml_path,
        pdf_html_path,
        stylesheet=ROOT / "nmap-pdf-olive-legacy.xsl",
        get_app_version=lambda: "test-version",
    )

    if os.environ.get("NMAPUI_RUN_BROWSER_REGRESSION") == "1":
        pdf_path = tmp_path / "scan_report.pdf"
        assert convert_html_to_pdf(pdf_html_path, pdf_path)
        assert pdf_path.read_bytes().startswith(b"%PDF-")
        assert pdf_path.stat().st_size > 5_000

    web_html = web_html_path.read_text(encoding="utf-8")
    pdf_html = pdf_html_path.read_text(encoding="utf-8")

    for landmark in (
        'id="scannedhosts"',
        'id="openservices"',
        'id="onlinehosts"',
        "Scanned Hosts",
        "Open Services",
        "Online Hosts",
        "Instrument Serif",
        "router.local",
        "192.168.1.10",
    ):
        assert landmark in web_html
        assert landmark in pdf_html

    runtime_source = (ROOT / "static" / "js" / "report_runtime.js").read_text(encoding="utf-8")
    csp = report_content_security_policy()
    script_policy = next(part for part in csp.split(";") if part.strip().startswith("script-src "))
    assert "unsafe-inline" not in script_policy
    assert "'sha256-" in script_policy
    assert "sandbox allow-scripts" in csp

    for html in (web_html, pdf_html):
        assert '<style id="nmapui-tailwind-css">' in html
        assert f'<script id="nmapui-report-runtime">{runtime_source}</script>' in html
        assert 'name="nmapui-report-policy" content="v1"' in html
        assert "script-src &#x27;sha256-" in html
        assert "script-src &#x27;unsafe-inline" not in html
        assert "cdn.tailwindcss.com" not in html
        assert "cdn.datatables.net" not in html
        assert "code.jquery.com" not in html
        assert "fonts.googleapis.com" not in html
        assert "fonts.gstatic.com" not in html
        assert "onclick=" not in html
        assert "__NMAPUI_" not in html
        assert "&lt;img src=x onerror=alert(1)&gt;" in html
        assert "<img src=x onerror=alert(1)>" not in html
        assert "No findings do not prove a host is free of vulnerabilities." in html
        for severity in ("critical", "high", "medium", "low"):
            assert re.search(
                rf'<span id="vuln-{severity}-count"[^>]*>\s*1\s*</span>', html
            ), f"{severity} CVSS count should count structured findings"

    assert re.search(r'<div id="vuln-critical-total"[^>]*>\s*1\s*</div>', web_html)
    assert re.search(r'<span id="vuln-host-output-count"[^>]*>\s*1\s*</span>', web_html)
    assert "Hosts with Vulners Output" in web_html

    for html in (web_html, pdf_html):
        assert "Target:</span>\u00a0192.168.1.0/24" in html
        assert "IPs:</span>\u00a01" in html
        assert "Started:</span>\u00a0Sat Mar 14 12:00:00 2026" in html
        assert "Duration:</span>\u00a060.00s" in html
        assert 'class="progress-bar mb-6" aria-hidden="true"' in html
        assert "0 Down" not in html


def test_generated_report_content_security_policy_is_isolated_and_hash_based():
    csp = report_content_security_policy()
    script_policy = next(part for part in csp.split(";") if part.strip().startswith("script-src "))

    assert "'unsafe-inline'" not in script_policy
    assert "'sha256-" in script_policy
    assert "connect-src 'none'" in csp
    assert "font-src 'none'" in csp
    assert "fonts.googleapis.com" not in csp
    assert "fonts.gstatic.com" not in csp
    assert "sandbox allow-scripts" in csp
    assert "allow-same-origin" not in csp
