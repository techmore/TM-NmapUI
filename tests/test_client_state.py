from nmapui.client_state import ClientStateRegistry
from nmapui.app_bindings import build_client_state_helpers
from nmapui.runtime_state import (
    set_last_scan_target_state as set_last_scan_target_state_impl,
    set_network_key_state as set_network_key_state_impl,
)
from nmapui.workflow_context import build_report_workflow_context
from nmapui.workflows import generate_report_task


def test_client_state_registry_isolates_customer_and_network_state():
    registry = ClientStateRegistry()

    registry.set_current_customer("sid-a", {"id": "cust-a", "name": "Acme", "confidence": 1.0})
    registry.set_network_key("sid-a", {"target": "10.0.0.1", "total_hops": 2})
    registry.set_last_scan_target("sid-a", "10.0.0.0/24")

    state_a = registry.get_state("sid-a")
    state_b = registry.get_state("sid-b")

    assert state_a["current_customer"]["id"] == "cust-a"
    assert state_a["network_key"]["target"] == "10.0.0.1"
    assert state_a["last_scan_target"] == "10.0.0.0/24"
    assert state_b["current_customer"]["id"] == "unknown"
    assert state_b["network_key"]["target"] == "1.1.1.1"
    assert state_b["last_scan_target"] is None


def test_client_state_registry_returns_copies():
    registry = ClientStateRegistry()
    state = registry.get_state("sid-a")
    state["current_customer"]["name"] = "Changed"

    assert registry.get_state("sid-a")["current_customer"]["name"] == "Unknown Network"


def test_client_state_registry_defaults_seed_future_tabs():
    registry = ClientStateRegistry()
    registry.set_default_customer({"id": "cust-1", "name": "Acme", "confidence": 1.0})
    registry.set_default_network_key({"target": "10.0.0.0/24", "total_hops": 2})
    registry.set_default_last_scan_target("10.0.0.0/24")

    state_b = registry.get_state("sid-b")

    assert state_b["current_customer"]["id"] == "cust-1"
    assert state_b["network_key"]["target"] == "10.0.0.0/24"
    assert state_b["last_scan_target"] == "10.0.0.0/24"


def test_runtime_state_syncs_default_network_key_and_target_into_registry():
    registry = ClientStateRegistry()
    default_network_key = {"target": "1.1.1.1", "total_hops": 0}
    default_target = {"value": None}

    set_network_key_state_impl(
        value={"target": "192.168.222.0/24", "total_hops": 8},
        sid=None,
        client_state_registry=registry,
        set_default_network_key=lambda value: default_network_key.update(value),
    )
    set_last_scan_target_state_impl(
        value="192.168.222.0/24",
        sid=None,
        client_state_registry=registry,
        set_default_last_scan_target=lambda value: default_target.__setitem__("value", value),
    )

    state = registry.get_state("sid-future")

    assert default_network_key["target"] == "192.168.222.0/24"
    assert default_target["value"] == "192.168.222.0/24"
    assert state["network_key"]["target"] == "192.168.222.0/24"
    assert state["network_key"]["total_hops"] == 8
    assert state["last_scan_target"] == "192.168.222.0/24"


def test_client_state_helpers_persist_runtime_snapshots():
    registry = ClientStateRegistry()
    current_customer = {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}
    network_key = {"target": "1.1.1.1", "total_hops": 0}
    last_scan_target = {"value": None}
    snapshots = {}

    class RuntimeStoreStub:
        def upsert_runtime_snapshot(self, key, payload):
            snapshots[key] = payload

    helpers = build_client_state_helpers(
        client_state_registry=registry,
        get_current_customer=lambda: current_customer,
        get_network_key=lambda: network_key,
        get_last_scan_target=lambda: last_scan_target["value"],
        set_default_customer=lambda value: current_customer.update(value),
        set_default_network_key=lambda value: network_key.update(value),
        set_default_last_scan_target=lambda value: last_scan_target.__setitem__("value", value),
        runtime_store=RuntimeStoreStub(),
    )

    helpers["set_current_customer_state"]({"id": "cust-1", "name": "Acme", "confidence": 1.0})
    helpers["set_network_key_state"]({"target": "192.168.222.0/24", "total_hops": 8})
    helpers["set_last_scan_target_state"]("192.168.222.0/24")

    assert snapshots["current_customer"]["id"] == "cust-1"
    assert snapshots["network_key"]["target"] == "192.168.222.0/24"
    assert snapshots["last_scan_target"] == {"value": "192.168.222.0/24"}


class IdleStateStub:
    def start_operation(self, operation_id: str):
        self.operation_id = operation_id

    def end_operation(self, operation_id: str):
        self.ended_operation_id = operation_id


def test_generate_report_task_prefers_per_client_state_snapshot(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-13" / "scan_010000_target"
    captured = {}
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "update": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def save_scan_metadata_stub(
        scan_dir,
        customer_name,
        target,
        files,
        network_key,
        current_customer,
        start_time,
        end_time,
        runtime_store=None,
    ):
        captured["network_key"] = network_key
        captured["current_customer"] = current_customer

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": IdleStateStub(),
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": tmp_path,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": lambda *args, **kwargs: {"success": True},
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": lambda *args, **kwargs: True,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": "nmap-modern.xsl",
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": save_scan_metadata_stub,
            "network_key": {"target": "shared"},
            "current_customer": {"id": "shared", "name": "Shared"},
            "get_client_state": lambda sid: {
                "network_key": {"target": "sid-specific", "total_hops": 5},
                "current_customer": {"id": "cust-123", "name": "Acme Customer", "confidence": 0.9},
            },
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": type(
                "FingerprinterStub",
                (),
                {
                    "customers": [],
                    "update_last_scan_duration": lambda self, customer_id, duration: None,
                },
            )(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme Customer",
        },
    )

    assert captured["network_key"]["target"] == "sid-specific"
    assert captured["current_customer"]["id"] == "cust-123"


def test_generate_report_task_uses_distinct_web_and_pdf_stylesheets(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-13" / "scan_010000_target"
    convert_calls = []
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "update": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def convert_xml_to_html_stub(xml_path, html_path, *, stylesheet, get_app_version, feedback=None, report_target=None, report_customer_id=None):
        convert_calls.append((html_path.name, stylesheet))
        return True

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": IdleStateStub(),
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: None,
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": tmp_path,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": lambda *args, **kwargs: {"success": True},
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": convert_xml_to_html_stub,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": "web.xsl",
            "web_stylesheet": "web.xsl",
            "pdf_stylesheet": "pdf.xsl",
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": lambda *args, **kwargs: None,
            "get_client_state": lambda sid=None: {
                "network_key": {"target": "shared"},
                "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            },
            "network_key": {"target": "shared"},
            "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": type(
                "FingerprinterStub",
                (),
                {
                    "customers": [],
                    "update_last_scan_duration": lambda self, customer_id, duration: None,
                },
            )(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme Customer",
        },
    )

    assert convert_calls == [
        ("scan_web.html", "web.xsl"),
        ("scan_pdf.html", "pdf.xsl"),
    ]


def test_generate_report_task_injects_diff_summary_into_generated_html(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    previous_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    previous_dir.mkdir(parents=True)
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "update": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    (previous_dir / "metadata.json").write_text(
        '{"path":"Acme/2026-03-13/scan_010000_target","customer_id":"cust-123","target":"192.168.1.0/24","timestamp":"2026-03-13T01:00:00"}'
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

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def run_nmap_with_xml_output_stub(target, output_base, scan_type, sid=None, **kwargs):
        output_base.with_suffix(".xml").write_text(
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
        return {"success": True}

    def convert_xml_to_html_stub(xml_path, html_path, *, stylesheet, get_app_version, feedback=None, report_target=None, report_customer_id=None):
        html_path.write_text("<html><body><h1>Report</h1></body></html>", encoding="utf-8")
        return True

    observed_events = []

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": IdleStateStub(),
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: observed_events.append((event, data)),
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: [target],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": scans_dir,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": run_nmap_with_xml_output_stub,
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": convert_xml_to_html_stub,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": "web.xsl",
            "web_stylesheet": "web.xsl",
            "pdf_stylesheet": "pdf.xsl",
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": lambda *args, **kwargs: None,
            "get_client_state": lambda sid=None: {
                "network_key": {"target": "shared"},
                "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            },
            "network_key": {"target": "shared"},
            "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": type(
                "FingerprinterStub",
                (),
                {
                    "customers": [],
                    "update_last_scan_duration": lambda self, customer_id, duration: None,
                },
            )(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme Customer",
        },
    )

    assert 'id="scan-diff-summary"' in (scan_dir / "scan_web.html").read_text(encoding="utf-8")
    assert 'id="scan-diff-summary"' in (scan_dir / "scan_pdf.html").read_text(encoding="utf-8")
    report_complete = next(payload for event, payload in observed_events if event == "report_complete")
    assert report_complete["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"


def test_generate_report_task_respects_non_chunked_full_scan_requests(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-14" / "scan_030000_target"
    observed_targets = []
    observed_events = []
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "update": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def run_nmap_with_xml_output_stub(target, output_base, scan_type, sid=None, **kwargs):
        observed_targets.append(target)
        output_base.with_suffix(".xml").write_text("<nmaprun></nmaprun>", encoding="utf-8")
        return {"success": True}

    def convert_xml_to_html_stub(xml_path, html_path, *, stylesheet, get_app_version, feedback=None, report_target=None, report_customer_id=None):
        html_path.write_text("<html><body>Report</body></html>", encoding="utf-8")
        return True

    generate_report_task(
        build_report_workflow_context(
            {
            "job_registry": registry,
            "idle_state_manager": IdleStateStub(),
            "emit_job_status": lambda sid, job_type: None,
            "emit_to_client": lambda sid, event, data=None: observed_events.append((event, data)),
            "update_job_progress": lambda *args, **kwargs: None,
            "validate_target": lambda target: (True, None),
            "split_subnet_into_chunks": lambda target: ["192.168.1.0/25", "192.168.1.128/25"],
            "create_scan_folder": create_scan_folder_stub,
            "scans_dir": tmp_path,
            "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
            "run_nmap_with_xml_output": run_nmap_with_xml_output_stub,
            "merge_nmap_xml_files": lambda *args, **kwargs: None,
            "socketio_sleep": lambda value: None,
            "convert_xml_to_html": convert_xml_to_html_stub,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "stylesheet": "web.xsl",
            "web_stylesheet": "web.xsl",
            "pdf_stylesheet": "pdf.xsl",
            "get_app_version": lambda: "v1.0.0",
            "save_scan_metadata": lambda *args, **kwargs: None,
            "get_client_state": lambda sid=None: {
                "network_key": {"target": "shared"},
                "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            },
            "network_key": {"target": "shared"},
            "current_customer": {"id": "cust-123", "name": "Acme Customer"},
            "extract_scan_statistics": lambda path: {},
            "customer_fingerprinter": type(
                "FingerprinterStub",
                (),
                {
                    "customers": [],
                    "update_last_scan_duration": lambda self, customer_id, duration: None,
                },
            )(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme Customer",
            "chunked": False,
        },
    )

    assert observed_targets == ["192.168.1.0/24"]
    assert (
        "scan_feedback",
        "Running a single comprehensive scan without chunking",
    ) in observed_events


def test_generate_report_task_overrides_non_chunked_large_network_reports(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-13" / "scan_010000_target"
    observed_targets = []
    observed_events = []
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "update": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def run_nmap_with_xml_output_stub(target, output_base, scan_type, sid=None, **kwargs):
        observed_targets.append(target)
        output_base.with_suffix(".xml").write_text("<nmaprun></nmaprun>", encoding="utf-8")
        return {"success": True}

    def convert_xml_to_html_stub(xml_path, html_path, *, stylesheet, get_app_version, feedback=None, report_target=None, report_customer_id=None):
        html_path.write_text("<html><body>Report</body></html>", encoding="utf-8")
        return True

    generate_report_task(
        build_report_workflow_context(
            {
                "job_registry": registry,
                "idle_state_manager": IdleStateStub(),
                "emit_job_status": lambda sid, job_type: None,
                "emit_to_client": lambda sid, event, data=None: observed_events.append((event, data)),
                "update_job_progress": lambda *args, **kwargs: None,
                "validate_target": lambda target: (True, None),
                "split_subnet_into_chunks": lambda target: ["unexpected-default-chunk"],
                "create_scan_folder": create_scan_folder_stub,
                "scans_dir": tmp_path,
                "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
                "run_nmap_with_xml_output": run_nmap_with_xml_output_stub,
                "merge_nmap_xml_files": lambda *args, **kwargs: None,
                "socketio_sleep": lambda value: None,
                "convert_xml_to_html": convert_xml_to_html_stub,
                "convert_html_to_pdf": lambda *args, **kwargs: True,
                "stylesheet": "web.xsl",
                "web_stylesheet": "web.xsl",
                "pdf_stylesheet": "pdf.xsl",
                "get_app_version": lambda: "v1.0.0",
                "save_scan_metadata": lambda *args, **kwargs: None,
                "get_client_state": lambda sid=None: {
                    "network_key": {"target": "shared"},
                    "current_customer": {"id": "cust-123", "name": "Acme Customer"},
                },
                "network_key": {"target": "shared"},
                "current_customer": {"id": "cust-123", "name": "Acme Customer"},
                "extract_scan_statistics": lambda path: {},
                "customer_fingerprinter": type(
                    "FingerprinterStub",
                    (),
                    {
                        "customers": [],
                        "update_last_scan_duration": lambda self, customer_id, duration: None,
                    },
                )(),
            }
        ),
        "sid-1",
        {
            "target": "192.168.0.0/22",
            "customer_name": "Acme Customer",
            "chunked": False,
        },
    )

    assert observed_targets == [
        "192.168.0.0/24",
        "192.168.1.0/24",
        "192.168.2.0/24",
        "192.168.3.0/24",
    ]
    assert (
        "scan_feedback",
        "Large network detected - overriding single-pass report scan with 4 /24 chunks to avoid timeouts",
    ) in observed_events
    assert (
        "scan_feedback",
        "Large network detected - scanning in 4 chunks",
    ) in observed_events


def test_generate_report_task_auto_uploads_to_google_drive_when_enabled(tmp_path):
    scan_dir = tmp_path / "Acme" / "2026-03-14" / "scan_040000_target"
    upload_calls = []
    observed_events = []
    registry = type(
        "JobRegistryStub",
        (),
        {
            "complete": lambda self, *args, **kwargs: None,
            "update": lambda self, *args, **kwargs: None,
            "is_cancelled": lambda self, *args, **kwargs: False,
            "get": lambda self, *args, **kwargs: {"status": "completed"},
            "clear_if_disconnected": lambda self, *args, **kwargs: None,
        },
    )()

    def create_scan_folder_stub(*args, **kwargs):
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def run_nmap_with_xml_output_stub(target, output_base, scan_type, sid=None, **kwargs):
        output_base.with_suffix(".xml").write_text("<nmaprun></nmaprun>", encoding="utf-8")
        return {"success": True}

    def convert_xml_to_html_stub(xml_path, html_path, *, stylesheet, get_app_version, feedback=None, report_target=None, report_customer_id=None):
        html_path.write_text("<html><body>Report</body></html>", encoding="utf-8")
        return True

    def convert_html_to_pdf_stub(html_path, pdf_path, feedback=None):
        pdf_path.write_bytes(b"%PDF-1.4 test")
        return True

    def upload_report_artifacts_to_google_drive_stub(**kwargs):
        upload_calls.append(kwargs)
        return {"success": True, "status": "Uploaded 3 file(s) to Google Drive"}

    generate_report_task(
        build_report_workflow_context(
            {
                "job_registry": registry,
                "idle_state_manager": IdleStateStub(),
                "emit_job_status": lambda sid, job_type: None,
                "emit_to_client": lambda sid, event, data=None: observed_events.append((event, data)),
                "update_job_progress": lambda *args, **kwargs: None,
                "validate_target": lambda target: (True, None),
                "split_subnet_into_chunks": lambda target: [target],
                "create_scan_folder": create_scan_folder_stub,
                "scans_dir": tmp_path,
                "sanitize_customer_dir_name": lambda value: value.replace(" ", "_"),
                "run_nmap_with_xml_output": run_nmap_with_xml_output_stub,
                "merge_nmap_xml_files": lambda *args, **kwargs: None,
                "socketio_sleep": lambda value: None,
                "convert_xml_to_html": convert_xml_to_html_stub,
                "convert_html_to_pdf": convert_html_to_pdf_stub,
                "stylesheet": "web.xsl",
                "web_stylesheet": "web.xsl",
                "pdf_stylesheet": "pdf.xsl",
                "get_app_version": lambda: "v1.0.0",
                "save_scan_metadata": lambda *args, **kwargs: None,
                "get_client_state": lambda sid=None: {
                    "network_key": {"target": "shared"},
                    "current_customer": {"id": "cust-123", "name": "Acme Customer"},
                },
                "network_key": {"target": "shared"},
                "current_customer": {"id": "cust-123", "name": "Acme Customer"},
                "extract_scan_statistics": lambda path: {},
                "customer_fingerprinter": type(
                    "FingerprinterStub",
                    (),
                    {
                        "customers": [],
                        "update_last_scan_duration": lambda self, customer_id, duration: None,
                    },
                )(),
                "settings_state": {"sync": {"google_drive": {"enabled": True, "folder_id": "folder-123"}}},
                "upload_report_artifacts_to_google_drive": upload_report_artifacts_to_google_drive_stub,
            }
        ),
        "sid-1",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme Customer",
        },
    )

    assert len(upload_calls) == 1
    assert upload_calls[0]["scan_path"].startswith("Acme/")
    uploaded_names = sorted(path.name for path in upload_calls[0]["file_paths"])
    assert uploaded_names == ["scan.xml", "scan_report.pdf", "scan_web.html"]

    report_complete = next(payload for event, payload in observed_events if event == "report_complete")
    assert report_complete["google_drive_upload"]["enabled"] is True
    assert report_complete["google_drive_upload"]["attempted"] is True
    assert report_complete["google_drive_upload"]["success"] is True
