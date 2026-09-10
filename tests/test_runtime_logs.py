import base64
import subprocess

from flask import Flask

from nmapui.app_bindings import build_event_helpers
from nmapui.handlers.routes import register_core_routes
from nmapui.runtime_history import backfill_runtime_history_artifacts
from nmapui.startup_checks import run_startup_checks
from nmapui.traceroute import run_traceroute


def test_runtime_logs_route_returns_persisted_entries():
    class RuntimeStoreStub:
        def get_recent_logs(self, category=None, limit=200):
            return [
                {
                    "id": 1,
                    "category": "runtime",
                    "level": "INFO",
                    "message": "Hydrated network topology",
                    "payload": {"target": "192.168.222.0/24"},
                    "created_at": "2026-03-14T20:00:00+00:00",
                }
            ]

    app = Flask(__name__)
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().get("/api/runtime/logs?limit=50")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["entries"][0]["message"] == "Hydrated network topology"


def test_runtime_export_route_downloads_sqlite_database(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    db_path = tmp_path / "runtime.sqlite3"
    db_path.write_bytes(b"SQLite format 3\x00runtime-test")

    class RuntimeStoreStub:
        def export_snapshot(self):
            export_path = tmp_path / "runtime-export.sqlite3"
            export_path.write_bytes(db_path.read_bytes())
            return export_path

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().get(
        "/api/runtime/export",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert response.data.startswith(b"SQLite format 3")
    assert "attachment;" in response.headers["Content-Disposition"]
    assert "nmapui-runtime-" in response.headers["Content-Disposition"]


def test_runtime_reports_route_returns_persisted_artifacts(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_120000_192.168.222.0_24",
                    "customer_id": "cust-1",
                    "target": "192.168.222.0/24",
                    "html_path": "scan_web.html",
                    "pdf_path": "scan_report.pdf",
                    "xml_path": "scan.xml",
                    "payload": {
                        "timestamp": "2026-03-14T12:00:00",
                        "customer_name": "Auto-detect network...",
                        "customer_id": "auto-wan-123",
                        "network_key": {"public_ip": "203.0.113.10"},
                        "status": "completed",
                    },
                    "generated_at": "2026-03-14T12:00:00",
                    "updated_at": "2026-03-14T12:00:00",
                }
            ]

    class CustomerFingerprinterStub:
        def get_customer_by_id(self, customer_id):
            return None

        def match_customer(self, network_key):
            return ({"id": "cust-1", "name": "Acme HQ"}, 1.0)

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "customer_fingerprinter": CustomerFingerprinterStub(),
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/runtime/reports",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["reports"][0]["path"] == "Acme/2026-03-14/scan_120000_192.168.222.0_24"
    assert payload["reports"][0]["customer_name"] == "Acme HQ"
    assert payload["reports"][0]["customer_id"] == "cust-1"
    assert payload["reports"][0]["has_pdf"] is True
    assert payload["reports"][0]["downloads"]["pdf"].startswith("Nmap_Audit_Acme_HQ_")


def test_runtime_report_file_routes_serve_persisted_artifacts(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    scans_dir = tmp_path / "scans"
    scan_dir = scans_dir / "Acme" / "2026-03-14" / "scan_120000_192.168.222.0_24"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "runtime.html").write_text("<html><body>runtime report</body></html>")
    (scan_dir / "runtime.pdf").write_bytes(b"%PDF-1.4 runtime")
    (scan_dir / "runtime.xml").write_text("<nmaprun><host /></nmaprun>")

    class RuntimeStoreStub:
        def get_report_artifact(self, scan_path):
            if scan_path != "Acme/2026-03-14/scan_120000_192.168.222.0_24":
                return None
            return {
                "scan_path": scan_path,
                "html_path": "Acme/2026-03-14/scan_120000_192.168.222.0_24/runtime.html",
                "pdf_path": "Acme/2026-03-14/scan_120000_192.168.222.0_24/runtime.pdf",
                "xml_path": "Acme/2026-03-14/scan_120000_192.168.222.0_24/runtime.xml",
                "payload": {
                    "customer_name": "Auto-detect network...",
                    "customer_id": "auto-wan-123",
                    "target": "192.168.222.0/24",
                    "date": "2026-03-14",
                    "time": "120000",
                    "network_key": {"public_ip": "203.0.113.10"},
                },
            }

        def list_report_artifacts(self, customer_id=None):
            return []

    app = Flask(__name__)
    app.config["TESTING"] = True

    class CustomerFingerprinterStub:
        def get_customer_by_id(self, customer_id):
            return None

        def match_customer(self, network_key):
            return ({"id": "cust-1", "name": "Acme HQ"}, 1.0)

    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "customer_fingerprinter": CustomerFingerprinterStub(),
            "scans_dir": scans_dir,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    client = app.test_client()
    headers = {"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()}
    environ = {"REMOTE_ADDR": "127.0.0.1"}

    html_response = client.get(
        "/api/runtime/reports/Acme/2026-03-14/scan_120000_192.168.222.0_24/html",
        headers=headers,
        environ_overrides=environ,
    )
    pdf_response = client.get(
        "/api/runtime/reports/Acme/2026-03-14/scan_120000_192.168.222.0_24/pdf",
        headers=headers,
        environ_overrides=environ,
    )
    xml_response = client.get(
        "/api/runtime/reports/Acme/2026-03-14/scan_120000_192.168.222.0_24/xml",
        headers=headers,
        environ_overrides=environ,
    )

    assert html_response.status_code == 200
    assert b"runtime report" in html_response.data
    assert pdf_response.status_code == 200
    assert "filename=" in pdf_response.headers["Content-Disposition"]
    assert "Acme_HQ" in pdf_response.headers["Content-Disposition"]
    assert xml_response.status_code == 200
    assert "filename=" in xml_response.headers["Content-Disposition"]
    assert "Acme_HQ" in xml_response.headers["Content-Disposition"]


def test_runtime_history_delete_route_removes_scan_and_runtime_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    scans_dir = tmp_path / "scans"
    scan_dir = scans_dir / "Acme" / "2026-03-14" / "scan_120000_192.168.222.0_24"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-14T12:00:00","customer_name":"Acme","customer_id":"cust-1","target":"192.168.222.0/24"}'
    )

    deleted_paths = []

    class RuntimeStoreStub:
        def delete_report_artifact(self, scan_path):
            deleted_paths.append(scan_path)

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": __import__("persistence").load_json_document,
            "normalize_scan_metadata_document": __import__("persistence").normalize_scan_metadata_document,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    headers = {"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()}
    response = client.delete(
        "/api/runtime/history/Acme/2026-03-14/scan_120000_192.168.222.0_24",
        headers=headers,
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"success": True}
    assert deleted_paths == ["Acme/2026-03-14/scan_120000_192.168.222.0_24"]
    assert not scan_dir.exists()


def test_runtime_history_route_merges_runtime_reports_with_metadata_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    scans_dir = tmp_path / "scans"
    legacy_dir = scans_dir / "Legacy" / "2026-03-13" / "scan_010000_target"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Legacy","target":"10.0.0.0/24","status":"failed"}'
    )

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_120000_192.168.222.0_24",
                    "customer_id": "cust-1",
                    "target": "192.168.222.0/24",
                    "html_path": "scan_web.html",
                    "pdf_path": "scan_report.pdf",
                    "xml_path": "scan.xml",
                    "payload": {
                        "timestamp": "2026-03-14T12:00:00",
                        "customer_name": "Acme",
                        "status": "completed",
                    },
                    "generated_at": "2026-03-14T12:00:00",
                    "updated_at": "2026-03-14T12:00:00",
                }
            ]

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": __import__("persistence").load_json_document,
            "normalize_scan_metadata_document": __import__("persistence").normalize_scan_metadata_document,
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": scans_dir,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/runtime/history",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["history"][0]["customer_name"] == "Acme"
    assert any(item["customer_name"] == "Legacy" for item in payload["history"])


def test_runtime_history_route_backfills_legacy_metadata_into_runtime_store(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    scans_dir = tmp_path / "scans"
    legacy_dir = scans_dir / "Legacy" / "2026-03-13" / "scan_010000_target"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Legacy","customer_id":"cust-legacy","target":"10.0.0.0/24","status":"failed"}'
    )
    (legacy_dir / "scan.xml").write_text("<nmaprun></nmaprun>")

    runtime_calls = []

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            return []

        def get_report_artifact(self, scan_path):
            return None

        def upsert_report_artifact(self, **kwargs):
            runtime_calls.append(kwargs)

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": __import__("persistence").load_json_document,
            "normalize_scan_metadata_document": __import__("persistence").normalize_scan_metadata_document,
            "resolve_scan_path": lambda path: scans_dir / path,
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": scans_dir,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/runtime/history",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert runtime_calls
    assert runtime_calls[0]["scan_path"] == "Legacy/2026-03-13/scan_010000_target"
    assert runtime_calls[0]["customer_id"] == "cust-legacy"
    assert runtime_calls[0]["target"] == "10.0.0.0/24"
    assert runtime_calls[0]["xml_path"] == "scan.xml"
    assert runtime_calls[0]["payload"]["status"] == "failed"


def test_backfill_runtime_history_artifacts_populates_missing_runtime_rows(tmp_path):
    scans_dir = tmp_path / "scans"
    legacy_dir = scans_dir / "Legacy" / "2026-03-13" / "scan_010000_target"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Legacy","customer_id":"cust-legacy","target":"10.0.0.0/24","status":"failed"}'
    )
    (legacy_dir / "scan_report.pdf").write_bytes(b"%PDF-1.4")

    runtime_calls = []

    class RuntimeStoreStub:
        def get_report_artifact(self, scan_path):
            return None

        def upsert_report_artifact(self, **kwargs):
            runtime_calls.append(kwargs)

    backfilled = backfill_runtime_history_artifacts(
        runtime_store=RuntimeStoreStub(),
        scans_dir=scans_dir,
        load_json_document=__import__("persistence").load_json_document,
        normalize_scan_metadata_document=__import__("persistence").normalize_scan_metadata_document,
        logger=None,
    )

    assert backfilled == 1
    assert runtime_calls[0]["scan_path"] == "Legacy/2026-03-13/scan_010000_target"
    assert runtime_calls[0]["pdf_path"] == "scan_report.pdf"


def test_runtime_backfill_route_runs_authenticated_backfill(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    scans_dir = tmp_path / "scans"
    legacy_dir = scans_dir / "Legacy" / "2026-03-13" / "scan_010000_target"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Legacy","customer_id":"cust-legacy","target":"10.0.0.0/24","status":"failed"}'
    )

    runtime_calls = []
    snapshot_calls = []

    class RuntimeStoreStub:
        def get_report_artifact(self, scan_path):
            return None

        def upsert_report_artifact(self, **kwargs):
            runtime_calls.append(kwargs)

        def upsert_runtime_snapshot(self, key, payload):
            snapshot_calls.append((key, payload))

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": __import__("persistence").load_json_document,
            "normalize_scan_metadata_document": __import__("persistence").normalize_scan_metadata_document,
            "resolve_scan_path": lambda path: scans_dir / path,
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": scans_dir,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.post(
        "/api/runtime/maintenance/backfill",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["backfilled"] == 1
    assert "last_run_at" in payload
    assert runtime_calls[0]["scan_path"] == "Legacy/2026-03-13/scan_010000_target"
    assert snapshot_calls[0][0] == "maintenance_backfill_status"
    assert snapshot_calls[0][1]["last_backfilled"] == 1


def test_runtime_settings_summary_includes_backfill_status():
    class RuntimeStoreStub:
        def get_runtime_snapshot(self, key):
            if key == "maintenance_backfill_status":
                return {
                    "last_run_at": "2026-03-14T21:00:00+00:00",
                    "last_backfilled": 4,
                }
            return None

    app = Flask(__name__)
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {"scan_rules": {}, "sync": {}, "target_profiles": []},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    payload = app.test_client().get("/api/runtime/settings-summary").get_json()

    assert payload["maintenance_backfill"]["last_backfilled"] == 4
    assert payload["maintenance_backfill"]["last_run_at"] == "2026-03-14T21:00:00+00:00"


def test_runtime_settings_summary_includes_retention_status():
    class RuntimeStoreStub:
        def get_runtime_snapshot(self, key):
            if key == "maintenance_retention_status":
                return {
                    "last_run_at": "2026-03-14T22:00:00+00:00",
                    "deleted_runtime_logs": 25,
                    "deleted_customer_scan_history": 8,
                    "after_bytes": 4096,
                }
            return None

        def count_report_artifacts(self):
            return 1

        def count_customer_scan_history(self):
            return 2

        def count_runtime_logs(self):
            return 3

    app = Flask(__name__)
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {"scan_rules": {}, "sync": {}, "target_profiles": []},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    payload = app.test_client().get("/api/runtime/settings-summary").get_json()

    assert payload["maintenance_retention"]["deleted_runtime_logs"] == 25
    assert payload["maintenance_retention"]["deleted_customer_scan_history"] == 8
    assert payload["maintenance_retention"]["after_bytes"] == 4096


def test_runtime_backfill_route_requires_auth(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": __import__("persistence").load_json_document,
            "normalize_scan_metadata_document": __import__("persistence").normalize_scan_metadata_document,
            "resolve_scan_path": lambda path: tmp_path / "scans" / path,
            "runtime_store": object(),
            "scans_dir": tmp_path / "scans",
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    response = app.test_client().post("/api/runtime/maintenance/backfill")

    assert response.status_code == 401


def test_runtime_retention_route_prunes_and_persists_status(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    retention_calls = []
    snapshot_calls = []

    class RuntimeStoreStub:
        def apply_retention_policies(
            self,
            *,
            runtime_logs_keep_latest,
            customer_history_keep_latest,
            compact,
        ):
            retention_calls.append(
                {
                    "runtime_logs_keep_latest": runtime_logs_keep_latest,
                    "customer_history_keep_latest": customer_history_keep_latest,
                    "compact": compact,
                }
            )
            return {
                "deleted_runtime_logs": 12,
                "deleted_customer_scan_history": 5,
                "runtime_logs_keep_latest": runtime_logs_keep_latest,
                "customer_history_keep_latest": customer_history_keep_latest,
                "before_bytes": 8192,
                "after_bytes": 4096,
            }

        def upsert_runtime_snapshot(self, key, payload):
            snapshot_calls.append((key, payload))

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().post(
        "/api/runtime/maintenance/retention",
        json={
            "runtime_logs_keep_latest": 300,
            "customer_history_keep_latest": 120,
            "compact": True,
        },
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["deleted_runtime_logs"] == 12
    assert payload["deleted_customer_scan_history"] == 5
    assert payload["after_bytes"] == 4096
    assert retention_calls[0]["runtime_logs_keep_latest"] == 300
    assert retention_calls[0]["customer_history_keep_latest"] == 120
    assert retention_calls[0]["compact"] is True
    assert snapshot_calls[0][0] == "maintenance_retention_status"
    assert snapshot_calls[0][1]["deleted_runtime_logs"] == 12


def test_runtime_retention_route_requires_auth(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": object(),
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().post("/api/runtime/maintenance/retention")

    assert response.status_code == 401


def test_runtime_history_compare_prefers_runtime_artifact_payloads(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)

    class RuntimeStoreStub:
        def get_report_artifact(self, scan_path):
            payloads = {
                "Acme/2026-03-14/base": {
                    "scan_path": "Acme/2026-03-14/base",
                    "payload": {
                        "customer_id": "cust-1",
                        "target": "192.168.222.0/24",
                        "asset_snapshot": [{"ip": "192.168.222.10", "ports": "80 (http)", "vulnerabilities": []}],
                        "timestamp": "2026-03-14T11:00:00",
                    },
                },
                "Acme/2026-03-14/current": {
                    "scan_path": "Acme/2026-03-14/current",
                    "payload": {
                        "customer_id": "cust-1",
                        "target": "192.168.222.0/24",
                        "asset_snapshot": [{"ip": "192.168.222.10", "ports": "80 (http), 443 (https)", "vulnerabilities": []}],
                        "timestamp": "2026-03-14T12:00:00",
                    },
                },
            }
            return payloads.get(scan_path)

        def list_report_artifacts(self, customer_id=None):
            return []

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ok"}, 200),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": lambda *args, **kwargs: {},
            "normalize_scan_metadata_document": lambda payload: payload,
            "resolve_scan_path": lambda path: None,
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": None,
            "settings_state": {},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.get(
        "/api/runtime/history/compare?base_path=Acme/2026-03-14/base&current_path=Acme/2026-03-14/current",
        headers={"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["base_scan"]["path"] == "Acme/2026-03-14/base"
    assert payload["current_scan"]["path"] == "Acme/2026-03-14/current"
    assert payload["diff_summary"]["new_ports"] == ["443 (https)"]


def test_startup_checks_append_runtime_log_entries():
    entries = []

    class RuntimeStoreStub:
        def append_log(self, **kwargs):
            entries.append(kwargs)
            return len(entries)

    run_startup_checks(
        {
            "begin_startup_state": lambda startup_state, quick=False: startup_state.update({"startup_complete": False}),
            "check_arp_scan": lambda: False,
            "check_nmap": lambda: "nmap 7.97",
            "check_vulners": lambda path: None,
            "complete_startup_state": lambda startup_state, traceroute_initialized=False: startup_state.update({"startup_complete": True, "traceroute_initialized": traceroute_initialized}),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "load_auto_scan_config": lambda config: None,
            "load_current_assignment": lambda: None,
            "logger": type("LoggerStub", (), {"info": lambda self, *a, **k: None})(),
            "run_traceroute": lambda target: {"target": target, "total_hops": 3},
            "safe_emit": lambda *args, **kwargs: None,
            "startup_state": {},
            "tool_versions": type("ToolVersionsStub", (), {"set_version": lambda self, key, value: None})(),
            "auto_scan_config": {"enabled": False},
            "runtime_store": RuntimeStoreStub(),
            "vulners_script": __import__("pathlib").Path("."),
        },
        quick=True,
    )

    assert [entry["message"] for entry in entries] == [
        "Startup checks started",
        "Startup network initialization completed",
        "Startup checks completed",
    ]


def test_startup_checks_records_missing_dependencies_without_exiting():
    """Missing nmap/vulners must degrade readiness, not terminate the process."""
    startup_state = {}
    versions = {}

    run_startup_checks(
        {
            "begin_startup_state": lambda state, quick=False: state.update(
                {"startup_complete": False, "errors": []}
            ),
            "check_arp_scan": lambda: False,
            "check_nmap": lambda: None,
            "check_vulners": lambda path: False,
            "complete_startup_state": lambda state, traceroute_initialized=False: state.update(
                {"startup_complete": True, "traceroute_initialized": traceroute_initialized}
            ),
            "get_app_version": lambda: "v1.0.0",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1.0.0"},
            "load_auto_scan_config": lambda config: None,
            "load_current_assignment": lambda: None,
            "logger": type(
                "LoggerStub",
                (),
                {
                    "info": lambda self, *a, **k: None,
                    "error": lambda self, *a, **k: None,
                },
            )(),
            "run_traceroute": lambda target: {"target": target, "total_hops": 3},
            "safe_emit": lambda *args, **kwargs: None,
            "startup_state": startup_state,
            "tool_versions": type(
                "ToolVersionsStub",
                (),
                {"set_version": lambda self, key, value: versions.__setitem__(key, value)},
            )(),
            "auto_scan_config": {"enabled": False},
            "runtime_store": None,
            "vulners_script": __import__("pathlib").Path("/nonexistent/vulners.nse"),
        },
        quick=False,
    )

    assert startup_state["dependencies_ok"] is False
    assert any("nmap" in error for error in startup_state["errors"])
    assert any("Vulners" in error for error in startup_state["errors"])
    assert versions["nmap"] == "Not installed"


def test_traceroute_appends_success_runtime_log():
    entries = []

    class RuntimeStoreStub:
        def append_log(self, **kwargs):
            entries.append(kwargs)
            return len(entries)

    class FingerprinterStub:
        last_match_method = "public_ip"

        def match_customer(self, network_key):
            return ({"id": "cust-1", "name": "Acme"}, 1.0)

        def save_scan_result(self, *args, **kwargs):
            return None

        def save_traceroute_to_history(self, *args, **kwargs):
            return None

    original = subprocess.check_output
    subprocess.check_output = lambda *args, **kwargs: b" 1  192.168.1.1  1.0 ms\n 2  1.1.1.1  2.0 ms\n"
    try:
        run_traceroute(
            "1.1.1.1",
            deps={
                "emit_to_client": lambda *args, **kwargs: None,
                "safe_emit": lambda *args, **kwargs: None,
                "get_client_state": lambda sid=None: {
                    "network_key": {"target": "1.1.1.1"},
                    "current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0},
                },
                "socketio_sleep": lambda value: None,
                "logger": type("LoggerStub", (), {"info": lambda self, *a, **k: None, "warning": lambda self, *a, **k: None, "error": lambda self, *a, **k: None})(),
                "is_private_ip": lambda ip: ip.startswith("192.168."),
                "requests": type("RequestsStub", (), {"get": staticmethod(lambda url, timeout=5: type("Resp", (), {"text": "203.0.113.10"})())}),
                "set_network_key_state": lambda *, value, sid=None: None,
                "get_customer_fingerprinter": lambda: FingerprinterStub(),
                "merge_customer_metadata": lambda active, customer: {**active, **customer},
                "set_current_customer_state": lambda *, value, sid=None: None,
                "get_current_customer_state": lambda sid=None: {"id": "cust-1", "name": "Acme", "confidence": 1.0},
                "runtime_store": RuntimeStoreStub(),
            },
        )
    finally:
        subprocess.check_output = original

    assert entries[-1]["message"] == "Traceroute completed and customer identified"
    assert entries[-1]["category"] == "topology"


def test_event_helpers_persist_structured_runtime_logs():
    entries = []

    class RuntimeStoreStub:
        def append_log(self, **kwargs):
            entries.append(kwargs)
            return len(entries)

    class JobRegistryStub:
        def get(self, sid, job_type):
            return {"status": "running", "details": {"target": "192.168.222.0/24"}}

    socketio = type("SocketStub", (), {"emit": lambda self, event, data=None, to=None: None})()
    helpers = build_event_helpers(
        socketio=socketio,
        job_registry=JobRegistryStub(),
        runtime_store=RuntimeStoreStub(),
    )

    helpers["emit_to_client"]("sid-1", "scan_feedback", "Running quick scan")
    helpers["emit_job_status"]("sid-1", "scan")
    helpers["emit_to_client"]("sid-1", "report_complete", {"path": "scan_report.pdf"})

    assert [entry["category"] for entry in entries] == ["scan", "job", "report"]
    assert entries[0]["message"] == "Running quick scan"
    assert entries[1]["payload"]["job_type"] == "scan"
    assert entries[2]["message"] == "Report generation completed"


def test_event_helpers_broadcast_job_status_to_existing_subscribers():
    emitted = []

    class BroadcasterStub:
        def get_subscribers(self, sid, job_type="scan"):
            assert sid == "sid-1"
            assert job_type == "report"
            return {"sid-1", "sid-2"}

    class JobRegistryStub:
        def get(self, sid, job_type):
            assert job_type == "report"
            return {
                "status": "running",
                "started_at": "2026-03-14T21:28:07",
                "details": {"target": "192.168.222.0/24", "chunked": False},
            }

    class SocketStub:
        def emit(self, event, data=None, to=None):
            emitted.append((event, data, to))

    helpers = build_event_helpers(
        socketio=SocketStub(),
        job_registry=JobRegistryStub(),
        broadcaster=BroadcasterStub(),
        runtime_store=None,
    )

    helpers["emit_job_status"]("sid-1", "report")

    assert len(emitted) == 2
    assert {target for _, _, target in emitted} == {"sid-1", "sid-2"}
    assert all(event == "job_status" for event, _, _ in emitted)
    assert all(
        payload == {
            "status": "running",
            "started_at": "2026-03-14T21:28:07",
            "details": {"target": "192.168.222.0/24", "chunked": False},
            "job_type": "report",
        }
        for _, payload, _ in emitted
    )
