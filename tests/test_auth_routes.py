import base64

from flask import Flask
from flask_socketio import SocketIO
import pytest

from nmapui import auth as auth_module, session as session_module
from nmapui.handlers.auto_scan import register_auto_scan_handlers
from nmapui.handlers.routes import register_core_routes
from nmapui.handlers.scans import register_scan_routes
from nmapui.handlers.settings import register_settings_routes
from nmapui.settings import (
    load_remote_sync_secret,
    load_settings_state,
    normalize_settings_document,
    save_settings_state,
)
from persistence import load_json_document, normalize_scan_metadata_document


def basic_auth_header(username="scanner", password="secret-pass"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def configure_auth(monkeypatch, username="scanner", password="secret-pass", allow_defaults=False):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    if allow_defaults:
        monkeypatch.setenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "true")
    else:
        monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def build_scan_app(tmp_path):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    scan_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","target":"10.0.0.0/24"}'
    )
    (scan_dir / "scan_web.html").write_text("<html></html>")
    (scan_dir / "scan_report.pdf").write_bytes(b"%PDF-1.4")
    (scan_dir / "scan.xml").write_text("<nmaprun></nmaprun>")

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
            "runtime_store": None,
        },
    )
    return app


def build_scan_app_with_real_metadata(tmp_path, metadata):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    scan_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metadata.json").write_text(metadata)

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
            "runtime_store": None,
        },
    )
    return app


def build_scan_app_with_runtime_artifacts(tmp_path):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    scan_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "runtime_scan_web.html").write_text("<html><body>runtime html</body></html>")
    (scan_dir / "runtime_scan_report.pdf").write_bytes(b"%PDF-1.4 runtime")
    (scan_dir / "runtime_scan.xml").write_text("<nmaprun><host /></nmaprun>")

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_020000_target",
                    "customer_id": "cust-123",
                    "target": "10.0.0.0/24",
                    "html_path": "Acme/2026-03-14/scan_020000_target/runtime_scan_web.html",
                    "pdf_path": "Acme/2026-03-14/scan_020000_target/runtime_scan_report.pdf",
                    "xml_path": "Acme/2026-03-14/scan_020000_target/runtime_scan.xml",
                    "payload": {
                        "timestamp": "2026-03-14T02:00:00",
                        "customer_name": "Acme",
                        "customer_id": "cust-123",
                        "target": "10.0.0.0/24",
                        "status": "completed",
                        "completed_successfully": True,
                        "downloads": {
                            "pdf": "Nmap_Audit_Acme_10.0.0.0_24_2026-03-14_020000.pdf",
                            "xml": "Nmap_Raw_Acme_10.0.0.0_24_2026-03-14_020000.xml",
                        },
                    },
                    "generated_at": "2026-03-14T02:00:00",
                    "updated_at": "2026-03-14T02:00:00",
                }
            ]

        def get_report_artifact(self, scan_path):
            artifacts = self.list_report_artifacts()
            for artifact in artifacts:
                if artifact["scan_path"] == scan_path:
                    return artifact
            return None

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
            "runtime_store": RuntimeStoreStub(),
        },
    )
    return app


def build_scan_app_with_runtime_artifact_delete(tmp_path, runtime_calls):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    scan_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","customer_id":"cust-1","target":"10.0.0.0/24"}'
    )

    class RuntimeStoreStub:
        def delete_report_artifact(self, scan_path):
            runtime_calls.append(scan_path)

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
            "runtime_store": RuntimeStoreStub(),
        },
    )
    return app


def build_compare_app_with_runtime_artifacts(tmp_path):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    (scans_dir / "Acme" / "2026-03-13" / "scan_010000_target").mkdir(parents=True, exist_ok=True)
    (scans_dir / "Acme" / "2026-03-14" / "scan_020000_target").mkdir(parents=True, exist_ok=True)

    class RuntimeStoreStub:
        def get_report_artifact(self, scan_path):
            artifacts = {
                "Acme/2026-03-13/scan_010000_target": {
                    "scan_path": "Acme/2026-03-13/scan_010000_target",
                    "payload": {
                        "timestamp": "2026-03-13T01:00:00",
                        "customer_name": "Acme",
                        "customer_id": "cust-123",
                        "target": "10.0.0.0/24",
                        "status": "completed",
                        "asset_snapshot": [
                            {"ip": "10.0.0.10", "hostname": "", "mac": "", "ports": "80 (http)", "vulnerabilities": []}
                        ],
                    },
                },
                "Acme/2026-03-14/scan_020000_target": {
                    "scan_path": "Acme/2026-03-14/scan_020000_target",
                    "payload": {
                        "timestamp": "2026-03-14T01:00:00",
                        "customer_name": "Acme",
                        "customer_id": "cust-123",
                        "target": "10.0.0.0/24",
                        "status": "completed",
                        "asset_snapshot": [
                            {"ip": "10.0.0.10", "hostname": "", "mac": "", "ports": "443 (https)", "vulnerabilities": []},
                            {"ip": "10.0.0.20", "hostname": "", "mac": "", "ports": "", "vulnerabilities": []},
                        ],
                    },
                },
            }
            return artifacts.get(scan_path)

        def list_report_artifacts(self, customer_id=None):
            return []

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
            "runtime_store": RuntimeStoreStub(),
        },
    )
    return app


def build_auto_scan_app():
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    config = {
        "enabled": False,
        "start_time": "01:00",
        "end_time": "03:00",
        "last_run": None,
    }
    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": config,
            "save_auto_scan_config": lambda updated: None,
            "logger": app.logger,
        },
    )
    return app


def build_settings_app(backfill_result=None, backfill_calls=None, save_settings=None, disconnect_google_drive=None):
    app = Flask(__name__)
    settings_state = {
        "target_profiles": [],
        "scan_rules": {"scan_only_mode": False, "excluded_targets": []},
        "sync": {
            "google_drive": {"enabled": False, "folder_id": "", "status": "Not configured"},
            "remote_sync": {"enabled": False, "endpoint": "", "api_key": "", "api_key_configured": False, "status": "Not configured"},
        },
    }
    register_settings_routes(
        app,
        {
            "settings_state": settings_state,
            "save_settings": save_settings or (lambda payload: payload),
            "validate_google_drive": lambda folder_id: {
                "success": True,
                "status": f"Drive OK:{folder_id}",
            },
            "validate_remote_sync": lambda endpoint, api_key: {
                "success": True,
                "status": f"Remote OK:{endpoint}:{api_key}",
            },
            "get_google_drive_auth_status": lambda: {"configured": True, "connected": False, "status": "Not connected"},
            "build_google_drive_auth_url": lambda redirect_uri: {"success": True, "auth_url": f"https://example.com/auth?redirect_uri={redirect_uri}"},
            "exchange_google_drive_auth_code": lambda code, state: {"success": True, "status": "Google Drive connected"},
            "ensure_google_drive_reports_folder": lambda: {"success": True, "folder_id": "test-folder-id", "status": "Drive folder ready"},
            "save_google_drive_credentials": lambda credentials: {"success": True, "status": "Google Drive credentials saved"},
            "disconnect_google_drive": disconnect_google_drive or (lambda: {"success": True, "status": "Google Drive disconnected"}),
            "upload_latest_report_to_google_drive": lambda: (
                backfill_calls.append(True) if backfill_calls is not None else None
            ) or (
                backfill_result
                or {
                    "success": False,
                    "attempted": False,
                    "error": "No completed reports are available yet",
                }
            ),
        },
    )
    return app, settings_state


@pytest.mark.parametrize("authentication", ["session", "basic", "local"])
def test_browser_form_cannot_disconnect_drive_from_another_local_port(monkeypatch, authentication):
    configure_auth(monkeypatch)
    monkeypatch.delenv("NMAPUI_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("NMAPUI_COOKIE_SECURE", raising=False)
    monkeypatch.setattr(auth_module, "_session_secret_cache", b"x" * 32)
    calls = []
    app, _ = build_settings_app(
        disconnect_google_drive=lambda: calls.append("disconnect") or {"success": True}
    )
    client = app.test_client()
    headers = {"Origin": "http://localhost:9999", "Sec-Fetch-Site": "same-site"}
    if authentication == "session":
        token = session_module.issue_token(auth_module._session_signing_secret(), "scanner")
        client.set_cookie(session_module.SESSION_COOKIE, token)
    elif authentication == "basic":
        headers.update(basic_auth_header())
    else:
        monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")

    response = client.post(
        "/api/settings/google-drive/disconnect", base_url="http://localhost:9000",
        data={"submit": "1"}, headers=headers,
    )
    assert response.status_code == 403
    assert calls == []

    headers["Origin"] = "http://localhost:9000"
    headers["Sec-Fetch-Site"] = "same-origin"
    response = client.post(
        "/api/settings/google-drive/disconnect", base_url="http://localhost:9000",
        data={"submit": "1"}, headers=headers,
    )
    assert response.status_code == 200
    assert calls == ["disconnect"]


def test_unicode_basic_credentials_authorize_api_requests(monkeypatch):
    configure_auth(monkeypatch, username="scannér", password="sécret-pass")
    app, _ = build_settings_app()
    client = app.test_client()
    response = client.get("/api/settings", headers=basic_auth_header("scannér", "sécret-pass"))
    assert response.status_code == 200
    rejected = client.get("/api/settings", headers=basic_auth_header("scannér", "wrong"))
    assert rejected.status_code == 401


@pytest.mark.parametrize("browser_headers", [
    {"Origin": "null"},
    {"Origin": "http://localhost:9000.attacker.example"},
    {"Origin": "http://localhost:9000/path"},
    {"Origin": "http://user@localhost:9000"},
    {"Origin": "https://localhost:9000"},
    {"Origin": "http://localhost:0"},
    {"Referer": "http://localhost:9999/form"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_authenticated_mutations_reject_untrusted_browser_metadata(monkeypatch, browser_headers):
    configure_auth(monkeypatch)
    monkeypatch.delenv("NMAPUI_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("NMAPUI_COOKIE_SECURE", raising=False)
    app, _ = build_settings_app()
    response = app.test_client().post(
        "/api/settings/google-drive/disconnect", base_url="http://localhost:9000",
        headers={**basic_auth_header(), **browser_headers},
    )
    assert response.status_code == 403


@pytest.mark.parametrize("base_url, origin, secure, allowed", [
    ("http://scanner.example:80", "http://scanner.example", "false", ""),
    ("http://[::1]:9000", "http://[::1]:9000", "false", ""),
    ("http://scanner.example", "https://scanner.example", "true", ""),
    ("http://127.0.0.1:9000", "https://scanner.example", "true", "https://scanner.example"),
    ("http://localhost:9000", "https://ui.example", "false", "https://ui.example"),
])
def test_browser_mutations_allow_app_and_explicit_frontend_origins(monkeypatch, base_url, origin, secure, allowed):
    configure_auth(monkeypatch)
    monkeypatch.setenv("NMAPUI_COOKIE_SECURE", secure)
    monkeypatch.setenv("NMAPUI_ALLOWED_ORIGINS", allowed)
    app, _ = build_settings_app()
    response = app.test_client().post(
        "/api/settings/google-drive/disconnect", base_url=base_url,
        headers={**basic_auth_header(), "Origin": origin},
    )
    assert response.status_code == 200


def build_runtime_reports_app(tmp_path, upload_result=None, upload_calls=None):
    app = Flask(__name__)
    scans_dir = tmp_path / "scans"
    scan_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "runtime_scan_web.html").write_text("<html><body>runtime html</body></html>")
    (scan_dir / "runtime_scan_report.pdf").write_bytes(b"%PDF-1.4 runtime")
    (scan_dir / "runtime_scan.xml").write_text("<nmaprun><host /></nmaprun>")

    class RuntimeStoreStub:
        def list_report_artifacts(self, customer_id=None):
            return [
                {
                    "scan_path": "Acme/2026-03-14/scan_020000_target",
                    "customer_id": "cust-123",
                    "target": "10.0.0.0/24",
                    "html_path": "Acme/2026-03-14/scan_020000_target/runtime_scan_web.html",
                    "pdf_path": "Acme/2026-03-14/scan_020000_target/runtime_scan_report.pdf",
                    "xml_path": "Acme/2026-03-14/scan_020000_target/runtime_scan.xml",
                    "payload": {
                        "timestamp": "2026-03-14T02:00:00",
                        "customer_name": "Acme",
                        "customer_id": "cust-123",
                        "target": "10.0.0.0/24",
                        "status": "completed",
                        "completed_successfully": True,
                    },
                }
            ]

        def get_report_artifact(self, scan_path):
            return self.list_report_artifacts()[0]

    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"ok": True},
            "build_readiness_payload": lambda **kwargs: ({"ok": True}, 200),
            "get_app_version": lambda: "v1",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "resolve_scan_path": lambda path: scans_dir / path,
            "runtime_store": RuntimeStoreStub(),
            "scans_dir": scans_dir,
            "settings_state": {"sync": {"google_drive": {"enabled": True, "folder_id": "folder-123"}}},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
            "upload_report_artifacts_to_google_drive": lambda **kwargs: (
                upload_calls.append(kwargs) if upload_calls is not None else None
            ) or (upload_result or {"success": True, "status": "Uploaded 3 file(s) to Google Drive"}),
        },
    )
    return app


def test_scan_routes_require_http_basic_auth(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get("/api/scans")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized"}


def test_scan_routes_allow_authorized_access(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get("/api/scans", headers=basic_auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scans"][0]["customer_name"] == "Acme"
    assert response.headers["Deprecation"] == "true"
    assert response.headers["Sunset"] == "runtime-api-preferred"
    assert response.headers["Link"] == '</api/runtime/history>; rel="successor-version"'


def test_scan_routes_prefer_runtime_report_artifacts(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app_with_runtime_artifacts(tmp_path)
    client = app.test_client()

    response = client.get("/api/scans", headers=basic_auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scans"][0]["path"] == "Acme/2026-03-14/scan_020000_target"
    assert payload["scans"][0]["has_html"] is True
    assert payload["scans"][0]["has_pdf"] is True
    assert payload["scans"][0]["has_xml"] is True


def test_scan_download_routes_prefer_runtime_artifact_download_names(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app_with_runtime_artifacts(tmp_path)
    client = app.test_client()
    scan_dir = tmp_path / "scans" / "Acme" / "2026-03-14" / "scan_020000_target"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan_report.pdf").write_bytes(b"%PDF-1.4")
    (scan_dir / "scan.xml").write_text("<nmaprun></nmaprun>")

    pdf_response = client.get(
        "/api/scans/Acme/2026-03-14/scan_020000_target/pdf",
        headers=basic_auth_header(),
    )
    xml_response = client.get(
        "/api/scans/Acme/2026-03-14/scan_020000_target/xml",
        headers=basic_auth_header(),
    )

    assert pdf_response.status_code == 200
    assert pdf_response.headers["Deprecation"] == "true"
    assert "filename=Nmap_Audit_Acme_10.0.0.0_24_2026-03-14_020000.pdf" in pdf_response.headers["Content-Disposition"]
    assert xml_response.status_code == 200
    assert xml_response.headers["Deprecation"] == "true"
    assert "filename=Nmap_Raw_Acme_10.0.0.0_24_2026-03-14_020000.xml" in xml_response.headers["Content-Disposition"]


def test_scan_file_routes_prefer_runtime_artifact_paths(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app_with_runtime_artifacts(tmp_path)
    client = app.test_client()

    html_response = client.get(
        "/api/scans/Acme/2026-03-14/scan_020000_target/html",
        headers=basic_auth_header(),
    )
    pdf_response = client.get(
        "/api/scans/Acme/2026-03-14/scan_020000_target/pdf",
        headers=basic_auth_header(),
    )
    xml_response = client.get(
        "/api/scans/Acme/2026-03-14/scan_020000_target/xml",
        headers=basic_auth_header(),
    )

    assert html_response.status_code == 200
    assert b"runtime html" in html_response.data
    assert pdf_response.status_code == 200
    assert pdf_response.data.startswith(b"%PDF-1.4 runtime")
    assert xml_response.status_code == 200
    assert b"<host />" in xml_response.data


def test_scan_routes_reject_spoofed_local_host_without_loopback_peer(tmp_path, monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get(
        "/api/scans",
        headers={"Host": "localhost:9000"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.7"},
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized"}


def test_scan_routes_allow_trusted_loopback_peer_without_basic_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get(
        "/api/scans",
        headers={"Host": "127.0.0.1:9000"},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scans"][0]["customer_name"] == "Acme"


def test_scan_routes_surface_failed_report_metadata(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app_with_real_metadata(
        tmp_path,
        """
        {
          "timestamp": "2026-03-13T01:00:00",
          "customer_name": "Acme",
          "target": "10.0.0.0/24",
          "status": "failed",
          "failure_stage": "scan_chunks",
          "failure_error": "Nmap scan failed on chunk 2",
          "completed_successfully": false
        }
        """,
    )
    client = app.test_client()

    response = client.get("/api/scans", headers=basic_auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scans"][0]["status"] == "failed"
    assert payload["scans"][0]["failure_stage"] == "scan_chunks"
    assert payload["scans"][0]["failure_error"] == "Nmap scan failed on chunk 2"
    assert payload["scans"][0]["completed_successfully"] is False


def test_scan_routes_include_diff_summary_against_previous_scan(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    older = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    newer = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    older.mkdir(parents=True, exist_ok=True)
    newer.mkdir(parents=True, exist_ok=True)
    (older / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24"}'
    )
    (newer / "metadata.json").write_text(
        '{"timestamp":"2026-03-14T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24"}'
    )
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
              <script id="vulners">
                <table><elem key="id">CVE-2026-0009</elem></table>
              </script>
            </ports>
          </host>
          <host>
            <status state="up"/>
            <address addr="10.0.0.20" addrtype="ipv4"/>
          </host>
        </nmaprun>
        """
    )

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
        },
    )
    client = app.test_client()

    response = client.get("/api/scans", headers=basic_auth_header())

    assert response.status_code == 200
    payload = response.get_json()
    latest = payload["scans"][0]
    assert latest["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert latest["diff_summary"]["added_hosts"] == ["10.0.0.20"]
    assert latest["diff_summary"]["new_ports"] == ["443 (https)"]


def test_compare_scans_returns_explicit_diff_summary(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    base_scan = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    current_scan = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    base_scan.mkdir(parents=True, exist_ok=True)
    current_scan.mkdir(parents=True, exist_ok=True)
    (base_scan / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24","status":"completed"}'
    )
    (current_scan / "metadata.json").write_text(
        '{"timestamp":"2026-03-14T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24","status":"completed"}'
    )
    (base_scan / "scan.xml").write_text(
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
    (current_scan / "scan.xml").write_text(
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

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
        },
    )

    response = app.test_client().get(
        "/api/scans/compare?base_path=Acme/2026-03-13/scan_010000_target&current_path=Acme/2026-03-14/scan_020000_target",
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["base_scan"]["path"] == "Acme/2026-03-13/scan_010000_target"
    assert payload["current_scan"]["path"] == "Acme/2026-03-14/scan_020000_target"
    assert payload["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert payload["diff_summary"]["added_hosts"] == ["10.0.0.20"]
    assert payload["diff_summary"]["new_ports"] == ["443 (https)"]


def test_compare_scans_prefers_runtime_artifact_asset_snapshots(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_compare_app_with_runtime_artifacts(tmp_path)

    response = app.test_client().get(
        "/api/scans/compare?base_path=Acme/2026-03-13/scan_010000_target&current_path=Acme/2026-03-14/scan_020000_target",
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["diff_summary"]["added_hosts"] == ["10.0.0.20"]
    assert payload["diff_summary"]["new_ports"] == ["443 (https)"]


def test_compare_scans_rejects_mismatched_targets(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    base_scan = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    current_scan = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    base_scan.mkdir(parents=True, exist_ok=True)
    current_scan.mkdir(parents=True, exist_ok=True)
    (base_scan / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24"}'
    )
    (current_scan / "metadata.json").write_text(
        '{"timestamp":"2026-03-14T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.1.0/24"}'
    )
    (base_scan / "scan.xml").write_text("<nmaprun></nmaprun>")
    (current_scan / "scan.xml").write_text("<nmaprun></nmaprun>")

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
        },
    )

    response = app.test_client().get(
        "/api/scans/compare?base_path=Acme/2026-03-13/scan_010000_target&current_path=Acme/2026-03-14/scan_020000_target",
        headers=basic_auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "success": False,
        "error": "Scans must target the same network",
    }


def test_compare_scans_rejects_mismatched_customers(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    base_scan = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    current_scan = scans_dir / "Bravo" / "2026-03-14" / "scan_020000_target"
    base_scan.mkdir(parents=True, exist_ok=True)
    current_scan.mkdir(parents=True, exist_ok=True)
    (base_scan / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24"}'
    )
    (current_scan / "metadata.json").write_text(
        '{"timestamp":"2026-03-14T01:00:00","customer_name":"Bravo","customer_id":"cust-456","target":"10.0.0.0/24"}'
    )
    (base_scan / "scan.xml").write_text("<nmaprun></nmaprun>")
    (current_scan / "scan.xml").write_text("<nmaprun></nmaprun>")

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
        },
    )

    response = app.test_client().get(
        "/api/scans/compare?base_path=Acme/2026-03-13/scan_010000_target&current_path=Bravo/2026-03-14/scan_020000_target",
        headers=basic_auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "success": False,
        "error": "Scans must belong to the same customer",
    }


def test_delete_scan_removes_index_entry(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = build_scan_app_with_real_metadata(
        tmp_path,
        """
        {
          "timestamp": "2026-03-13T01:00:00",
          "customer_name": "Acme",
          "target": "10.0.0.0/24"
        }
        """,
    )
    client = app.test_client()

    list_response = client.get("/api/scans", headers=basic_auth_header())
    assert list_response.status_code == 200
    index_path = tmp_path / "scans" / ".scan_metadata_index.json"
    assert index_path.exists()

    delete_response = client.delete(
        "/api/scans/Acme/2026-03-13/scan_010000_target",
        headers=basic_auth_header(),
    )

    assert delete_response.status_code == 200
    assert delete_response.get_json() == {"success": True}
    assert __import__("json").loads(index_path.read_text())["entries"] == []


def test_delete_scan_removes_runtime_artifact(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    runtime_calls = []
    app = build_scan_app_with_runtime_artifact_delete(tmp_path, runtime_calls)
    client = app.test_client()

    response = client.delete(
        "/api/scans/Acme/2026-03-13/scan_010000_target",
        headers=basic_auth_header(),
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"success": True}
    assert runtime_calls == ["Acme/2026-03-13/scan_010000_target"]


def test_delete_scan_refreshes_successor_diff_summary(tmp_path, monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    scans_dir = tmp_path / "scans"
    oldest = scans_dir / "Acme" / "2026-03-12" / "scan_000000_target"
    middle = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    newest = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    oldest.mkdir(parents=True, exist_ok=True)
    middle.mkdir(parents=True, exist_ok=True)
    newest.mkdir(parents=True, exist_ok=True)

    (oldest / "metadata.json").write_text(
        '{"timestamp":"2026-03-12T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24"}'
    )
    (middle / "metadata.json").write_text(
        '{"timestamp":"2026-03-13T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24"}'
    )
    (newest / "metadata.json").write_text(
        '{"timestamp":"2026-03-14T01:00:00","customer_name":"Acme","customer_id":"cust-123","target":"10.0.0.0/24","diff_summary":{"has_changes":true,"baseline_path":"Acme/2026-03-13/scan_010000_target","baseline_timestamp":"2026-03-13T01:00:00","added_hosts":["10.0.0.30"],"removed_hosts":[],"changed_hosts":[],"new_ports":[],"removed_ports":[],"new_vulnerabilities":[],"removed_vulnerabilities":[]}}'
    )

    (oldest / "scan.xml").write_text(
        """
        <nmaprun>
          <host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/></host>
        </nmaprun>
        """
    )
    (middle / "scan.xml").write_text(
        """
        <nmaprun>
          <host><status state="up"/><address addr="10.0.0.20" addrtype="ipv4"/></host>
        </nmaprun>
        """
    )
    (newest / "scan.xml").write_text(
        """
        <nmaprun>
          <host><status state="up"/><address addr="10.0.0.20" addrtype="ipv4"/></host>
          <host><status state="up"/><address addr="10.0.0.30" addrtype="ipv4"/></host>
        </nmaprun>
        """
    )

    register_scan_routes(
        app,
        {
            "scans_dir": scans_dir,
            "resolve_scan_path": lambda path: scans_dir / path,
            "load_json_document": load_json_document,
            "normalize_scan_metadata_document": normalize_scan_metadata_document,
            "logger": app.logger,
        },
    )
    client = app.test_client()

    client.get("/api/scans", headers=basic_auth_header())
    delete_response = client.delete(
        "/api/scans/Acme/2026-03-13/scan_010000_target",
        headers=basic_auth_header(),
    )

    assert delete_response.status_code == 200
    newest_metadata = __import__("json").loads((newest / "metadata.json").read_text())
    assert newest_metadata["diff_summary"]["baseline_path"] == "Acme/2026-03-12/scan_000000_target"


def test_auto_scan_routes_require_http_basic_auth(monkeypatch):
    configure_auth(monkeypatch)
    app = build_auto_scan_app()
    client = app.test_client()

    response = client.get("/api/auto_scan/status")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized"}


def test_auto_scan_routes_allow_authorized_access(monkeypatch):
    configure_auth(monkeypatch)
    app = build_auto_scan_app()
    client = app.test_client()

    response = client.get("/api/auto_scan/status", headers=basic_auth_header())

    assert response.status_code == 200
    assert response.get_json() == {
        "enabled": False,
        "start_time": "01:00",
        "end_time": "03:00",
        "last_run": None,
        "next_run": None,
        "seconds_until_next_run": None,
        "warning_active": False,
    }


def test_settings_routes_require_http_basic_auth(monkeypatch):
    configure_auth(monkeypatch)
    app, _ = build_settings_app()
    client = app.test_client()

    response = client.get("/api/settings")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized"}


def test_settings_routes_save_normalized_payload(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    saved = {}
    register_settings_routes(
        app,
        {
            "settings_state": {},
            "save_settings": lambda payload: saved.setdefault(
                "value", normalize_settings_document(payload)
            ),
            "validate_google_drive": lambda folder_id: {"success": True, "status": "Configured"},
            "validate_remote_sync": lambda endpoint, api_key: {"success": True, "status": "Configured"},
            "get_google_drive_auth_status": lambda: {"configured": True, "connected": False, "status": "Not connected"},
            "build_google_drive_auth_url": lambda redirect_uri: {"success": True, "auth_url": "https://example.com/auth"},
            "exchange_google_drive_auth_code": lambda code, state: {"success": True, "status": "Google Drive connected"},
            "ensure_google_drive_reports_folder": lambda: {"success": True, "folder_id": "test-folder-id", "status": "Drive folder ready"},
            "save_google_drive_credentials": lambda credentials: {"success": True, "status": "Google Drive credentials saved"},
            "disconnect_google_drive": lambda: {"success": True, "status": "Google Drive disconnected"},
        },
    )

    response = app.test_client().post(
        "/api/settings",
        json={
            "target_profiles": [
                {
                    "name": "HQ",
                    "target": "192.168.1.0/24",
                    "customer_id": "cust-123",
                    "customer_name": "Acme",
                    "notes": "Primary office",
                }
            ],
            "scan_rules": {
                "scan_only_mode": True,
                "excluded_targets": ["192.168.1.10", "192.168.1.11"],
            },
            "sync": {
                "google_drive": {"enabled": True, "folder_id": "folder-123", "status": "Configured"},
                "remote_sync": {"enabled": True, "endpoint": "https://pilot.example/api", "api_key": "secret", "status": "Configured"},
            },
        },
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["settings"]["target_profiles"][0]["name"] == "HQ"
    assert payload["settings"]["target_profiles"][0]["scan_rules"]["scan_only_mode"] is False
    assert payload["settings"]["target_profiles"][0]["scan_rules"]["excluded_targets"] == []
    assert payload["settings"]["scan_rules"]["scan_only_mode"] is True
    assert payload["settings"]["scan_rules"]["excluded_targets"] == ["192.168.1.10", "192.168.1.11"]
    assert payload["settings"]["sync"]["remote_sync"]["api_key"] == ""
    assert payload["settings"]["sync"]["remote_sync"]["api_key_configured"] is True


def test_settings_routes_preserve_profile_level_scan_rule_overrides(monkeypatch):
    configure_auth(monkeypatch)
    app, _ = build_settings_app()

    response = app.test_client().post(
        "/api/settings",
        json={
            "target_profiles": [
                {
                    "name": "HQ",
                    "target": "192.168.1.0/24",
                    "customer_id": "cust-123",
                    "customer_name": "Acme",
                    "notes": "Primary office",
                    "scan_rules": {
                        "scan_only_mode": True,
                        "excluded_targets": ["192.168.1.99"],
                    },
                }
            ],
            "scan_rules": {
                "scan_only_mode": False,
                "excluded_targets": [],
            },
            "sync": {
                "google_drive": {"enabled": False, "folder_id": "", "status": "Not configured"},
                "remote_sync": {"enabled": False, "endpoint": "", "api_key": "", "status": "Not configured"},
            },
        },
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    payload = response.get_json()
    profile_rules = payload["settings"]["target_profiles"][0]["scan_rules"]
    assert profile_rules["scan_only_mode"] is True
    assert profile_rules["excluded_targets"] == ["192.168.1.99"]


def test_settings_save_preserves_server_owned_auto_monitor_progress(monkeypatch):
    configure_auth(monkeypatch)
    app, settings_state = build_settings_app()
    settings_state["auto_monitor"] = {
        "defaults": {"recurrence": "daily"},
        "rules": [{
            "id": "existing", "customer_id": "cust-1", "enabled": True,
            "last_run": "2026-09-26T09:00:00+00:00",
            "created_at": "2026-09-01T00:00:00+00:00",
        }],
    }

    response = app.test_client().post(
        "/api/settings",
        json={
            "auto_monitor": {
                "defaults": {"recurrence": "weekly"},
                "rules": [
                    {
                        "id": "existing", "customer_id": "cust-1", "enabled": True,
                        "last_run": "2026-09-01T00:00:00+00:00",
                        "created_at": "2020-01-01T00:00:00+00:00",
                    },
                    {
                        "id": "new", "customer_id": "cust-2", "enabled": True,
                        "last_run": "2099-01-01T00:00:00+00:00",
                        "created_at": "2020-01-01T00:00:00+00:00",
                    },
                ],
            },
        },
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    rules = {rule["id"]: rule for rule in settings_state["auto_monitor"]["rules"]}
    assert settings_state["auto_monitor"]["defaults"]["recurrence"] == "weekly"
    assert rules["existing"]["last_run"] == "2026-09-26T09:00:00+00:00"
    assert rules["existing"]["created_at"] == "2026-09-01T00:00:00+00:00"
    assert rules["new"]["last_run"] is None
    assert rules["new"]["created_at"] != "2020-01-01T00:00:00+00:00"


def test_settings_save_failure_keeps_running_configuration(monkeypatch):
    configure_auth(monkeypatch)

    def fail_save(_payload):
        raise OSError("disk is read-only")

    app, settings_state = build_settings_app(save_settings=fail_save)
    original = __import__("copy").deepcopy(settings_state)

    response = app.test_client().post(
        "/api/settings",
        json={"scan_rules": {"scan_only_mode": True}},
        headers=basic_auth_header(),
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "success": False,
        "error": "Could not save settings",
    }
    assert settings_state == original


def test_settings_routes_validate_google_drive(monkeypatch):
    configure_auth(monkeypatch)
    app, _ = build_settings_app()

    response = app.test_client().post(
        "/api/settings/validate/google-drive",
        json={"folder_id": "folder-123"},
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json() == {"success": True, "status": "Drive OK:folder-123"}


def test_settings_routes_expose_google_drive_auth_status(monkeypatch):
    configure_auth(monkeypatch)
    app, _ = build_settings_app()

    response = app.test_client().get(
        "/api/settings/google-drive/status",
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "Not connected"


def test_settings_routes_return_google_drive_auth_url(monkeypatch):
    configure_auth(monkeypatch)
    app, _ = build_settings_app()

    response = app.test_client().get(
        "/api/settings/google-drive/auth-url",
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    assert "https://example.com/auth" in response.get_json()["auth_url"]


def test_settings_routes_callback_backfills_latest_report_when_drive_connects(monkeypatch):
    configure_auth(monkeypatch)
    backfill_calls = []
    app, _ = build_settings_app(
        backfill_result={
            "success": True,
            "attempted": True,
            "status": "Uploaded 3 file(s) to Google Drive",
            "scan_path": "Acme/2026-03-14/scan_020000_target",
        },
        backfill_calls=backfill_calls,
    )

    response = app.test_client().get(
        "/api/settings/google-drive/callback?code=abc&state=xyz",
    )

    assert response.status_code == 200
    assert b"Google Drive connected. Reports will sync to nmapui-reports." in response.data
    assert b"Latest completed report was uploaded." in response.data
    assert len(backfill_calls) == 1


def test_settings_routes_callback_reports_when_no_backfill_report_available(monkeypatch):
    configure_auth(monkeypatch)
    app, _ = build_settings_app(
        backfill_result={
            "success": False,
            "attempted": False,
            "error": "No completed reports are available yet",
        },
    )

    response = app.test_client().get(
        "/api/settings/google-drive/callback?code=abc&state=xyz",
    )

    assert response.status_code == 200
    assert b"No saved report was uploaded automatically." in response.data


def test_settings_routes_callback_returns_html_when_unexpected_error_occurs(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    register_settings_routes(
        app,
        {
            "settings_state": {},
            "save_settings": lambda payload: payload,
            "validate_google_drive": lambda folder_id: {"success": True, "status": "Configured"},
            "validate_remote_sync": lambda endpoint, api_key: {"success": True, "status": "Configured"},
            "get_google_drive_auth_status": lambda: {"configured": True, "connected": False, "status": "Not connected"},
            "build_google_drive_auth_url": lambda redirect_uri: {"success": True, "auth_url": "https://example.com/auth"},
            "exchange_google_drive_auth_code": lambda code, state: {"success": True, "status": "Google Drive connected"},
            "ensure_google_drive_reports_folder": lambda: (_ for _ in ()).throw(RuntimeError("folder api exploded")),
            "save_google_drive_credentials": lambda credentials: {"success": True, "status": "Google Drive credentials saved"},
            "disconnect_google_drive": lambda: {"success": True, "status": "Google Drive disconnected"},
            "upload_latest_report_to_google_drive": lambda: {"success": False, "attempted": False},
        },
    )

    response = app.test_client().get(
        "/api/settings/google-drive/callback?code=abc&state=xyz",
    )

    assert response.status_code == 500
    assert b"Google Drive connection failed" in response.data
    assert b"Unexpected callback error: folder api exploded" in response.data


def test_runtime_reports_can_upload_to_google_drive(monkeypatch, tmp_path):
    configure_auth(monkeypatch)
    upload_calls = []
    app = build_runtime_reports_app(tmp_path, upload_calls=upload_calls)

    response = app.test_client().post(
        "/api/runtime/reports/Acme/2026-03-14/scan_020000_target/upload/google-drive",
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert upload_calls[0]["scan_path"] == "Acme/2026-03-14/scan_020000_target"
    assert len(upload_calls[0]["file_paths"]) == 3


def test_settings_routes_validate_remote_sync(monkeypatch):
    configure_auth(monkeypatch)
    app, _ = build_settings_app()

    response = app.test_client().post(
        "/api/settings/validate/remote-sync",
        json={"endpoint": "https://pilot.example/api", "api_key": "secret"},
        headers=basic_auth_header(),
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "success": True,
        "status": "Remote OK:https://pilot.example/api:secret",
    }


def test_save_settings_state_moves_remote_sync_secret_out_of_settings_json(tmp_path):
    settings_path = tmp_path / "settings.json"
    secret_path = tmp_path / "remote_sync_secret.json"
    secret_key_path = tmp_path / "remote_sync_secret.key"

    saved = save_settings_state(
        settings_path=settings_path,
        save_json_document=lambda path, payload: path.write_text(__import__("json").dumps(payload, indent=2)),
        settings_state={
            "sync": {
                "google_drive": {"enabled": False, "folder_id": "", "status": "Not configured"},
                "remote_sync": {
                    "enabled": True,
                    "endpoint": "https://pilot.example/api",
                    "api_key": "secret-token",
                    "status": "Configured",
                },
            }
        },
        remote_sync_secret_path=secret_path,
        remote_sync_secret_key_path=secret_key_path,
    )

    persisted = __import__("json").loads(settings_path.read_text())
    assert persisted["sync"]["remote_sync"]["api_key"] == ""
    assert persisted["sync"]["remote_sync"]["api_key_configured"] is True
    assert saved["sync"]["remote_sync"]["api_key"] == ""
    assert load_remote_sync_secret(secret_path=secret_path, key_path=secret_key_path) == "secret-token"


def test_load_settings_state_redacts_remote_sync_secret_but_preserves_configured_flag(tmp_path):
    settings_path = tmp_path / "settings.json"
    secret_path = tmp_path / "remote_sync_secret.json"
    secret_key_path = tmp_path / "remote_sync_secret.key"
    settings_path.write_text(
        __import__("json").dumps(
            {
                "schema_version": 1,
                "target_profiles": [],
                "scan_rules": {"scan_only_mode": False, "excluded_targets": []},
                "sync": {
                    "google_drive": {"enabled": False, "folder_id": "", "status": "Not configured"},
                    "remote_sync": {
                        "enabled": True,
                        "endpoint": "https://pilot.example/api",
                        "api_key": "",
                        "status": "Configured",
                    },
                },
            },
            indent=2,
        )
    )
    save_settings_state(
        settings_path=settings_path,
        save_json_document=lambda path, payload: path.write_text(__import__("json").dumps(payload, indent=2)),
        settings_state={
            "sync": {
                "google_drive": {"enabled": False, "folder_id": "", "status": "Not configured"},
                "remote_sync": {
                    "enabled": True,
                    "endpoint": "https://pilot.example/api",
                    "api_key": "secret-token",
                    "status": "Configured",
                },
            }
        },
        remote_sync_secret_path=secret_path,
        remote_sync_secret_key_path=secret_key_path,
    )

    loaded = load_settings_state(
        settings_path=settings_path,
        load_json_document=lambda path, default: __import__("json").loads(path.read_text()),
        remote_sync_secret_path=secret_path,
        remote_sync_secret_key_path=secret_key_path,
    )

    assert loaded["sync"]["remote_sync"]["api_key"] == ""
    assert loaded["sync"]["remote_sync"]["api_key_configured"] is True


def test_http_auth_rejects_builtin_default_credentials_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("NMAPUI_USERNAME", raising=False)
    monkeypatch.delenv("NMAPUI_PASSWORD", raising=False)
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    app = build_scan_app(tmp_path)
    client = app.test_client()

    response = client.get(
        "/api/scans",
        headers=basic_auth_header(username="admin", password="nmapui123"),
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Authentication is not configured securely"}


def test_http_auth_rejects_builtin_password_with_custom_username(tmp_path, monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.delenv("NMAPUI_PASSWORD", raising=False)
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    app = build_scan_app(tmp_path)

    response = app.test_client().get(
        "/api/scans",
        headers=basic_auth_header(username="scanner", password="nmapui123"),
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Authentication is not configured securely"}


def test_http_auth_rejects_empty_password(tmp_path, monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "   ")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    app = build_scan_app(tmp_path)

    response = app.test_client().get(
        "/api/scans", headers=basic_auth_header(username="scanner", password="   ")
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Authentication is not configured securely"}


def test_default_password_acknowledgement_does_not_allow_remote_bind(tmp_path, monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "admin")
    monkeypatch.setenv("NMAPUI_PASSWORD", "nmapui123")
    monkeypatch.setenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "true")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.setenv("NMAPUI_HOST", "0.0.0.0")
    app = build_scan_app(tmp_path)

    response = app.test_client().get(
        "/api/scans",
        headers={"Host": "scanner.example:9000", **basic_auth_header("admin", "nmapui123")},
        environ_overrides={"REMOTE_ADDR": "203.0.113.7"},
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Authentication is not configured securely"}
