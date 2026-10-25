"""The status endpoint contains scan targets and customer/session identifiers."""

import base64

from flask import Flask
import pytest

from nmapui import auth, session
from nmapui.handlers.routes import register_core_routes


@pytest.fixture
def status_app(monkeypatch):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner-雪")
    monkeypatch.setenv("NMAPUI_PASSWORD", "private-contraseña-🔐")
    monkeypatch.setattr(auth, "_session_secret_cache", b"status-test-secret" * 2)
    snapshots = []

    class Registry:
        def snapshot(self):
            snapshots.append(True)
            return {
                "has_active_jobs": True,
                "active_jobs": [{"sid": "private-owner", "job_type": "scan", "status": "running",
                                 "details": {"target": "192.0.2.0/24", "customer_name": "Private customer"}}],
            }

    app = Flask(__name__)
    register_core_routes(app, {
        "build_liveness_payload": lambda **kwargs: {"ok": True},
        "build_readiness_payload": lambda **kwargs: ({"ready": True}, 200),
        "get_app_version": lambda: "v-test",
        "get_default_interface_cached": lambda: "test-interface",
        "get_versions": lambda: {},
        "job_registry": Registry(), "settings_state": {},
        "startup_state": {"startup_complete": True}, "get_auto_scan_thread": lambda: None,
    })
    return app, snapshots


@pytest.mark.parametrize("peer", ["127.0.0.1", "192.0.2.50"])
@pytest.mark.parametrize("credentials", [None, "wrong:password"])
def test_strict_status_rejects_unauthenticated_peers_before_reading_jobs(status_app, peer, credentials):
    app, snapshots = status_app
    headers = {} if credentials is None else {"Authorization": "Basic " + base64.b64encode(credentials.encode()).decode()}
    response = app.test_client().get("/api/runtime/status", headers=headers, environ_overrides={"REMOTE_ADDR": peer})
    assert response.status_code == 401
    assert snapshots == []
    assert "Private customer" not in response.get_data(as_text=True)
    assert "192.0.2.0/24" not in response.get_data(as_text=True)


@pytest.mark.parametrize("authentication", ["basic", "session"])
def test_status_accepts_unicode_api_credentials_and_browser_sessions(status_app, authentication):
    app, snapshots = status_app
    client = app.test_client()
    headers = {}
    if authentication == "basic":
        credentials = "scanner-雪:private-contraseña-🔐"
        headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
    else:
        client.set_cookie(session.SESSION_COOKIE, session.issue_token(auth._session_signing_secret(), "scanner-雪"))
    response = client.get("/api/runtime/status", headers=headers, environ_overrides={"REMOTE_ADDR": "192.0.2.50"})
    assert response.status_code == 200
    assert response.json["active_jobs"][0]["details"]["customer_name"] == "Private customer"
    assert response.headers["Cache-Control"] == "no-store"
    assert snapshots == [True]


def test_trusted_loopback_status_does_not_trust_remote_peers(status_app, monkeypatch):
    app, snapshots = status_app
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    client = app.test_client()
    assert client.get("/api/runtime/status").status_code == 200
    assert client.get("/api/runtime/status", environ_overrides={"REMOTE_ADDR": "192.0.2.50"}).status_code == 401
    assert snapshots == [True]


def test_insecure_auth_configuration_does_not_expose_status(status_app, monkeypatch):
    app, snapshots = status_app
    monkeypatch.setenv("NMAPUI_PASSWORD", auth.DEFAULT_AUTH_PASSWORD)
    response = app.test_client().get("/api/runtime/status")
    assert response.status_code == 503
    assert snapshots == []
    assert "Private customer" not in response.get_data(as_text=True)


def test_public_health_probes_do_not_require_scan_status_access(status_app):
    app, snapshots = status_app
    client = app.test_client()
    assert client.get("/api/health/live").status_code == 200
    assert client.get("/api/health/ready").status_code == 200
    assert snapshots == []
