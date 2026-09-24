"""Tests for long-lived session tokens and the browser login flow."""

import base64
import time

from flask import Flask
from flask_socketio import SocketIO

from nmapui import auth as auth_module
from nmapui import session as session_module
from nmapui.handlers.routes import register_core_routes


def build_session_app():
    """Minimal app exposing the real login/logout/session/health routes."""
    app = Flask(__name__, template_folder="../templates")
    SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"status": "ok"},
            "build_readiness_payload": lambda **kwargs: ({"status": "ready"}, 200),
            "get_app_version": lambda: "test",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {},
            "job_registry": None,
            "settings_state": {},
            "startup_state": {},
            "get_auto_scan_thread": lambda: None,
            "socket_auth_token": "token",
        },
    )
    return app


def configure_auth(monkeypatch, username="scanner", password="secret-pass"):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def test_issue_and_verify_token_roundtrip():
    secret = b"x" * 32

    token = session_module.issue_token(secret, "scanner")

    assert session_module.verify_token(secret, token) == "scanner"


def test_verify_token_rejects_tampering():
    secret = b"x" * 32
    token = session_module.issue_token(secret, "scanner")
    payload, signature = token.split(".", 1)
    tampered = f"{payload}.{signature[:-2]}AA"

    assert session_module.verify_token(secret, tampered) is None


def test_verify_token_rejects_wrong_secret():
    token = session_module.issue_token(b"a" * 32, "scanner")

    assert session_module.verify_token(b"b" * 32, token) is None


def test_verify_token_rejects_expired_token():
    secret = b"x" * 32
    issued = int(time.time()) - 10
    token = session_module.issue_token(secret, "scanner", now=issued, ttl=5)

    assert session_module.verify_token(secret, token) is None


def test_session_outlives_the_one_year_unattended_target():
    assert session_module.SESSION_TTL_SECONDS > 365 * 24 * 60 * 60


def test_load_or_create_secret_persists_with_owner_only_permissions(tmp_path):
    secret_path = tmp_path / "session.key"

    created = session_module.load_or_create_secret(secret_path)
    reloaded = session_module.load_or_create_secret(secret_path)

    assert created == reloaded
    assert len(created) == 32
    assert (secret_path.stat().st_mode & 0o777) == 0o600


def test_check_auth_uses_constant_time_comparison(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")

    assert auth_module.check_auth("scanner", "secret-pass") is True
    assert auth_module.check_auth("scanner", "wrong") is False


def test_login_sets_a_long_lived_session_cookie(monkeypatch):
    configure_auth(monkeypatch)
    app = build_session_app()

    with app.test_client() as client:
        response = client.post(
            "/login",
            data={"username": "scanner", "password": "secret-pass"},
            headers={"Accept": "text/html"},
        )

    assert response.status_code == 302
    cookie_header = response.headers.get("Set-Cookie", "")
    assert session_module.SESSION_COOKIE in cookie_header
    assert "HttpOnly" in cookie_header
    assert "Max-Age=" in cookie_header


def test_login_rejects_bad_credentials(monkeypatch):
    configure_auth(monkeypatch)
    app = build_session_app()

    with app.test_client() as client:
        response = client.post(
            "/login",
            data={"username": "scanner", "password": "nope"},
            headers={"Accept": "text/html"},
        )

    assert response.status_code == 401
    assert session_module.SESSION_COOKIE not in response.headers.get("Set-Cookie", "")


def test_session_cookie_authorizes_an_api_request(monkeypatch):
    """A signed cookie must satisfy require_auth without Basic credentials."""
    configure_auth(monkeypatch)
    # Deterministic key so we can mint a valid cookie directly.
    monkeypatch.setattr(auth_module, "_session_secret_cache", b"k" * 32, raising=False)
    app = build_session_app()

    cookie = session_module.issue_token(b"k" * 32, "scanner")

    with app.test_client() as client:
        client.set_cookie(session_module.SESSION_COOKIE, cookie)
        # A remote address that is not loopback forces the auth path.
        response = client.get(
            "/api/session/status",
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )

    assert response.status_code == 200
    assert response.get_json()["authenticated"] is True


def test_basic_auth_still_works_for_api_clients(monkeypatch):
    configure_auth(monkeypatch)
    app = build_session_app()

    token = base64.b64encode(b"scanner:secret-pass").decode()

    with app.test_client() as client:
        response = client.get(
            "/api/session/status",
            headers={"Authorization": f"Basic {token}"},
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )

    assert response.status_code == 200


def test_unauthenticated_api_request_is_rejected(monkeypatch):
    configure_auth(monkeypatch)
    app = build_session_app()

    with app.test_client() as client:
        response = client.get(
            "/api/session/status",
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )

    assert response.status_code == 401


def test_logs_and_settings_summary_require_auth(monkeypatch):
    """These leaked targets, paths and exception strings to any local process."""
    configure_auth(monkeypatch)
    app = build_session_app()

    with app.test_client() as client:
        for path in ("/api/runtime/logs", "/api/runtime/settings-summary"):
            response = client.get(path, environ_overrides={"REMOTE_ADDR": "10.1.2.3"})
            assert response.status_code == 401, path


def test_health_endpoints_stay_public_for_supervision(monkeypatch):
    """launchd/CI health probes must not need credentials."""
    configure_auth(monkeypatch)
    app = build_session_app()

    with app.test_client() as client:
        for path in ("/api/health/live", "/api/health/ready"):
            response = client.get(path, environ_overrides={"REMOTE_ADDR": "10.1.2.3"})
            assert response.status_code == 200, path


def test_socket_token_requires_auth(monkeypatch):
    """A local process must not collect the handshake token without creds."""
    configure_auth(monkeypatch)
    app = build_session_app()

    with app.test_client() as client:
        response = client.get(
            "/api/socket-token", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
        )

    assert response.status_code == 401


def test_authenticated_remote_browser_can_fetch_socket_token(monkeypatch):
    """Remote web clients still need a signed session to start a socket."""
    configure_auth(monkeypatch)
    monkeypatch.setattr(auth_module, "_session_secret_cache", b"k" * 32, raising=False)
    app = build_session_app()
    cookie = session_module.issue_token(b"k" * 32, "scanner")

    with app.test_client() as client:
        client.set_cookie(session_module.SESSION_COOKIE, cookie)
        response = client.get(
            "/api/socket-token",
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )

    assert response.status_code == 200
    assert response.get_json() == {"token": "token"}
