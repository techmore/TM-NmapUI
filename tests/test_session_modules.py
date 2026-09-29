"""Tests for long-lived session tokens and the browser login flow."""

import base64
import time

from flask import Flask
from flask_socketio import SocketIO
import pytest

from nmapui import auth as auth_module
from nmapui import private_storage
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
    monkeypatch.delenv("NMAPUI_COOKIE_SECURE", raising=False)
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


def test_session_secret_rejects_corrupt_existing_key_instead_of_rotating(tmp_path):
    secret_path = tmp_path / "session.key"
    secret_path.write_bytes(b"short")

    with pytest.raises(ValueError, match="too short"):
        session_module.load_or_create_secret(secret_path)

    assert secret_path.read_bytes() == b"short"


def test_session_secret_does_not_return_ephemeral_key_after_write_failure(tmp_path, monkeypatch):
    secret_path = tmp_path / "session.key"

    def fail_sync(_file_descriptor):
        raise OSError("sync failed")

    monkeypatch.setattr(private_storage.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="sync failed"):
        session_module.load_or_create_secret(secret_path)

    assert not secret_path.exists()
    assert not list(tmp_path.glob(".session.key.*.tmp"))


def test_check_auth_uses_constant_time_comparison(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")

    assert auth_module.check_auth("scanner", "secret-pass") is True
    assert auth_module.check_auth("scanner", "wrong") is False
    assert auth_module.check_auth("scanner", None) is False
    assert auth_module.check_auth(None, "secret-pass") is False


def test_default_password_acknowledgement_requires_trusted_loopback(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "admin")
    monkeypatch.setenv("NMAPUI_PASSWORD", "nmapui123")
    monkeypatch.setenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "true")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.setenv("NMAPUI_HOST", "127.0.0.1")

    assert auth_module.auth_uses_insecure_defaults() is False

    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    assert auth_module.auth_uses_insecure_defaults() is True

    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.setenv("NMAPUI_HOST", "0.0.0.0")
    assert auth_module.auth_uses_insecure_defaults() is True


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
    assert "Secure" not in cookie_header


def test_login_rejects_foreign_origin_without_issuing_session(monkeypatch):
    configure_auth(monkeypatch)
    monkeypatch.delenv("NMAPUI_ALLOWED_ORIGINS", raising=False)
    app = build_session_app()
    response = app.test_client().post(
        "/login", base_url="http://localhost:9000",
        data={"username": "scanner", "password": "secret-pass"},
        headers={"Origin": "http://localhost:9999", "Sec-Fetch-Site": "same-site"},
    )
    assert response.status_code == 403
    assert session_module.SESSION_COOKIE not in response.headers.get("Set-Cookie", "")


def test_unicode_credentials_login_and_session_roundtrip(monkeypatch):
    configure_auth(monkeypatch, username="scannér", password="sécret-pass")
    app = build_session_app()
    client = app.test_client()
    response = client.post(
        "/login", data={"username": "scannér", "password": "sécret-pass"},
    )
    assert response.status_code == 302
    assert session_module.SESSION_COOKIE in response.headers.get("Set-Cookie", "")
    status = client.get("/api/session/status")
    assert status.status_code == 200
    assert status.get_json()["username"] == "scannér"


def test_login_marks_cookie_secure_when_configured(monkeypatch):
    configure_auth(monkeypatch)
    monkeypatch.setenv("NMAPUI_COOKIE_SECURE", "true")
    app = build_session_app()

    with app.test_client() as client:
        response = client.post(
            "/login",
            data={"username": "scanner", "password": "secret-pass"},
            headers={"Accept": "text/html"},
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )

    assert response.status_code == 302
    assert "Secure" in response.headers.get("Set-Cookie", "")


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


def test_loopback_ui_opens_without_credentials_by_default(monkeypatch):
    monkeypatch.delenv("NMAPUI_USERNAME", raising=False)
    monkeypatch.delenv("NMAPUI_PASSWORD", raising=False)
    monkeypatch.delenv("NMAPUI_TRUST_LOCAL_UI", raising=False)
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    app = build_session_app()
    headers = {"Host": "127.0.0.1:9000"}
    local = {"REMOTE_ADDR": "127.0.0.1"}

    with app.test_client() as client:
        login = client.get("/login", headers=headers, environ_overrides=local)
        status = client.get("/api/session/status", headers=headers, environ_overrides=local)
        socket_token = client.get("/api/socket-token", headers=headers, environ_overrides=local)

    assert login.status_code == 302
    assert login.location == "/"
    assert status.status_code == 200
    assert status.get_json()["local_trust"] is True
    assert socket_token.status_code == 200


def test_default_local_trust_does_not_trust_remote_peers(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.delenv("NMAPUI_TRUST_LOCAL_UI", raising=False)
    app = build_session_app()

    with app.test_client() as client:
        response = client.get(
            "/api/session/status",
            headers={"Host": "127.0.0.1:9000"},
            environ_overrides={"REMOTE_ADDR": "203.0.113.7"},
        )

    assert response.status_code == 401
    assert session_module.SESSION_COOKIE not in response.headers.get("Set-Cookie", "")


@pytest.mark.parametrize(
    "origin, fetch_site, expected_status",
    [
        ("http://127.0.0.1:9000", "same-origin", 200),
        ("http://localhost:9000", "same-origin", 200),
        ("http://localhost:9000", "cross-site", 401),
        ("http://localhost.evil.example", "same-origin", 401),
        ("http://127.0.0.1.evil.example", "same-origin", 401),
        ("http://evil.example/?next=localhost", "same-origin", 401),
        ("http://evil.example@localhost:9000", "same-origin", 401),
        ("null", "same-origin", 401),
        ("", "cross-site", 401),
    ],
)
def test_local_trust_requires_actual_loopback_origin(monkeypatch, origin, fetch_site, expected_status):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app = build_session_app()
    headers = {"Host": "127.0.0.1:9000", "Sec-Fetch-Site": fetch_site}
    if origin:
        headers["Origin"] = origin

    with app.test_client() as client:
        response = client.get(
            "/api/session/status",
            headers=headers,
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )

    assert response.status_code == expected_status


def test_ipv6_loopback_ui_origin_is_trusted(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app = build_session_app()

    with app.test_client() as client:
        response = client.get(
            "/api/session/status",
            headers={"Host": "[::1]:9000", "Origin": "http://[::1]:9000"},
            environ_overrides={"REMOTE_ADDR": "::1"},
        )

    assert response.status_code == 200


def test_local_trust_rejects_foreign_referer_without_origin(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app = build_session_app()

    with app.test_client() as client:
        foreign = client.get(
            "/api/session/status",
            headers={"Host": "127.0.0.1:9000", "Referer": "https://localhost.evil.example/page"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        local = client.get(
            "/api/session/status",
            headers={"Host": "127.0.0.1:9000", "Referer": "http://127.0.0.1:9000/page"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )

    assert foreign.status_code == 401
    assert local.status_code == 200


def test_session_cookie_authorizes_an_api_request(monkeypatch):
    """A signed cookie must satisfy require_auth without Basic credentials."""
    configure_auth(monkeypatch)
    # Deterministic key so we can mint a valid cookie directly.
    monkeypatch.setattr(auth_module, "_session_secret_cache", b"k" * 32, raising=False)
    app = build_session_app()

    cookie = session_module.issue_token(auth_module._session_signing_secret(), "scanner")

    with app.test_client() as client:
        client.set_cookie(session_module.SESSION_COOKIE, cookie)
        # A remote address that is not loopback forces the auth path.
        response = client.get(
            "/api/session/status",
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )

    assert response.status_code == 200
    assert response.get_json()["authenticated"] is True


def test_rotating_auth_credentials_revokes_existing_session(monkeypatch):
    configure_auth(monkeypatch)
    monkeypatch.setattr(auth_module, "_session_secret_cache", b"k" * 32, raising=False)
    app = build_session_app()

    with app.test_client() as client:
        login = client.post(
            "/login",
            data={"username": "scanner", "password": "secret-pass"},
            headers={"Accept": "text/html"},
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )
        before_rotation = client.get(
            "/api/session/status", environ_overrides={"REMOTE_ADDR": "10.1.2.3"}
        )

        monkeypatch.setenv("NMAPUI_PASSWORD", "rotated-secret")
        after_rotation = client.get(
            "/api/session/status", environ_overrides={"REMOTE_ADDR": "10.1.2.3"}
        )

    assert login.status_code == 302
    assert before_rotation.status_code == 200
    assert after_rotation.status_code == 401


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
    cookie = session_module.issue_token(auth_module._session_signing_secret(), "scanner")

    with app.test_client() as client:
        client.set_cookie(session_module.SESSION_COOKIE, cookie)
        response = client.get(
            "/api/socket-token",
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )

    assert response.status_code == 200
    assert response.get_json() == {"token": "token"}
