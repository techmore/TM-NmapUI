"""Browser origin checks exercise actual protected fallback Settings handlers."""

import base64

from flask import Flask
from werkzeug.test import create_environ
from werkzeug.wrappers import Response
import pytest

from nmapui.handlers.settings import register_settings_routes


def basic_header():
    return {"Authorization": "Basic " + base64.b64encode("scanner:secret-pass".encode()).decode()}


@pytest.fixture
def origin_app(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOWED_ORIGINS", raising=False)
    calls = []
    app = Flask(__name__)
    register_settings_routes(app, {
        "settings_state": {}, "save_settings": lambda payload: payload,
        "validate_google_drive": lambda **kwargs: {}, "validate_remote_sync": lambda **kwargs: {},
        "get_google_drive_auth_status": lambda: calls.append("status") or {"status": "Private account state"},
        "build_google_drive_auth_url": lambda **kwargs: calls.append("auth-url") or {"success": True, "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?state=synthetic"},
        "exchange_google_drive_auth_code": lambda **kwargs: {},
        "ensure_google_drive_reports_folder": lambda: {}, "save_google_drive_credentials": lambda payload: {},
        "disconnect_google_drive": lambda: calls.append("disconnect") or {"success": True},
        "upload_latest_report_to_google_drive": lambda: {},
    })
    return app, calls


def test_lookalike_local_origin_cannot_read_private_drive_state(origin_app, monkeypatch):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app, calls = origin_app
    response = app.test_client().get("/api/settings/google-drive/status", base_url="http://localhost:9000",
                                    headers={"Origin": "https://localhost.attacker.invalid"})
    assert response.status_code == 401
    assert "Private account state" not in response.get_data(as_text=True)
    assert calls == []


def test_foreign_origin_cannot_disconnect_with_cached_basic_credentials(origin_app):
    app, calls = origin_app
    response = app.test_client().post("/api/settings/google-drive/disconnect", base_url="http://localhost:9000",
        headers={**basic_header(), "Origin": "http://localhost:9999", "Sec-Fetch-Site": "same-site"}, data={"submit": "1"})
    assert response.status_code == 403
    assert calls == []


@pytest.mark.parametrize("headers", [
    {"Origin": "null"}, {"Origin": ""}, {"Origin": "http://127.0.0.1.attacker.invalid"},
    {"Origin": "http://localhost:9000/path"}, {"Origin": "http://user@localhost:9000"},
    {"Origin": "http://localhost:0"}, {"Referer": "https://localhost.attacker.invalid/page"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_untrusted_browser_metadata_never_gets_local_bypass(origin_app, monkeypatch, headers):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app, calls = origin_app
    response = app.test_client().get("/api/settings/google-drive/status", base_url="http://localhost:9000", headers=headers)
    assert response.status_code == 401
    assert calls == []


@pytest.mark.parametrize("host", ["localhost:0", "localhost:not-a-port", "localhost@localhost", "localhost/path", ""])
def test_malformed_host_never_gets_local_bypass(origin_app, monkeypatch, host):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app, calls = origin_app
    # Pass raw WSGI input: newer Werkzeug rejects malformed Host headers
    # while constructing a test URL, before the auth guard can inspect them.
    environ = create_environ(path="/api/settings/google-drive/status", environ_base={"REMOTE_ADDR": "127.0.0.1"})
    environ["HTTP_HOST"] = host
    response = Response.from_app(app, environ)
    assert response.status_code == 401
    assert calls == []


@pytest.mark.parametrize("headers", [
    {"Origin": "null"}, {"Origin": ""}, {"Origin": "https://localhost.attacker.invalid"},
    {"Origin": "http://localhost:9999"}, {"Origin": "https://localhost:9000"},
    {"Origin": "http://localhost:9000/path"}, {"Origin": "http://user@localhost:9000"},
    {"Referer": "http://localhost:9999/form"}, {"Sec-Fetch-Site": "cross-site"},
])
def test_authenticated_mutations_reject_foreign_or_malformed_metadata(origin_app, headers):
    app, calls = origin_app
    response = app.test_client().post("/api/settings/google-drive/disconnect", base_url="http://localhost:9000",
                                     headers={**basic_header(), **headers})
    assert response.status_code == 403
    assert calls == []


@pytest.mark.parametrize("base_url,headers,allowed", [
    ("http://localhost:9000", {}, ""),
    ("http://localhost:9000", {"Origin": "http://localhost:9000"}, ""),
    ("http://localhost:9000", {"Referer": "http://localhost:9000/settings?tab=sync"}, ""),
    ("http://localhost:9000", {"Sec-Fetch-Site": "none"}, ""),
    ("http://[::1]:9000", {"Origin": "http://[::1]:9000"}, ""),
    ("https://scanner.example", {"Origin": "https://scanner.example"}, ""),
    ("http://localhost:9000", {"Origin": "https://ui.example", "Sec-Fetch-Site": "cross-site"}, "https://ui.example"),
])
def test_authenticated_cli_same_origin_and_explicit_frontends_remain_supported(origin_app, monkeypatch, base_url, headers, allowed):
    monkeypatch.setenv("NMAPUI_ALLOWED_ORIGINS", allowed)
    app, calls = origin_app
    response = app.test_client().post("/api/settings/google-drive/disconnect", base_url=base_url,
                                     headers={**basic_header(), **headers})
    assert response.status_code == 200
    assert calls == ["disconnect"]


@pytest.mark.parametrize("base_url,peer,headers", [
    ("http://localhost:9000", "127.0.0.1", {}),
    ("http://localhost:9000", "127.0.0.1", {"Origin": "http://localhost:9000"}),
    ("http://localhost:9000", "127.0.0.1", {"Referer": "http://localhost:9000/settings"}),
    ("http://[::1]:9000", "::1", {"Origin": "http://[::1]:9000"}),
    ("http://127.0.0.1:9000", "::ffff:127.0.0.1", {"Sec-Fetch-Site": "none"}),
])
def test_trusted_loopback_supports_valid_ipv4_ipv6_and_absent_browser_metadata(origin_app, monkeypatch, base_url, peer, headers):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app, calls = origin_app
    response = app.test_client().get("/api/settings/google-drive/status", base_url=base_url,
                                   headers=headers, environ_overrides={"REMOTE_ADDR": peer})
    assert response.status_code == 200
    assert calls == ["status"]


@pytest.mark.parametrize("authentication", ["basic", "local"])
@pytest.mark.parametrize("headers,local_denied", [
    ({"Origin": "http://localhost:9999"}, False),
    ({"Origin": "https://localhost.attacker.invalid"}, True),
    ({"Origin": "null"}, True),
    ({"Referer": "http://localhost:9999/form"}, False),
    ({"Sec-Fetch-Site": "cross-site"}, True),
])
def test_oauth_state_creation_get_rejects_untrusted_browser_metadata(origin_app, monkeypatch, authentication, headers, local_denied):
    app, calls = origin_app
    if authentication == "local":
        monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    else:
        headers = {**basic_header(), **headers}
    response = app.test_client().get("/api/settings/google-drive/auth-url", base_url="http://localhost:9000", headers=headers)
    assert response.status_code == (401 if authentication == "local" and local_denied else 403)
    assert calls == []


@pytest.mark.parametrize("authentication", ["basic", "local"])
@pytest.mark.parametrize("headers", [{}, {"Origin": "http://localhost:9000"}, {"Referer": "http://localhost:9000/settings"}])
def test_oauth_state_creation_get_accepts_cli_and_same_origin_browser(origin_app, monkeypatch, authentication, headers):
    app, calls = origin_app
    if authentication == "local":
        monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    else:
        headers = {**basic_header(), **headers}
    response = app.test_client().get("/api/settings/google-drive/auth-url", base_url="http://localhost:9000", headers=headers)
    assert response.status_code == 200
    assert calls == ["auth-url"]


def test_oauth_state_creation_get_accepts_explicit_authenticated_frontend(origin_app, monkeypatch):
    monkeypatch.setenv("NMAPUI_ALLOWED_ORIGINS", "https://ui.example")
    app, calls = origin_app
    response = app.test_client().get("/api/settings/google-drive/auth-url", base_url="http://localhost:9000",
                                    headers={**basic_header(), "Origin": "https://ui.example", "Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 200
    assert calls == ["auth-url"]
