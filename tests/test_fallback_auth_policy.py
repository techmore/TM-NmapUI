"""Exercise the fallback's shared credential policy through HTTP and Socket.IO."""

import base64

from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
import pytest

from nmapui import auth


@pytest.fixture
def guarded_app():
    app = Flask(__name__)
    socketio = SocketIO(app, async_mode="threading", test_mode=True)
    calls = []

    @app.get("/guarded")
    @auth.require_auth
    def guarded_http():
        calls.append("http")
        return jsonify(success=True)

    @socketio.on("guarded")
    @auth.require_socket_auth()
    def guarded_socket():
        calls.append("socket")
        emit("protected_result", {"success": True})

    return app, socketio, calls


def invoke(guarded_app, transport, username, password):
    app, socketio, calls = guarded_app
    headers = {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()}
    if transport == "http":
        response = app.test_client().get("/guarded", headers=headers, environ_overrides={"REMOTE_ADDR": "192.0.2.50"})
        return response.status_code
    client = socketio.test_client(app, headers=headers)
    try:
        client.emit("guarded")
        messages = client.get_received()
        if any(message["name"] == "protected_result" for message in messages):
            return 200
        errors = [message["args"][0]["error"] for message in messages if message["name"] == "auth_error"]
        assert errors == ["Authentication is not configured securely"]
        return 503
    finally:
        client.disconnect()


@pytest.mark.parametrize("transport", ["http", "socket"])
@pytest.mark.parametrize("username,password", [
    ("", "valid-password"), ("   ", "valid-password"), ("scanner", ""),
    ("scanner", " \t"), ("", ""), ("custom-user", auth.DEFAULT_AUTH_PASSWORD),
])
def test_insecure_configured_credentials_never_reach_protected_handlers(monkeypatch, guarded_app, transport, username, password):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    assert invoke(guarded_app, transport, username, password) == 503
    assert guarded_app[2] == []


@pytest.mark.parametrize("transport", ["http", "socket"])
@pytest.mark.parametrize("trusted,bind,allowed", [
    ("false", "127.0.0.1", False), ("true", "0.0.0.0", False),
    ("true", "", False), ("true", "   ", False),
    ("true", "example.invalid", False), ("true", "127.0.0.1", True),
    ("true", "[::1]", True), ("true", "localhost", True),
])
def test_explicit_default_acknowledgement_requires_trusted_loopback_binding(monkeypatch, guarded_app, transport, trusted, bind, allowed):
    monkeypatch.setenv("NMAPUI_USERNAME", "custom-user")
    monkeypatch.setenv("NMAPUI_PASSWORD", auth.DEFAULT_AUTH_PASSWORD)
    monkeypatch.setenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "true")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", trusted)
    monkeypatch.setenv("NMAPUI_HOST", bind)
    assert invoke(guarded_app, transport, "custom-user", auth.DEFAULT_AUTH_PASSWORD) == (200 if allowed else 503)
    assert guarded_app[2] == ([transport] if allowed else [])


@pytest.mark.parametrize("transport", ["http", "socket"])
def test_valid_unicode_credentials_still_authorize_http_and_socket(monkeypatch, guarded_app, transport):
    username, password = "scanner-雪", "private-contraseña-🔐"
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    assert invoke(guarded_app, transport, username, password) == 200
    assert guarded_app[2] == [transport]


def test_explicit_trusted_loopback_bypass_remains_available(monkeypatch, guarded_app):
    monkeypatch.setenv("NMAPUI_USERNAME", "")
    monkeypatch.setenv("NMAPUI_PASSWORD", "")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    response = guarded_app[0].test_client().get("/guarded")
    assert response.status_code == 200
    assert guarded_app[2] == ["http"]
