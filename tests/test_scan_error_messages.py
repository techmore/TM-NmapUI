"""Rejected scan requests must reach the browser as a single, readable message."""

import base64
from types import SimpleNamespace

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.scan_jobs import register_scan_job_handlers
from nmapui.jobs import ClientJobRegistry
from nmapui.validation import validate_target


def _build_client(monkeypatch, validate=validate_target):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "test-password")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    app = Flask(__name__)
    socketio = SocketIO(app, test_mode=True)
    registry = ClientJobRegistry()
    monkeypatch.setattr(socketio, "start_background_task", lambda *args, **kwargs: None)
    register_scan_job_handlers(
        socketio,
        {
            "validate_target": validate,
            "rate_limiter": SimpleNamespace(can_scan=lambda *args: (True, None), record_scan=lambda *args: None),
            "job_registry": registry,
            "emit_job_status": lambda *args: None,
            "set_last_scan_target_state": lambda **kwargs: None,
            "start_scan_task": lambda *args: None,
            "generate_report_task": lambda *args: None,
            "get_client_state": lambda **kwargs: {"current_customer": {"id": "c", "name": "C"}},
        },
    )
    token = base64.b64encode(b"scanner:test-password").decode()
    client = socketio.test_client(app, headers={"Authorization": "Basic " + token})
    return client, registry


def _scan_errors(client):
    return [packet["args"][0] for packet in client.get_received() if packet["name"] == "scan_error"]


def test_invalid_target_error_is_not_double_prefixed(monkeypatch):
    client, registry = _build_client(monkeypatch)
    try:
        client.emit("start_quick_scan", {"target": "not a target; rm -rf /"})
        errors = _scan_errors(client)
        assert errors == ["Invalid target: not a target; rm -rf /"]
        assert registry.snapshot()["active_jobs"] == []
    finally:
        client.disconnect()


def test_validation_messages_without_prefix_gain_one(monkeypatch):
    client, _ = _build_client(monkeypatch, validate=lambda target: (False, "Target cannot be empty"))
    try:
        client.emit("start_quick_scan", {"target": ""})
        assert _scan_errors(client) == ["Invalid target: Target cannot be empty"]
    finally:
        client.disconnect()
