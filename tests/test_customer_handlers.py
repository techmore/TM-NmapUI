from pathlib import Path

import base64

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.customers import register_customer_handlers


def build_customer_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_customer_handlers(socketio, deps)
    return app, socketio


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


def test_assign_customer_updates_current_customer_and_persists_assignment(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}}
    saved = {"called": False}
    logger = Flask(__name__).logger

    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [{"id": "cust-1", "name": "Acme Customer"}],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: saved.__setitem__("called", True),
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("assign_customer", {"customer_id": "cust-1"})
    received = client.get_received()

    assert state["current_customer"] == {
        "id": "cust-1",
        "name": "Acme Customer",
        "confidence": 1.0,
        "manual_assignment": True,
    }
    assert saved["called"] is True
    assert any(event["name"] == "customer_assigned" for event in received)


def test_get_customer_info_auto_detects_when_session_is_unassigned(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "", "name": "Unknown Network", "confidence": 0.0}}
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
            "match_customer": lambda self, network_key: (
                {"id": "cust-2", "name": "Detected Customer", "metadata": {"isp": "Acme ISP"}},
                0.92,
            ),
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {"public_ip": "203.0.113.10"},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_customer_info")
    received = client.get_received()

    assert state["current_customer"] == {
        "id": "cust-2",
        "name": "Detected Customer",
        "confidence": 0.92,
        "metadata": {"isp": "Acme ISP"},
    }
    assert any(
        event["name"] == "customer_info"
        and event["args"] == [state["current_customer"]]
        for event in received
    )


def test_get_customer_info_supports_sid_scoped_network_key_provider(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "", "name": "Unknown Network", "confidence": 0.0}}
    observed = {}
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
            "match_customer": lambda self, network_key: (
                observed.setdefault("network_key", network_key),
                0.0,
            ),
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": lambda sid=None: {"public_ip": "203.0.113.77", "sid": sid},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_customer_info")

    assert observed["network_key"]["public_ip"] == "203.0.113.77"
    assert observed["network_key"]["sid"]


def test_update_customer_persists_public_ip_metadata(monkeypatch):
    configure_auth(monkeypatch)
    saved = {"called": False}
    logger = Flask(__name__).logger
    existing_customer = {
        "id": "cust-1",
        "name": "Acme Customer",
        "description": "Old description",
        "confidence": 0.7,
        "networks": {
            "public_ip": "dynamic",
            "public_ips": [],
            "private_ranges": [],
            "exit_ips": "dynamic",
            "gateway_pattern": "",
        },
        "fingerprints": [{"type": "direct", "hop_count": "2-10"}],
        "metadata": {"location": "Unknown"},
    }
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [existing_customer],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
            "get_customer_by_id": lambda self, customer_id: existing_customer if customer_id == "cust-1" else None,
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {},
            "get_current_customer": lambda: {"id": "cust-1", "name": "Acme Customer", "confidence": 1.0},
            "set_current_customer": lambda value: None,
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: saved.__setitem__("called", True),
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit(
        "update_customer",
        {
            "customer_id": "cust-1",
            "id": "cust-1",
            "name": "Acme HQ",
            "description": "Updated description",
            "public_ip": "203.0.113.10",
            "private_ranges": "192.168.1.0/24",
            "exit_ips": "1.1.1.1,8.8.8.8",
            "gateway_pattern": "192.168.1.1",
            "location": "NYC",
            "connection_type": "vpn",
            "hop_count": "3-5",
        },
    )
    received = client.get_received()

    assert saved["called"] is True
    assert existing_customer["name"] == "Acme HQ"
    assert existing_customer["networks"]["public_ip"] == "203.0.113.10"
    assert "203.0.113.10" in existing_customer["networks"]["public_ips"]
    assert existing_customer["metadata"]["location"] == "NYC"
    assert any(event["name"] == "customer_updated" for event in received)


def test_customer_handlers_reject_unauthorized_socket_client(monkeypatch):
    configure_auth(monkeypatch)
    state = {"current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0}}
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [{"id": "cust-1", "name": "Acme Customer"}],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {},
            "get_current_customer": lambda: state["current_customer"],
            "set_current_customer": lambda value: state.__setitem__("current_customer", value),
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app)
    client.emit("get_customers")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Unauthorized"}]
        for event in received
    )
    assert not any(event["name"] == "customers_list" for event in received)


def test_get_network_statistics_prefers_runtime_store_history(monkeypatch):
    configure_auth(monkeypatch)
    logger = Flask(__name__).logger
    customer_fingerprinter = type(
        "FingerprinterStub",
        (),
        {
            "customers": [],
            "unknown_customer": {"id": "unknown", "name": "Unknown Network"},
            "customer_traceroutes": {},
            "get_scan_history": lambda self, customer_id=None, limit=50: [
                {
                    "timestamp": "2026-03-14T12:00:00",
                    "customer_id": "cust-1",
                    "customer_name": "Acme",
                    "status": "completed",
                    "source": "runtime_store",
                },
                {
                    "timestamp": "2026-03-14T11:00:00",
                    "customer_id": "cust-1",
                    "customer_name": "Acme",
                    "status": "completed",
                    "source": "runtime_store",
                },
            ],
        },
    )()

    app, socketio = build_customer_app(
        {
            "get_customer_fingerprinter": lambda: customer_fingerprinter,
            "network_key": {},
            "get_current_customer": lambda: {"id": "cust-1", "name": "Acme", "confidence": 1.0},
            "set_current_customer": lambda value: None,
            "merge_customer_metadata": lambda customer, saved_customer: customer,
            "save_current_assignment": lambda: None,
            "save_customers_config": lambda: None,
            "normalize_scan_metadata_document": lambda value: value,
            "load_json_document": lambda path, default: default,
            "save_json_document": lambda path, value: None,
            "logger": logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_network_statistics")
    received = client.get_received()

    stats_event = next(event for event in received if event["name"] == "network_statistics")
    payload = stats_event["args"][0]
    assert payload["total_scans"] == 2
    assert payload["unique_customers"] == 1
    assert payload["most_common_customer"]["id"] == "cust-1"
    assert payload["most_common_customer"]["name"] == "Acme"


def test_resolve_report_path_confines_writes_to_the_scans_directory(tmp_path, monkeypatch):
    """assign_report_to_customer writes metadata.json; the path must be contained."""
    from nmapui import paths
    from nmapui.handlers.customers import _resolve_report_path

    monkeypatch.setattr(paths, "SCANS_DIR", tmp_path)

    inside = tmp_path / "Acme" / "2026-03-14" / "scan_010000_target"
    inside.mkdir(parents=True)
    (inside / "metadata.json").write_text("{}")

    outside = tmp_path.parent / "nmapui-outside-target"
    outside.mkdir(exist_ok=True)
    (outside / "metadata.json").write_text("{}")

    # Absolute and scans-relative forms of an in-tree path both resolve.
    assert _resolve_report_path(str(inside)) == inside.resolve()
    assert _resolve_report_path("Acme/2026-03-14/scan_010000_target") == inside.resolve()

    # Anything outside the scans directory is rejected.
    assert _resolve_report_path(str(outside)) is None
    assert _resolve_report_path("../nmapui-outside-target") is None
    assert _resolve_report_path("") is None
