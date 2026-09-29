from pathlib import Path

from flask import Flask, request
from flask_socketio import SocketIO, emit

from nmapui.handlers.history import register_history_handlers
from nmapui.jobs import ClientJobRegistry


def basic_auth_header(username="scanner", password="secret-pass"):
    import base64

    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def configure_auth(monkeypatch, username="scanner", password="secret-pass"):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def build_history_app(job_registry, release_client_state=None, broadcaster=None):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)

    @socketio.on("whoami")
    def whoami_event():
        emit("whoami", {"sid": request.sid})

    def emit_job_status(sid, job_type):
        job = job_registry.get(sid, job_type)
        emit(
            "job_status",
            {
                "job_type": job_type,
                "status": job.get("status") if job else "idle",
                "details": job.get("details", {}) if job else {},
            },
        )

    def emit_to_client(sid, event, data=None):
        socketio.emit(event, data, to=sid)

    customer_fingerprinter = type("FingerprinterStub", (), {"customers": []})()

    register_history_handlers(
        socketio,
        {
            "get_most_recent_scan_xml": lambda *args, **kwargs: (None, None),
            "customer_fingerprinter": customer_fingerprinter,
            "scans_dir": Path("/tmp"),
            "sanitize_customer_dir_name": lambda value: value,
            "parse_scan_xml_for_assets": lambda *args, **kwargs: [],
            "get_versions": lambda: {"nmap": "7.95"},
            "emit_job_status": emit_job_status,
            "job_registry": job_registry,
            "emit_to_client": emit_to_client,
            "release_client_state": release_client_state,
            "broadcaster": broadcaster,
            "logger": app.logger,
        },
    )

    return app, socketio


def get_socket_sid(client):
    client.emit("whoami")
    for event in client.get_received():
        if event["name"] == "whoami":
            return event["args"][0]["sid"]
    raise AssertionError("whoami event did not return a socket session id")


def test_cancel_job_is_scoped_to_requesting_client(monkeypatch):
    configure_auth(monkeypatch)
    registry = ClientJobRegistry()
    app, socketio = build_history_app(registry)
    headers = basic_auth_header()
    client_a = socketio.test_client(app, headers=headers)
    client_b = socketio.test_client(app, headers=headers)
    sid_a = get_socket_sid(client_a)
    sid_b = get_socket_sid(client_b)

    assert registry.start(sid_a, "scan", {"target": "10.0.0.0/24"}) is True
    assert registry.start(sid_b, "scan", {"target": "10.0.1.0/24"}) is True

    client_a.emit("cancel_job", {"job_type": "scan"})

    assert registry.get(sid_a, "scan")["status"] == "cancelling"
    assert registry.get(sid_b, "scan")["status"] == "running"
    assert any(
        event["name"] == "job_cancelled"
        and event["args"] == [{"job_type": "scan", "message": "Cancelling scan job..."}]
        for event in client_a.get_received()
    )
    assert client_b.get_received() == []


def test_legacy_stop_scan_event_cancels_the_requesting_clients_scan(monkeypatch):
    configure_auth(monkeypatch)
    registry = ClientJobRegistry()
    app, socketio = build_history_app(registry)
    client = socketio.test_client(app, headers=basic_auth_header())
    sid = get_socket_sid(client)
    assert registry.start(sid, "scan", {"target": "10.0.0.0/24"}) is True

    client.emit("stop_scan")

    assert registry.get(sid, "scan")["status"] == "cancelling"
    assert any(
        event["name"] == "job_cancelled"
        and event["args"] == [{"job_type": "scan", "message": "Cancelling scan job..."}]
        for event in client.get_received()
    )


def test_get_job_status_reports_only_the_current_client_jobs(monkeypatch):
    configure_auth(monkeypatch)
    registry = ClientJobRegistry()
    app, socketio = build_history_app(registry)
    headers = basic_auth_header()
    client_a = socketio.test_client(app, headers=headers)
    client_b = socketio.test_client(app, headers=headers)
    sid_a = get_socket_sid(client_a)
    sid_b = get_socket_sid(client_b)

    registry.start(sid_a, "scan", {"target": "10.0.0.0/24"})
    registry.complete(sid_a, "report", status="completed", details={"path": "a"})
    registry.start(sid_b, "report", {"target": "10.0.1.0/24"})

    client_a.emit("get_job_status")
    client_b.emit("get_job_status")

    client_a_events = [event for event in client_a.get_received() if event["name"] == "job_status"]
    client_b_events = [event for event in client_b.get_received() if event["name"] == "job_status"]

    assert client_a_events == [
        {"name": "job_status", "args": [{"job_type": "scan", "status": "running", "details": {"target": "10.0.0.0/24"}}], "namespace": "/"},
        {"name": "job_status", "args": [{"job_type": "report", "status": "completed", "details": {"path": "a"}}], "namespace": "/"},
    ]
    assert client_b_events == [
        {"name": "job_status", "args": [{"job_type": "scan", "status": "idle", "details": {}}], "namespace": "/"},
        {"name": "job_status", "args": [{"job_type": "report", "status": "running", "details": {"target": "10.0.1.0/24"}}], "namespace": "/"},
    ]


def test_get_job_status_prefers_active_owner_state_for_new_tab(monkeypatch):
    configure_auth(monkeypatch)
    registry = ClientJobRegistry()
    owner_sid = {"value": None}

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            if job_type == "scan":
                return owner_sid["value"]
            return None

    app, socketio = build_history_app(registry, broadcaster=BroadcasterStub())
    headers = basic_auth_header()
    client_a = socketio.test_client(app, headers=headers)
    client_b = socketio.test_client(app, headers=headers)
    owner_sid["value"] = get_socket_sid(client_a)
    _sid_b = get_socket_sid(client_b)

    registry.start(owner_sid["value"], "scan", {"target": "10.0.0.0/24"})

    client_b.emit("get_job_status")

    client_b_events = [event for event in client_b.get_received() if event["name"] == "job_status"]

    assert client_b_events[0]["name"] == "job_status"
    assert client_b_events[0]["args"][0]["job_type"] == "scan"
    assert client_b_events[0]["args"][0]["status"] == "running"
    assert client_b_events[0]["args"][0]["details"] == {"target": "10.0.0.0/24"}
    assert client_b_events[1] == {
        "name": "job_status",
        "args": [{"job_type": "report", "status": "idle", "details": {}}],
        "namespace": "/",
    }


def test_disconnect_marks_only_that_clients_running_jobs(monkeypatch):
    configure_auth(monkeypatch)
    registry = ClientJobRegistry()
    app, socketio = build_history_app(registry)
    headers = basic_auth_header()
    client_a = socketio.test_client(app, headers=headers)
    client_b = socketio.test_client(app, headers=headers)
    sid_a = get_socket_sid(client_a)
    sid_b = get_socket_sid(client_b)

    registry.start(sid_a, "scan", {"target": "10.0.0.0/24"})
    registry.complete(sid_a, "report", status="completed", details={"path": "done"})
    registry.start(sid_b, "scan", {"target": "10.0.1.0/24"})

    client_a.disconnect()

    disconnected_scan = registry.get(sid_a, "scan")

    assert disconnected_scan["status"] == "running"
    assert disconnected_scan["disconnected"] is True
    assert registry.get(sid_a, "report") is None
    assert registry.get(sid_b, "scan")["status"] == "running"


def test_disconnect_releases_client_state_for_that_sid(monkeypatch):
    configure_auth(monkeypatch)
    registry = ClientJobRegistry()
    released = []
    app, socketio = build_history_app(
        registry,
        release_client_state=lambda sid: released.append(sid),
    )
    client = socketio.test_client(app, headers=basic_auth_header())
    sid = get_socket_sid(client)

    client.disconnect()

    assert released == [sid]


def test_history_handlers_reject_unauthenticated_socket_events(monkeypatch):
    configure_auth(monkeypatch)
    registry = ClientJobRegistry()
    app, socketio = build_history_app(registry)
    client = socketio.test_client(app)

    client.emit("get_job_status")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Unauthorized"}]
        for event in received
    )
    assert not any(event["name"] == "job_status" for event in received)
