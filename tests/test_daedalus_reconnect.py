"""Offline Socket.IO/SQLite fixtures; never execute a scanner workflow."""
import logging
import base64

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.connections import register_connection_handlers
from nmapui.jobs import ClientJobRegistry, ScanBroadcaster
from nmapui.runtime_db import create_runtime_state_store
from nmapui.scan_runtime import make_broadcast_emit


def connection_fixture(monkeypatch, broadcaster, registry, store, emitted):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.setenv("NMAPUI_USERNAME", "fixture-user")
    monkeypatch.setenv("NMAPUI_PASSWORD", "fixture-password")
    app = Flask(__name__)
    socket = SocketIO(app, test_mode=True)
    register_connection_handlers(socket, {
        "broadcaster": broadcaster, "job_registry": registry, "runtime_store": store,
        "emit_to_client": lambda sid, name, payload=None: emitted.append((sid, name, payload)),
        "get_client_state": lambda sid=None: {"current_customer": {}, "network_key": {}, "last_scan_target": "fixture"},
        "set_current_customer_state": lambda **kwargs: None,
        "set_network_key_state": lambda **kwargs: None,
        "set_last_scan_target_state": lambda **kwargs: None,
        "logger": logging.getLogger("fixture"),
    })
    return app, socket


def bridge_client(app, socket):
    value = base64.b64encode(b"fixture-user:fixture-password").decode()
    return socket.test_client(app, auth={"daedalus_bridge": True}, headers={"Authorization": "Basic " + value})


def test_bridge_rejoins_disconnected_owner_without_completing_active_work(monkeypatch, tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.db")
    broadcaster = ScanBroadcaster()
    registry = ClientJobRegistry(runtime_store=store)
    broadcaster.register_client("owner")
    assert registry.start("owner", "scan", {"target": "fixture"})
    broadcaster.start_job("owner", source_job_id=registry.get("owner", "scan")["source_job_id"])
    emitted = []
    send = make_broadcast_emit(owner_sid="owner", broadcaster=broadcaster,
        emit_to_client=lambda sid, name, payload=None: emitted.append((sid, name, payload)), runtime_store=store)
    send("owner", "scan_feedback", "fixture progress")
    original = broadcaster.get_bridge_replay_buffer("owner")[0]
    registry.mark_disconnected("owner")
    broadcaster.unsubscribe("owner")
    app, socket = connection_fixture(monkeypatch, broadcaster, registry, store, emitted)
    client = bridge_client(app, socket)
    assert client.is_connected()
    assert registry.get("owner", "scan")["status"] == "running"
    assert broadcaster.find_active_owner() == "owner"
    replay = [payload for _, name, payload in emitted if name == "daedalus_event"]
    assert original in replay
    assert all(event == original for event in replay)
    send("owner", "scan_results", [{"ip": "fixture-host"}])
    assert any(name == "daedalus_event" and payload["event_name"] == "scan_results" for _, name, payload in emitted)
    client.disconnect()


def test_bridge_recovers_completed_persisted_event_with_original_identity(monkeypatch, tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.db")
    broadcaster = ScanBroadcaster()
    registry = ClientJobRegistry(runtime_store=store)
    broadcaster.register_client("owner")
    assert registry.start("owner", "scan")
    broadcaster.start_job("owner", source_job_id=registry.get("owner", "scan")["source_job_id"])
    send = make_broadcast_emit(owner_sid="owner", broadcaster=broadcaster,
        emit_to_client=lambda *args: None, runtime_store=store)
    send("owner", "scan_results", [{"ip": "fixture-host"}])
    original = broadcaster.get_bridge_replay_buffer("owner")[0]
    registry.complete("owner", "scan")
    broadcaster.end_job("owner")
    restored = create_runtime_state_store(tmp_path / "runtime.db")
    saved = restored.list_job_events(job_id=f"source-job:{original['source_job_id']}")[0]
    assert saved["payload"] == original["payload"]
    assert saved["source_event"] == original
    emitted = []
    app, socket = connection_fixture(monkeypatch, ScanBroadcaster(), ClientJobRegistry(runtime_store=restored), restored, emitted)
    first = bridge_client(app, socket)
    first.disconnect()
    second = bridge_client(app, socket)
    replay = [payload for _, name, payload in emitted if name == "daedalus_event"]
    assert replay == [original, original]
    second.disconnect()


def test_browser_payloads_and_replay_bound_are_preserved():
    broadcaster = ScanBroadcaster()
    broadcaster.MAX_BUFFER = 2
    broadcaster.register_client("browser")
    broadcaster.start_job("browser")
    emitted = []
    send = make_broadcast_emit(owner_sid="browser", broadcaster=broadcaster,
        emit_to_client=lambda sid, name, payload=None: emitted.append((sid, name, payload)))
    for number in range(3):
        send("browser", "scan_feedback", number)
    assert emitted == [("browser", "scan_feedback", number) for number in range(3)]
    assert broadcaster.get_replay_buffer("browser") == [("scan_feedback", 1), ("scan_feedback", 2)]
    assert len(broadcaster.get_bridge_replay_buffer("browser")) == 2


def test_memory_and_persisted_replay_have_byte_limits(tmp_path):
    broadcaster = ScanBroadcaster()
    broadcaster.MAX_BUFFER_BYTES = 1_000
    broadcaster.register_client("owner")
    broadcaster.start_job("owner")
    broadcaster.record("owner", "scan_results", "x" * 2_000)
    assert broadcaster.get_replay_buffer("owner") == []
    assert broadcaster.get_bridge_replay_buffer("owner") == []
    store = create_runtime_state_store(tmp_path / "runtime.db")
    for number in range(3):
        store.append_job_event(job_id="owner:scan", owner_sid="owner", job_type="scan",
            event_name="scan_feedback", payload={"number": number, "padding": "x" * 100}, max_bytes=300)
    saved = store.list_job_events(job_id="owner:scan")
    assert len(saved) <= 2
    assert saved[-1]["payload"]["number"] == 2


def test_finished_jobs_older_than_recovery_window_are_not_replayed(monkeypatch, tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.db")
    registry = ClientJobRegistry(runtime_store=store)
    registry.start("old-owner", "scan")
    registry.complete("old-owner", "scan")
    store.append_job_event(job_id="old-owner:scan", owner_sid="old-owner", job_type="scan", event_name="scan_results", payload=[])
    with store.connect() as db:
        db.execute("UPDATE jobs SET updated_at = '2000-01-01T00:00:00+00:00'")
        db.commit()
    emitted = []
    app, socket = connection_fixture(monkeypatch, ScanBroadcaster(), registry, store, emitted)
    client = bridge_client(app, socket)
    assert not [payload for _, name, payload in emitted if name == "daedalus_event"]
    client.disconnect()
