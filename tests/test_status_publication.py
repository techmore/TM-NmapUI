"""Real registry/publication races with owned thread barriers; no scanner workflows."""
import copy
import threading

import pytest

from nmapui.app_bindings import build_event_helpers
from nmapui.events import emit_job_status
from nmapui.jobs import ClientJobRegistry, ScanBroadcaster


class DelayedSocket:
    def __init__(self, delayed_status):
        self.delayed_status = delayed_status
        self.captured = threading.Event()
        self.release = threading.Event()
        self.deliveries = []
        self.newer_attempted = threading.Event()
        self.newer_thread = None
        self.handlers = {}

    def on(self, name):
        def register(function):
            self.handlers[name] = function
            return function
        return register

    def emit(self, name, payload=None, **kwargs):
        delayed = (name == "job_status" and payload["status"] == self.delayed_status
                   or name == "sync_state" and self.delayed_status == "bootstrap-idle" and not payload["isScanning"])
        if delayed and not self.captured.is_set():
            self.captured.set()
            assert self.release.wait(3), "test did not release owned publication"
        self.deliveries.append((name, copy.deepcopy(payload), kwargs))
        if threading.current_thread() is self.newer_thread:
            self.newer_attempted.set()


def publisher(kind, socket, registry, broadcaster=None):
    if kind == "helper":
        return build_event_helpers(socketio=socket, job_registry=registry, broadcaster=broadcaster)["emit_job_status"]
    return lambda sid, kind: emit_job_status(socket, registry, sid, kind)


def race(first, second, socket, mutate, registry):
    errors = []
    def run(fn):
        try:
            fn()
        except BaseException as error:
            errors.append(error)
    older = threading.Thread(target=run, args=(first,), daemon=True)
    newer_started = threading.Event()
    def publish_newer():
        newer_started.set()
        mutate()
        second()
    newer = threading.Thread(target=run, args=(publish_newer,), daemon=True)
    socket.newer_thread = newer
    lock = getattr(registry, "status_publication_lock", threading.RLock())

    class ObservedPublicationLock:
        def __enter__(self):
            if threading.current_thread() is newer:
                socket.newer_attempted.set()
            return lock.__enter__()

        def __exit__(self, *args):
            return lock.__exit__(*args)

    registry.status_publication_lock = ObservedPublicationLock()
    older.start()
    try:
        assert socket.captured.wait(2)
        newer.start()
        assert newer_started.wait(2)
        # Fixed code acknowledges attempting the occupied publication lock.
        # Unfixed code acknowledges actual newer delivery instead. Either is a
        # causal receipt, without a sleep/scheduler-opportunity assumption.
        assert socket.newer_attempted.wait(2)
    finally:
        socket.release.set()
        older.join(3)
        if newer.ident is not None:
            newer.join(3)
    assert not older.is_alive() and not newer.is_alive()
    assert not errors


@pytest.mark.parametrize("first_kind,second_kind", [("helper", "helper"), ("runtime", "helper"), ("helper", "runtime"), ("runtime", "runtime")])
def test_idle_capture_cannot_arrive_after_newer_running_publication(first_kind, second_kind):
    registry = ClientJobRegistry()
    socket = DelayedSocket("idle")
    first = publisher(first_kind, socket, registry)
    second = publisher(second_kind, socket, registry)
    race(lambda: first("owner", "scan"), lambda: second("owner", "scan"), socket,
         lambda: registry.start("owner", "scan", {"target": "owned-fixture"}), registry)
    assert [p["status"] for n, p, _ in socket.deliveries if n == "job_status"] == ["idle", "running"]
    assert registry.get("owner", "scan")["status"] == "running"


def test_cancelling_capture_cannot_arrive_after_completion_and_bridge_identity_survives():
    registry = ClientJobRegistry()
    broadcaster = ScanBroadcaster()
    broadcaster.register_client("owner")
    broadcaster.register_client("bridge")
    broadcaster.set_bridge_client("bridge")
    assert registry.start("owner", "scan", {"target": "owned-fixture"})
    source = registry.get("owner", "scan")["source_job_id"]
    broadcaster.start_job("owner", source_job_id=source)
    assert registry.cancel("owner", "scan")
    socket = DelayedSocket("cancelling")
    emit = publisher("helper", socket, registry, broadcaster)
    race(lambda: emit("owner", "scan"), lambda: emit("owner", "scan"), socket,
         lambda: registry.complete("owner", "scan", status="cancelled"), registry)
    assert [p["status"] for n, p, _ in socket.deliveries if n == "job_status"] == ["cancelling", "cancelled"]
    envelopes = [p for n, p, _ in socket.deliveries if n == "daedalus_event"]
    assert [p["payload"]["status"] for p in envelopes] == ["cancelling", "cancelled"]
    assert all(p["source_job_id"] == source and p["source_job_type"] == "scan" for p in envelopes)
    assert len({p["client_event_id"] for p in envelopes}) == 2


def test_completion_listener_can_publish_without_registry_lock_inversion():
    registry = ClientJobRegistry()
    assert registry.start("owner", "scan")
    assert registry.cancel("owner", "scan")
    socket = DelayedSocket("cancelling")
    emit = publisher("helper", socket, registry)
    registry.add_completion_listener(lambda sid, kind, job: emit(sid, kind))
    race(lambda: emit("owner", "scan"), lambda: None, socket,
         lambda: registry.complete("owner", "scan", status="cancelled"), registry)
    assert [payload["status"] for name, payload, _ in socket.deliveries if name == "job_status"] == ["cancelling", "cancelled"]


def handler_fixture(monkeypatch, socket, registry, broadcaster):
    from flask import Flask, request
    from types import SimpleNamespace
    import logging
    from nmapui.handlers.connections import register_connection_handlers
    from nmapui.handlers.history import register_history_handlers

    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    monkeypatch.delenv("NMAPUI_SOCKET_AUTH_DISABLED", raising=False)
    app = Flask(__name__)
    helpers = build_event_helpers(socketio=socket, job_registry=registry, broadcaster=broadcaster)
    register_connection_handlers(socket, {
        **helpers, "broadcaster": broadcaster, "job_registry": registry,
        "get_client_state": lambda sid=None: {"current_customer": {}, "network_key": {}, "last_scan_target": "owned-fixture"},
        "set_current_customer_state": lambda **kw: None,
        "set_last_scan_target_state": lambda **kw: None,
        "set_network_key_state": lambda **kw: None, "logger": logging.getLogger(__name__),
    })
    register_history_handlers(socket, {
        **helpers, "broadcaster": broadcaster, "job_registry": registry,
        "get_most_recent_scan_xml": None, "customer_fingerprinter": SimpleNamespace(customers={}),
        "scans_dir": None, "sanitize_customer_dir_name": None, "parse_scan_xml_for_assets": None,
        "get_versions": lambda: {}, "logger": logging.getLogger(__name__),
    })

    def call(name, auth=None):
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            request.sid = "observer"
            return socket.handlers[name](auth) if name == "connect" else socket.handlers[name]()
    return call, helpers["emit_job_status"]


@pytest.mark.parametrize("event", ["connect", "get_initial_data"])
def test_idle_bootstrap_cannot_arrive_after_live_running(monkeypatch, event):
    registry = ClientJobRegistry()
    broadcaster = ScanBroadcaster()
    broadcaster.register_client("observer")
    socket = DelayedSocket("bootstrap-idle")
    call, emit = handler_fixture(monkeypatch, socket, registry, broadcaster)

    def start():
        assert registry.start("owner", "scan", {"target": "owned-fixture"})
        broadcaster.start_job("owner", source_job_id=registry.get("owner", "scan")["source_job_id"])

    race(lambda: call(event), lambda: emit("owner", "scan"), socket, start, registry)
    observations = [(name, payload) for name, payload, kw in socket.deliveries if kw.get("to") == "observer" and name in {"sync_state", "job_status"}]
    assert observations[0][0] == "sync_state" and not observations[0][1]["isScanning"]
    assert observations[-1][0] == "job_status" and observations[-1][1]["status"] == "running"


def test_preferred_active_owner_snapshot_cannot_follow_newer_terminal(monkeypatch):
    registry = ClientJobRegistry()
    broadcaster = ScanBroadcaster()
    broadcaster.register_client("observer")
    assert registry.start("owner", "scan")
    broadcaster.start_job("owner", source_job_id=registry.get("owner", "scan")["source_job_id"])
    socket = DelayedSocket("running")
    call, emit = handler_fixture(monkeypatch, socket, registry, broadcaster)
    race(lambda: call("get_job_status"), lambda: emit("owner", "scan"), socket,
         lambda: registry.complete("owner", "scan", status="cancelled"), registry)
    statuses = [payload["status"] for name, payload, kw in socket.deliveries
                if name == "job_status" and payload["job_type"] == "scan" and kw["to"] == "observer"]
    assert statuses == ["running", "cancelled"]


@pytest.mark.parametrize("event", ["connect", "get_initial_data"])
@pytest.mark.parametrize("job_type", ["scan", "report"])
def test_bootstrap_replay_finishes_with_fresh_unpublished_pause(monkeypatch, event, job_type):
    registry = ClientJobRegistry()
    broadcaster = ScanBroadcaster()
    broadcaster.register_client("owner")
    broadcaster.register_client("observer")
    assert registry.start("owner", job_type)
    source = registry.get("owner", job_type)["source_job_id"]
    broadcaster.start_job("owner", job_type=job_type, source_job_id=source)
    setup = DelayedSocket(None)
    publisher("helper", setup, registry, broadcaster)("owner", job_type)
    original = broadcaster.get_bridge_replay_buffer("owner", job_type=job_type)
    # The real registry changed before its next publication; retained replay is
    # intentionally still the earlier unpaused state.
    registry.update("owner", job_type, paused=True, pause_requested=False)
    socket = DelayedSocket(None)
    call, _ = handler_fixture(monkeypatch, socket, registry, broadcaster)
    call(event)
    statuses = [payload for name, payload, kw in socket.deliveries if name == "job_status" and kw["to"] == "observer"]
    assert any(payload["paused"] is False for payload in statuses)
    assert statuses[-1]["paused"] is True and statuses[-1]["source_job_id"] == source
    assert broadcaster.get_bridge_replay_buffer("owner", job_type=job_type) == original


def test_bridge_connect_preserves_historical_envelopes_then_sends_current_status(monkeypatch):
    registry = ClientJobRegistry()
    broadcaster = ScanBroadcaster()
    broadcaster.register_client("owner")
    assert registry.start("owner", "scan")
    source = registry.get("owner", "scan")["source_job_id"]
    broadcaster.start_job("owner", source_job_id=source)
    publisher("helper", DelayedSocket(None), registry, broadcaster)("owner", "scan")
    original = broadcaster.get_bridge_replay_buffer("owner")
    registry.update("owner", "scan", paused=True)
    socket = DelayedSocket(None)
    call, _ = handler_fixture(monkeypatch, socket, registry, broadcaster)
    call("connect", {"daedalus_bridge": True})
    assert [payload for name, payload, _ in socket.deliveries if name == "daedalus_event"] == original
    last = [payload for name, payload, _ in socket.deliveries if name == "job_status"][-1]
    assert last["paused"] is True and last["source_job_id"] == source
