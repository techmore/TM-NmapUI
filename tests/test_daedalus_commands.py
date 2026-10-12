"""Socket.IO/SQLite command receipts only; no scanner tasks or subprocesses run."""
import base64
import logging

import pytest
from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.connections import register_connection_handlers
from nmapui.handlers.history import register_history_handlers
from nmapui.handlers.scan_jobs import register_scan_job_handlers
from nmapui.handlers.updates import register_update_handlers
from nmapui.jobs import ClientJobRegistry, ScanBroadcaster
from nmapui.recovery import reconcile_interrupted_jobs
from nmapui.runtime_db import create_runtime_state_store


def fixture(monkeypatch, tmp_path, *, update_result=None, rate_result=(True, None)):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.setenv("NMAPUI_USERNAME", "fixture-user")
    monkeypatch.setenv("NMAPUI_PASSWORD", "fixture-password")
    app = Flask(__name__)
    socket = SocketIO(app, test_mode=True)
    store = create_runtime_state_store(tmp_path / "commands.db")
    broadcaster = ScanBroadcaster()
    registry = ClientJobRegistry(runtime_store=store)
    emitted, tasks = [], []
    send = lambda sid, event, payload=None: emitted.append((sid, event, payload))
    socket.start_background_task = lambda fn, *args: tasks.append(args)
    common = {"broadcaster": broadcaster, "job_registry": registry, "runtime_store": store, "emit_to_client": send, "logger": logging.getLogger("fixture"), "emit_job_status": lambda *args: None}
    register_connection_handlers(socket, {**common,
        "get_client_state": lambda sid=None: {"current_customer": {}, "network_key": {}, "last_scan_target": "fixture"},
        "set_current_customer_state": lambda **kwargs: None,
        "set_network_key_state": lambda **kwargs: None,
        "set_last_scan_target_state": lambda **kwargs: None})
    register_scan_job_handlers(socket, {**common,
        "validate_target": lambda target: (target != "reject", "fixture rejected"),
        "rate_limiter": type("Rate", (), {"can_scan": lambda self, sid: rate_result, "record_scan": lambda self, sid: None})(),
        "set_last_scan_target_state": lambda **kwargs: None,
        "start_scan_task": lambda *args: pytest.fail("No scan task may execute"),
        "generate_report_task": lambda *args: pytest.fail("No report task may execute")})
    register_history_handlers(socket, {**common,
        "get_most_recent_scan_xml": lambda *args, **kwargs: None,
        "customer_fingerprinter": None, "scans_dir": tmp_path,
        "sanitize_customer_dir_name": lambda x: x, "parse_scan_xml_for_assets": lambda *args: [], "get_versions": lambda: {}})
    update_check_calls = []
    def check_for_updates(*, operator_requested=False):
        update_check_calls.append(operator_requested)
        return update_result if update_result is not None else {"available": False}
    store.update_check_calls = update_check_calls
    register_update_handlers(socket, {**common,
        "check_for_updates": check_for_updates,
        "idle_state_manager": type("Idle", (), {"set_update_available": lambda self, *args: None})()})
    return app, socket, store, broadcaster, registry, emitted, tasks


COMMAND_NAMESPACE = "a" * 24


def test_rate_limited_command_reports_retry_time_without_running_scan(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(
        monkeypatch, tmp_path, rate_result=(False, "Cooldown active. Try again in 120s"))
    bridge = client(app, socket)
    bridge.emit("start_scan", {"target": "fixture", "daedalus_command_id": 999})
    terminal = receipts(emitted)[-1]
    assert terminal["status"] == "failed"
    assert "120s" in str(terminal)
    assert not tasks
    bridge.disconnect()


def client(app, socket, *, bridge=True, namespace=COMMAND_NAMESPACE):
    token = base64.b64encode(b"fixture-user:fixture-password").decode()
    instance = socket.test_client(app, auth={"daedalus_bridge": True, "command_namespace": namespace} if bridge else None, headers={"Authorization": "Basic " + token})
    original_emit = instance.emit
    def emit_with_namespace(event, data=None, *args, **kwargs):
        if bridge and isinstance(data, dict) and "daedalus_command_id" in data:
            data = {"daedalus_command_namespace": namespace, **data}
        return original_emit(event, data, *args, **kwargs)
    instance.emit = emit_with_namespace
    return instance


def receipts(emitted):
    return [data["payload"] for _, event, data in emitted if event == "daedalus_event" and data["event_name"] == "daedalus_command_result"]


def test_scan_completion_is_correlated_and_browser_payload_cannot_claim_command(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    bridge = client(app, socket)
    assert any(event == "daedalus_protocol" and data.get("command_results") is True for _, event, data in emitted)
    bridge.emit("start_scan", {"target": "fixture", "daedalus_command_id": 101})
    sid = tasks[0][0]
    assert registry.get(sid, "scan")["details"]["daedalus_command_id"] == 101
    # A separate browser scan completing cannot resolve command 101.
    assert registry.start("browser-unrelated", "scan")
    registry.complete("browser-unrelated", "scan")
    assert [item["status"] for item in receipts(emitted)] == ["accepted"]
    registry.complete(sid, "scan")
    assert [(item["command_id"], item["status"]) for item in receipts(emitted)] == [(101, "accepted"), (101, "succeeded")]
    browser = client(app, socket, bridge=False)
    browser.emit("start_scan", {"target": "fixture", "daedalus_command_id": 202})
    assert "daedalus_command_id" not in registry.get(tasks[1][0], "scan")["details"]
    registry.complete(tasks[1][0], "scan")
    assert not any(item["command_id"] == 202 for item in receipts(emitted))
    bridge.disconnect(); browser.disconnect()


def test_cancel_after_reconnect_resolves_only_selected_scan_commands(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    first = client(app, socket)
    first.emit("start_scan", {"target": "fixture", "daedalus_command_id": 301})
    owner = tasks[0][0]
    first.disconnect()
    second = client(app, socket)
    second.emit("cancel_job", {"job_type": "scan", "daedalus_command_id": 302})
    assert registry.get(owner, "scan")["status"] == "cancelling"
    registry.complete(owner, "scan", status="cancelled")
    assert any(item["command_id"] == 301 and item["status"] == "failed" for item in receipts(emitted))
    assert any(item["command_id"] == 302 and item["status"] == "succeeded" for item in receipts(emitted))
    terminal = store.list_job_events(job_id=f"daedalus-command:{COMMAND_NAMESPACE}:302")[-1]["source_event"]
    second.disconnect()
    third = client(app, socket)
    replay = [data for _, event, data in emitted if event == "daedalus_event"]
    assert replay.count(terminal) >= 2
    third.disconnect()


def test_rejected_and_duplicate_scan_commands_are_durable_without_running_tasks(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    bridge = client(app, socket)
    bridge.emit("start_scan", {"target": "reject", "daedalus_command_id": 401})
    assert [item["status"] for item in receipts(emitted)] == ["accepted", "failed"]
    saved = store.list_job_events(job_id=f"daedalus-command:{COMMAND_NAMESPACE}:401")[-1]["source_event"]
    bridge.emit("start_scan", {"target": "fixture", "daedalus_command_id": 401})
    assert tasks == []
    assert saved in [data for _, event, data in emitted if event == "daedalus_event"]
    bridge.disconnect()


@pytest.mark.parametrize("result,status", [({"available": False}, "succeeded"), ({"disabled": True, "available": False}, "failed"), ({"error": "fixture failure", "available": False}, "failed")])
def test_update_receipt_reports_actual_check_outcome(monkeypatch, tmp_path, result, status):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path, update_result=result)
    bridge = client(app, socket)
    bridge.emit("check_app_updates", {"daedalus_command_id": 501})
    assert [item["status"] for item in receipts(emitted)] == ["accepted", status]
    assert store.update_check_calls == [True]
    assert tasks == []
    bridge.disconnect()


def test_interrupted_command_replays_a_stable_failed_receipt(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    first = client(app, socket)
    first.emit("start_scan", {"target": "fixture", "daedalus_command_id": 601})
    first.disconnect()
    reconcile_interrupted_jobs(runtime_store=store)
    second = client(app, socket)
    terminal = store.list_job_events(job_id=f"daedalus-command:{COMMAND_NAMESPACE}:601")[-1]["source_event"]
    assert terminal["payload"]["status"] == "failed"
    second.disconnect()
    third = client(app, socket)
    assert terminal in [data for _, event, data in emitted if event == "daedalus_event"]
    third.disconnect()


def test_background_scheduling_failure_resolves_the_correlated_command(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    def cannot_schedule(*args):
        raise RuntimeError("fixture scheduling failure")
    socket.start_background_task = cannot_schedule
    bridge = client(app, socket)
    bridge.emit("start_scan", {"target": "fixture", "daedalus_command_id": 701})
    assert [item["status"] for item in receipts(emitted)] == ["accepted", "failed"]
    assert broadcaster.find_active_owner("scan") is None
    bridge.disconnect()


def test_cancellation_metadata_survives_owner_disconnect_until_terminal_receipt(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    first = client(app, socket)
    first.emit("start_scan", {"target": "fixture", "daedalus_command_id": 801})
    owner = tasks[0][0]
    first.emit("cancel_job", {"job_type": "scan", "daedalus_command_id": 802})
    first.disconnect()
    assert registry.get(owner, "scan")["status"] == "cancelling"
    second = client(app, socket)
    registry.complete(owner, "scan", status="cancelled")
    assert any(item["command_id"] == 802 and item["status"] == "succeeded" for item in receipts(emitted))
    second.disconnect()


def test_namespace_is_bound_to_bridge_session_and_isolates_same_numeric_ids(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    first = client(app, socket, namespace=COMMAND_NAMESPACE)
    second_namespace = "b" * 24
    second = client(app, socket, namespace=second_namespace)
    first.emit("start_scan", {"target": "fixture", "daedalus_command_id": 901})
    first_owner = tasks[0][0]
    second.emit("start_scan", {"target": "fixture", "daedalus_command_id": 901})
    second_owner = tasks[1][0]
    registry.complete(first_owner, "scan")
    first_terminal = store.list_job_events(job_id=f"daedalus-command:{COMMAND_NAMESPACE}:901")[-1]["source_event"]
    assert first_terminal["payload"]["command_namespace"] == COMMAND_NAMESPACE
    assert all(sid == first_owner for sid, event, data in emitted if event == "daedalus_event" and data == first_terminal)
    assert store.get_job(f"daedalus-command:{second_namespace}:901")["status"] == "running"
    registry.complete(second_owner, "scan")
    second.disconnect()
    reconnect_offset = len(emitted)
    replacement = client(app, socket, namespace=second_namespace)
    assert all(item["command_namespace"] == second_namespace for item in receipts(emitted[reconnect_offset:]))
    emitted.clear()
    replacement.emit("start_scan", {"target": "fixture", "daedalus_command_id": 901})
    assert len(tasks) == 2
    assert all(item["command_namespace"] == second_namespace for item in receipts(emitted))
    replacement.emit("start_scan", {"target": "fixture", "daedalus_command_id": 902, "daedalus_command_namespace": COMMAND_NAMESPACE})
    assert len(tasks) == 2
    assert store.get_job(f"daedalus-command:{COMMAND_NAMESPACE}:902") is None
    first.disconnect(); replacement.disconnect()


def test_bridge_cannot_cancel_another_namespace_owned_scan(monkeypatch, tmp_path):
    app, socket, store, broadcaster, registry, emitted, tasks = fixture(monkeypatch, tmp_path)
    first = client(app, socket)
    first.emit("start_scan", {"target": "fixture", "daedalus_command_id": 1001})
    second = client(app, socket, namespace="b" * 24)
    second.emit("cancel_job", {"job_type": "scan", "daedalus_command_id": 1002})
    assert registry.get(tasks[0][0], "scan")["status"] == "running"
    assert any(item["command_id"] == 1002 and item["status"] == "failed" for item in receipts(emitted))
    first.disconnect(); second.disconnect()
