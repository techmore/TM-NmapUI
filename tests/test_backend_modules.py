from datetime import datetime
from pathlib import Path
import base64
import logging

from flask import Flask
from flask_socketio import SocketIO

from nmapui.auto_scan import (
    DEFAULT_AUTO_SCAN_CONFIG,
    build_auto_scan_status_payload,
    get_next_auto_scan_run,
    should_run_auto_scan,
    validate_auto_scan_config_update,
)
from nmapui.auto_scan_runtime import AUTO_SCAN_SID, execute_auto_scan
from nmapui.handlers.auto_scan import (
    acquire_auto_scan_scheduler_lock,
    register_auto_scan_handlers,
    start_auto_scan_thread,
)
from nmapui.jobs import ClientJobRegistry
from nmapui.paths import AUTO_SCAN_SCHEDULER_LOCK_FILE, resolve_scan_path
from nmapui.runtime import env_flag


def basic_auth_header(username="scanner", password="secret-pass"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def configure_auth(monkeypatch, username="scanner", password="secret-pass", allow_defaults=False):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    if allow_defaults:
        monkeypatch.setenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "true")
    else:
        monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def test_should_run_auto_scan_allows_same_day_window():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config.update({"enabled": True, "start_time": "09:00", "end_time": "17:00"})

    assert (
        should_run_auto_scan(
            config,
            now=datetime(2026, 3, 13, 10, 30),
            startup_at=datetime(2026, 3, 13, 9, 0),
            startup_grace_seconds=300,
        )
        is True
    )


def test_should_run_auto_scan_allows_cross_midnight_window():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config.update({"enabled": True, "start_time": "22:00", "end_time": "06:00"})

    assert (
        should_run_auto_scan(
            config,
            now=datetime(2026, 3, 14, 1, 15),
            startup_at=datetime(2026, 3, 13, 20, 0),
            startup_grace_seconds=300,
        )
        is True
    )


def test_should_run_auto_scan_respects_startup_grace_period():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config["enabled"] = True

    assert (
        should_run_auto_scan(
            config,
            now=datetime(2026, 3, 13, 1, 30),
            startup_at=datetime(2026, 3, 13, 1, 28),
            startup_grace_seconds=300,
        )
        is False
    )


def test_get_next_auto_scan_run_returns_today_before_window():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config.update({"enabled": True, "start_time": "09:00", "end_time": "17:00"})

    next_run = get_next_auto_scan_run(config, now=datetime(2026, 3, 14, 8, 15))

    assert next_run == datetime(2026, 3, 14, 9, 0)


def test_build_auto_scan_status_payload_marks_two_hour_warning_window():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    config.update({"enabled": True, "start_time": "09:00", "end_time": "17:00"})

    payload = build_auto_scan_status_payload(
        config,
        now=datetime(2026, 3, 14, 7, 30),
    )

    assert payload["next_run"] == "2026-03-14T09:00:00"
    assert payload["seconds_until_next_run"] == 5400
    assert payload["warning_active"] is True


def test_validate_auto_scan_config_rejects_invalid_socket_payload():
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)
    original = dict(config)

    is_valid, error = validate_auto_scan_config_update({"enabled": "yes"})

    assert is_valid is False
    assert error == "'enabled' must be a boolean"
    assert config == original


def test_http_auto_scan_update_rejects_invalid_payload(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)

    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": config,
            "save_auto_scan_config": lambda updated: None,
            "validate_auto_scan_config_update": validate_auto_scan_config_update,
            "logger": app.logger,
        },
    )

    client = app.test_client()
    response = client.post(
        "/api/auto_scan/update",
        json={"enabled": "yes"},
        headers=basic_auth_header(),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "success": False,
        "error": "'enabled' must be a boolean",
    }
    assert config == DEFAULT_AUTO_SCAN_CONFIG


def test_socket_auto_scan_update_rejects_invalid_payload(monkeypatch):
    configure_auth(monkeypatch)
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    config = dict(DEFAULT_AUTO_SCAN_CONFIG)

    register_auto_scan_handlers(
        app,
        socketio,
        {
            "auto_scan_config": config,
            "save_auto_scan_config": lambda updated: None,
            "validate_auto_scan_config_update": validate_auto_scan_config_update,
            "logger": app.logger,
        },
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("update_auto_scan", {"enabled": "yes"})
    received = client.get_received()

    assert any(
        event["name"] == "auto_scan_error"
        and event["args"] == [{"error": "'enabled' must be a boolean"}]
        for event in received
    )
    assert config == DEFAULT_AUTO_SCAN_CONFIG


def test_resolve_scan_path_rejects_traversal():
    assert resolve_scan_path("../outside") is None


def test_resolve_scan_path_accepts_nested_scan_path():
    resolved = resolve_scan_path("Customer/2026-03-13/scan_010000_target")

    assert isinstance(resolved, Path)
    assert "data/scans" in str(resolved)


def test_env_flag_parses_truthy_values(monkeypatch):
    monkeypatch.setenv("NMAPUI_TEST_FLAG", "yes")

    assert env_flag("NMAPUI_TEST_FLAG", default=False) is True


def test_client_job_registry_snapshot_reports_active_jobs():
    registry = ClientJobRegistry()
    registry.start("sid-1", "scan", {"message": "Scanning"})
    registry.complete("sid-2", "report", status="completed", details={"message": "Done"})

    snapshot = registry.snapshot()

    assert snapshot["has_active_jobs"] is True
    assert len(snapshot["active_jobs"]) == 1
    assert snapshot["active_jobs"][0]["sid"] == "sid-1"
    assert snapshot["active_jobs"][0]["job_type"] == "scan"
    assert snapshot["active_jobs"][0]["status"] == "running"
    assert snapshot["active_jobs"][0]["details"] == {"message": "Scanning"}
    assert snapshot["active_jobs"][0]["cancel_requested"] is False
    assert snapshot["active_jobs"][0]["disconnected"] is False
    assert {job["job_type"] for job in snapshot["jobs"]} == {"scan", "report"}


def test_acquire_auto_scan_scheduler_lock_uses_configured_lock_file(tmp_path):
    lock_file = tmp_path / "auto_scan_scheduler.lock"

    handle = acquire_auto_scan_scheduler_lock(lock_file=lock_file)

    try:
        assert handle is not None
        assert lock_file.exists()
        assert lock_file != AUTO_SCAN_SCHEDULER_LOCK_FILE
    finally:
        handle.close()


def test_start_auto_scan_thread_skips_start_when_lock_unavailable():
    class LoggerStub:
        def __init__(self):
            self.messages = []

        def info(self, message, *args):
            self.messages.append(message % args if args else message)

    thread_ref = {"thread": None}
    logger = LoggerStub()

    start_auto_scan_thread(
        thread_ref=thread_ref,
        socketio=type("SocketStub", (), {"sleep": lambda self, value: None})(),
        auto_scan_config=dict(DEFAULT_AUTO_SCAN_CONFIG),
        should_run_auto_scan=lambda *args, **kwargs: False,
        startup_at=datetime(2026, 3, 13, 0, 0),
        startup_grace_seconds=300,
        execute_auto_scan=lambda: None,
        logger=logger,
        acquire_scheduler_lock=lambda: None,
    )

    assert thread_ref["thread"] is None
    assert "another process owns the scheduler" in logger.messages[0]


def test_start_auto_scan_thread_starts_when_lock_acquired():
    class ThreadStub:
        def __init__(self, target, kwargs, daemon):
            self.target = target
            self.kwargs = kwargs
            self.daemon = daemon
            self.started = False

        def start(self):
            self.started = True

        def is_alive(self):
            return self.started

    created = {}

    def thread_factory(target, kwargs, daemon):
        created["thread"] = ThreadStub(target, kwargs, daemon)
        return created["thread"]

    app = Flask(__name__)
    logger = app.logger
    thread_ref = {"thread": None}

    from nmapui.handlers import auto_scan as auto_scan_handlers

    original_thread = auto_scan_handlers.threading.Thread
    auto_scan_handlers.threading.Thread = thread_factory
    try:
        start_auto_scan_thread(
            thread_ref=thread_ref,
            socketio=type("SocketStub", (), {"sleep": lambda self, value: None})(),
            auto_scan_config=dict(DEFAULT_AUTO_SCAN_CONFIG),
            should_run_auto_scan=lambda *args, **kwargs: False,
            startup_at=datetime(2026, 3, 13, 0, 0),
            startup_grace_seconds=300,
            execute_auto_scan=lambda: None,
            logger=logger,
            acquire_scheduler_lock=lambda: object(),
        )
    finally:
        auto_scan_handlers.threading.Thread = original_thread

    assert thread_ref["thread"] is created["thread"]
    assert thread_ref["lock_handle"] is not None
    assert created["thread"].daemon is True
    assert created["thread"].started is True


def build_auto_scan_deps(**overrides):
    """Build a complete execute_auto_scan dependency set for tests."""
    saved = {"started": [], "report_calls": [], "customer_state": [], "targets": []}

    class RateLimiterStub:
        def can_scan(self, sid):
            saved["can_scan_sid"] = sid
            return True, None

        def record_scan(self, sid):
            saved["record_scan_sid"] = sid

    class JobRegistryStub:
        def __init__(self, start_result=True):
            self.start_result = start_result
            self.completed = []

        def start(self, sid, job_type, details=None):
            saved["started"].append((sid, job_type, details))
            return self.start_result

        def complete(self, sid, job_type, status="completed", details=None):
            self.completed.append((sid, job_type, status))

    deps = {
        "auto_scan_config": dict(DEFAULT_AUTO_SCAN_CONFIG),
        "current_customer": {"id": "cust-1", "name": "Acme Customer (0.82)"},
        "get_last_scan_target": lambda: "192.168.1.0/24",
        "logger": logging.getLogger(__name__),
        "network_key": {"cidr": "10.0.0.0/24"},
        "rate_limiter": RateLimiterStub(),
        "safe_emit": lambda event, data=None: saved.setdefault("emitted", []).append((event, data)),
        "save_auto_scan_config": lambda config: saved.setdefault("config", dict(config)),
        "validate_target": lambda target: (True, None),
        "job_registry": JobRegistryStub(),
        "emit_job_status": lambda sid, job_type: saved.setdefault("job_status", []).append((sid, job_type)),
        "generate_report_task": lambda sid, payload: saved["report_calls"].append((sid, payload)),
        "set_current_customer_state": lambda value, sid=None: saved["customer_state"].append((value, sid)),
        "set_last_scan_target_state": lambda value, sid=None: saved["targets"].append((value, sid)),
    }
    deps.update(overrides)
    return deps, saved


def test_execute_auto_scan_enqueues_a_real_report_job():
    deps, saved = build_auto_scan_deps()

    execute_auto_scan(deps=deps)

    assert saved["started"] == [
        (
            AUTO_SCAN_SID,
            "report",
            {
                "target": "192.168.1.0/24",
                "customer_name": "Acme Customer",
                "chunked": False,
                "auto_scan": True,
            },
        )
    ]
    assert saved["report_calls"] == [
        (
            AUTO_SCAN_SID,
            {
                "target": "192.168.1.0/24",
                "customer_name": "Acme Customer",
                "chunked": False,
                "auto_scan": True,
            },
        )
    ]
    assert saved["job_status"] == [(AUTO_SCAN_SID, "report")]
    assert saved["can_scan_sid"] == AUTO_SCAN_SID
    assert saved["record_scan_sid"] == AUTO_SCAN_SID
    assert saved["config"]["last_run"] is not None
    # The broken fire-and-forget Socket.IO event must no longer be emitted.
    assert "trigger_generate_report" not in [event for event, _ in saved.get("emitted", [])]


def test_execute_auto_scan_skips_when_a_report_job_is_already_running():
    deps, saved = build_auto_scan_deps()
    deps["job_registry"] = type(
        "BusyJobRegistryStub",
        (),
        {"start": lambda self, sid, job_type, details=None: False},
    )()

    execute_auto_scan(deps=deps)

    assert saved["report_calls"] == []
    assert "config" not in saved


def test_execute_auto_scan_emits_validation_error_without_running():
    deps, saved = build_auto_scan_deps(
        get_last_scan_target=lambda: "not-a-target",
        network_key={"cidr": ""},
        validate_target=lambda target: (False, "Invalid target"),
    )

    execute_auto_scan(deps=deps)

    assert saved["emitted"] == [("auto_scan_error", {"error": "Invalid target"})]
    assert saved["started"] == []
    assert saved["report_calls"] == []
