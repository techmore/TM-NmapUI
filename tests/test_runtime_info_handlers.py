from flask import Flask
from flask_socketio import SocketIO

from nmapui.app_bindings import build_event_helpers
from nmapui.handlers.connections import register_connection_handlers
from nmapui.handlers.runtime_info import register_runtime_info_handlers
from nmapui.handlers.scan_jobs import register_scan_job_handlers
from nmapui.jobs import ClientJobRegistry, ScanBroadcaster


def basic_auth_header(username="scanner", password="secret-pass"):
    import base64

    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def configure_auth(monkeypatch, username="scanner", password="secret-pass"):
    monkeypatch.setenv("NMAPUI_USERNAME", username)
    monkeypatch.setenv("NMAPUI_PASSWORD", password)
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)


def build_runtime_info_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_runtime_info_handlers(socketio, deps)
    return app, socketio


def build_scan_jobs_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_scan_job_handlers(socketio, deps)
    return app, socketio


def build_live_scan_jobs_app():
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    broadcaster = ScanBroadcaster()
    job_registry = ClientJobRegistry()
    event_helpers = build_event_helpers(
        socketio=socketio,
        job_registry=job_registry,
        broadcaster=broadcaster,
        runtime_store=None,
    )
    observed = {"background_tasks": []}

    def record_background_task(fn, *args):
        observed["background_tasks"].append((getattr(fn, "__name__", str(fn)), args))
        return None

    socketio.start_background_task = record_background_task

    register_connection_handlers(
        socketio,
        {
            "auto_scan_config": None,
            "broadcaster": broadcaster,
            "emit_to_client": event_helpers["emit_to_client"],
            "get_client_state": lambda sid=None: {
                "current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0},
                "network_key": {"target": "1.1.1.1", "total_hops": 0, "private_hops": [], "public_hops": [], "exit_ip": None},
                "last_scan_target": None,
            },
            "job_registry": job_registry,
            "logger": app.logger,
            "set_current_customer_state": lambda *, value, sid=None: None,
            "set_last_scan_target_state": lambda *, value, sid=None: None,
            "set_network_key_state": lambda *, value, sid=None: None,
        },
    )
    register_scan_job_handlers(
        socketio,
        {
            "validate_target": lambda target: (True, None),
            "rate_limiter": type(
                "RateLimiterStub",
                (),
                {
                    "can_scan": lambda self, sid=None: (True, None),
                    "record_scan": lambda self, sid=None: None,
                },
            )(),
            "job_registry": job_registry,
            "emit_job_status": event_helpers["emit_job_status"],
            "set_last_scan_target_state": lambda *, value, sid=None: None,
            "start_scan_task": lambda sid, target: None,
            "generate_report_task": lambda sid, data: None,
            "generate_pdf_from_saved_task": lambda sid, data: None,
            "broadcaster": broadcaster,
        },
    )

    return app, socketio, observed


def build_connection_app(deps):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    register_connection_handlers(
        socketio,
        {
            "auto_scan_config": deps.get("auto_scan_config"),
            "broadcaster": deps["broadcaster"],
            "emit_to_client": deps["emit_to_client"],
            "get_client_state": deps.get(
                "get_client_state",
                lambda sid=None: {
                    "current_customer": {"id": "unknown", "name": "Unknown Network", "confidence": 0.0},
                    "network_key": {"target": "1.1.1.1", "total_hops": 0, "private_hops": [], "public_hops": [], "exit_ip": None},
                    "last_scan_target": None,
                },
            ),
            "job_registry": deps["job_registry"],
            "logger": deps["logger"],
            "runtime_store": deps.get("runtime_store"),
            "set_current_customer_state": deps.get(
                "set_current_customer_state",
                lambda *, value, sid=None: None,
            ),
            "set_last_scan_target_state": deps.get(
                "set_last_scan_target_state",
                lambda *, value, sid=None: None,
            ),
            "set_network_key_state": deps.get(
                "set_network_key_state",
                lambda *, value, sid=None: None,
            ),
        },
    )
    return app, socketio


def test_get_network_key_uses_keyword_client_state_lookup(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    def get_client_state_stub(*, sid=None):
        observed["sid"] = sid
        return {
            "network_key": {
                "total_hops": 1,
                "private_hops": [],
                "public_hops": [],
                "exit_ip": "1.1.1.1",
                "hops": [{"ip": "1.1.1.1", "is_private": False}],
            }
        }

    app, socketio = build_runtime_info_app(
        {
            "calculate_cidr": lambda ip, mask: "192.168.1.0/24",
            "get_client_state": get_client_state_stub,
            "get_default_interface_cached": lambda: "en0",
            "get_report_counts": lambda: {},
            "logger": Flask(__name__).logger,
            "netifaces": None,
            "requests": None,
            "run_traceroute": lambda target, sid=None: {},
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_network_key")
    received = client.get_received()

    assert observed["sid"]
    assert any(event["name"] == "network_key" for event in received)


def test_start_scan_persists_last_target_with_keyword_state_setter(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    class RateLimiterStub:
        def can_scan(self):
            return True, None

        def record_scan(self):
            observed["rate_recorded"] = True

    class JobRegistryStub:
        def start(self, sid, job_type, details):
            observed["job_start"] = (sid, job_type, details)
            return True

    app, socketio = build_scan_jobs_app(
        {
            "validate_target": lambda target: (True, None),
            "rate_limiter": RateLimiterStub(),
            "job_registry": JobRegistryStub(),
            "emit_job_status": lambda sid, job_type: observed.setdefault("job_status", []).append((sid, job_type)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("last_target", (sid, value)),
            "start_scan_task": lambda sid, target: None,
            "generate_report_task": lambda sid, data: None,
            "generate_pdf_from_saved_task": lambda sid, data: None,
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("start_scan", "192.168.1.0/24")

    assert observed["last_target"][0]
    assert observed["last_target"][1] == "192.168.1.0/24"
    assert observed["job_start"][1] == "scan"
    assert observed["rate_recorded"] is True


def test_start_scan_uses_sid_scoped_rate_limit_and_broadcaster(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    class RateLimiterStub:
        def can_scan(self, sid):
            observed["can_scan_sid"] = sid
            return True, None

        def record_scan(self, sid):
            observed["record_scan_sid"] = sid

    class JobRegistryStub:
        def start(self, sid, job_type, details):
            observed["job_start"] = (sid, job_type, details)
            return True

    class BroadcasterStub:
        def start_job(self, sid, job_type="scan"):
            observed["broadcaster"] = (sid, job_type)

    app, socketio = build_scan_jobs_app(
        {
            "validate_target": lambda target: (True, None),
            "rate_limiter": RateLimiterStub(),
            "job_registry": JobRegistryStub(),
            "emit_job_status": lambda sid, job_type: observed.setdefault("job_status", []).append((sid, job_type)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("last_target", (sid, value)),
            "start_scan_task": lambda sid, target: None,
            "generate_report_task": lambda sid, data: None,
            "generate_pdf_from_saved_task": lambda sid, data: None,
            "broadcaster": BroadcasterStub(),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("start_scan", "192.168.1.0/24")

    assert observed["can_scan_sid"]
    assert observed["record_scan_sid"] == observed["can_scan_sid"]
    assert observed["broadcaster"] == (observed["can_scan_sid"], "scan")


def test_runtime_info_handlers_reject_unauthenticated_socket_events(monkeypatch):
    configure_auth(monkeypatch)
    app, socketio = build_runtime_info_app(
        {
            "calculate_cidr": lambda ip, mask: "192.168.1.0/24",
            "get_client_state": lambda *, sid=None: {"network_key": {}},
            "get_default_interface_cached": lambda: "en0",
            "get_report_counts": lambda: {},
            "logger": Flask(__name__).logger,
            "netifaces": None,
            "requests": None,
            "run_traceroute": lambda target, sid=None: {},
        }
    )

    client = socketio.test_client(app)
    client.emit("get_network_key")
    received = client.get_received()

    assert any(
        event["name"] == "auth_error"
        and event["args"] == [{"error": "Unauthorized"}]
        for event in received
    )
    assert not any(event["name"] == "network_key" for event in received)


def test_get_local_ip_still_emits_cidr_when_public_ip_lookup_fails(monkeypatch):
    configure_auth(monkeypatch)

    class NetifacesStub:
        AF_INET = object()

        @staticmethod
        def ifaddresses(interface):
            return {
                NetifacesStub.AF_INET: [
                    {
                        "addr": "192.168.1.42",
                        "netmask": "255.255.255.0",
                    }
                ]
            }

    class RequestsStub:
        @staticmethod
        def get(url, timeout=None):
            raise RuntimeError("ipify unavailable")

    app, socketio = build_runtime_info_app(
        {
            "calculate_cidr": lambda ip, mask: "192.168.1.0/24",
            "get_client_state": lambda *, sid=None: {"network_key": {}},
            "get_default_interface_cached": lambda: "en0",
            "get_report_counts": lambda: {},
            "logger": Flask(__name__).logger,
            "netifaces": NetifacesStub,
            "requests": RequestsStub,
            "run_traceroute": lambda target, sid=None: {},
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("get_local_ip")
    received = client.get_received()

    local_ip_event = next(event for event in received if event["name"] == "local_ip")
    payload = local_ip_event["args"][0]

    assert payload["local_ip"] == "192.168.1.42"
    assert payload["subnet_mask"] == "255.255.255.0"
    assert payload["cidr"] == "192.168.1.0/24"
    assert payload["public_ip"] == ""


def test_generate_pdf_from_saved_rejects_invalid_payload(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    app, socketio = build_scan_jobs_app(
        {
            "validate_target": lambda target: (True, None),
            "rate_limiter": type("RateLimiterStub", (), {"can_scan": lambda self: (True, None), "record_scan": lambda self: None})(),
            "job_registry": type("JobRegistryStub", (), {"start": lambda self, sid, job_type, details: True})(),
            "emit_job_status": lambda sid, job_type: observed.setdefault("job_status", []).append((sid, job_type)),
            "set_last_scan_target_state": lambda *, value, sid=None: None,
            "start_scan_task": lambda sid, target: None,
            "generate_report_task": lambda sid, data: None,
            "generate_pdf_from_saved_task": lambda sid, data: observed.setdefault("pdf_calls", []).append((sid, data)),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())
    client.emit("generate_pdf_from_saved", "invalid")
    received = client.get_received()

    assert any(
        event["name"] == "report_error"
        and event["args"] == [{"error": "Invalid PDF request"}]
        for event in received
    )
    assert "pdf_calls" not in observed


def test_connect_replays_active_scan_events_to_new_tab(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            observed.setdefault("active_lookups", []).append(job_type)
            return "owner-sid" if job_type == "scan" else None

        def get_replay_buffer(self, owner_sid, job_type="scan"):
            observed["buffer_lookup"] = (owner_sid, job_type)
            return [("scan_feedback", "Scanning..."), ("scan_progress", {"pct": 50})]

        def subscribe(self, owner_sid, new_sid, job_type="scan"):
            observed["subscribe"] = (owner_sid, new_sid, job_type)
            return True

        def end_job(self, owner_sid, job_type="scan"):
            observed["ended_owner"] = (owner_sid, job_type)

    class JobRegistryStub:
        def get(self, sid, job_type):
            observed["job_lookup"] = (sid, job_type)
            return {"status": "running", "details": {"target": "192.168.1.0/24"}}

    emitted = []
    app, socketio = build_connection_app(
        {
            "auto_scan_config": {"enabled": True, "start_time": "01:00", "end_time": "03:00"},
            "broadcaster": BroadcasterStub(),
            "emit_to_client": lambda sid, event, data=None: emitted.append((sid, event, data)),
            "get_client_state": lambda sid=None: {
                "current_customer": {"id": "cust-123", "name": "Acme", "confidence": 0.9},
                "network_key": {"target": "10.0.0.0/24", "total_hops": 2, "private_hops": [], "public_hops": [], "exit_ip": "1.1.1.1"},
                "last_scan_target": "10.0.0.0/24",
            },
            "job_registry": JobRegistryStub(),
            "logger": Flask(__name__).logger,
            "set_current_customer_state": lambda *, value, sid=None: observed.setdefault("customer_state", []).append((sid, value)),
            "set_network_key_state": lambda *, value, sid=None: observed.setdefault("network_state", []).append((sid, value)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("target_state", []).append((sid, value)),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())

    assert client.is_connected()
    assert observed["job_lookup"] == ("owner-sid", "scan")
    assert observed["buffer_lookup"] == ("owner-sid", "scan")
    assert observed["subscribe"][0] == "owner-sid"
    assert observed["customer_state"][0][1]["id"] == "cust-123"
    assert observed["network_state"][0][1]["target"] == "10.0.0.0/24"
    assert observed["target_state"][0][1] == "10.0.0.0/24"
    bridge_events = {"sync_state", "initial_data"}
    contract_events = [e for e in emitted if e[1] not in bridge_events]
    assert [event for _, event, _ in contract_events[:4]] == [
        "customer_info",
        "network_key",
        "client_state_snapshot",
        "auto_scan_status",
    ]
    assert contract_events[4][1] == "job_status"
    assert contract_events[4][2]["job_type"] == "scan"
    assert [e for e in contract_events[5:]] == [
        (observed["subscribe"][1], "scan_feedback", "Scanning..."),
        (observed["subscribe"][1], "scan_progress", {"pct": 50}),
    ]


def test_start_scan_broadcasts_running_job_status_to_existing_open_tabs(monkeypatch):
    configure_auth(monkeypatch)
    app, socketio, observed = build_live_scan_jobs_app()
    client_a = socketio.test_client(app, headers=basic_auth_header())
    client_b = socketio.test_client(app, headers=basic_auth_header())

    client_a.get_received()
    client_b.get_received()

    client_a.emit("start_scan", "192.168.1.0/24")

    received_a = client_a.get_received()
    received_b = client_b.get_received()

    assert any(
        event["name"] == "job_status"
        and event["args"][0]["job_type"] == "scan"
        and event["args"][0]["status"] == "running"
        for event in received_a
    )
    assert any(
        event["name"] == "job_status"
        and event["args"][0]["job_type"] == "scan"
        and event["args"][0]["status"] == "running"
        for event in received_b
    )
    assert len(observed["background_tasks"]) == 1
    assert observed["background_tasks"][0][1][1] == "192.168.1.0/24"


def test_generate_report_broadcasts_running_job_status_to_existing_open_tabs(monkeypatch):
    configure_auth(monkeypatch)
    app, socketio, observed = build_live_scan_jobs_app()
    client_a = socketio.test_client(app, headers=basic_auth_header())
    client_b = socketio.test_client(app, headers=basic_auth_header())

    client_a.get_received()
    client_b.get_received()

    client_a.emit(
        "generate_report",
        {
            "target": "192.168.1.0/24",
            "customer_name": "Acme",
            "chunked": False,
        },
    )

    received_a = client_a.get_received()
    received_b = client_b.get_received()

    assert any(
        event["name"] == "job_status"
        and event["args"][0]["job_type"] == "report"
        and event["args"][0]["status"] == "running"
        and event["args"][0]["details"].get("chunked") is False
        for event in received_a
    )
    assert any(
        event["name"] == "job_status"
        and event["args"][0]["job_type"] == "report"
        and event["args"][0]["status"] == "running"
        and event["args"][0]["details"].get("chunked") is False
        for event in received_b
    )
    assert len(observed["background_tasks"]) == 1
    assert observed["background_tasks"][0][1][1] == {
        "target": "192.168.1.0/24",
        "customer_name": "Acme",
        "chunked": False,
    }


def test_connect_replays_active_report_events_to_new_tab(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            observed.setdefault("active_lookups", []).append(job_type)
            if job_type == "report":
                return "owner-sid"
            return None

        def get_replay_buffer(self, owner_sid, job_type="scan"):
            observed["buffer_lookup"] = (owner_sid, job_type)
            return [
                ("scan_feedback", "Generating PDF report..."),
                ("report_complete", {"path": "Acme/2026-03-14/scan_120000_10.0.0.0_24"}),
            ]

        def subscribe(self, owner_sid, new_sid, job_type="scan"):
            observed["subscribe"] = (owner_sid, new_sid, job_type)
            return True

        def end_job(self, owner_sid, job_type="scan"):
            observed["ended_owner"] = (owner_sid, job_type)

    class JobRegistryStub:
        def get(self, sid, job_type):
            observed["job_lookup"] = (sid, job_type)
            return {"status": "running", "details": {"target": "10.0.0.0/24"}}

    emitted = []
    app, socketio = build_connection_app(
        {
            "auto_scan_config": {"enabled": False},
            "broadcaster": BroadcasterStub(),
            "emit_to_client": lambda sid, event, data=None: emitted.append((sid, event, data)),
            "get_client_state": lambda sid=None: {
                "current_customer": {"id": "cust-123", "name": "Acme", "confidence": 0.9},
                "network_key": {"target": "10.0.0.0/24", "total_hops": 2, "private_hops": [], "public_hops": [], "exit_ip": "1.1.1.1"},
                "last_scan_target": "10.0.0.0/24",
            },
            "job_registry": JobRegistryStub(),
            "logger": Flask(__name__).logger,
            "set_current_customer_state": lambda *, value, sid=None: observed.setdefault("customer_state", []).append((sid, value)),
            "set_network_key_state": lambda *, value, sid=None: observed.setdefault("network_state", []).append((sid, value)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("target_state", []).append((sid, value)),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())

    assert client.is_connected()
    assert observed["active_lookups"] == ["scan", "report"]
    assert observed["job_lookup"] == ("owner-sid", "report")
    assert observed["buffer_lookup"] == ("owner-sid", "report")
    assert observed["subscribe"][2] == "report"
    bridge_events = {"sync_state", "initial_data"}
    contract_events = [e for e in emitted if e[1] not in bridge_events]
    assert contract_events[4][1] == "job_status"
    assert contract_events[4][2]["job_type"] == "report"
    assert [e for e in contract_events[5:]] == [
        (observed["subscribe"][1], "scan_feedback", "Generating PDF report..."),
        (
            observed["subscribe"][1],
            "report_complete",
            {"path": "Acme/2026-03-14/scan_120000_10.0.0.0_24"},
        ),
    ]


def test_connect_hydrates_new_tab_from_shared_snapshot_without_active_scan(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}
    emitted = []

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            return None

    app, socketio = build_connection_app(
        {
            "auto_scan_config": {"enabled": False},
            "broadcaster": BroadcasterStub(),
            "emit_to_client": lambda sid, event, data=None: emitted.append((sid, event, data)),
            "get_client_state": lambda sid=None: {
                "current_customer": {"id": "cust-999", "name": "Shared Customer", "confidence": 1.0},
                "network_key": {"target": "192.168.1.0/24", "total_hops": 3, "private_hops": [], "public_hops": [], "exit_ip": "8.8.8.8"},
                "last_scan_target": "192.168.1.0/24",
            },
            "job_registry": type("JobRegistryStub", (), {})(),
            "logger": Flask(__name__).logger,
            "set_current_customer_state": lambda *, value, sid=None: observed.setdefault("customer_state", []).append((sid, value)),
            "set_network_key_state": lambda *, value, sid=None: observed.setdefault("network_state", []).append((sid, value)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("target_state", []).append((sid, value)),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())

    assert client.is_connected()
    assert observed["customer_state"][0][1]["id"] == "cust-999"
    assert observed["network_state"][0][1]["target"] == "192.168.1.0/24"
    assert observed["target_state"][0][1] == "192.168.1.0/24"
    assert [event for _, event, _ in emitted][:4] == [
        "customer_info",
        "network_key",
        "client_state_snapshot",
        "auto_scan_status",
    ]
    # Legacy protocol bridge (#230): sync_state/initial_data follow the contract events.
    assert "sync_state" in [event for _, event, _ in emitted]
    assert "initial_data" in [event for _, event, _ in emitted]


def test_connect_hydrates_new_tab_from_sqlite_snapshot_without_active_scan(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}
    emitted = []

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            return None

    class RuntimeStoreStub:
        def get_runtime_snapshot(self, key):
            snapshots = {
                "current_customer": {"id": "cust-sqlite", "name": "Persisted Customer", "confidence": 1.0},
                "network_key": {
                    "target": "10.10.10.0/24",
                    "total_hops": 4,
                    "private_hops": [],
                    "public_hops": [],
                    "exit_ip": "8.8.4.4",
                },
                "last_scan_target": "10.10.10.0/24",
            }
            return snapshots.get(key)

    app, socketio = build_connection_app(
        {
            "auto_scan_config": {"enabled": False},
            "broadcaster": BroadcasterStub(),
            "emit_to_client": lambda sid, event, data=None: emitted.append((sid, event, data)),
            "get_client_state": lambda sid=None: {
                "current_customer": {"id": "cust-memory", "name": "Memory Customer", "confidence": 0.4},
                "network_key": {"target": "192.168.1.0/24", "total_hops": 3, "private_hops": [], "public_hops": [], "exit_ip": "1.1.1.1"},
                "last_scan_target": "192.168.1.0/24",
            },
            "job_registry": type("JobRegistryStub", (), {})(),
            "logger": Flask(__name__).logger,
            "runtime_store": RuntimeStoreStub(),
            "set_current_customer_state": lambda *, value, sid=None: observed.setdefault("customer_state", []).append((sid, value)),
            "set_network_key_state": lambda *, value, sid=None: observed.setdefault("network_state", []).append((sid, value)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("target_state", []).append((sid, value)),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())

    assert client.is_connected()
    assert observed["customer_state"][0][1]["id"] == "cust-sqlite"
    assert observed["network_state"][0][1]["target"] == "10.10.10.0/24"
    assert observed["target_state"][0][1] == "10.10.10.0/24"
    assert emitted[0][2]["id"] == "cust-sqlite"
    assert emitted[1][2]["target"] == "10.10.10.0/24"
    assert emitted[2][2] == {"last_scan_target": "10.10.10.0/24"}


def test_connect_normalizes_persisted_last_scan_target_snapshot_dict(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}
    emitted = []

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            return None

    class RuntimeStoreStub:
        def get_runtime_snapshot(self, key):
            snapshots = {
                "current_customer": {"id": "cust-sqlite", "name": "Persisted Customer", "confidence": 1.0},
                "network_key": {
                    "target": "10.10.10.0/24",
                    "total_hops": 4,
                    "private_hops": [],
                    "public_hops": [],
                    "exit_ip": "8.8.4.4",
                },
                "last_scan_target": {"value": "10.10.10.0/24"},
            }
            return snapshots.get(key)

    app, socketio = build_connection_app(
        {
            "auto_scan_config": {"enabled": False},
            "broadcaster": BroadcasterStub(),
            "emit_to_client": lambda sid, event, data=None: emitted.append((sid, event, data)),
            "get_client_state": lambda sid=None: {
                "current_customer": {"id": "cust-memory", "name": "Memory Customer", "confidence": 0.4},
                "network_key": {"target": "192.168.1.0/24", "total_hops": 3, "private_hops": [], "public_hops": [], "exit_ip": "1.1.1.1"},
                "last_scan_target": "192.168.1.0/24",
            },
            "job_registry": type("JobRegistryStub", (), {})(),
            "logger": Flask(__name__).logger,
            "runtime_store": RuntimeStoreStub(),
            "set_current_customer_state": lambda *, value, sid=None: observed.setdefault("customer_state", []).append((sid, value)),
            "set_network_key_state": lambda *, value, sid=None: observed.setdefault("network_state", []).append((sid, value)),
            "set_last_scan_target_state": lambda *, value, sid=None: observed.setdefault("target_state", []).append((sid, value)),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())

    assert client.is_connected()
    assert observed["target_state"][0][1] == "10.10.10.0/24"
    assert emitted[2][2] == {"last_scan_target": "10.10.10.0/24"}


def test_connect_emits_persisted_active_job_status_without_active_owner(monkeypatch):
    configure_auth(monkeypatch)
    emitted = []

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            return None

    class RuntimeStoreStub:
        def get_runtime_snapshot(self, key):
            return None

        def list_jobs(self, statuses=None, limit=50):
            return [
                {
                    "job_id": "owner-sid:report",
                    "owner_sid": "owner-sid",
                    "job_type": "report",
                    "status": "running",
                    "payload": {
                        "cancel_requested": False,
                        "details": {"target": "10.10.10.0/24", "customer_name": "Persisted"},
                        "started_at": "2026-03-14T12:00:00",
                        "finished_at": None,
                        "disconnected": True,
                    },
                    "created_at": "2026-03-14T12:00:00",
                    "updated_at": "2026-03-14T12:05:00",
                }
            ]

        def list_job_events(self, job_id, limit=200):
            return [
                {
                    "id": 1,
                    "job_id": job_id,
                    "owner_sid": "owner-sid",
                    "job_type": "report",
                    "event_name": "scan_feedback",
                    "payload": {"message": "Generating report...", "target": "10.10.10.0/24"},
                    "created_at": "2026-03-14T12:01:00",
                }
            ]

    app, socketio = build_connection_app(
        {
            "auto_scan_config": {"enabled": False},
            "broadcaster": BroadcasterStub(),
            "emit_to_client": lambda sid, event, data=None: emitted.append((sid, event, data)),
            "job_registry": type("JobRegistryStub", (), {})(),
            "logger": Flask(__name__).logger,
            "runtime_store": RuntimeStoreStub(),
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())

    assert client.is_connected()
    assert emitted[-2][1] == "job_status"
    assert emitted[-2][2]["job_type"] == "report"
    assert emitted[-2][2]["status"] == "running"
    assert emitted[-2][2]["details"]["target"] == "10.10.10.0/24"
    assert emitted[-1] == (
        emitted[-1][0],
        "scan_feedback",
        {"message": "Generating report...", "target": "10.10.10.0/24"},
    )


def test_connect_clears_stale_broadcast_slot_when_no_scan_job(monkeypatch):
    configure_auth(monkeypatch)
    observed = {}

    class BroadcasterStub:
        def find_active_owner(self, job_type="scan"):
            return "owner-sid" if job_type == "scan" else None

        def end_job(self, owner_sid, job_type="scan"):
            observed["ended_owner"] = (owner_sid, job_type)

    class JobRegistryStub:
        def get(self, sid, job_type):
            observed["job_lookup"] = (sid, job_type)
            return None

    app, socketio = build_connection_app(
        {
            "broadcaster": BroadcasterStub(),
            "emit_to_client": lambda sid, event, data=None: None,
            "job_registry": JobRegistryStub(),
            "logger": Flask(__name__).logger,
        }
    )

    client = socketio.test_client(app, headers=basic_auth_header())

    assert client.is_connected()
    assert observed["job_lookup"] == ("owner-sid", "scan")
    assert observed["ended_owner"] == ("owner-sid", "scan")
