from flask import Flask

from nmapui.handlers.routes import register_core_routes
from nmapui import health
from nmapui.health import build_readiness_payload
from nmapui.settings import get_effective_scan_rules


def test_readiness_does_not_require_public_traceroute_on_isolated_network():
    payload, status_code = build_readiness_payload(
        startup_state={
            "startup_complete": True,
            "dependency_checks_skipped": False,
            "dependencies_ok": True,
            "traceroute_initialized": False,
            "errors": [],
        },
        app_version="v1",
        default_interface="eth0",
        auto_scan_thread_alive=True,
        tool_versions={"nmap": "7.95"},
    )

    assert status_code == 200
    assert payload["ready"] is True
    assert payload["startup"]["traceroute_initialized"] is False


def test_readiness_is_degraded_when_scheduler_thread_has_stopped():
    payload, status_code = build_readiness_payload(
        startup_state={"startup_complete": True, "dependencies_ok": True},
        app_version="v1",
        default_interface="eth0",
        auto_scan_thread_alive=False,
        tool_versions={"nmap": "7.95"},
    )

    assert status_code == 503
    assert payload["ready"] is False
    assert payload["auto_scan_thread_alive"] is False


def test_readiness_is_degraded_when_stale_job_recovery_failed():
    recovery = {"ok": False, "failed_jobs": 200, "listing_error": None}
    payload, status_code = build_readiness_payload(
        startup_state={
            "startup_complete": True,
            "dependencies_ok": True,
            "recovery": recovery,
        },
        app_version="v1",
        default_interface="eth0",
        auto_scan_thread_alive=True,
        tool_versions={"nmap": "7.95"},
    )

    assert status_code == 503
    assert payload["ready"] is False
    assert payload["startup"]["recovery"] == recovery


def test_readiness_reports_staged_release_identity(tmp_path, monkeypatch):
    (tmp_path / "release_id").write_text("b" * 32 + "\n", encoding="ascii")
    monkeypatch.setattr(health, "BASE_DIR", tmp_path)

    payload, status_code = build_readiness_payload(
        startup_state={"startup_complete": True, "dependencies_ok": True},
        app_version="v1",
        default_interface="eth0",
        auto_scan_thread_alive=True,
        tool_versions={},
    )

    assert status_code == 200
    assert payload["release_id"] == "b" * 32


def test_runtime_status_route_reports_active_jobs():
    app = Flask(__name__)

    class JobRegistryStub:
        def snapshot(self):
            return {
                "has_active_jobs": True,
                "active_jobs": [
                    {
                        "sid": "abc",
                        "job_type": "report",
                        "status": "running",
                        "details": {"message": "Generating report"},
                    }
                ],
                "jobs": [],
            }

    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"ok": True},
            "build_readiness_payload": lambda **kwargs: ({"ok": True}, 200),
            "get_app_version": lambda: "v1",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1"},
            "job_registry": JobRegistryStub(),
            "settings_state": {"target_profiles": [], "scan_rules": {"scan_only_mode": False, "excluded_targets": []}, "sync": {}},
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().get("/api/runtime/status")

    assert response.status_code == 200
    assert response.get_json() == {
        "has_active_jobs": True,
        "active_job_types": ["report"],
        "active_jobs": [
            {
                "sid": "abc",
                "job_type": "report",
                "status": "running",
                "details": {"message": "Generating report"},
            }
        ],
    }


def test_runtime_settings_summary_reports_settings_state(monkeypatch):
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "true")
    app = Flask(__name__)

    class RuntimeStoreStub:
        def count_report_artifacts(self):
            return 4

        def count_customer_scan_history(self):
            return 7

        def count_runtime_logs(self):
            return 12

    register_core_routes(
        app,
        {
            "build_liveness_payload": lambda **kwargs: {"ok": True},
            "build_readiness_payload": lambda **kwargs: ({"ok": True}, 200),
            "get_app_version": lambda: "v1",
            "get_default_interface_cached": lambda: "en0",
            "get_versions": lambda: {"app": "v1", "nmap": "7.95", "vulners": "runtime-only", "arp_scan": "1.10"},
            "job_registry": type("JobRegistryStub", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
            "runtime_store": RuntimeStoreStub(),
            "settings_state": {
                "target_profiles": [{"id": "1", "name": "HQ", "target": "192.168.1.0/24"}],
                "scan_rules": {"scan_only_mode": True, "excluded_targets": ["192.168.1.10"]},
                "sync": {
                    "google_drive": {"enabled": True},
                    "remote_sync": {"enabled": False},
                },
            },
            "startup_state": {"startup_complete": True},
            "get_auto_scan_thread": lambda: None,
        },
    )

    response = app.test_client().get("/api/runtime/settings-summary")

    assert response.status_code == 200
    assert response.get_json() == {
        "scan_only_mode": True,
        "excluded_targets_count": 1,
        "target_profiles_count": 1,
        "max_scan_minutes": 120,
        "reports_save_to_desktop": False,
        "google_drive_enabled": True,
        "remote_sync_enabled": False,
        "tool_versions": {
            "app": "v1",
            "nmap": "7.95",
            "vulners": "runtime-only",
            "arp_scan": "1.10",
        },
        "maintenance_backfill": {},
        "maintenance_retention": {},
        "automatic_retention": {},
        "persisted_counts": {
            "report_artifacts": 4,
            "customer_scan_history": 7,
            "runtime_logs": 12,
        },
    }


def test_effective_scan_rules_prefer_matching_target_profile():
    rules = get_effective_scan_rules(
        settings_state={
            "target_profiles": [
                {
                    "name": "HQ",
                    "target": "192.168.1.0/24",
                    "customer_id": "cust-1",
                    "scan_rules": {
                        "scan_only_mode": True,
                        "excluded_targets": ["192.168.1.50"],
                    },
                }
            ],
            "scan_rules": {
                "scan_only_mode": False,
                "excluded_targets": ["192.168.1.10"],
            },
        },
        target="192.168.1.0/24",
        customer_id="cust-1",
    )

    assert rules == {
        "scan_only_mode": True,
        "excluded_targets": ["192.168.1.50"],
        "max_scan_minutes": 120,
    }
