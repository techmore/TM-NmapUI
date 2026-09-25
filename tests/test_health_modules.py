from flask import Flask

from nmapui.handlers.routes import register_core_routes
from nmapui.settings import get_effective_scan_rules


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
