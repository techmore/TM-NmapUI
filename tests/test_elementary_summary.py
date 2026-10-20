import importlib.machinery
import importlib.util
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "packaging/elementary/nmapui-summary"
loader = importlib.machinery.SourceFileLoader("nmapui_summary", str(path))
spec = importlib.util.spec_from_loader("nmapui_summary", loader)
summary = importlib.util.module_from_spec(spec)
loader.exec_module(summary)

HEALTH = {"app_version": "v1", "tool_versions": {"nmap": "7.94"}}


def test_unreachable_service_is_offline_and_unknown():
    out = summary.summarize(None, None, None, None)
    assert out["state"] == "offline" and out["hosts"] is None and out["alerts"] == []


def test_active_scan_reports_progress_and_hosts():
    runtime = {"active_jobs": [{"job_type": "scan", "status": "running",
                                "details": {"progress": 40, "message": "Service scan 2/5", "host_count": 5}}]}
    out = summary.summarize(HEALTH, runtime, {"history": []}, None)
    assert (out["state"], out["progress"], out["hosts"]) == ("scanning", 40, 5)


def test_cancelling_scan_is_stopping():
    runtime = {"active_jobs": [{"job_type": "scan", "status": "cancelling", "details": {}}]}
    assert summary.summarize(HEALTH, runtime, None, None)["state"] == "stopping"


def test_changes_and_critical_cves_raise_attention():
    history = {"history": [{"timestamp": "2026-10-19T10:00:00Z", "customer_name": "Penn", "host_count": 24,
                            "critical_cves": 2, "diff_summary": {"has_changes": True}}]}
    out = summary.summarize(HEALTH, {"active_jobs": []}, history, {"enabled": True, "next_run": "01:00"})
    assert out["state"] == "attention" and out["hosts"] == 24 and out["critical"] == 2
    assert out["monitor"] == "01:00" and len(out["alerts"]) == 2


def test_missing_nmap_is_flagged_not_hidden():
    out = summary.summarize({"tool_versions": {"nmap": "Not installed"}}, {"active_jobs": []}, {"history": []}, None)
    assert out["tools_missing"] == ["nmap"] and out["state"] == "attention"


def test_clean_idle_has_no_alerts_and_unknown_counts_stay_none():
    out = summary.summarize(HEALTH, {"active_jobs": []}, {"history": []}, None)
    assert out["state"] == "idle" and out["hosts"] is None and out["critical"] is None


def test_scan_details_parse_step_total_and_elapsed(monkeypatch):
    monkeypatch.setattr(summary, "network_info", lambda iface: {"interface": iface})
    runtime = {"active_jobs": [{"job_type": "scan", "status": "running", "started_at": "2026-10-19T21:34:17",
                                "details": {"target": "10.0.0.0/24", "phase": "service_scan", "progress": 60,
                                            "message": "Service scan 2/30: 10.0.0.8"}}]}
    out = summary.summarize({"default_interface": "wld0", "tool_versions": {"nmap": "7"}}, runtime, None, None)
    assert out["hosts"] == 30 and out["network"] == {"interface": "wld0"}
    assert out["scan"]["index"] == 2 and out["scan"]["total"] == 30 and out["scan"]["current"] == "10.0.0.8"
    assert out["scan"]["target"] == "10.0.0.0/24" and out["scan"]["elapsed_seconds"] >= 0


def test_network_info_without_interface_is_all_unknown(monkeypatch):
    monkeypatch.setattr(summary, "run_json", lambda command: None)
    assert summary.network_info(None)["address"] is None


def test_devices_are_sorted_numerically_and_fill_host_count():
    live = {"hosts": [{"ip": "10.0.0.20", "hostname": "b", "vendor": "V", "open_ports": 1},
                      {"ip": "10.0.0.3", "hostname": "", "vendor": "W", "open_ports": None}, {"hostname": "no-ip"}]}
    out = summary.summarize(HEALTH, {"active_jobs": []}, {"history": []}, None, live)
    assert [d["ip"] for d in out["devices"]] == ["10.0.0.3", "10.0.0.20"]
    assert out["hosts"] == 2 and out["devices"][1]["open_ports"] == 1
