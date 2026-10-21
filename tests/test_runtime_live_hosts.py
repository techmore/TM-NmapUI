from nmapui.runtime_live_hosts import latest_scan_hosts


class Store:
    def __init__(self, jobs, events):
        self.jobs, self.events = jobs, events

    def list_jobs(self, **kwargs):
        return self.jobs[: kwargs.get("limit", 50)]

    def list_job_events(self, **kwargs):
        return self.events


def test_no_store_or_jobs_is_empty():
    assert latest_scan_hosts(None) == {"scan": None, "hosts": []}
    assert latest_scan_hosts(Store([], []))["hosts"] == []


def test_lists_discovered_hosts_with_bounded_fields():
    job = {"job_id": "source-job:x", "job_type": "scan", "status": "running", "updated_at": "t",
           "payload": {"details": {"target": "10.0.0.0/24"}}}
    events = [{"event_name": "scan_results", "payload": [
        {"ip": "10.0.0.1", "hostname": "gw", "vendor": "V" * 500, "mac": "aa:bb", "status": "up"},
        {"hostname": "no-ip"},
    ]}]
    out = latest_scan_hosts(Store([job], events))
    assert out["scan"]["status"] == "running" and out["scan"]["host_count"] == 1
    assert out["hosts"][0]["ip"] == "10.0.0.1" and len(out["hosts"][0]["vendor"]) == 120
    assert out["hosts"][0]["open_ports"] is None


def test_saved_snapshot_fills_in_when_early_events_were_pruned():
    job = {"job_id": "source-job:x", "job_type": "scan", "status": "completed", "updated_at": "t", "payload": {}}

    class Pruned(Store):
        def get_runtime_snapshot(self, key):
            return {"job_id": "source-job:x", "hosts": [{"ip": "10.0.0.9", "hostname": "kept", "vendor": "V"}]}

    out = latest_scan_hosts(Pruned([job], []))
    assert out["hosts"][0]["hostname"] == "kept"


def test_store_keeps_discovered_hosts_after_event_pruning(tmp_path):
    from nmapui.runtime_db import create_runtime_state_store
    store = create_runtime_state_store(str(tmp_path / "r.sqlite3"))
    store.upsert_job(job_id="source-job:j", owner_sid="s", job_type="scan", status="running", payload={"details": {}})
    store.append_job_event(job_id="source-job:j", owner_sid="s", job_type="scan", event_name="scan_results",
                           payload=[{"ip": "10.0.0.1", "hostname": "gw"}], max_events=3)
    for i in range(10):
        store.append_job_event(job_id="source-job:j", owner_sid="s", job_type="scan", event_name="scan_feedback",
                               payload=str(i), max_events=3)
    assert not [e for e in store.list_job_events(job_id="source-job:j") if e["event_name"] == "scan_results"]
    out = latest_scan_hosts(store)
    assert [h["ip"] for h in out["hosts"]] == ["10.0.0.1"]
