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
