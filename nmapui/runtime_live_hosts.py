"""Compact device list for the latest scan, running or finished.

Read-only projection of persisted job events: discovered hosts from scan_results
plus open-port counts from completed service scans. Strings are bounded and no
session identifiers are exposed.
"""

from nmapui.runtime_scan_history import public_scan_id, scan_run_details

MAX_HOSTS = 512


def _text(value, limit=120):
    return str(value or "")[:limit]


def latest_scan_hosts(store):
    empty = {"scan": None, "hosts": []}
    if store is None or not hasattr(store, "list_jobs") or not hasattr(store, "list_job_events"):
        return empty
    jobs = store.list_jobs(job_type="scan", limit=1)
    if not jobs:
        return empty
    job = jobs[0]
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    discovered = []
    for event in store.list_job_events(job_id=job["job_id"], limit=2000):
        if event.get("event_name") == "scan_results" and isinstance(event.get("payload"), list):
            discovered = event["payload"]
    open_ports = {}
    run = scan_run_details(store, public_scan_id(job["job_id"])) or {}
    for host in run.get("hosts", []):
        if isinstance(host, dict) and host.get("ip"):
            open_ports[host["ip"]] = sum(1 for port in host.get("ports", []) if port.get("state") == "open")
    hosts = []
    for entry in discovered[:MAX_HOSTS]:
        if not isinstance(entry, dict) or not entry.get("ip"):
            continue
        ip = _text(entry["ip"], 64)
        hosts.append({
            "ip": ip, "hostname": _text(entry.get("hostname")), "vendor": _text(entry.get("vendor")),
            "mac": _text(entry.get("mac"), 32), "status": _text(entry.get("status") or "up", 16),
            "open_ports": open_ports.get(ip),
        })
    return {
        "scan": {"status": job.get("status"), "target": _text(details.get("target"), 255),
                 "updated_at": job.get("updated_at"), "host_count": len(hosts)},
        "hosts": hosts,
    }
