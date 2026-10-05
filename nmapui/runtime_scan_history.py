"""Public projections of persisted scanner jobs; no session or command secrets."""

import hashlib


def public_scan_id(job_id):
    return hashlib.sha256(str(job_id).encode()).hexdigest()


def scan_run_rows(store):
    if store is None or not hasattr(store, 'list_jobs'):
        return []
    rows = []
    for job in store.list_jobs(job_type='scan', limit=200):
        payload = job.get('payload') if isinstance(job.get('payload'), dict) else {}
        details = payload.get('details') if isinstance(payload.get('details'), dict) else {}
        rows.append({
            'record_type': 'scan_run', 'job_id': public_scan_id(job['job_id']),
            'path': 'runtime-job:' + public_scan_id(job['job_id']),
            'timestamp': job.get('created_at', ''),
            'updated_at': job.get('updated_at', ''),
            'target': str(details.get('target') or '')[:255],
            'customer_name': 'Scanner run', 'customer_id': '',
            'status': job.get('status', 'unknown'),
            'host_count': details.get('host_count'),
            'has_html': False, 'has_pdf': False, 'has_xml': False,
        })
    return rows


def scan_run_details(store, job_id):
    if store is None or not hasattr(store, 'list_jobs'):
        return None
    job = next((row for row in store.list_jobs(job_type='scan', limit=200) if public_scan_id(row['job_id']) == job_id), None)
    if not job:
        return None
    job_id = job['job_id']
    if job.get('job_type', 'scan') != 'scan':
        return None
    hosts = {}
    truncated = False
    events = store.list_job_events(job_id=job_id, limit=500)
    for event in events:
        if event.get('event_name') != 'deep_scan_results':
            continue
        data = event.get('payload')
        if not isinstance(data, list):
            continue
        truncated = truncated or len(data) > 256
        for host in data[:256]:
            if not isinstance(host, dict) or not isinstance(host.get('ip'), str):
                continue
            key = host['ip'][:255]
            if key not in hosts and len(hosts) >= 256:
                truncated = True
                continue
            ports = []
            reported_ports = host.get('ports') if isinstance(host.get('ports'), list) else []
            truncated = truncated or len(reported_ports) > 1024
            for port in reported_ports[:1024]:
                if isinstance(port, dict):
                    ports.append({k: str(port.get(k) or '')[:500] for k in ('port', 'protocol', 'state', 'service')})
            hosts[host['ip'][:255]] = {'ip': host['ip'][:255], 'ports': ports}
    return {'status': job.get('status'), 'hosts': list(hosts.values()),
            'evidence_scope': 'Saved deep scan events; discovery-only runs may have no port evidence.',
            'bounded': len(events) >= 500 or truncated}
