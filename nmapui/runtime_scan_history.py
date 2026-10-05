"""Public projections of persisted scanner jobs; no session or command secrets."""

import hashlib
import ipaddress


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
    evidence_valid = True
    events = store.list_job_events(job_id=job_id, limit=500)
    for event in events:
        if event.get('event_name') != 'deep_scan_results':
            continue
        data = event.get('payload')
        if not isinstance(data, list):
            evidence_valid = False
            continue
        truncated = truncated or len(data) > 256
        for host in data[:256]:
            if not isinstance(host, dict) or not isinstance(host.get('ip'), str):
                evidence_valid = False
                continue
            try:
                ipaddress.ip_address(host['ip'])
            except ValueError:
                evidence_valid = False
                continue
            key = host['ip'][:255]
            if key not in hosts and len(hosts) >= 256:
                truncated = True
                continue
            ports = []
            reported_ports = host.get('ports') if isinstance(host.get('ports'), list) else []
            if not isinstance(host.get('ports'), list):
                evidence_valid = False
            truncated = truncated or len(reported_ports) > 1024
            for port in reported_ports[:1024]:
                if not isinstance(port, dict):
                    evidence_valid = False
                    continue
                projected = {k: str(port.get(k) or '')[:500] for k in ('port', 'protocol', 'state', 'service')}
                if any(len(str(port.get(k) or '')) > 500 for k in projected):
                    truncated = True
                if not projected['port'].isdigit() or not 1 <= int(projected['port']) <= 65535 or projected['protocol'] not in {'tcp', 'udp'} or projected['state'] not in {'open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'}:
                    evidence_valid = False
                ports.append(projected)
            hosts[host['ip'][:255]] = {'ip': host['ip'][:255], 'ports': ports}
    payload = job.get('payload') if isinstance(job.get('payload'), dict) else {}
    details = payload.get('details') if isinstance(payload.get('details'), dict) else {}
    return {'status': job.get('status'), 'target': str(details.get('target') or '').strip(),
            'evidence_valid': evidence_valid, 'hosts': list(hosts.values()),
            'evidence_scope': 'Saved deep scan events; discovery-only runs may have no port evidence.',
            'bounded': len(events) >= 500 or truncated}


def compare_scan_runs(store, base_id, current_id):
    if base_id == current_id:
        raise ValueError('Select two different saved runs.')
    baseline = scan_run_details(store, base_id)
    current = scan_run_details(store, current_id)
    if baseline is None or current is None:
        raise ValueError('A selected scan is outside the available history window.')
    if not baseline['target'] or baseline['target'] != current['target']:
        raise ValueError('Compare scans of the same target.')
    if any(run['status'] != 'completed' or run['bounded'] or not run['evidence_valid'] or not run['hosts'] for run in (baseline, current)):
        raise ValueError('Comparison requires completed runs with valid, untruncated saved deep-scan evidence.')
    old = {host['ip']: host for host in baseline['hosts']}
    new = {host['ip']: host for host in current['hosts']}
    changes = []
    for ip in sorted(old.keys() & new.keys()):
        def ports(host):
            return {(port['protocol'], port['port']): (port['state'], port['service']) for port in host['ports']}
        previous, latest = ports(old[ip]), ports(new[ip])
        for key in sorted(previous.keys() | latest.keys()):
            if previous.get(key) != latest.get(key):
                if len(changes) >= 5000:
                    raise ValueError('Comparison exceeds 5,000 observation changes; no partial comparison was produced.')
                changes.append({'ip': ip, 'protocol': key[0], 'port': key[1],
                                'previous': previous.get(key), 'current': latest.get(key)})
    return {'comparison_type': 'scan_observations', 'target': current['target'],
            'added_host_observations': sorted(new.keys() - old.keys()),
            'missing_host_observations': sorted(old.keys() - new.keys()),
            'port_observation_changes': changes,
            'scope': 'Differences in saved observations only. Scan coverage is unverified; missing hosts or ports do not prove removal or remediation.'}
