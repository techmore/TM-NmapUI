import json
from nmapui.runtime_scan_history import scan_run_rows, scan_run_details
from nmapui.runtime_history import build_history_rows


class Store:
    def list_jobs(self, **kwargs):
        assert kwargs == {'job_type': 'scan', 'limit': 200}
        return [{'job_id': 'source-job:abc', 'status': 'completed', 'created_at': '2026-10-05T15:00:00Z',
                 'owner_sid': 'private-session', 'payload': {'details': {'target': '127.0.0.1', 'host_count': 1}, 'secret': 'private-token'}}]

    def list_report_artifacts(self):
        return []

    def get_job(self, job_id):
        return {'job_type': 'scan' if job_id == 'source-job:abc' else 'command', 'status': 'completed'}

    def list_job_events(self, **kwargs):
        assert kwargs == {'job_id': 'source-job:abc', 'limit': 500}
        return [{'event_name': 'deep_scan_results', 'payload': [{'ip': '127.0.0.1', 'ports': [{'port': '22', 'state': 'open', 'protocol': 'tcp', 'service': '<script>bad</script>', 'secret': 'private-token'}]}]},
                {'event_name': 'scan_raw_output', 'payload': 'private-token'}]


def test_scan_only_runs_appear_without_report_artifacts():
    rows = build_history_rows(runtime_store=Store(), scans_dir=None, load_json_document=None, normalize_scan_metadata_document=None, logger=None)
    assert len(rows) == 1
    assert rows[0]['record_type'] == 'scan_run'
    assert rows[0]['host_count'] == 1
    assert rows[0]['target'] == '127.0.0.1'
    assert not rows[0]['has_pdf']
    assert 'private-' not in json.dumps(rows)


def test_details_expose_port_evidence_without_session_or_raw_output():
    result = scan_run_details(Store(), 'source-job:abc')
    assert result['hosts'][0]['ports'][0]['port'] == '22'
    assert result['bounded'] is False
    assert 'private-' not in json.dumps(result)
    assert scan_run_details(Store(), 'command:1') is None


def test_malformed_payloads_are_ignored():
    class Broken(Store):
        def list_jobs(self, **kwargs):
            return [{'job_id': 'old', 'payload': [], 'status': 'failed'}]
        def list_job_events(self, **kwargs):
            return [{'event_name': 'deep_scan_results', 'payload': [{'ip': '127.0.0.1', 'ports': 'bad'}, None]}]
    assert scan_run_rows(Broken())[0]['target'] == ''
    assert scan_run_details(Broken(), 'source-job:abc')['hosts'][0]['ports'] == []


def test_saved_result_route_requires_auth_and_rejects_non_scan_jobs(monkeypatch):
    from flask import Flask
    from nmapui.handlers.routes import register_core_routes
    import base64
    monkeypatch.setenv('NMAPUI_USERNAME', 'scanner')
    monkeypatch.setenv('NMAPUI_PASSWORD', 'test-only-password')
    monkeypatch.setenv('NMAPUI_TRUST_LOCAL_UI', 'false')
    app = Flask(__name__)
    register_core_routes(app, {'runtime_store': Store(), 'build_liveness_payload': lambda **kw: {}, 'build_readiness_payload': lambda **kw: ({}, 200), 'get_app_version': lambda: 'test', 'get_default_interface_cached': lambda: 'en0', 'get_versions': lambda: {}, 'job_registry': None, 'settings_state': {}, 'startup_state': {}, 'get_auto_scan_thread': lambda: None})
    client = app.test_client()
    assert client.get('/api/runtime/scan-runs/source-job:abc').status_code != 200
    headers = {'Authorization': 'Basic ' + base64.b64encode(b'scanner:test-only-password').decode()}
    response = client.get('/api/runtime/scan-runs/source-job:abc', headers=headers)
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.json['hosts'][0]['ip'] == '127.0.0.1'
    assert client.get('/api/runtime/scan-runs/command:1', headers=headers).status_code == 404
