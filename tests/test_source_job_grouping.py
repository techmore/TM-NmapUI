"""Offline run-identity fixtures; no endpoint scans or processes."""
import uuid

from nmapui.app_bindings import build_event_helpers
from nmapui.jobs import ClientJobRegistry, ScanBroadcaster
from nmapui.recovery import reconcile_interrupted_jobs
from nmapui.runtime_db import create_runtime_state_store
from nmapui.scan_runtime import make_broadcast_emit
from test_daedalus_reconnect import connection_fixture, bridge_client


def start(registry, broadcaster, job_type='scan'):
    assert registry.start('owner', job_type)
    run_id = registry.get('owner', job_type)['source_job_id']
    assert str(uuid.UUID(run_id)) == run_id
    broadcaster.start_job('owner', job_type=job_type, source_job_id=run_id)
    return run_id


def test_sequential_same_sid_runs_have_distinct_immutable_ids_and_rows(tmp_path):
    store = create_runtime_state_store(tmp_path / 'runtime.db')
    registry, broadcaster = ClientJobRegistry(runtime_store=store), ScanBroadcaster()
    broadcaster.register_client('owner')
    first = start(registry, broadcaster)
    emit_first = make_broadcast_emit(owner_sid='owner', broadcaster=broadcaster, emit_to_client=lambda *args: None, runtime_store=store)
    emit_first('owner', 'scan_results', [{'ip': '127.0.0.1'}])
    registry.update('owner', 'scan', source_job_id=str(uuid.uuid4()), source_job_type='report')
    assert registry.get('owner', 'scan')['source_job_id'] == first
    registry.complete('owner', 'scan')
    broadcaster.end_job('owner')
    second = start(registry, broadcaster)
    emit_second = make_broadcast_emit(owner_sid='owner', broadcaster=broadcaster, emit_to_client=lambda *args: None, runtime_store=store)
    emit_second('owner', 'scan_results', [])
    emit_first('owner', 'scan_feedback', 'Delayed event from first run')
    assert first != second
    assert len(store.list_jobs()) == 2
    first_events = store.list_job_events(job_id=f'source-job:{first}')
    second_events = store.list_job_events(job_id=f'source-job:{second}')
    assert len(first_events) == 2 and len(second_events) == 1
    assert {e['source_event']['source_job_id'] for e in first_events} == {first}
    assert {e['source_event']['source_job_id'] for e in second_events} == {second}
    assert len(broadcaster.get_bridge_replay_buffer('owner')) == 1


def test_job_status_uses_same_run_identity_as_results_for_scan_and_report(tmp_path):
    store = create_runtime_state_store(tmp_path / 'runtime.db')
    registry, broadcaster = ClientJobRegistry(runtime_store=store), ScanBroadcaster()
    broadcaster.register_client('bridge')
    broadcaster.set_bridge_client('bridge')
    emitted = []
    socket = type('Socket', (), {'emit': lambda self, event, data=None, to=None: emitted.append((to, event, data))})()
    helpers = build_event_helpers(socketio=socket, job_registry=registry, broadcaster=broadcaster, runtime_store=store)
    for job_type in ['scan', 'report']:
        run_id = start(registry, broadcaster, job_type)
        helpers['emit_job_status']('owner', job_type)
        registry.complete('owner', job_type)
        helpers['emit_job_status']('owner', job_type)
        envelopes = [payload for to, event, payload in emitted if to == 'bridge' and event == 'daedalus_event' and payload['source_job_id'] == run_id]
        assert [e['payload']['status'] for e in envelopes] == ['running', 'completed']
        assert {e['source_job_type'] for e in envelopes} == {job_type}
        assert len({e['client_event_id'] for e in envelopes}) == 2
        assert len(store.list_job_events(job_id=f'source-job:{run_id}')) == 2
        broadcaster.end_job('owner', job_type)


def test_restart_retains_metadata_and_replays_original_plus_interrupted_status(monkeypatch, tmp_path):
    path = tmp_path / 'runtime.db'
    store = create_runtime_state_store(path)
    registry, broadcaster = ClientJobRegistry(runtime_store=store), ScanBroadcaster()
    run_id = start(registry, broadcaster)
    emit = make_broadcast_emit(owner_sid='owner', broadcaster=broadcaster, emit_to_client=lambda *args: None, runtime_store=store)
    emit('owner', 'scan_results', [{'ip': '127.0.0.1'}])
    original = store.list_job_events(job_id=f'source-job:{run_id}')[0]['source_event']
    restarted = create_runtime_state_store(path)
    assert reconcile_interrupted_jobs(runtime_store=restarted) == [f'source-job:{run_id}']
    assert restarted.get_job(f'source-job:{run_id}')['payload']['source_job_id'] == run_id
    stored = restarted.list_job_events(job_id=f'source-job:{run_id}')
    assert stored[0]['source_event'] == original
    assert stored[1]['source_event']['source_job_id'] == run_id
    assert stored[1]['payload']['status'] == 'interrupted'
    emitted = []
    app, socket = connection_fixture(monkeypatch, ScanBroadcaster(), ClientJobRegistry(runtime_store=restarted), restarted, emitted)
    bridge = bridge_client(app, socket)
    replay = [payload for _, name, payload in emitted if name == 'daedalus_event']
    assert replay == [e['source_event'] for e in stored]
    bridge.disconnect()


def test_legacy_source_envelopes_are_not_backfilled_with_grouping(monkeypatch, tmp_path):
    store = create_runtime_state_store(tmp_path / 'runtime.db')
    source = {'client_event_id': str(uuid.uuid4()), 'occurred_at': '2026-09-29T12:00:00+00:00', 'event_name': 'scan_results', 'payload': []}
    store.upsert_job(job_id='legacy:scan', owner_sid='legacy', job_type='scan', status='completed', payload={})
    store.append_job_event(job_id='legacy:scan', owner_sid='legacy', job_type='scan', event_name='scan_results', payload=[], source_event=source)
    emitted = []
    app, socket = connection_fixture(monkeypatch, ScanBroadcaster(), ClientJobRegistry(runtime_store=store), store, emitted)
    bridge = bridge_client(app, socket)
    replay = [payload for _, name, payload in emitted if name == 'daedalus_event']
    assert replay == [source]
    assert 'source_job_id' not in replay[0]
    bridge.disconnect()
