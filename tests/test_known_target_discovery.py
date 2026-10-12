import json
import logging
import re
import subprocess
import pytest
from pathlib import Path
from types import SimpleNamespace

from nmapui.jobs import ClientJobRegistry
from nmapui.settings import DEFAULT_APP_SETTINGS, normalize_settings_document, get_effective_scan_rules, load_settings_state, save_settings_state
from nmapui.workflow_context import build_scan_workflow_context
from nmapui.workflows import start_scan_task, start_deep_scan
from nmapui import scanning


def test_known_target_default_and_strict_boolean():
    assert DEFAULT_APP_SETTINGS['scan_rules']['skip_host_discovery'] is False
    for value in [None, False, 'true', 'false', 1]:
        assert normalize_settings_document({'scan_rules': {'skip_host_discovery': value}})['scan_rules']['skip_host_discovery'] is False
    assert normalize_settings_document({'scan_rules': {'skip_host_discovery': True}})['scan_rules']['skip_host_discovery'] is True


def test_known_target_global_profile_persistence(tmp_path):
    document = {'scan_rules': {'skip_host_discovery': True}, 'target_profiles': [
        {'name': 'Known loopback', 'target': '127.0.0.1', 'scan_rules': {'skip_host_discovery': True}},
        {'name': 'Discover', 'target': '192.168.1.1', 'scan_rules': {'skip_host_discovery': False}},
        {'name': 'Inherit', 'target': '192.168.1.2'},
    ]}
    path = tmp_path / 'settings.json'
    save_settings_state(settings_path=path, save_json_document=lambda p, d: Path(p).write_text(json.dumps(d)), settings_state=document)
    saved = load_settings_state(settings_path=path, load_json_document=lambda p, default: json.loads(Path(p).read_text()))
    assert get_effective_scan_rules(settings_state=saved, target='127.0.0.1')['skip_host_discovery'] is True
    assert get_effective_scan_rules(settings_state=saved, target='192.168.1.1')['skip_host_discovery'] is False
    assert get_effective_scan_rules(settings_state=saved, target='192.168.1.2')['skip_host_discovery'] is True
    assert get_effective_scan_rules(settings_state=saved, target='192.168.2.1')['skip_host_discovery'] is True


@pytest.mark.parametrize("scan_only, exclusions", [(True, []), (False, ["192.168.1.9"])])
def test_known_target_workflow_passes_flag_through_both_phases(scan_only, exclusions):
    commands, deep_calls, events = [], [], []
    registry = ClientJobRegistry()
    registry.start('sid', 'scan')
    context = build_scan_workflow_context({
        'get_client_state': lambda **kwargs: {}, 'settings_state': {'scan_rules': {'skip_host_discovery': True, 'scan_only_mode': scan_only, 'excluded_targets': exclusions}},
        'ensure_job_not_cancelled': lambda *args: None,
        'idle_state_manager': SimpleNamespace(start_operation=lambda *args: None, end_operation=lambda *args: None),
        'update_job_progress': lambda *args, **kwargs: registry.update('sid', 'scan', details=kwargs.get('details', {})),
        'emit_to_client': lambda sid, event, data=None: events.append((event, data)), 'socketio_sleep': lambda *args: None,
        'run_cancellable_command': lambda argv, **kwargs: commands.append(argv) or SimpleNamespace(stdout='Nmap scan report for 127.0.0.1\nHost is up.\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n'),
        'run_arp_scan': lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('scan_only must skip ARP')),
        'identify_gateway_firewall_targets': lambda hosts: (hosts, []),
        'start_deep_scan': lambda *args, **kwargs: deep_calls.append(kwargs), 'job_registry': registry,
        'emit_job_status': lambda *args: None, 'logger': logging.getLogger('fixture'), 'vulners_script': Path('vulners.nse'), 'ip_sort_key': lambda ip: ip,
    })
    start_scan_task(context, 'sid', '127.0.0.1')
    assert commands == [["nmap", *(["--exclude", "192.168.1.9"] if exclusions else []), '-sn', '-Pn', '127.0.0.1']]
    if exclusions:
        assert any('skipping ARP enrichment' in str(data) for event, data in events if event == 'scan_feedback')
    assert deep_calls == [{'is_gateway_phase': False, 'skip_host_discovery': True}]
    assert registry.get('sid', 'scan')['details']['host_count'] == 1


@pytest.mark.parametrize("override, expected", [(True, True), (False, False)])
def test_per_scan_known_target_override_controls_discovery_and_deep_scan(override, expected):
    commands, deep_calls = [], []
    saved_settings = {'scan_rules': {'skip_host_discovery': not expected}}
    registry = ClientJobRegistry()
    registry.start('sid', 'scan')
    context = build_scan_workflow_context({
        'get_client_state': lambda **kwargs: {},
        'settings_state': saved_settings,
        'ensure_job_not_cancelled': lambda *args: None,
        'idle_state_manager': SimpleNamespace(start_operation=lambda *args: None, end_operation=lambda *args: None),
        'update_job_progress': lambda *args, **kwargs: registry.update('sid', 'scan', details=kwargs.get('details', {})),
        'emit_to_client': lambda *args: None,
        'socketio_sleep': lambda *args: None,
        'run_cancellable_command': lambda argv, **kwargs: commands.append(argv) or SimpleNamespace(stdout='Nmap scan report for 127.0.0.1\nHost is up.\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds\n'),
        'run_arp_scan': lambda *args, **kwargs: {},
        'identify_gateway_firewall_targets': lambda hosts: (hosts, hosts),
        'start_deep_scan': lambda *args, **kwargs: deep_calls.append(kwargs),
        'job_registry': registry, 'emit_job_status': lambda *args: None,
        'logger': logging.getLogger('fixture'), 'vulners_script': Path('unused'), 'ip_sort_key': lambda ip: ip,
    })

    start_scan_task(context, 'sid', '127.0.0.1', skip_host_discovery_override=override)

    assert ('-Pn' in commands[0]) is expected
    assert deep_calls == [
        {'is_gateway_phase': False, **({'skip_host_discovery': True} if expected else {})},
        {'is_gateway_phase': True, **({'skip_host_discovery': True} if expected else {})},
    ]
    assert registry.get('sid', 'scan')['details']['skip_host_discovery'] is expected
    assert saved_settings['scan_rules']['skip_host_discovery'] is not expected


def test_per_scan_override_must_be_a_strict_boolean():
    context = SimpleNamespace(settings_state={'scan_rules': {}}, get_client_state=lambda **kwargs: {})
    with pytest.raises(ValueError, match='must be a boolean'):
        start_scan_task(context, 'sid', '127.0.0.1', skip_host_discovery_override=1)


def test_known_target_deep_scan_keeps_product_pn(monkeypatch):
    monkeypatch.setenv('NMAPUI_ENABLE_VULNERS', 'false')
    commands = []
    context = SimpleNamespace(emit_to_client=lambda *args: None, socketio_sleep=lambda *args: None, ensure_job_not_cancelled=lambda *args: None, run_cancellable_command=lambda argv, **kwargs: commands.append(argv) or SimpleNamespace(stdout=''), vulners_script='unused', cve_pattern=re.compile('CVE-'), port_info_regex=re.compile('unused'))
    start_deep_scan(context, ['127.0.0.1'], 'sid', skip_host_discovery=True)
    assert len(commands) == 1
    assert commands[0][:5] == ['nmap', '-T3', '-sV', '-Pn', '-oX']
    assert commands[0][-1] == '127.0.0.1'


def test_known_target_xml_quick_scan_propagates_pn(monkeypatch, tmp_path):
    monkeypatch.setattr(scanning.privileged, 'privileged_prefix', lambda: [])
    monkeypatch.setattr(scanning.privileged, 'is_root', lambda: False)
    monkeypatch.setattr(scanning.privileged, 'sudo_available', lambda: False)
    commands = []
    scanning.run_nmap_with_xml_output('127.0.0.1', tmp_path / 'scan', scan_type='quick', scan_only_mode=True, skip_host_discovery=True, vulners_script='unused', stylesheet_pdf='unused', emit_to_client=lambda *args: None, socketio_emit=lambda *args: None, socketio_sleep=lambda *args: None, run_cancellable_command=lambda argv, **kwargs: commands.append(argv) or subprocess.CompletedProcess(argv, 0, '', ''))
    assert commands and commands[0][1:3] == ['-sT', '-Pn']
    assert commands[0].count('-Pn') == 1


def test_actual_bound_report_runner_accepts_default_and_explicit_flag(monkeypatch, tmp_path):
    import inspect
    from nmapui.app_task_bindings import build_task_bindings
    monkeypatch.setattr(scanning.privileged, 'privileged_prefix', lambda: [])
    monkeypatch.setattr(scanning.privileged, 'is_root', lambda: False)
    monkeypatch.setattr(scanning.privileged, 'sudo_available', lambda: False)
    commands = []
    kwargs = {name: None for name in inspect.signature(build_task_bindings).parameters}
    kwargs.update(emit_to_client=lambda *args: None, socketio=SimpleNamespace(emit=lambda *args: None, sleep=lambda *args: None), run_cancellable_command=lambda argv, **kw: commands.append(argv) or subprocess.CompletedProcess(argv, 0, '', ''), vulners_script='unused', stylesheet_pdf='unused')
    bound = build_task_bindings(**kwargs)['run_nmap_with_xml_output']
    bound('127.0.0.1', tmp_path / 'scan', scan_type='quick', scan_only_mode=True)
    bound('127.0.0.1', tmp_path / 'known', scan_type='quick', scan_only_mode=True, skip_host_discovery=True)
    assert '-Pn' not in commands[0]
    assert commands[1].count('-Pn') == 1


@pytest.mark.parametrize("protocol,state", [("tcp", "open"), ("udp", "open|filtered")])
def test_deep_results_preserve_literal_reported_protocol(protocol, state, monkeypatch):
    monkeypatch.setenv('NMAPUI_ENABLE_VULNERS', 'false')
    emitted = []
    # Use the shipped parser context rather than a replacement test regex.
    deps = {'get_client_state': lambda **kwargs: {}, 'ensure_job_not_cancelled': lambda *args: None,
            'idle_state_manager': object(), 'update_job_progress': lambda *args, **kwargs: None,
            'emit_to_client': lambda sid, event, data=None: emitted.append((event, data)),
            'socketio_sleep': lambda *args: None,
            'run_cancellable_command': lambda *args, **kwargs: SimpleNamespace(stdout=f"12345/{protocol} {state} example-service 1.0\n"),
            'run_arp_scan': lambda *args, **kwargs: {}, 'identify_gateway_firewall_targets': lambda hosts: (hosts, []),
            'start_deep_scan': lambda *args, **kwargs: None, 'job_registry': ClientJobRegistry(),
            'emit_job_status': lambda *args: None, 'logger': logging.getLogger('fixture'),
            'vulners_script': Path('unused'), 'ip_sort_key': lambda ip: ip}
    context = build_scan_workflow_context(deps)
    start_deep_scan(context, ['127.0.0.1'], 'sid')
    payload = next(data for event, data in emitted if event == 'deep_scan_results')
    assert payload[0]['ports'] == [{'port': '12345', 'protocol': protocol, 'state': state, 'service': 'example-service 1.0'}]
    quick_match = context.open_port_regex.match(f"12345/{protocol} {state} example-service")
    assert quick_match and quick_match.group(0).split('/', 1)[1].split()[0] == protocol
