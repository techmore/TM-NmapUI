"""No provisioning, builds, sudo, chown or installer execution in these tests."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/ci/macos_installed_qualification.py'
spec = importlib.util.spec_from_file_location('mac_qualification', SCRIPT)
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


def valid_environment():
    return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS',
            'GITHUB_REPOSITORY': 'techmore/TM-NmapUI', 'GITHUB_REF': qualification.BRANCH,
            'NMAPUI_DISPOSABLE_MAC_QUALIFICATION': '1', 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_RUN_ID': '123', 'GITHUB_SHA': 'b' * 40, 'NMAPUI_QUALIFIED_SOURCE': 'a' * 40}


@pytest.mark.parametrize('key,value', [
    ('GITHUB_ACTIONS', ''), ('RUNNER_ENVIRONMENT', 'self-hosted'), ('RUNNER_OS', 'Linux'),
    ('GITHUB_REPOSITORY', 'fork/TM-NmapUI'), ('GITHUB_REF', 'refs/heads/main'),
    ('NMAPUI_DISPOSABLE_MAC_QUALIFICATION', ''), ('GITHUB_EVENT_NAME', 'pull_request'),
    ('GITHUB_RUN_ID', ''), ('GITHUB_SHA', 'main'), ('NMAPUI_QUALIFIED_SOURCE', 'main'),
])
def test_each_disposable_guard_is_mandatory(key, value):
    environment = valid_environment(); environment[key] = value
    with pytest.raises(RuntimeError):
        qualification.require_disposable_host(environment, 'Darwin', 'arm64', 0)


@pytest.mark.parametrize('system,machine,uid', [('Linux', 'arm64', 0), ('Darwin', 'x86_64', 0), ('Darwin', 'arm64', 501)])
def test_platform_architecture_and_privilege_cannot_be_overridden(system, machine, uid):
    with pytest.raises(RuntimeError):
        qualification.require_disposable_host(valid_environment(), system, machine, uid)


def test_guard_accepts_only_the_explicit_disposable_context():
    qualification.require_disposable_host(valid_environment(), 'Darwin', 'arm64', 0)


def test_main_refuses_before_any_command_or_filesystem_provision(monkeypatch):
    commands = []
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), '--source', '/nonexistent'])
    monkeypatch.setattr(qualification.subprocess, 'run', lambda *a, **kw: commands.append(a))
    monkeypatch.setattr(qualification, 'provision', lambda *a: pytest.fail('provision must not be reached'))
    monkeypatch.setenv('NMAPUI_DISPOSABLE_MAC_QUALIFICATION', '')
    with pytest.raises(RuntimeError):
        qualification.main()
    assert commands == []


@pytest.mark.parametrize('kind', ['directory', 'file', 'dangling-symlink'])
def test_existing_targets_refuse_without_mutation(tmp_path, kind):
    target = tmp_path / 'target'
    if kind == 'directory': target.mkdir()
    elif kind == 'file': target.write_text('preserve')
    else: target.symlink_to(tmp_path / 'absent')
    with pytest.raises(RuntimeError, match='pre-existing'):
        qualification.require_absent([target])
    assert target.is_symlink() if kind == 'dangling-symlink' else target.exists()


def test_preflight_refuses_existing_prefix_before_launchctl_or_git(monkeypatch, tmp_path):
    monkeypatch.setattr(qualification, 'ROOT', tmp_path)
    monkeypatch.setattr(qualification.subprocess, 'run', lambda *a, **kw: pytest.fail('must refuse before commands'))
    with pytest.raises(RuntimeError, match='pre-existing'):
        qualification.preflight(tmp_path)


@pytest.mark.parametrize('returncode,stderr', [(0, ''), (1, 'Operation not permitted'), (1, 'unrecognized failure')])
def test_preflight_does_not_confuse_loaded_or_uninspectable_service_with_absence(monkeypatch, returncode, stderr):
    monkeypatch.setattr(qualification, 'require_absent', lambda paths: None)
    monkeypatch.setattr(qualification.subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a, returncode, '', stderr))
    monkeypatch.setattr(qualification, 'protected_parent', lambda *a: pytest.fail('must refuse before later stages'))
    with pytest.raises(RuntimeError):
        qualification.preflight(Path('/unused'))


@pytest.mark.parametrize('member_type,name', [(tarfile.REGTYPE, '../escape'), (tarfile.SYMTYPE, 'source/link'), (tarfile.FIFOTYPE, 'source/fifo')])
def test_verified_source_extraction_still_rejects_unsafe_members(tmp_path, member_type, name):
    archive = tmp_path / 'source.tar'
    with tarfile.open(archive, 'w') as stream:
        member = tarfile.TarInfo(name); member.type = member_type
        if member_type == tarfile.REGTYPE:
            member.size = 1; stream.addfile(member, io.BytesIO(b'x'))
        else: stream.addfile(member)
    destination = tmp_path / 'output'; destination.mkdir()
    with pytest.raises(RuntimeError, match='Unsafe'):
        qualification.extract_verified(archive, destination, hashlib.sha256(archive.read_bytes()).hexdigest())
    assert list(destination.iterdir()) == []
    assert not (tmp_path / 'escape').exists()


def test_archive_checksum_mismatch_refuses_before_extraction(tmp_path):
    archive = tmp_path / 'corrupt.tar'; archive.write_bytes(b'not a tar')
    with pytest.raises(RuntimeError, match='SHA256'):
        qualification.extract_verified(archive, tmp_path, '0' * 64)


def test_protected_relative_wheel_dependencies_resolve_without_blanket_exemption(tmp_path):
    binary = tmp_path / 'site/package/module.so'
    library = tmp_path / 'site/package/.libs/crypto.dylib'
    library.parent.mkdir(parents=True); library.write_bytes(b'fixture')
    python = tmp_path / 'python/bin/python3.11'
    assert qualification.resolve_dependency('@loader_path/.libs/crypto.dylib', binary, python, []) == library
    assert qualification.resolve_dependency('@rpath/crypto.dylib', binary, python, ['@loader_path/.libs']) == library
    with pytest.raises(RuntimeError, match='Unresolved'):
        qualification.resolve_dependency('@rpath/missing.dylib', binary, python, ['@loader_path/.libs'])
    with pytest.raises(RuntimeError, match='nonabsolute'):
        qualification.resolve_dependency('libcrypto.dylib', binary, python, [])


def test_macho_parser_records_rpaths_and_dependency_paths():
    assert qualification.macho_rpaths('Load command 1\n cmd LC_RPATH\n cmdsize 48\n path @loader_path/.libs (offset 12)\n') == ['@loader_path/.libs']
    assert qualification.macho_dependencies('module.so:\n @loader_path/lib.dylib (compatibility version 0.0.0)\n /usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n') == ['@loader_path/lib.dylib', '/usr/lib/libSystem.B.dylib']


def test_plan_is_unprivileged_and_has_no_execution(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), '--plan'])
    monkeypatch.setattr(qualification.subprocess, 'run', lambda *a, **kw: pytest.fail('plan must not execute commands'))
    qualification.main()
    assert json.loads(capsys.readouterr().out)['root'] == '/Library/NmapUIQualification'


def test_workflow_is_exclusive_to_reviewed_branch_and_never_pull_requests():
    workflow = yaml.safe_load((ROOT / '.github/workflows/macos-installed-qualification.yml').read_text())
    triggers = workflow.get('on', workflow.get(True))
    assert set(triggers) == {'push', 'workflow_dispatch'}
    assert triggers['push']['branches'] == ['codex/macos-installed-qualification-2026-10-25']
    job = workflow['jobs']['installed-macos']
    assert job['runs-on'] == 'macos-15'
    assert 'github.repository ==' in job['if'] and qualification.BRANCH in job['if']
    assert 'inputs.confirm_disposable_install == true' in job['if']
    commands = '\n'.join(step.get('run', '') for step in job['steps'])
    assert 'sudo -n /usr/bin/env -i' in commands
    assert "RUNNER_ENVIRONMENT='${{ runner.environment }}'" in commands
    assert 'NMAPUI_DISPOSABLE_MAC_QUALIFICATION=1' in commands
    assert 'git -C runtime rev-parse HEAD' in commands
    assert workflow['permissions'] == {'contents': 'read'}


def api_chunks(xml):
    data = xml.encode()
    return [{'target': '127.0.0.1', 'sha256': hashlib.sha256(data).hexdigest(), 'byte_count': len(data),
             'chunk_count': 1, 'chunk_index': 0, 'xml': xml}]


VALID_XML = '<nmaprun><scaninfo type="syn"/><host><address addrtype="ipv4" addr="127.0.0.1"/></host><runstats><finished exit="success"/></runstats></nmaprun>'


def test_api_xml_receipt_requires_real_complete_loopback_syn_evidence():
    assert qualification.verified_api_xml(api_chunks(VALID_XML)) == VALID_XML.encode()


@pytest.mark.parametrize('xml', [VALID_XML.replace('127.0.0.1', '192.0.2.1'),
                                VALID_XML.replace('type="syn"', 'type="connect"'),
                                VALID_XML.replace('exit="success"', 'exit="error"'),
                                VALID_XML.replace('</host>', '</host><host><address addrtype="ipv4" addr="127.0.0.2"/></host>')])
def test_api_xml_cannot_claim_another_target_technique_or_failed_scan(xml):
    with pytest.raises(RuntimeError):
        qualification.verified_api_xml(api_chunks(xml))


@pytest.mark.parametrize('mutation', ['digest', 'length', 'missing', 'duplicate', 'mixed', 'target'])
def test_api_xml_chunk_integrity_cannot_be_masked(mutation):
    chunks = api_chunks(VALID_XML)
    if mutation == 'digest': chunks[0]['sha256'] = '0' * 64
    if mutation == 'length': chunks[0]['byte_count'] += 1
    if mutation == 'missing': chunks[0]['chunk_count'] = 2
    if mutation == 'duplicate': chunks += [dict(chunks[0])]
    if mutation == 'mixed': chunks[0]['chunk_index'] = 1
    if mutation == 'target': chunks[0]['target'] = '192.0.2.1'
    with pytest.raises(RuntimeError):
        qualification.verified_api_xml(chunks)


def test_macho_audit_reads_load_commands_and_does_not_load_library_install_id():
    commands = '''Load command 0
          cmd LC_ID_DYLIB
      cmdsize 64
         name @rpath/private.dylib (offset 24)
Load command 1
          cmd LC_LOAD_DYLIB
      cmdsize 64
         name @loader_path/crypto.dylib (offset 24)
Load command 2
          cmd LC_LOAD_WEAK_DYLIB
      cmdsize 64
         name /usr/lib/libSystem.B.dylib (offset 24)
'''
    assert qualification.macho_loads(commands) == ['@loader_path/crypto.dylib', '/usr/lib/libSystem.B.dylib']
    with pytest.raises(RuntimeError, match='Malformed'):
        qualification.macho_loads('Load command 0\ncmd LC_LOAD_DYLIB\n')


@pytest.mark.parametrize('kind', ['partial-current', 'partial-plist', 'loaded-service', 'uninspectable-service'])
def test_failed_initial_install_cannot_be_assumed_clean(monkeypatch, tmp_path, kind):
    current, plist = tmp_path / 'current', tmp_path / 'plist'
    for name in ['CURRENT', 'PREVIOUS', 'PLIST', 'WRAPPER', 'HELPER', 'SUDOERS']:
        monkeypatch.setattr(qualification, name, tmp_path / name.lower())
    if kind == 'partial-current': current.symlink_to(tmp_path / 'missing-release')
    if kind == 'partial-plist': plist.write_text('partial')
    result = subprocess.CompletedProcess([], 0 if kind == 'loaded-service' else 1, '',
        'Operation not permitted' if kind == 'uninspectable-service' else 'Could not find service')
    monkeypatch.setattr(qualification.subprocess, 'run', lambda *a, **kw: result)
    monkeypatch.setattr(qualification, 'receipt', lambda *a: pytest.fail('no clean receipt permitted'))
    with pytest.raises(RuntimeError):
        qualification.assert_initial_install_failure_restored()


def test_clean_failed_initial_install_requires_both_files_and_launchd_absent(monkeypatch):
    calls = []
    monkeypatch.setattr(qualification, 'require_absent', lambda paths: calls.append(('paths', paths)))
    monkeypatch.setattr(qualification.subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess([], 113, '', 'Could not find service'))
    monkeypatch.setattr(qualification, 'receipt', lambda name, value: calls.append((name, value)))
    qualification.assert_initial_install_failure_restored()
    assert calls[0][0] == 'paths'
    assert calls[1] == ('initial-install-failure-restored', {'loaded_service': False, 'active_artifacts': False})


def test_terminal_callback_does_not_race_ahead_of_results_and_complete_xml():
    jobs = [{'job_type': 'scan', 'status': 'completed', 'source_job_id': 'owned-source'}]
    assert not qualification.api_evidence_ready(jobs, [], [])
    assert not qualification.api_evidence_ready(jobs, [{'hosts_up': 1}], [])
    chunks = api_chunks(VALID_XML)
    chunks[0]['chunk_count'] = 2
    assert not qualification.api_evidence_ready(jobs, [{'hosts_up': 1}], chunks)
    chunks.append({**chunks[0], 'chunk_index': 1})
    assert qualification.api_evidence_ready(jobs, [{'hosts_up': 1}], chunks)
    assert qualification.api_evidence_ready([{'job_type': 'scan', 'status': 'failed', 'source_job_id': 'owned-source'}], [], [])
