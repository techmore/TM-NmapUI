import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from nmapui.workflows import _run_deep_scan_with_xml


def test_original_xml_is_chunked_losslessly_and_temporary_file_is_removed():
    original = '<nmaprun>' + '\u00e9' * 40000 + '</nmaprun>'
    events = []
    paths = []

    def run(argv, **kwargs):
        path = Path(argv[argv.index('-oX') + 1])
        paths.append(path)
        path.write_bytes(original.encode())
        assert argv[-1] == '127.0.0.1'
        assert kwargs == {'sid': 'sid', 'job_type': 'scan', 'timeout': 135}
        return SimpleNamespace(stdout='normal nmap text')

    context = SimpleNamespace(run_cancellable_command=run, emit_to_client=lambda *args: events.append(args))
    result = _run_deep_scan_with_xml(context, ['nmap', '-sV', '127.0.0.1'], 'sid', '127.0.0.1')
    assert result.stdout == 'normal nmap text'
    chunks = [args[2] for args in events if args[1] == 'scan_xml_chunk']
    assert len(chunks) == 2
    assert ''.join(chunk['xml'] for chunk in chunks) == original
    assert all(chunk['sha256'] == hashlib.sha256(original.encode()).hexdigest() for chunk in chunks)
    assert all(len(json.dumps(chunk).encode()) < 512000 for chunk in chunks)
    assert not paths[0].exists()


import pytest

from nmapui.workflows import service_scan_host_timeout


@pytest.mark.parametrize("value, expected", [(None, 120), ("300", 300), ("30", 30), ("3600", 3600), ("29", 120), ("4000", 120), ("abc", 120), ("", 120)])
def test_service_scan_host_timeout_is_bounded(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("NMAPUI_SERVICE_SCAN_HOST_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("NMAPUI_SERVICE_SCAN_HOST_TIMEOUT", value)
    assert service_scan_host_timeout() == expected


def test_configured_timeout_reaches_nmap_and_process_deadline(monkeypatch):
    monkeypatch.setenv("NMAPUI_SERVICE_SCAN_HOST_TIMEOUT", "300")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout="")

    context = SimpleNamespace(run_cancellable_command=run, emit_to_client=lambda *args: None)
    _run_deep_scan_with_xml(context, ["nmap", "-sV", "127.0.0.1"], "sid", "127.0.0.1")
    argv, kwargs = calls[0]
    assert argv[argv.index("--host-timeout") + 1] == "300s"
    assert kwargs["timeout"] == 315
