from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

import nmapui.scanning as scanning
from nmapui.scanning import create_scan_folder
from nmapui.networking import is_private_ip
from nmapui.jobs import ClientJobRegistry
from nmapui.workflows import _finalize_scan_job_if_active, start_deep_scan


def test_create_scan_folder_uses_customer_and_target_structure(tmp_path):
    scan_dir = create_scan_folder(
        "Acme Customer",
        "192.168.1.0/24",
        scans_dir=tmp_path,
        sanitize_customer_dir_name=lambda value: value.replace(" ", "_"),
    )

    assert isinstance(scan_dir, Path)
    assert scan_dir.parent.parent == tmp_path / "Acme_Customer"
    assert scan_dir.name.startswith("scan_")
    assert "192.168.1.0_24" in scan_dir.name


def test_deep_scan_propagates_cancellation_to_top_level_job_finalizer():
    def raise_cancellation(_sid, _job_type):
        raise RuntimeError("scan cancelled")

    context = SimpleNamespace(
        emit_to_client=lambda *args, **kwargs: None,
        socketio_sleep=lambda _seconds: None,
        ensure_job_not_cancelled=raise_cancellation,
        run_cancellable_command=lambda *args, **kwargs: None,
        vulners_script="vulners.nse",
    )

    with pytest.raises(RuntimeError, match="scan cancelled"):
        start_deep_scan(context, ["127.0.0.1"], "sid-test")


def test_deep_scan_can_disable_vulners_egress(monkeypatch):
    monkeypatch.setenv("NMAPUI_ENABLE_VULNERS", "false")
    commands = []
    context = SimpleNamespace(
        emit_to_client=lambda *_args, **_kwargs: None,
        socketio_sleep=lambda _seconds: None,
        ensure_job_not_cancelled=lambda _sid, _job_type: None,
        run_cancellable_command=lambda cmd, **_kwargs: (
            commands.append(cmd) or SimpleNamespace(stdout="")
        ),
        vulners_script="vulners.nse",
        cve_pattern=re.compile(r"CVE-"),
        port_info_regex=re.compile(r""),
    )

    start_deep_scan(context, ["127.0.0.1"], "sid-test")

    assert commands == [["nmap", "-T3", "-sV", "127.0.0.1"]]


def test_disabled_deep_scan_still_discloses_missing_vulners_enrichment(monkeypatch):
    monkeypatch.setenv("NMAPUI_ENABLE_VULNERS", "false")
    events = []
    context = SimpleNamespace(
        emit_to_client=lambda _sid, event, data=None: events.append((event, data)),
        socketio_sleep=lambda _seconds: None,
        ensure_job_not_cancelled=lambda _sid, _job_type: None,
        run_cancellable_command=lambda _cmd, **_kwargs: SimpleNamespace(stdout=""),
        vulners_script="vulners.nse",
        cve_pattern=re.compile(r"CVE-"),
        port_info_regex=re.compile(r""),
    )

    start_deep_scan(context, ["127.0.0.1"], "sid-test")

    assert any(
        event == "scan_feedback" and "will not query Vulners.com" in data
        for event, data in events
    )


def test_scan_job_finalizer_closes_a_cancellation_that_races_completion():
    registry = ClientJobRegistry()
    sid = "late-cancellation"
    assert registry.start(sid, "scan", {"target": "127.0.0.1"})
    assert registry.cancel(sid, "scan")
    events = []
    context = SimpleNamespace(
        job_registry=registry,
        emit_job_status=lambda client_sid, job_type: events.append(
            ("job_status", client_sid, job_type, registry.get(client_sid, job_type)["status"])
        ),
        emit_to_client=lambda client_sid, event, data: events.append(
            (event, client_sid, data)
        ),
    )

    _finalize_scan_job_if_active(context, sid)

    assert registry.get(sid, "scan")["status"] == "cancelled"
    assert events == [
        ("job_status", sid, "scan", "cancelled"),
        ("scan_error", sid, "Scan cancelled"),
    ]


def test_get_nmap_scan_technique_uses_connect_scan_without_root(monkeypatch):
    monkeypatch.setattr(scanning.os, "geteuid", lambda: 501, raising=False)
    assert scanning.get_nmap_scan_technique() == "-sT"


def test_get_nmap_scan_technique_uses_syn_scan_as_root(monkeypatch):
    monkeypatch.setattr(scanning.os, "geteuid", lambda: 0, raising=False)
    assert scanning.get_nmap_scan_technique() == "-sS"


def test_run_arp_scan_reports_missing_privilege_as_nonfatal(monkeypatch):
    calls = []
    emitted = []
    monkeypatch.setattr(scanning.privileged, "privileged_prefix", lambda: [])

    def run_cancellable_command(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr="arp-scan: Permission denied",
        )

    result = scanning.run_arp_scan(
        "192.168.1.0/24",
        interface="en0",
        sid="sid-1",
        get_default_interface_cached=lambda: "en0",
        which=lambda name: "/usr/local/bin/arp-scan",
        emit_to_client=lambda sid, event, data: emitted.append((sid, event, data)),
        socketio_emit=lambda event, data: emitted.append((None, event, data)),
        socketio_sleep=lambda value: None,
        run_cancellable_command=run_cancellable_command,
    )

    assert result == {}
    assert calls == [["arp-scan", "192.168.1.0/24", "--interface", "en0"]]
    assert emitted[-1] == (
        "sid-1",
        "scan_feedback",
        "MAC/vendor detection was skipped because ARP privileges are unavailable; "
        "the Nmap scan completed normally",
    )


def test_run_arp_scan_uses_the_installed_privileged_helper(monkeypatch):
    helper_prefix = ["sudo", "-n", "/usr/local/libexec/nmapui-privileged-scanner"]
    monkeypatch.setattr(scanning.privileged, "privileged_prefix", lambda: helper_prefix)
    calls = []

    def run_cancellable_command(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="192.168.1.12 00:11:22:33:44:55 Example Vendor\n",
            stderr="",
        )

    result = scanning.run_arp_scan(
        "192.168.1.0/24",
        interface="en0",
        sid="sid-1",
        get_default_interface_cached=lambda: "en0",
        which=lambda name: "/usr/local/bin/arp-scan",
        emit_to_client=lambda *args, **kwargs: None,
        socketio_emit=lambda *args, **kwargs: None,
        socketio_sleep=lambda value: None,
        run_cancellable_command=run_cancellable_command,
    )

    assert calls == [
        [
            *helper_prefix,
            "arp-scan",
            "192.168.1.0/24",
            "--interface",
            "en0",
        ]
    ]
    assert result == {
        "192.168.1.12": {
            "mac": "00:11:22:33:44:55",
            "vendor": "Example Vendor",
        }
    }


def test_split_subnet_into_chunks_splits_large_networks():
    chunks = scanning.split_subnet_into_chunks("192.168.1.0/24")

    assert chunks[0] == "192.168.1.0/29"
    assert len(chunks) > 1


def test_split_subnet_into_chunks_returns_original_target_for_invalid_input():
    assert scanning.split_subnet_into_chunks("not-a-target") == ["not-a-target"]


def test_is_private_ip_supports_private_and_cgnat_ranges():
    assert is_private_ip("192.168.1.10") is True
    assert is_private_ip("100.64.1.10") is True
    assert is_private_ip("8.8.8.8") is False


def test_check_nmap_returns_none_instead_of_exiting_when_missing(monkeypatch):
    """A missing nmap must degrade the server, not kill it before it binds."""
    monkeypatch.setattr(scanning.shutil, "which", lambda name: None)

    assert scanning.check_nmap() is None


def test_check_nmap_returns_none_instead_of_exiting_on_version_failure(monkeypatch):
    monkeypatch.setattr(scanning.shutil, "which", lambda name: "/usr/bin/nmap")

    def raise_oserror(*args, **kwargs):
        raise OSError("nmap exploded")

    monkeypatch.setattr(scanning.subprocess, "check_output", raise_oserror)

    assert scanning.check_nmap() is None


def test_check_vulners_returns_false_instead_of_exiting_when_missing(tmp_path):
    """A missing vulners script degrades CVE detection but must not exit."""
    missing = tmp_path / "vulners.nse"

    assert scanning.check_vulners(missing) is False


def test_check_vulners_returns_true_when_present(tmp_path):
    script = tmp_path / "vulners.nse"
    script.write_text("-- vulners")

    assert scanning.check_vulners(script) is True
