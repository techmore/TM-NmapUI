from pathlib import Path
import subprocess

import nmapui.scanning as scanning
from nmapui.scanning import create_scan_folder
from nmapui.networking import is_private_ip


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


def test_get_nmap_scan_technique_uses_connect_scan_without_root(monkeypatch):
    monkeypatch.setattr(scanning.os, "geteuid", lambda: 501, raising=False)
    assert scanning.get_nmap_scan_technique() == "-sT"


def test_get_nmap_scan_technique_uses_syn_scan_as_root(monkeypatch):
    monkeypatch.setattr(scanning.os, "geteuid", lambda: 0, raising=False)
    assert scanning.get_nmap_scan_technique() == "-sS"


def test_run_arp_scan_does_not_retry_with_sudo_on_permission_error():
    calls = []
    emitted = []

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
        "arp-scan requires elevated privileges; skipping MAC/vendor detection",
    )


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
