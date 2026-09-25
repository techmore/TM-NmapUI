"""Tests for prompt-free privilege handling and nmap argv construction."""

import subprocess

from nmapui import privileged, scanning


def _denied(cmd):
    return subprocess.CompletedProcess(
        args=cmd, returncode=1, stdout="", stderr="sudo: a password is required"
    )


def _ok(cmd):
    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")


def _run(captured, results):
    def run_cancellable_command(cmd, **kwargs):
        captured.append(cmd)
        return results.pop(0)

    return run_cancellable_command


def _base_kwargs(runner):
    return {
        "vulners_script": "/tmp/vulners.nse",
        "stylesheet_pdf": "/tmp/nmap.xsl",
        "emit_to_client": lambda *a, **k: None,
        "socketio_emit": lambda *a, **k: None,
        "socketio_sleep": lambda value: None,
        "run_cancellable_command": runner,
    }


def test_privileged_prefix_is_empty_as_root(monkeypatch):
    monkeypatch.setattr(privileged, "is_root", lambda: True)
    assert privileged.privileged_prefix() == []


def test_privileged_prefix_uses_non_interactive_sudo(monkeypatch):
    monkeypatch.setattr(privileged, "is_root", lambda: False)
    monkeypatch.setattr(privileged, "sudo_available", lambda: True)

    prefix = privileged.privileged_prefix()

    assert prefix == ["sudo", "-n"]
    # -n is what guarantees the appliance never blocks on a password prompt.
    assert "-n" in prefix


def test_privileged_prefix_empty_without_sudo(monkeypatch):
    monkeypatch.setattr(privileged, "is_root", lambda: False)
    monkeypatch.setattr(privileged, "sudo_available", lambda: False)

    assert privileged.privileged_prefix() == []


def test_is_permission_denied_detects_sudo_password_requirement():
    assert privileged.is_permission_denied(_denied(["nmap"])) is True
    assert privileged.is_permission_denied(_ok(["nmap"])) is False


def test_nmap_argv_owns_the_technique_slot():
    argv = privileged.nmap_argv(
        "-sS", ["--exclude", "10.0.0.5", "-Pn"], "10.0.0.0/24", prefix=[]
    )

    assert argv == ["nmap", "-sS", "--exclude", "10.0.0.5", "-Pn", "10.0.0.0/24"]


def test_unprivileged_fallback_preserves_exclusions(monkeypatch):
    """Regression: the retry used to overwrite --exclude and scan excluded hosts."""
    monkeypatch.setattr(privileged, "privileged_prefix", lambda: ["sudo", "-n"])
    captured = []
    runner = _run(captured, [_denied(["first"]), _ok(["second"])])

    result = scanning.run_nmap_with_xml_output(
        "10.0.0.0/24",
        "/tmp/out",
        scan_type="comprehensive",
        excluded_targets=["10.0.0.5", "10.0.0.9"],
        force_privileged_scan=True,
        **_base_kwargs(runner),
    )

    assert result["success"] is True
    assert len(captured) == 2

    first, fallback = captured
    for cmd in (first, fallback):
        assert "--exclude" in cmd
        assert cmd[cmd.index("--exclude") + 1] == "10.0.0.5,10.0.0.9"
        # The exclusion list must appear exactly once — as the --exclude value,
        # never as a bare positional target (the old failure mode).
        assert cmd.count("10.0.0.5,10.0.0.9") == 1
        # Exactly one technique flag, and the scan target is last.
        assert sum(flag in cmd for flag in ("-sS", "-sT")) == 1
        assert cmd[-1] == "10.0.0.0/24"

    # First attempt is privileged; the retry is unprivileged and uses -sT.
    assert "-sS" in first
    assert "sudo" in first
    assert "sudo" not in fallback
    assert "-sT" in fallback
    assert "-sS" not in fallback


def test_scan_only_mode_wins_over_forced_privileged_scan(monkeypatch):
    """Regression: scan_only_mode was silently overridden by force_privileged_scan."""
    monkeypatch.setattr(privileged, "privileged_prefix", lambda: ["sudo", "-n"])
    captured = []
    runner = _run(captured, [_ok(["scan"])])

    scanning.run_nmap_with_xml_output(
        "10.0.0.0/24",
        "/tmp/out",
        scan_type="comprehensive",
        scan_only_mode=True,
        force_privileged_scan=True,
        **_base_kwargs(runner),
    )

    assert "-sT" in captured[0]
    assert "-sS" not in captured[0]
