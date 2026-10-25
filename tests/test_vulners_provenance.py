"""Bundled NSE identity must describe its bytes, not a containing app checkout."""

import hashlib
import logging
from pathlib import Path
import subprocess

from nmapui import scanning, startup_checks


def startup_versions(script: Path, monkeypatch) -> dict[str, str]:
    monkeypatch.setenv("NMAPUI_STARTUP_TRACEROUTE", "false")
    versions = {}

    class Versions:
        def set_version(self, name, value):
            versions[name] = value

    def no_traceroute(_):
        raise AssertionError("Version discovery must not probe a network")

    startup_checks.run_startup_checks({
        "begin_startup_state": lambda state, **kwargs: None,
        "check_arp_scan": lambda: False, "check_nmap": lambda: "fixture-nmap",
        "check_vulners": scanning.check_vulners,
        "complete_startup_state": lambda state, **kwargs: None,
        "get_app_version": lambda: "fixture-app", "get_default_interface_cached": lambda: "fixture",
        "get_versions": lambda: versions, "load_auto_scan_config": lambda config: None,
        "load_current_assignment": lambda: None, "logger": logging.getLogger(__name__),
        "run_traceroute": no_traceroute, "safe_emit": lambda *args: None,
        "startup_state": {}, "tool_versions": Versions(), "auto_scan_config": {"enabled": False},
        "vulners_script": script,
    })
    return versions


def test_startup_identifies_nse_bytes_independently_of_parent_commits(tmp_path, monkeypatch):
    checkout = tmp_path / "application"
    script = checkout / "nmap-vulners/vulners.nse"
    script.parent.mkdir(parents=True)
    script.write_bytes(b"-- bundled NSE fixture\n")

    def git(*args):
        return subprocess.run(["git", "-C", str(checkout), *args], check=True, capture_output=True, text=True)

    def commit(message):
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", message)

    git("init", "-q")
    commit("Unrelated application release")
    expected = "vulners.nse sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()[:16]
    assert startup_versions(script, monkeypatch)["vulners"] == expected
    (checkout / "README").write_text("Only application documentation changed\n")
    commit("Another unrelated application release")
    assert startup_versions(script, monkeypatch)["vulners"] == expected

    def no_git(*args, **kwargs):
        raise AssertionError("Bundled identity must work without Git")

    monkeypatch.setattr(subprocess, "run", no_git)
    assert startup_versions(script, monkeypatch)["vulners"] == expected
    script.write_bytes(b"-- updated NSE fixture\n")
    changed = startup_versions(script, monkeypatch)["vulners"]
    assert changed == "vulners.nse sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()[:16]
    assert changed != expected


def test_missing_script_is_not_reported_as_parent_repository_version(tmp_path, monkeypatch):
    script = tmp_path / "vulners.nse"
    assert startup_versions(script, monkeypatch)["vulners"] == "Not installed"
