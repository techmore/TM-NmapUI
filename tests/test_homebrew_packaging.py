"""Homebrew packaging: non-root service, helper-only privilege, pinned deps."""
import importlib.machinery
import importlib.util
import os
import re
import subprocess
from pathlib import Path

import pytest

from nmapui import privileged

ROOT = Path(__file__).resolve().parents[1]
BREW = ROOT / "packaging" / "homebrew"
HELPER_PATH = ROOT / "packaging" / "macos" / "nmapui-privileged-scanner"


def _load_helper():
    loader = importlib.machinery.SourceFileLoader("nmapui_helper_brew", str(HELPER_PATH))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


@pytest.mark.parametrize("value, expected", [("true", []), ("1", []), ("false", ["sudo", "-n"]), ("", ["sudo", "-n"])])
def test_require_scan_helper_disables_raw_sudo_nmap(monkeypatch, value, expected):
    monkeypatch.setenv("NMAPUI_REQUIRE_SCAN_HELPER", value)
    monkeypatch.setattr(privileged, "is_root", lambda: False)
    monkeypatch.setattr(privileged, "sudo_available", lambda: True)
    monkeypatch.setattr(privileged, "scanner_helper_path", lambda: "")
    assert privileged.privileged_prefix() == expected


def test_require_scan_helper_still_uses_the_helper(monkeypatch):
    monkeypatch.setenv("NMAPUI_REQUIRE_SCAN_HELPER", "true")
    monkeypatch.setattr(privileged, "is_root", lambda: False)
    monkeypatch.setattr(privileged, "sudo_available", lambda: True)
    monkeypatch.setattr(privileged, "scanner_helper_path", lambda: "/usr/local/libexec/nmapui-privileged-scanner")
    assert privileged.privileged_prefix() == ["sudo", "-n", "/usr/local/libexec/nmapui-privileged-scanner"]


def test_helper_ignores_a_user_owned_data_dir_config(tmp_path):
    helper = _load_helper()
    config = tmp_path / "privileged-scanner.conf"
    config.write_text("data_dir=/Users/attacker/anything\n")
    # tmp_path is user-owned, so the file is not trusted.
    assert helper._configured_data_dir(str(config), default="/default") == "/default"
    assert helper._configured_data_dir(str(tmp_path / "missing.conf"), default="/default") == "/default"


def test_helper_reads_a_root_owned_data_dir_config(tmp_path, monkeypatch):
    helper = _load_helper()
    config = tmp_path / "privileged-scanner.conf"
    config.write_text("# comment\ndata_dir=/Users/someone/Library/Application Support/NmapUI-brew/data\n")
    monkeypatch.setattr(helper, "_root_owned_chain", lambda path: True)
    assert helper._configured_data_dir(str(config), default="/d") == "/Users/someone/Library/Application Support/NmapUI-brew/data"
    config.write_text("data_dir=relative/path\n")
    assert helper._configured_data_dir(str(config), default="/d") == "/d"
    config.write_text("data_dir=/a/../etc\n")
    assert helper._configured_data_dir(str(config), default="/d") == "/d"


def test_root_owned_chain_rejects_user_paths(tmp_path):
    helper = _load_helper()
    assert helper._root_owned_chain("/usr/bin/true") is True
    target = tmp_path / "f"
    target.write_text("x")
    assert helper._root_owned_chain(str(target)) is False


def test_lock_pins_every_runtime_requirement_with_hashes():
    runtime = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        if line.startswith("# Test dependencies"):
            break
        if line.strip() and not line.startswith("#"):
            runtime.append(line.strip().lower())
    lock = (BREW / "requirements.lock").read_text().lower()
    for pin in runtime:
        assert pin in lock, pin
    entries = re.findall(r"^([a-z0-9_.-]+==[^\s\\]+)", lock, re.M)
    assert entries
    for entry in entries:
        block = lock.split(entry, 1)[1].split("\n\n")[0]
        assert "--hash=sha256:" in block, entry


@pytest.mark.parametrize("script", ["nmapui-server", "nmapui-privileged-setup"])
def test_brew_scripts_are_valid_bash_and_executable(script):
    path = BREW / script
    assert os.access(path, os.X_OK)
    subprocess.run(["bash", "-n", str(path)], check=True)


def test_setup_never_grants_sudo_for_nmap_itself():
    text = (BREW / "nmapui-privileged-setup").read_text()
    rules = re.findall(r'local rule="([^"]+)"', text)
    assert rules == ["$user ALL=(root) NOPASSWD: $HELPER_DEST"]
    assert "visudo -cf" in text


def test_server_paths_command_uses_user_state(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    out = subprocess.run([str(BREW / "nmapui-server"), "paths"], env=env, capture_output=True, text=True, check=True).stdout
    assert str(tmp_path) in out
    assert "127.0.0.1:9000" in out


def test_server_settings_file_is_parsed_not_sourced(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    marker = tmp_path / "pwned"
    (state / "nmapui.env").write_text(
        "# comment\nNMAPUI_PORT=9123\nNMAPUI_PASSWORD=a=b$(touch %s)\nPATH=/evil\n" % marker
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "NMAPUI_STATE_DIR": str(state)}
    result = subprocess.run([str(BREW / "nmapui-server"), "paths"], env=env, capture_output=True, text=True, check=True)
    assert "127.0.0.1:9123" in result.stdout
    assert "ignoring unsupported setting 'PATH'" in result.stderr
    assert not marker.exists()


def test_environment_wins_over_settings_file(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "nmapui.env").write_text("NMAPUI_PORT=9123\n")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "NMAPUI_STATE_DIR": str(state), "NMAPUI_PORT": "9555"}
    out = subprocess.run([str(BREW / "nmapui-server"), "paths"], env=env, capture_output=True, text=True, check=True).stdout
    assert "127.0.0.1:9555" in out
