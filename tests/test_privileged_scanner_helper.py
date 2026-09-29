"""Tests for the root-owned validating scanner helper and its wiring.

The helper is what sudoers grants NOPASSWD for, so its allowlist is the actual
privilege boundary. These tests exercise validation directly, without root.
"""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from nmapui import privileged

HELPER_PATH = (
    Path(__file__).resolve().parents[1]
    / "packaging"
    / "macos"
    / "nmapui-privileged-scanner"
)


def load_helper():
    spec = importlib.util.spec_from_loader(
        "nmapui_privileged_scanner",
        importlib.machinery.SourceFileLoader(
            "nmapui_privileged_scanner", str(HELPER_PATH)
        ),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_helper_never_takes_its_trusted_asset_root_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_PRIVILEGED_ASSETS", str(tmp_path))
    module = load_helper()
    assert module.ASSET_DIR in (module.RELEASE_ASSET_DIR, module.LEGACY_ASSET_DIR)
    assert module.ASSET_DIR != str(tmp_path)


def test_helper_prefers_assets_from_the_active_release(monkeypatch):
    expected = "/usr/local/lib/nmapui/current/privileged-assets"
    original_isdir = os.path.isdir
    monkeypatch.setattr(os.path, "isdir", lambda path: path == expected or original_isdir(path))

    module = load_helper()

    assert module.ASSET_DIR == expected


def test_helper_ignores_caller_data_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("NMAPUI_DATA_DIR", str(tmp_path))

    module = load_helper()

    assert module.DATA_DIR == "/Library/Application Support/NmapUI/data"


def test_helper_rejects_user_owned_scanner_binary(tmp_path):
    module = load_helper()
    binary = tmp_path / "nmap"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    module.TRUSTED_BIN_DIRS = (str(tmp_path),)

    with pytest.raises(module.Rejected, match="untrusted scanner binaries"):
        module._resolve_program("nmap")


def test_helper_requires_trusted_nmap_data_tree(helper, tmp_path):
    program = tmp_path / "bin" / "nmap"
    data = tmp_path / "share" / "nmap"
    (data / "scripts").mkdir(parents=True)
    (data / "nselib").mkdir()
    (data / "nmap-services").write_text("services")
    (data / "nmap-os-db").write_text("os")
    assert helper._verified_nmap_data_dir(str(program)) == str(data)

    (data / "scripts" / "unsafe.nse").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(helper.Rejected, match="symlink"):
        helper._verified_nmap_data_dir(str(program))


@pytest.fixture()
def helper(tmp_path):
    module = load_helper()
    assets = tmp_path / "assets"
    data = tmp_path / "data"
    bindir = tmp_path / "bin"
    for directory in (assets, data, bindir):
        directory.mkdir()
    (assets / "vulners.nse").write_text("-- vulners")
    (assets / "nmap.xsl").write_text("<xsl/>")
    # Fake scanner binaries so validation is testable without nmap installed
    # (CI runs on Linux without nmap) and without touching the real PATH.
    for name in ("nmap", "arp-scan"):
        fake = bindir / name
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
    module.ASSET_DIR = str(assets)
    module.DATA_DIR = str(data)
    module.TRUSTED_BIN_DIRS = (str(bindir),)
    module._verify_root_owned_command = lambda command: None
    return module


def test_allowlist_accepts_a_real_comprehensive_scan(helper, tmp_path):
    assets = Path(helper.ASSET_DIR)
    data = Path(helper.DATA_DIR)

    argv = helper.build_argv(
        [
            "nmap",
            "-sS",
            "-Pn",
            "-T4",
            "-A",
            "-sC",
            "--script",
            str(assets / "vulners.nse"),
            "--stylesheet",
            str(assets / "nmap.xsl"),
            "-oA",
            str(data / "scan_1"),
            "10.0.0.0/24",
        ]
    )

    assert argv[0].endswith("nmap")
    assert "-sS" in argv
    assert argv[-1] == "10.0.0.0/24"


def test_allowlist_accepts_a_real_quick_scan(helper):
    data = Path(helper.DATA_DIR)

    argv = helper.build_argv(
        ["nmap", "-sT", "-T3", "--top-ports", "100", "-oA", str(data / "scan_2"), "10.0.0.5"]
    )

    assert "--top-ports" in argv
    assert argv[-1] == "10.0.0.5"


def test_allowlist_accepts_arp_scan(helper):
    argv = helper.build_argv(["arp-scan", "192.168.1.0/24", "--interface", "en0"])

    assert argv[0].endswith("arp-scan")
    assert argv[-1] == "192.168.1.0/24"


def test_rejects_a_program_that_is_not_the_scanner(helper):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["sh", "-c", "id"])


def test_rejects_an_unknown_flag(helper):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "--interactive", "10.0.0.5"])


def test_rejects_forbidden_flags(helper):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "--script-args-file", "/tmp/x", "10.0.0.5"])


def test_rejects_a_script_outside_the_root_owned_asset_dir(helper, tmp_path):
    """A writable checkout must not be able to inject Lua into a root nmap."""
    outside = tmp_path / "evil.nse"
    outside.write_text("os.execute('id')")

    with pytest.raises(helper.Rejected):
        helper.build_argv(
            ["nmap", "-sS", "--script", str(outside), "10.0.0.5"]
        )


def test_rejects_output_outside_the_data_dir(helper, tmp_path):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "-oA", "/etc/nmapui_scan", "10.0.0.5"])


def test_rejects_output_base_at_data_root_and_symlinked_suffix(helper, tmp_path):
    data = Path(helper.DATA_DIR)
    with pytest.raises(helper.Rejected, match="must be inside"):
        helper.build_argv(["nmap", "-sS", "-oA", str(data), "10.0.0.5"])

    outside = tmp_path / "outside.xml"
    outside.write_text("untouched")
    (data / "scan.xml").symlink_to(outside)
    with pytest.raises(helper.Rejected, match="escape"):
        helper.build_argv(["nmap", "-sS", "-oA", str(data / "scan"), "10.0.0.5"])


def test_privileged_nmap_spools_output_then_publishes_without_following_symlink(helper, monkeypatch, tmp_path):
    data = Path(helper.DATA_DIR)
    outside = tmp_path / "outside.xml"
    outside.write_text("untouched")
    argv = helper.build_argv(["nmap", "-sS", "-oA", str(data / "scan"), "10.0.0.5"])
    monkeypatch.setattr(helper, "_verified_spool_parent", lambda: str(tmp_path))
    monkeypatch.setattr(helper, "_drop_to_service_user", lambda uid, gid: None)

    def fake_scan(command, *, check):
        assert check is False
        spool_base = Path(command[command.index("-oA") + 1])
        assert spool_base.parent != data
        for suffix in (".nmap", ".xml", ".gnmap"):
            Path(str(spool_base) + suffix).write_text(suffix)
        # Simulate the service user planting a symlink after validation.
        (data / "scan.xml").symlink_to(outside)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(helper.subprocess, "run", fake_scan)

    assert helper._run_nmap_with_safe_outputs(argv) == 0
    assert outside.read_text() == "untouched"
    assert not (data / "scan.xml").is_symlink()
    assert (data / "scan.xml").read_text() == ".xml"


def test_rejects_a_target_that_looks_like_an_option(helper):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "--exclude=10.0.0.5"])


def test_rejects_shell_metacharacters_in_the_target(helper):
    for malicious in ("10.0.0.5;id", "10.0.0.5$(id)", "10.0.0.5`id`", "10.0.0.5|id"):
        with pytest.raises(helper.Rejected):
            helper.build_argv(["nmap", "-sS", malicious])


def test_rejects_missing_or_multiple_targets(helper):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS"])
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "10.0.0.5", "10.0.0.6"])


def test_rejects_a_second_scan_technique(helper):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "-sT", "10.0.0.5"])


def test_rejects_a_non_numeric_value_flag(helper):
    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "--top-ports", "all", "10.0.0.5"])


def test_exclude_values_are_validated(helper):
    argv = helper.build_argv(
        ["nmap", "-sS", "--exclude", "10.0.0.5,10.0.0.9", "10.0.0.0/24"]
    )
    assert "10.0.0.5,10.0.0.9" in argv

    with pytest.raises(helper.Rejected):
        helper.build_argv(["nmap", "-sS", "--exclude", "10.0.0.5;id", "10.0.0.0/24"])


def test_privileged_prefix_uses_the_helper_when_installed(monkeypatch):
    monkeypatch.setattr(privileged, "is_root", lambda: False)
    monkeypatch.setattr(privileged, "sudo_available", lambda: True)
    monkeypatch.setattr(
        privileged, "scanner_helper_path", lambda: "/usr/local/libexec/nmapui-privileged-scanner"
    )

    assert privileged.privileged_prefix() == [
        "sudo",
        "-n",
        "/usr/local/libexec/nmapui-privileged-scanner",
    ]


def test_privileged_prefix_falls_back_to_raw_sudo_without_the_helper(monkeypatch):
    monkeypatch.setattr(privileged, "is_root", lambda: False)
    monkeypatch.setattr(privileged, "sudo_available", lambda: True)
    monkeypatch.setattr(privileged, "scanner_helper_path", lambda: "")

    assert privileged.privileged_prefix() == ["sudo", "-n"]


def test_nmap_argv_places_the_helper_before_nmap(monkeypatch):
    monkeypatch.setattr(
        privileged, "privileged_prefix", lambda: ["sudo", "-n", "/helper"]
    )

    argv = privileged.nmap_argv("-sS", ["-Pn"], "10.0.0.0/24")

    assert argv == ["sudo", "-n", "/helper", "nmap", "-sS", "-Pn", "10.0.0.0/24"]


def test_accepts_a_request_without_an_explicit_technique(helper):
    """nmap's own default is privileged-aware; the deep-scan shape is allowed."""
    argv = helper.build_argv(["nmap", "-T3", "-sV", "10.0.0.5"])

    assert "-T3" in argv
    assert "-sV" in argv
    assert argv[-1] == "10.0.0.5"
