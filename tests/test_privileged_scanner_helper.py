"""Tests for the root-owned validating scanner helper and its wiring.

The helper is what sudoers grants NOPASSWD for, so its allowlist is the actual
privilege boundary. These tests exercise validation directly, without root.
"""

import importlib.util
from pathlib import Path

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
