"""Calendar release versions must produce safe, ordered Apple bundle metadata."""

import os
from pathlib import Path
import runpy
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "packaging/macos/bundle_version.py"
bundle_versions = runpy.run_path(str(HELPER))["bundle_versions"]


@pytest.mark.parametrize("raw,short,build", [
    ("v2026.3.14.00_10", "2026.3.14", "2026.3.18730"),
    ("v2026.4.26.4.00", "2026.4.26", "2026.4.36240"),
    ("v2026.10.25", "2026.10.25", "2026.10.34560"),
    ("v2024.02.29.23_59", "2024.2.29", "2024.2.41759"),
])
def test_historical_and_date_only_versions(raw, short, build):
    for ending in ("", "\n", "\r\n"):
        assert bundle_versions(raw + ending) == (raw, short, build)


def test_build_numbers_increase_across_minutes_days_months_and_years():
    versions = [
        "v2026.3.14", "v2026.3.14.00_10", "v2026.3.14.00_11",
        "v2026.3.14.01_00", "v2026.3.14.23_59", "v2026.3.15",
        "v2026.3.31.23_59", "v2026.4.1", "v2026.12.31.23_59", "v2027.1.1",
    ]
    builds = [tuple(map(int, bundle_versions(raw)[2].split("."))) for raw in versions]
    assert all(left < right for left, right in zip(builds, builds[1:]))
    assert bundle_versions("v2026.4.26.4.00")[2] == bundle_versions("v2026.4.26.04_00")[2]


@pytest.mark.parametrize("raw", [
    "", "2026.10.25", "v2026.2.29", "v2026.13.1", "v0000.1.1", "v2026.0.1",
    "v2026.1.0", "v2026.1.32", "v2026.1.1.24_00", "v2026.1.1.00_60",
    "v2026.1.1.1", "v2026.1.1.1_1", "v2026.1.1.00_00.extra", " v2026.1.1",
    "v2026.1.1\n\n", "v2026.1.1\nv2026.1.2", "v2026.1.1\t",
    "v2026.1.1</string><key>Injected</key>", "$(touch injected)", "v２０２６.1.1",
])
def test_malformed_or_executable_version_is_rejected(raw):
    with pytest.raises(ValueError):
        bundle_versions(raw)


def test_build_rejects_invalid_version_before_sdk_or_artifact_work(tmp_path):
    shutil.copy2(ROOT / "build.sh", tmp_path / "build.sh")
    packaging = tmp_path / "packaging/macos"
    packaging.mkdir(parents=True)
    shutil.copy2(HELPER, packaging / HELPER.name)
    (tmp_path / "VERSION").write_text('v2026.1.1$(touch injected)</string>')
    tools = tmp_path / "tools"
    tools.mkdir()
    xcrun = tools / "xcrun"
    xcrun.write_text('#!/bin/sh\ntouch sdk-was-invoked\nexit 99\n')
    xcrun.chmod(0o755)
    env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}
    result = subprocess.run(["bash", "build.sh"], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "ERROR: Invalid VERSION:" in result.stderr
    assert not (tmp_path / "sdk-was-invoked").exists()
    assert not (tmp_path / "injected").exists()
    assert not (tmp_path / ".build").exists()
    assert not (tmp_path / "NmapUI.app").exists()
