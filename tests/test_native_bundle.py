"""Verify the native SwiftUI artifact without launching or installing it."""
import os
from pathlib import Path
import plistlib
import runpy
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging/macos"


def test_invalid_native_version_fails_before_swift_build(tmp_path):
    packaging = tmp_path / "packaging/macos"
    packaging.mkdir(parents=True)
    for name in ("bundle.sh", "bundle_version.py"):
        shutil.copy2(PACKAGING / name, packaging / name)
    (tmp_path / "VERSION").write_text('v2026.1.1$(touch injected)</string>')
    tool_dir = tmp_path / "tools"
    tool_dir.mkdir()
    swift = tool_dir / "swift"
    swift.write_text('#!/bin/sh\ntouch swift-was-invoked\nexit 99\n')
    swift.chmod(0o755)
    env = {**os.environ, "PATH": f"{tool_dir}:{os.environ['PATH']}"}
    result = subprocess.run(["bash", str(packaging / "bundle.sh")], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "ERROR: Invalid VERSION:" in result.stderr
    assert not (packaging / "swift-was-invoked").exists()
    assert not (tmp_path / "injected").exists()
    assert not (packaging / "build").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="Requires macOS packaging tools")
def test_real_native_bundle_versions_resources_and_signatures(tmp_path):
    if os.environ.get("NMAPUI_RUN_NATIVE_BUNDLE_SMOKE") != "1":
        pytest.skip("Set NMAPUI_RUN_NATIVE_BUNDLE_SMOKE=1 for actual SwiftUI packaging")
    bundle = tmp_path / "artifacts/NmapUI.app"
    env = {
        **os.environ,
        "APP_BUNDLE": str(bundle),
        "BUILD_DIR": os.environ.get("NMAPUI_NATIVE_BUILD_DIR", str(tmp_path / "swift-build")),
        "CODESIGN_IDENTITY": "-",
        "NMAPUI_DATA_DIR": str(tmp_path / "isolated-data"),
    }
    subprocess.run(["bash", str(PACKAGING / "bundle.sh")], env=env, check=True, timeout=600)
    raw, short, build = runpy.run_path(str(PACKAGING / "bundle_version.py"))["bundle_versions"]((ROOT / "VERSION").read_text())
    with (bundle / "Contents/Info.plist").open("rb") as stream:
        info = plistlib.load(stream)
    assert info["CFBundleIdentifier"] == "com.techmore.nmapui"
    assert info["CFBundleExecutable"] == "NmapUI"
    assert info["CFBundlePackageType"] == "APPL"
    assert info["CFBundleShortVersionString"] == short
    assert info["CFBundleVersion"] == build
    assert info["NmapUIProductVersion"] == raw
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    assert info["NmapUISourceRevision"] == revision
    resources = bundle / "Contents/Resources"
    assert (resources / "VERSION").read_text().strip() == raw
    for resource in ("NmapUI_NmapUIApp.bundle", "index.html", "nmap-modern.xsl", "static", "nmap-vulners", "AppIcon.icns", "techmore.png"):
        assert (resources / resource).exists(), resource
    for executable, identifier in {
        "NmapUI.real": "com.techmore.nmapui",
        "NmapPrivilegedHelper": "com.techmore.nmapui.nmap-helper",
        "GoogleDriveHelper": "com.techmore.nmapui.GoogleDriveHelper",
        "RuntimeReportHelper": "com.techmore.nmapui.RuntimeReportHelper",
    }.items():
        path = bundle / "Contents/MacOS" / executable
        assert os.access(path, os.X_OK)
        subprocess.run(["codesign", "--verify", "--strict", str(path)], check=True)
        signature = subprocess.run(["codesign", "-d", "--verbose=4", str(path)], capture_output=True, text=True, check=True)
        assert f"Identifier={identifier}\n" in signature.stderr
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(bundle)], check=True)
    # Exercise the production installer only into an isolated destination, with
    # opening disabled. Copying must retain every original nested signature.
    env["NMAPUI_APPLICATIONS_DIR"] = str(tmp_path / "isolated-install")
    env["OPEN_AFTER_INSTALL"] = "0"
    subprocess.run(["bash", str(PACKAGING / "install.sh")], env=env, check=True, timeout=600)
    installed = Path(env["NMAPUI_APPLICATIONS_DIR"]) / "NmapUI.app"
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(installed)], check=True)
    for name in ("NmapUI.real", "NmapPrivilegedHelper", "GoogleDriveHelper", "RuntimeReportHelper"):
        assert (installed / "Contents/MacOS" / name).read_bytes() == (bundle / "Contents/MacOS" / name).read_bytes()
    assert not (tmp_path / "isolated-data").exists(), "Bundling/installing must not launch the app/runtime"


def test_swift_entrypoints_use_portable_main_attribute_filenames():
    # Classic SwiftPM treats main.swift as top-level code; @main needs another filename.
    for source in (PACKAGING / "Sources").rglob("main.swift"):
        assert "@main" not in source.read_text(), source


@pytest.mark.parametrize("entrypoint", ["bundle.sh", "install.sh"])
def test_native_packaging_refuses_active_destination_before_rebuilding(tmp_path, entrypoint):
    packaging = tmp_path / "repo/packaging/macos"
    packaging.mkdir(parents=True)
    for name in (entrypoint, "bundle_version.py", "assert_bundle_stopped.py"):
        shutil.copy2(PACKAGING / name, packaging / name)
    (packaging.parent.parent / "VERSION").write_text("v2026.10.25")
    target = tmp_path / "selected-applications/NmapUI.app"
    resources = target / "Contents/Resources"
    resources.mkdir(parents=True)
    sentinel = resources / "preserve-me"
    sentinel.write_text("do not replace")
    unrelated = subprocess.Popen(["/bin/sleep", "60"])
    marker = resources / "nmapui-runtime.pid"
    marker.write_text(str(unrelated.pid))
    tools = tmp_path / "tools"
    tools.mkdir()
    swift = tools / "swift"
    swift.write_text('#!/bin/sh\ntouch swift-was-invoked\nexit 99\n')
    swift.chmod(0o755)
    env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "APP_BUNDLE": str(target),
           "NMAPUI_APPLICATIONS_DIR": str(target.parent), "OPEN_AFTER_INSTALL": "0"}
    try:
        result = subprocess.run(["bash", str(packaging / entrypoint)], env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode != 0
        assert "Refusing to replace active or unverified bundle" in result.stderr
        assert sentinel.read_text() == "do not replace"
        assert marker.read_text() == str(unrelated.pid)
        assert unrelated.poll() is None
        assert not (packaging / "swift-was-invoked").exists()
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)
