"""Run production build preflight against real processes and temporary bundles."""

import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "packaging/macos/assert_bundle_stopped.py"


def bundle_at(path):
    resources = path / "Contents/Resources"
    resources.mkdir(parents=True)
    (resources / "preserve-me").write_text("existing bundle")
    return resources


def run_preflight(*bundles):
    return subprocess.run([sys.executable, str(HELPER), *map(str, bundles)], capture_output=True, text=True, timeout=15)


def isolated_build(tmp_path, marker_pid):
    repo = tmp_path / "repo"
    packaging = repo / "packaging/macos"
    packaging.mkdir(parents=True)
    shutil.copy2(ROOT / "build.sh", repo / "build.sh")
    for helper in ("assert_bundle_stopped.py", "bundle_version.py"):
        shutil.copy2(ROOT / "packaging/macos" / helper, packaging / helper)
    (packaging / "NmapUIMenuBarLauncher.swift").write_text("// not compiled")
    (repo / "VERSION").write_text("v2026.10.25")
    resources = bundle_at(repo / "NmapUI.app")
    (resources / "nmapui-runtime.pid").write_text(str(marker_pid))
    installed = tmp_path / "selected-applications/NmapUI.app"
    bundle_at(installed)
    tools = tmp_path / "tools"
    tools.mkdir()
    sdk = tools / "xcrun"
    sdk.write_text('#!/bin/bash\nif [[ "$1" == "--show-sdk-path" ]]; then echo /test-sdk; else touch compiler-was-invoked; exit 99; fi\n')
    sdk.chmod(0o755)
    runtime = tmp_path / "shared-runtime"
    runtime.mkdir()
    lock = runtime / "auto_scan_scheduler.lock"
    lock.write_text("daemon owns this lock")
    original_inode = lock.stat().st_ino
    env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "NMAPUI_APPLICATIONS_DIR": str(installed.parent),
           "NMAPUI_DATA_DIR": str(runtime)}
    result = subprocess.run(["bash", str(repo / "build.sh")], cwd=repo, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "Refusing to replace active or unverified bundle" in result.stderr
    assert "Quit this copy of NmapUI" in result.stderr
    assert not (repo / "compiler-was-invoked").exists()
    assert (resources / "preserve-me").read_text() == "existing bundle"
    assert (installed / "Contents/Resources/preserve-me").read_text() == "existing bundle"
    assert (resources / "nmapui-runtime.pid").read_text() == str(marker_pid)
    assert lock.stat().st_ino == original_inode
    assert lock.read_text() == "daemon owns this lock"


def test_stale_marker_never_authorizes_signaling_unrelated_process(tmp_path):
    unrelated = subprocess.Popen(["/bin/sleep", "60"])
    try:
        isolated_build(tmp_path, unrelated.pid)
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_build_refuses_respawning_tree_without_signaling_or_orphaning_children(tmp_path):
    children_file = tmp_path / "children"
    owned = subprocess.Popen(["/bin/bash", "-c", "trap ':' TERM; while :; do /bin/sleep 60 & echo $! >> \"$1\"; wait $!; done", "owned-test", str(children_file)],
                             start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        while not children_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert children_file.exists()
        os.kill(owned.pid, signal.SIGTERM)  # Only the test causes a replacement child.
        while len(children_file.read_text().split()) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        descendants = list(map(int, children_file.read_text().split()))
        assert len(descendants) >= 2
        isolated_build(tmp_path, owned.pid)
        assert owned.poll() is None
        for pid in descendants:
            parent = subprocess.check_output(["/bin/ps", "-p", str(pid), "-o", "ppid="], text=True).strip()
            assert int(parent) == owned.pid, "Build must leave the entire live tree intact, not orphan children"
    finally:
        os.killpg(owned.pid, signal.SIGKILL)  # Exact process group created by this test.
        owned.wait(timeout=5)


def test_active_runtime_without_marker_blocks_replacement(tmp_path):
    bundle = tmp_path / "target.app"
    resources = bundle_at(bundle)
    child = subprocess.Popen(["/bin/sleep", "60"], cwd=resources)
    try:
        result = run_preflight(bundle)
        assert result.returncode != 0
        assert "active working directory" in result.stderr
        assert child.poll() is None
        assert (resources / "preserve-me").exists()
    finally:
        child.terminate()
        child.wait(timeout=5)


def test_unrelated_installed_bundle_is_untouched_by_selected_bundle_preflight(tmp_path):
    target = tmp_path / "selected/NmapUI.app"
    bundle_at(target)
    unrelated = tmp_path / "other-applications/NmapUI.app"
    resources = bundle_at(unrelated)
    process = subprocess.Popen(["/bin/sleep", "60"], cwd=resources)
    (resources / "nmapui-runtime.pid").write_text(str(process.pid))
    try:
        result = run_preflight(target)
        assert result.returncode == 0, result.stderr
        assert process.poll() is None
        assert (resources / "preserve-me").read_text() == "existing bundle"
        assert (resources / "nmapui-runtime.pid").read_text() == str(process.pid)
    finally:
        process.terminate()
        process.wait(timeout=5)
