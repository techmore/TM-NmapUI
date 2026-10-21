"""Pause / resume for scan jobs (issue #10).

A paused job stays ``status == "running"`` and carries ``paused`` /
``pause_requested`` / ``pause_mode`` so it keeps its capacity slot, blocks
maintenance and can still be cancelled.
"""

import os
import signal
import subprocess
import sys
import threading
import time

import pytest

from nmapui import jobs
from nmapui.jobs import ClientJobRegistry, run_cancellable_command
from nmapui.recovery import reconcile_interrupted_jobs
from nmapui.runtime_db import create_runtime_state_store

posix_only = pytest.mark.skipif(os.name != "posix", reason="Process suspension requires POSIX")

_TICK_SCRIPT = (
    "from pathlib import Path\n"
    "import sys, time\n"
    "path = Path(sys.argv[1])\n"
    "index = 0\n"
    "while True:\n"
    "    path.write_text(str(index))\n"
    "    index += 1\n"
    "    time.sleep(0.03)\n"
)


def _start_ticking_job(registry, tmp_path, sid="pause-sid", job_type="scan", timeout=None):
    """Run a ticking subprocess under the registry; returns (worker, result, ticks)."""
    assert registry.start(sid, job_type, {"target": "127.0.0.1"})
    ticks = tmp_path / "ticks.txt"
    result = {}

    def run():
        try:
            result["value"] = run_cancellable_command(
                registry,
                [sys.executable, "-c", _TICK_SCRIPT, str(ticks)],
                sid=sid,
                job_type=job_type,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced through the result dict
            result["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    deadline = time.monotonic() + 5
    while (not ticks.exists() or (sid, job_type) not in registry._processes) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ticks.exists() and (sid, job_type) in registry._processes, "the subprocess did not start"
    return worker, result, ticks


def _ticks_stay_frozen(ticks, seconds=0.3):
    first = ticks.read_text(encoding="utf-8")
    time.sleep(seconds)
    return ticks.read_text(encoding="utf-8") == first


@posix_only
def test_pause_suspends_the_scan_process_and_resume_continues_it(tmp_path):
    registry = ClientJobRegistry()
    worker, result, ticks = _start_ticking_job(registry, tmp_path)
    try:
        assert registry.pause("pause-sid", "scan") == (True, "paused")
        time.sleep(0.1)  # let an in-flight write land
        assert _ticks_stay_frozen(ticks), "a paused scan must stop making progress"

        job = registry.get("pause-sid", "scan")
        assert job["status"] == "running"  # still occupies its slot and stays cancellable
        assert job["paused"] is True and job["pause_requested"] is True
        assert job["pause_mode"] == "process"
        assert registry.is_paused("pause-sid", "scan")
        assert registry.snapshot()["active_jobs"][0]["paused"] is True

        before = ticks.read_text(encoding="utf-8")
        assert registry.resume("pause-sid", "scan") == (True, "resumed")
        deadline = time.monotonic() + 3
        while ticks.read_text(encoding="utf-8") == before and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ticks.read_text(encoding="utf-8") != before, "the resumed scan did not continue"
        job = registry.get("pause-sid", "scan")
        assert job["paused"] is False and job["pause_requested"] is False and job["pause_mode"] is None
        assert job["paused_seconds"] > 0
    finally:
        registry.cancel("pause-sid", "scan")
        worker.join(timeout=5)
    assert not worker.is_alive()


def test_pause_and_resume_reject_invalid_states():
    registry = ClientJobRegistry()
    assert registry.pause("nobody", "scan") == (False, "no_job")
    assert registry.resume("nobody", "scan") == (False, "no_job")

    assert registry.start("sid", "scan")
    source = registry.get("sid", "scan")["source_job_id"]
    assert registry.pause("sid", "scan", expected_source_job_id="old-run") == (False, "stale_job")
    assert registry.resume("sid", "scan") == (False, "not_paused")

    assert registry.pause("sid", "scan", expected_source_job_id=source)[0] is True
    assert registry.pause("sid", "scan") == (False, "already_paused")  # double pause is a no-op
    assert registry.resume("sid", "scan", expected_source_job_id="old-run") == (False, "stale_job")
    assert registry.resume("sid", "scan") == (True, "resumed")
    assert registry.resume("sid", "scan") == (False, "not_paused")

    registry.complete("sid", "scan")
    assert registry.pause("sid", "scan") == (False, "not_running")  # finished scan
    assert registry.resume("sid", "scan") == (False, "not_running")

    assert registry.start("sid-2", "scan")
    assert registry.cancel("sid-2", "scan")
    assert registry.pause("sid-2", "scan") == (False, "not_running")  # cancelled scan


def test_pause_is_unsupported_when_the_platform_cannot_suspend(monkeypatch):
    monkeypatch.setattr(jobs.os, "name", "nt")
    registry = ClientJobRegistry()
    assert registry.start("sid", "scan")
    assert registry.pause("sid", "scan") == (False, "unsupported")
    assert registry.get("sid", "scan")["pause_supported"] is False


def test_privileged_sudo_scans_pause_at_checkpoints_not_by_signal():
    sudo_scan = type("P", (), {"args": ["sudo", "-n", "/usr/local/libexec/nmapui-privileged-scanner", "nmap"]})()
    plain_scan = type("P", (), {"args": ["nmap", "-sn", "10.0.0.0/24"]})()
    assert jobs._process_is_pausable(sudo_scan) is False
    assert jobs._process_is_pausable(plain_scan) is (os.name == "posix")


def _wait_until_paused(registry, sid="sid"):
    deadline = time.monotonic() + 3
    while not registry.get(sid, "scan")["paused"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert registry.get(sid, "scan")["paused"] is True, "the checkpoint should make the pause effective"


def test_pause_without_a_stoppable_process_parks_the_workflow_at_the_next_checkpoint():
    registry = ClientJobRegistry()
    assert registry.start("sid", "scan")
    published = []

    assert registry.pause("sid", "scan") == (True, "pausing")
    job = registry.get("sid", "scan")
    assert job["pause_requested"] is True and job["paused"] is False and job["pause_mode"] == "checkpoint"

    reached = threading.Event()

    def workflow():
        jobs.ensure_job_not_cancelled(registry, "sid", "scan", on_pause=lambda: published.append("paused"))
        reached.set()

    worker = threading.Thread(target=workflow)
    worker.start()
    _wait_until_paused(registry)
    assert published == ["paused"]
    assert not reached.wait(0.3), "the workflow must stay parked while paused"

    assert registry.resume("sid", "scan") == (True, "resumed")
    assert reached.wait(3)
    worker.join(timeout=3)
    assert published == ["paused"]


def test_resuming_a_pending_pause_lets_the_workflow_run_without_parking():
    registry = ClientJobRegistry()
    assert registry.start("sid", "scan")
    assert registry.pause("sid", "scan")[0] is True
    assert registry.resume("sid", "scan")[0] is True
    jobs.ensure_job_not_cancelled(registry, "sid", "scan", on_pause=lambda: pytest.fail("never paused"))


def test_cancelling_a_parked_workflow_unblocks_and_cancels_it():
    registry = ClientJobRegistry()
    assert registry.start("sid", "scan")
    assert registry.pause("sid", "scan")[0] is True
    outcome = {}

    def workflow():
        try:
            jobs.ensure_job_not_cancelled(registry, "sid", "scan")
        except RuntimeError as exc:
            outcome["error"] = str(exc)

    worker = threading.Thread(target=workflow)
    worker.start()
    _wait_until_paused(registry)

    assert registry.cancel("sid", "scan") is True
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert outcome == {"error": "scan cancelled"}
    job = registry.get("sid", "scan")
    assert job["status"] == "cancelling" and job["paused"] is False and job["pause_requested"] is False


@posix_only
def test_cancelling_a_paused_scan_resumes_then_terminates_the_process_group(tmp_path):
    registry = ClientJobRegistry()
    worker, result, ticks = _start_ticking_job(registry, tmp_path)
    process = registry._processes[("pause-sid", "scan")]
    assert registry.pause("pause-sid", "scan") == (True, "paused")
    assert _ticks_stay_frozen(ticks)

    assert registry.cancel("pause-sid", "scan") is True
    worker.join(timeout=5)

    assert not worker.is_alive(), "cancelling a paused scan must not hang"
    assert isinstance(result.get("error"), RuntimeError) and str(result["error"]) == "scan cancelled"
    # A SIGTERM exit (not the SIGKILL fallback) proves the group was woken first.
    assert process.returncode == -signal.SIGTERM
    assert not jobs._scan_process_group_alive(process)
    assert ("pause-sid", "scan") not in registry._processes
    assert not registry.is_process_stopped("pause-sid", "scan")


@posix_only
def test_shutdown_terminates_a_paused_scan_cleanly(tmp_path):
    registry = ClientJobRegistry()
    worker, result, ticks = _start_ticking_job(registry, tmp_path)
    process = registry._processes[("pause-sid", "scan")]
    assert registry.pause("pause-sid", "scan") == (True, "paused")

    assert registry.terminate_all(grace_seconds=3) == 1
    worker.join(timeout=5)

    assert process.returncode == -signal.SIGTERM
    assert not jobs._scan_process_group_alive(process)


@posix_only
def test_paused_time_does_not_count_against_the_command_timeout(tmp_path):
    registry = ClientJobRegistry()
    worker, result, ticks = _start_ticking_job(registry, tmp_path, timeout=1.5)
    try:
        assert registry.pause("pause-sid", "scan") == (True, "paused")
        time.sleep(2.0)  # longer than the timeout
        assert worker.is_alive(), "a paused command must not time out"
        assert "error" not in result
        assert registry.resume("pause-sid", "scan")[0] is True
        worker.join(timeout=6)  # it then runs out its own remaining budget
        assert not worker.is_alive()
        assert isinstance(result.get("error"), subprocess.TimeoutExpired)
    finally:
        registry.cancel("pause-sid", "scan")
        worker.join(timeout=5)


@posix_only
def test_a_process_attached_while_a_pause_is_pending_is_stopped_immediately(tmp_path):
    registry = ClientJobRegistry()
    assert registry.start("sid", "scan")
    assert registry.pause("sid", "scan") == (True, "pausing")
    ticks = tmp_path / "ticks.txt"
    process = subprocess.Popen([sys.executable, "-c", _TICK_SCRIPT, str(ticks)], start_new_session=True)
    process._nmapui_process_group = True
    try:
        registry.attach_process("sid", "scan", process)
        job = registry.get("sid", "scan")
        assert job["paused"] is True and job["pause_mode"] == "process"
        assert registry.is_process_stopped("sid", "scan")
    finally:
        registry.cancel("sid", "scan")
        registry.terminate_all(grace_seconds=2)
        process.wait(timeout=5)


def test_pause_state_is_persisted_and_cleared_when_the_job_ends(tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    registry = ClientJobRegistry(runtime_store=store)
    assert registry.start("sid", "scan")
    job_id = f"source-job:{registry.get('sid', 'scan')['source_job_id']}"

    registry.pause("sid", "scan")
    assert store.get_job(job_id)["payload"]["pause_requested"] is True
    registry.resume("sid", "scan")
    assert store.get_job(job_id)["payload"]["pause_requested"] is False

    registry.pause("sid", "scan")
    registry.complete("sid", "scan")
    payload = store.get_job(job_id)["payload"]
    assert payload["paused"] is False and payload["pause_requested"] is False


def test_restart_recovery_does_not_leave_a_paused_job_paused(tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    registry = ClientJobRegistry(runtime_store=store)
    assert registry.start("sid", "scan")
    registry.pause("sid", "scan")
    job_id = f"source-job:{registry.get('sid', 'scan')['source_job_id']}"
    assert store.get_job(job_id)["payload"]["pause_requested"] is True

    # A new process has no in-memory registry; the persisted job is stale.
    assert reconcile_interrupted_jobs(runtime_store=store) == [job_id]
    saved = store.get_job(job_id)
    assert saved["status"] == "interrupted"
    assert saved["payload"]["paused"] is False and saved["payload"]["pause_requested"] is False
