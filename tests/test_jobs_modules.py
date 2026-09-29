import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from nmapui import jobs
from nmapui.jobs import ClientJobRegistry, RateLimiter, ScanBroadcaster, run_cancellable_command
from nmapui.runtime_db import create_runtime_state_store


def test_rate_limiter_records_and_allows_initial_scan():
    limiter = RateLimiter(max_scans_per_hour=1, cooldown_seconds=0)

    allowed, reason = limiter.can_scan()

    assert allowed is True
    assert reason is None

    limiter.record_scan()
    allowed, reason = limiter.can_scan()

    assert allowed is False
    assert "Rate limit reached" in reason


def test_client_job_registry_start_and_cancel():
    registry = ClientJobRegistry()

    assert registry.start("sid-1", "scan", {"target": "127.0.0.1"}) is True
    assert registry.cancel("sid-1", "scan") is True

    state = registry.get("sid-1", "scan")
    assert state["status"] == "cancelling"
    assert state["cancel_requested"] is True


@pytest.mark.skipif(os.name != "posix", reason="Subprocess cancellation requires POSIX")
@pytest.mark.parametrize("job_type", ["scan", "report"])
def test_cancelling_active_job_terminates_its_subprocess(tmp_path, job_type):
    registry = ClientJobRegistry()
    sid = f"cancel-{job_type}"
    assert registry.start(sid, job_type, {"target": "127.0.0.1"})
    ticks = tmp_path / f"{job_type}-ticks.txt"
    command = (
        "from pathlib import Path\n"
        "import sys, time\n"
        "path = Path(sys.argv[1])\n"
        "index = 0\n"
        "while True:\n"
        "    path.write_text(str(index))\n"
        "    index += 1\n"
        "    time.sleep(0.03)\n"
    )
    result = {}

    def run_job_command():
        try:
            result["value"] = run_cancellable_command(
                registry,
                [sys.executable, "-c", command, str(ticks)],
                sid=sid,
                job_type=job_type,
            )
        except Exception as exc:
            result["error"] = exc

    worker = threading.Thread(target=run_job_command)
    worker.start()
    deadline = time.monotonic() + 5
    while not ticks.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ticks.exists(), "the cancellable subprocess did not start"

    assert registry.cancel(sid, job_type)
    worker.join(timeout=5)

    assert not worker.is_alive(), "cancelled subprocess worker did not exit"
    assert isinstance(result.get("error"), RuntimeError)
    assert str(result["error"]) == f"{job_type} cancelled"
    assert (sid, job_type) not in registry._processes
    last_tick = ticks.read_text(encoding="utf-8")
    time.sleep(0.1)
    assert ticks.read_text(encoding="utf-8") == last_tick


def test_scan_signal_falls_back_to_leader_when_group_has_disappeared(monkeypatch):
    class ProcessStub:
        pid = 12345
        _nmapui_process_group = True
        terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

    def missing_group(_pid, _signal):
        raise ProcessLookupError

    monkeypatch.setattr(jobs.os, "killpg", missing_group)
    process = ProcessStub()
    jobs._signal_scan_process(process, signal.SIGTERM)

    assert process.terminated is True


@pytest.mark.skipif(os.name != "posix", reason="Scan process groups require POSIX")
def test_scan_timeout_stops_a_spawned_child_process(tmp_path):
    ticks = tmp_path / "ticks.txt"
    child_code = (
        "from pathlib import Path; import sys,time; "
        "path=Path(sys.argv[1]); "
        "[(path.write_text(str(i)), time.sleep(0.08)) for i in range(100)]"
    )
    parent_code = (
        "import subprocess,sys; "
        "subprocess.run([sys.executable, '-c', sys.argv[1], sys.argv[2]])"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        run_cancellable_command(
            None,
            [sys.executable, "-c", parent_code, child_code, str(ticks)],
            timeout=1.2,
        )

    assert ticks.exists()
    last_tick = ticks.read_text()
    time.sleep(0.35)
    assert ticks.read_text() == last_tick


@pytest.mark.skipif(os.name != "posix", reason="Scan process groups require POSIX")
def test_scan_subprocess_is_reaped_when_registry_check_raises(tmp_path):
    ticks = tmp_path / "ticks.txt"
    command = (
        "from pathlib import Path; import sys,time; "
        "path=Path(sys.argv[1]); "
        "[(path.write_text(str(i)), time.sleep(0.05)) for i in range(100)]"
    )

    class FailingRegistry:
        cleared = False

        def attach_process(self, sid, job_type, process):
            self.process = process

        def is_cancelled(self, sid, job_type):
            raise RuntimeError("registry check failed")

        def clear_process(self, sid, job_type):
            self.cleared = True

    registry = FailingRegistry()
    with pytest.raises(RuntimeError, match="registry check failed"):
        run_cancellable_command(
            registry, [sys.executable, "-c", command, str(ticks)],
            sid="sid-1", job_type="scan",
        )

    assert registry.cleared is True
    assert ticks.exists()
    last_tick = ticks.read_text()
    time.sleep(0.2)
    assert ticks.read_text() == last_tick


@pytest.mark.skipif(os.name != "posix", reason="Scan process groups require POSIX")
def test_successful_scan_command_does_not_leave_an_orphaned_child(tmp_path):
    ticks = tmp_path / "orphan-ticks.txt"
    child_pid_path = tmp_path / "orphan.pid"
    child_code = (
        "import signal,sys,time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "path=Path(sys.argv[1])\n"
        "index=0\n"
        "while True:\n"
        " path.write_text(str(index)); index+=1; time.sleep(0.05)\n"
    )
    parent_code = (
        "import subprocess,sys,time\n"
        "from pathlib import Path\n"
        "child=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "Path(sys.argv[3]).write_text(str(child.pid))\n"
        "time.sleep(0.2)\n"
    )
    result = run_cancellable_command(
        None, [sys.executable, "-c", parent_code, child_code, str(ticks), str(child_pid_path)],
    )
    child_pid = int(child_pid_path.read_text())
    try:
        assert result.returncode == 0
        assert ticks.exists()
        last_tick = ticks.read_text()
        time.sleep(0.2)
        assert ticks.read_text() == last_tick
    finally:
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_shutdown_rejects_new_jobs():
    registry = ClientJobRegistry()

    assert registry.terminate_all() == 0
    assert registry.start("sid-1", "scan") is False
    assert registry.get_start_rejection_reason("sid-1", "scan") == "Scanner is shutting down"


@pytest.mark.skipif(os.name != "posix", reason="Scan process groups require POSIX")
def test_scan_spawned_after_shutdown_snapshot_is_reaped(monkeypatch):
    registry = ClientJobRegistry()
    assert registry.terminate_all() == 0
    created = []
    original_popen = subprocess.Popen

    def tracked_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        created.append(process)
        return process

    monkeypatch.setattr(jobs.subprocess, "Popen", tracked_popen)
    try:
        with pytest.raises(RuntimeError, match="Scanner is shutting down"):
            run_cancellable_command(
                registry, [sys.executable, "-c", "import time; time.sleep(30)"],
                sid="sid-1", job_type="scan",
            )
        assert len(created) == 1
        created[0].wait(timeout=5)
        assert created[0].returncode is not None
    finally:
        for process in created:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def test_client_job_registry_enforces_global_active_job_capacity():
    registry = ClientJobRegistry(max_active_jobs=1)

    assert registry.start("sid-1", "scan") is True
    assert registry.start("sid-2", "report") is False
    assert "capacity" in registry.get_start_rejection_reason("sid-2", "report").lower()

    registry.complete("sid-1", "scan")
    assert registry.start("sid-2", "report") is True


def test_client_job_registry_does_not_restart_a_cancelling_job():
    registry = ClientJobRegistry(max_active_jobs=2)
    assert registry.start("sid-1", "scan") is True
    assert registry.cancel("sid-1", "scan") is True
    assert registry.start("sid-1", "scan") is False
    assert registry.get("sid-1", "scan")["status"] == "cancelling"


def test_client_job_registry_persists_jobs_to_runtime_store(tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    registry = ClientJobRegistry(runtime_store=store)

    assert registry.start("sid-1", "report", {"target": "10.0.0.0/24"}) is True
    registry.update("sid-1", "report", phase="rendering", details={"progress": 50})
    registry.complete("sid-1", "report", status="completed", details={"path": "scan_report.pdf"})

    persisted = store.get_job("sid-1:report")

    assert persisted is not None
    assert persisted["job_type"] == "report"
    assert persisted["status"] == "completed"
    assert persisted["payload"]["details"]["target"] == "10.0.0.0/24"
    assert persisted["payload"]["details"]["path"] == "scan_report.pdf"


def test_scan_broadcaster_subscribes_existing_connected_tabs_when_job_starts():
    broadcaster = ScanBroadcaster()

    broadcaster.register_client("sid-1")
    broadcaster.register_client("sid-2")
    broadcaster.start_job("sid-1", job_type="scan")

    assert broadcaster.get_subscribers("sid-1", job_type="scan") == {"sid-1", "sid-2"}
