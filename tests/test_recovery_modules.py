"""Tests for unclean-shutdown recovery: stale jobs and orphaned processes."""

from pathlib import Path
import os
import signal
import subprocess
import sys
import time

import pytest

from nmapui.handlers.auto_scan import acquire_auto_scan_scheduler_lock
from nmapui.jobs import ClientJobRegistry
from nmapui.runtime_db import create_runtime_state_store
from nmapui.recovery import (
    STALE_JOB_STATUSES,
    _signal_handlers_are_safe,
    install_process_reaper,
    reconcile_interrupted_jobs,
)


class RuntimeStoreStub:
    def __init__(self, jobs):
        self._jobs = jobs
        self.upserts = []
        for index, job in enumerate(self._jobs):
            job.setdefault("updated_at", f"{len(self._jobs) - index:08d}")

    def list_jobs(self, *, statuses=None, job_type=None, limit=50, before=None):
        assert statuses == STALE_JOB_STATUSES
        rows = [job for job in self._jobs if job["status"] in statuses]
        if before is not None:
            rows = [job for job in rows if (job["updated_at"], job["job_id"]) < before]
        return sorted(rows, key=lambda job: (job["updated_at"], job["job_id"]), reverse=True)[:limit]

    def upsert_job(self, *, job_id, owner_sid, job_type, status, payload):
        for job in self._jobs:
            if job["job_id"] == job_id:
                job["status"] = status
                job["payload"] = payload
                break
        self.upserts.append(
            {
                "job_id": job_id,
                "owner_sid": owner_sid,
                "job_type": job_type,
                "status": status,
                "payload": payload,
            }
        )


class ExplodingStore:
    def list_jobs(self, **_kwargs):
        raise RuntimeError("database is locked")


class ProcessStub:
    def __init__(self, running=True):
        self.running = running
        self.terminated = False

    def poll(self):
        return None if self.running else 1

    def terminate(self):
        self.terminated = True
        self.running = False


def test_reconcile_marks_running_jobs_interrupted():
    store = RuntimeStoreStub(
        [
            {
                "job_id": "job-1",
                "owner_sid": "__auto_scan__",
                "job_type": "report",
                "status": "running",
                "payload": {"target": "10.0.0.0/24"},
            }
        ]
    )

    recovery_status = {}
    recovered = reconcile_interrupted_jobs(runtime_store=store, status=recovery_status)

    assert recovered == ["job-1"]
    upsert = store.upserts[0]
    assert upsert["status"] == "interrupted"
    assert upsert["payload"]["interrupted"] is True
    assert upsert["payload"]["target"] == "10.0.0.0/24"
    assert upsert["payload"]["finished_at"] == upsert["payload"]["interrupted_at"]
    assert recovery_status == {"ok": True, "failed_jobs": 0, "listing_error": None}


def test_reconcile_is_a_noop_without_a_runtime_store():
    assert reconcile_interrupted_jobs(runtime_store=None) == []


def test_reconcile_drains_more_than_one_batch_of_stale_jobs(caplog):
    store = RuntimeStoreStub([
        {"job_id": f"job-{index}", "owner_sid": "sid", "job_type": "scan",
         "status": "running", "payload": {}}
        for index in range(235)
    ])

    recovered = reconcile_interrupted_jobs(runtime_store=store)

    assert len(recovered) == 235
    assert len(store.upserts) == 235
    assert all(job["status"] == "interrupted" for job in store._jobs)
    assert "(+225 more)" in caplog.text


def test_reconcile_does_not_retry_failed_job_forever():
    class PartlyFailingStore(RuntimeStoreStub):
        def upsert_job(self, **kwargs):
            if kwargs["job_id"] == "job-0":
                raise RuntimeError("simulated write failure")
            super().upsert_job(**kwargs)

    store = PartlyFailingStore([
        {"job_id": f"job-{index}", "owner_sid": "sid", "job_type": "scan",
         "status": "running", "payload": {}}
        for index in range(235)
    ])

    recovered = reconcile_interrupted_jobs(runtime_store=store)

    assert len(recovered) == 234
    assert store._jobs[0]["status"] == "running"
    assert all(job["status"] == "interrupted" for job in store._jobs[1:])


def test_reconcile_reaches_later_batches_even_when_first_batch_all_fail(caplog):
    class FirstBatchFailingStore(RuntimeStoreStub):
        def __init__(self, jobs):
            super().__init__(jobs)
            self.attempted = []

        def upsert_job(self, **kwargs):
            self.attempted.append(kwargs["job_id"])
            if int(kwargs["job_id"].split("-")[-1]) < 200:
                raise RuntimeError("simulated write failure")
            super().upsert_job(**kwargs)

    store = FirstBatchFailingStore([
        {"job_id": f"job-{index}", "owner_sid": "sid", "job_type": "scan",
         "status": "running", "payload": {}}
        for index in range(235)
    ])

    recovery_status = {}
    recovered = reconcile_interrupted_jobs(runtime_store=store, status=recovery_status)

    assert len(store.attempted) == 235
    assert len(set(store.attempted)) == 235
    assert len(recovered) == 35
    assert all(job["status"] == "running" for job in store._jobs[:200])
    assert all(job["status"] == "interrupted" for job in store._jobs[200:])
    assert recovery_status == {"ok": False, "failed_jobs": 200, "listing_error": None}
    assert "suppressed 190 additional" in caplog.text


def test_reconcile_drains_multiple_batches_from_runtime_database(tmp_path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    for index in range(205):
        store.upsert_job(
            job_id=f"job-{index}", owner_sid="sid", job_type="scan",
            status="running", payload={"target": "127.0.0.1"},
        )

    recovered = reconcile_interrupted_jobs(runtime_store=store)

    assert len(recovered) == 205
    assert store.list_jobs(statuses=STALE_JOB_STATUSES, limit=500) == []


def test_reconcile_survives_a_failing_store():
    """A broken DB must degrade the scheduler, not crash startup."""
    recovery_status = {}
    assert reconcile_interrupted_jobs(runtime_store=ExplodingStore(), status=recovery_status) == []
    assert recovery_status == {
        "ok": False, "failed_jobs": 0, "listing_error": "Could not list persisted jobs",
    }


def test_terminate_all_terminates_tracked_processes():
    registry = ClientJobRegistry()
    running = ProcessStub(running=True)
    finished = ProcessStub(running=False)
    registry.attach_process("sid-1", "report", running)
    registry.attach_process("sid-1", "scan", finished)

    signalled = registry.terminate_all()

    assert signalled == 1
    assert running.terminated is True
    assert finished.terminated is False


def test_terminate_all_is_safe_after_processes_cleared():
    registry = ClientJobRegistry()
    registry.attach_process("sid-1", "report", ProcessStub(running=True))

    assert registry.terminate_all() == 1
    # A second call must not raise or double-count.
    assert registry.terminate_all() == 0


@pytest.mark.skipif(os.name != "posix", reason="Scan process groups require POSIX")
def test_shutdown_reaper_kills_scan_group_that_ignores_sigterm(tmp_path):
    ticks = tmp_path / "ticks.txt"
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
        "import signal,subprocess,sys,time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]], "
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "while True: time.sleep(1)\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", parent_code, child_code, str(ticks)],
        start_new_session=True,
    )
    process._nmapui_process_group = True
    try:
        deadline = time.monotonic() + 5
        while not ticks.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ticks.exists(), "Stubborn child never started"

        registry = ClientJobRegistry()
        registry.attach_process("sid-1", "scan", process)
        assert registry.terminate_all(grace_seconds=0.3) == 1
        process.wait(timeout=5)

        last_tick = ticks.read_text()
        time.sleep(0.2)
        assert ticks.read_text() == last_tick
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.wait(timeout=5)


def test_process_reaper_skips_signal_handlers_under_pytest():
    """Tests must not take over the process's signal handlers."""
    assert _signal_handlers_are_safe() is False

    registry = ClientJobRegistry()
    assert install_process_reaper(job_registry=registry) is False


def test_process_reaper_ignores_reentrant_signals_without_buffered_logging(monkeypatch):
    from nmapui import recovery

    handlers = {}
    notices = []
    calls = []
    monkeypatch.setattr(recovery, "_signal_handlers_are_safe", lambda: True)
    monkeypatch.setattr(recovery.atexit, "register", lambda callback: None)
    monkeypatch.setattr(recovery.signal, "signal", lambda signum, handler: handlers.update({signum: handler}))
    monkeypatch.setattr(recovery.os, "write", lambda fd, message: notices.append((fd, message)))

    class Registry:
        def terminate_all(self):
            calls.append(True)
            handlers[signal.SIGTERM](signal.SIGTERM, None)

    class BufferedLogger:
        def warning(self, *args):
            raise AssertionError("Signal handler must not reenter buffered logging")

    assert install_process_reaper(job_registry=Registry(), logger=BufferedLogger())
    with pytest.raises(SystemExit) as stopped:
        handlers[signal.SIGTERM](signal.SIGTERM, None)
    assert stopped.value.code == 128 + signal.SIGTERM
    assert calls == [True]
    assert len(notices) == 1 and notices[0][0] == 2


def test_process_reaper_requires_a_registry():
    assert install_process_reaper(job_registry=None) is False


@pytest.mark.skipif(os.name != "posix", reason="Signal-based reaping requires POSIX")
def test_application_sigterm_reaps_stubborn_tracked_scan(tmp_path):
    import select

    ticks = tmp_path / "signal-ticks.txt"
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
        "import app,subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]], "
        "start_new_session=True)\n"
        "child._nmapui_process_group=True\n"
        "app.job_registry.attach_process('sid-1','scan',child)\n"
        "print('ready:'+str(child.pid),flush=True)\n"
        "while True: time.sleep(1)\n"
    )
    environment = dict(os.environ)
    environment.pop("PYTEST_CURRENT_TEST", None)
    environment.update({
        "NMAPUI_DATA_DIR": str(tmp_path / "data"),
        "NMAPUI_LOG_DIR": str(tmp_path / "logs"),
        "NMAPUI_SKIP_LEGACY_MIGRATION": "1",
    })
    process = subprocess.Popen(
        [sys.executable, "-c", parent_code, child_code, str(ticks)],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    child_pid = None
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert process.poll() is None, process.stderr.read()
            readable, _, _ = select.select([process.stdout], [], [], 0.2)
            if readable:
                line = process.stdout.readline().strip()
                if line.startswith("ready:"):
                    child_pid = int(line.split(":", 1)[1])
                    break
        assert child_pid is not None, "Application did not attach its scan child"
        deadline = time.monotonic() + 5
        while not ticks.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ticks.exists(), "Stubborn scan child never started"

        process.terminate()
        process.wait(timeout=10)
        last_tick = ticks.read_text()
        time.sleep(0.2)
        assert ticks.read_text() == last_tick
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if child_pid is not None:
            try:
                os.killpg(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_scheduler_lock_releases_after_owner_is_killed(tmp_path):
    """A real process crash must not permanently suppress scheduled work."""
    lock_path = tmp_path / "scheduler.lock"
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from nmapui.handlers.auto_scan import acquire_auto_scan_scheduler_lock\n"
        "lock = acquire_auto_scan_scheduler_lock(lock_file=Path(sys.argv[1]))\n"
        "assert lock is not None\n"
        "print('locked', flush=True)\n"
        "sys.stdin.read()\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(lock_path)],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        import select

        readable, _, _ = select.select([process.stdout], [], [], 10)
        assert readable, "Lock owner failed to start within ten seconds"
        assert process.stdout.readline().strip() == "locked"
        assert acquire_auto_scan_scheduler_lock(lock_file=lock_path) is None
        process.kill()
        process.wait(timeout=10)
        recovered = acquire_auto_scan_scheduler_lock(lock_file=lock_path)
        assert recovered is not None
        recovered.close()
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)
