"""Tests for unclean-shutdown recovery: stale jobs and orphaned processes."""

from pathlib import Path
import subprocess
import sys

from nmapui.handlers.auto_scan import acquire_auto_scan_scheduler_lock
from nmapui.jobs import ClientJobRegistry
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

    def list_jobs(self, *, statuses=None, job_type=None, limit=50):
        assert statuses == STALE_JOB_STATUSES
        return list(self._jobs)

    def upsert_job(self, *, job_id, owner_sid, job_type, status, payload):
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

    recovered = reconcile_interrupted_jobs(runtime_store=store)

    assert recovered == ["job-1"]
    upsert = store.upserts[0]
    assert upsert["status"] == "interrupted"
    assert upsert["payload"]["interrupted"] is True
    assert upsert["payload"]["target"] == "10.0.0.0/24"
    assert upsert["payload"]["finished_at"] == upsert["payload"]["interrupted_at"]


def test_reconcile_is_a_noop_without_a_runtime_store():
    assert reconcile_interrupted_jobs(runtime_store=None) == []


def test_reconcile_survives_a_failing_store():
    """A broken DB must degrade the scheduler, not crash startup."""
    assert reconcile_interrupted_jobs(runtime_store=ExplodingStore()) == []


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


def test_process_reaper_skips_signal_handlers_under_pytest():
    """Tests must not take over the process's signal handlers."""
    assert _signal_handlers_are_safe() is False

    registry = ClientJobRegistry()
    assert install_process_reaper(job_registry=registry) is False


def test_process_reaper_requires_a_registry():
    assert install_process_reaper(job_registry=None) is False


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
