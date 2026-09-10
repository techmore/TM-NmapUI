"""Recover cleanly from an unclean shutdown.

Two problems this solves for an appliance that restarts unattended:

1. Jobs persisted as ``running`` by a previous process are replayed to every
   new browser as "running" forever, permanently disabling the report button.
2. Child ``nmap``/``arp-scan`` processes are only tracked in memory, so a crash
   or a SIGKILL leaves them orphaned, holding sockets and CPU.

``reconcile_interrupted_jobs`` marks stale jobs interrupted at startup.
``install_process_reaper`` terminates tracked children on SIGTERM/SIGINT and at
process exit.
"""

from __future__ import annotations

import atexit
import logging
import os
import signal
import sys
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

STALE_JOB_STATUSES = ("running", "cancelling")


def reconcile_interrupted_jobs(*, runtime_store, logger=logger) -> list[str]:
    """Mark jobs left running by a previous process as interrupted.

    Returns the job ids that were reconciled.
    """
    if runtime_store is None or not hasattr(runtime_store, "list_jobs"):
        return []

    try:
        stale_jobs = runtime_store.list_jobs(statuses=STALE_JOB_STATUSES, limit=200)
    except Exception as exc:
        logger.error("Could not list persisted jobs for startup recovery: %s", exc)
        return []

    interrupted: list[str] = []
    for job in stale_jobs or []:
        job_id = job.get("job_id")
        if not job_id:
            continue
        payload = dict(job.get("payload") or {})
        finished_at = datetime.now(timezone.utc).isoformat()
        payload.update(
            {
                "interrupted": True,
                "recovery_note": "Process restarted while this job was running",
                "finished_at": finished_at,
                "interrupted_at": finished_at,
            }
        )
        try:
            runtime_store.upsert_job(
                job_id=job_id,
                owner_sid=job.get("owner_sid"),
                job_type=job.get("job_type") or "report",
                status="interrupted",
                payload=payload,
            )
            interrupted.append(job_id)
        except Exception as exc:
            logger.error("Failed to mark job %s as interrupted: %s", job_id, exc)

    if interrupted:
        logger.warning(
            "Recovered %d job(s) left running by a previous process: %s",
            len(interrupted),
            ", ".join(interrupted),
        )
    return interrupted


def _signal_handlers_are_safe() -> bool:
    """Signal handlers may only be installed on the main thread, and must not
    be installed while a test runner owns the process."""
    if threading.current_thread() is not threading.main_thread():
        return False
    if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    return True


def install_process_reaper(*, job_registry, logger=logger) -> bool:
    """Terminate tracked child processes on shutdown signals and at exit.

    Returns True when signal handlers were installed.
    """
    if job_registry is None or not hasattr(job_registry, "terminate_all"):
        return False

    # Always safe: runs on any interpreter exit path, including exceptions.
    atexit.register(job_registry.terminate_all)

    if not _signal_handlers_are_safe():
        return False

    def _handle_shutdown(signum, _frame):
        logger.warning(
            "Received signal %s; terminating tracked scan processes before exit",
            signum,
        )
        try:
            job_registry.terminate_all()
        except Exception:
            logger.exception("Failed to terminate scan processes during shutdown")
        raise SystemExit(128 + signum)

    installed = False
    for name in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            signal.signal(signum, _handle_shutdown)
            installed = True
        except (ValueError, OSError):
            logger.debug("Could not install %s handler", name)
    return installed
