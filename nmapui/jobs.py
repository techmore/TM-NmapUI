from datetime import datetime, timedelta
import logging
import os
import signal
import subprocess
import threading
import time


logger = logging.getLogger(__name__)


def _signal_scan_process(process: subprocess.Popen, sig: int) -> None:
    """Signal a scan's whole process group, including sudo/helper children."""
    if getattr(process, "_nmapui_process_group", False) and os.name == "posix":
        try:
            os.killpg(process.pid, sig)
            return
        except ProcessLookupError:
            pass
        except OSError:
            logger.exception("Failed to signal scan process group %s", process.pid)
    if process.poll() is None:
        if sig == signal.SIGKILL:
            process.kill()
        else:
            process.terminate()


def _scan_process_group_alive(process: subprocess.Popen) -> bool:
    if getattr(process, "_nmapui_process_group", False) and os.name == "posix":
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    return process.poll() is None


class RateLimiter:
    """Simple in-memory rate limiter for scan operations."""

    def __init__(self, max_scans_per_hour=10, cooldown_seconds=300):
        self.max_scans_per_hour = max_scans_per_hour
        self.cooldown_seconds = cooldown_seconds
        self.scan_timestamps = []
        self.last_scan_time = None
        self._lock = threading.Lock()

    def can_scan(self):
        with self._lock:
            now = datetime.now()

            if self.last_scan_time:
                elapsed = (now - self.last_scan_time).total_seconds()
                if elapsed < self.cooldown_seconds:
                    logger.warning(
                        "Scan cooldown active. Wait %ss more",
                        int(self.cooldown_seconds - elapsed),
                    )
                    return (
                        False,
                        f"Cooldown active. Try again in {int(self.cooldown_seconds - elapsed)}s",
                    )

            one_hour_ago = now - timedelta(hours=1)
            recent_scans = [ts for ts in self.scan_timestamps if ts > one_hour_ago]
            if len(recent_scans) >= self.max_scans_per_hour:
                logger.warning("Rate limit reached: %s scans/hour", self.max_scans_per_hour)
                return False, f"Rate limit reached ({self.max_scans_per_hour} scans/hour)"

            return True, None

    def record_scan(self):
        with self._lock:
            now = datetime.now()
            self.scan_timestamps.append(now)
            self.last_scan_time = now

            one_hour_ago = now - timedelta(hours=1)
            self.scan_timestamps = [ts for ts in self.scan_timestamps if ts > one_hour_ago]
            logger.info("Scan recorded. Total in last hour: %s", len(self.scan_timestamps))


class ScanBroadcaster:
    """
    Multi-tab delivery for active scan jobs.

    - The 'owner' sid is the tab that started the scan.
    - Additional tabs subscribe and receive all future events.
    - A replay buffer lets late-joining tabs catch up instantly.
    """

    MAX_BUFFER = 500

    def __init__(self):
        self._lock = threading.Lock()
        self._connected_sids: set[str] = set()
        # job_type -> owner_sid -> frozenset-like mutable set of subscriber sids
        self._subscribers: dict[str, dict[str, set[str]]] = {}
        # job_type -> owner_sid -> list of (event, data) tuples
        self._buffer: dict[str, dict[str, list]] = {}

    def register_client(self, sid: str) -> None:
        with self._lock:
            self._connected_sids.add(sid)

    def start_job(self, owner_sid: str, job_type: str = "scan") -> None:
        """Call when a scan starts — creates the slot."""
        with self._lock:
            subscriber_set = set(self._connected_sids) or {owner_sid}
            subscriber_set.add(owner_sid)
            self._subscribers.setdefault(job_type, {})[owner_sid] = subscriber_set
            self._buffer.setdefault(job_type, {})[owner_sid] = []

    def end_job(self, owner_sid: str, job_type: str = "scan") -> None:
        """Call when a scan ends — tears down the slot."""
        with self._lock:
            self._subscribers.get(job_type, {}).pop(owner_sid, None)
            self._buffer.get(job_type, {}).pop(owner_sid, None)

    def record(self, owner_sid: str, event: str, data, job_type: str = "scan") -> None:
        """Store an event in the replay buffer for this job."""
        with self._lock:
            buf = self._buffer.get(job_type, {}).get(owner_sid)
            if buf is not None:
                buf.append((event, data))
                if len(buf) > self.MAX_BUFFER:
                    buf[:] = buf[-self.MAX_BUFFER :]

    def get_subscribers(self, owner_sid: str, job_type: str = "scan") -> set[str]:
        with self._lock:
            return set(self._subscribers.get(job_type, {}).get(owner_sid, set()))

    def get_replay_buffer(self, owner_sid: str, job_type: str = "scan") -> list:
        with self._lock:
            return list(self._buffer.get(job_type, {}).get(owner_sid, []))

    def subscribe(self, owner_sid: str, new_sid: str, job_type: str = "scan") -> bool:
        """Add a late-joining tab. Returns False if job no longer active."""
        with self._lock:
            if owner_sid not in self._subscribers.get(job_type, {}):
                return False
            self._subscribers[job_type][owner_sid].add(new_sid)
            return True

    def unsubscribe(self, sid: str) -> None:
        """Remove a sid from every subscription set (call on disconnect)."""
        with self._lock:
            for subscriber_map in self._subscribers.values():
                for subs in subscriber_map.values():
                    subs.discard(sid)
            self._connected_sids.discard(sid)

    def find_active_owner(self, job_type: str = "scan") -> str | None:
        """Return any active job owner sid for the given job type."""
        with self._lock:
            return next(iter(self._subscribers.get(job_type, {})), None)

    def is_active(self) -> bool:
        with self._lock:
            return any(self._subscribers.values())


class PerClientRateLimiter:
    """Per-session rate limiter so one client cannot block others."""

    def __init__(self, max_scans_per_hour=10, cooldown_seconds=300):
        self._max_scans_per_hour = max_scans_per_hour
        self._cooldown_seconds = cooldown_seconds
        self._clients: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def _get(self, sid: str) -> RateLimiter:
        with self._lock:
            if sid not in self._clients:
                self._clients[sid] = RateLimiter(
                    max_scans_per_hour=self._max_scans_per_hour,
                    cooldown_seconds=self._cooldown_seconds,
                )
            return self._clients[sid]

    def can_scan(self, sid: str):
        return self._get(sid).can_scan()

    def record_scan(self, sid: str):
        self._get(sid).record_scan()

    def remove_client(self, sid: str):
        with self._lock:
            self._clients.pop(sid, None)


class ClientJobRegistry:
    """Track active scan/report jobs per connected client."""

    def __init__(self, runtime_store=None, max_active_jobs=None):
        self._jobs = {}
        self._lock = threading.Lock()
        self._processes = {}
        self._shutting_down = False
        self._runtime_store = runtime_store
        self._max_active_jobs = (
            max(1, int(max_active_jobs)) if max_active_jobs is not None else None
        )
        self._start_rejections = {}

    def _job_id(self, sid: str, job_type: str) -> str:
        return f"{sid}:{job_type}"

    def _persist_job(self, sid: str, job_type: str) -> None:
        if self._runtime_store is None:
            return
        job = self._jobs.get((sid, job_type))
        if not job:
            return
        self._runtime_store.upsert_job(
            job_id=self._job_id(sid, job_type),
            owner_sid=sid,
            job_type=job_type,
            status=job.get("status", "idle"),
            payload={
                "cancel_requested": bool(job.get("cancel_requested")),
                "details": dict(job.get("details", {})),
                "started_at": job.get("started_at"),
                "finished_at": job.get("finished_at"),
                "cancel_requested_at": job.get("cancel_requested_at"),
                "disconnected": bool(job.get("disconnected")),
            },
        )

    def start(self, sid: str, job_type: str, details=None) -> bool:
        with self._lock:
            key = (sid, job_type)
            if self._shutting_down:
                self._start_rejections[key] = "Scanner is shutting down"
                return False
            job = self._jobs.get(key)
            if job and job.get("status") in {"running", "cancelling"}:
                self._start_rejections[key] = "A job of this type is already running for this client"
                return False
            active_count = sum(
                1
                for active_job in self._jobs.values()
                if active_job.get("status") in {"running", "cancelling"}
            )
            if self._max_active_jobs is not None and active_count >= self._max_active_jobs:
                self._start_rejections[key] = (
                    "Scanner capacity is currently in use; try again when an active job finishes"
                )
                return False
            self._start_rejections.pop(key, None)
            self._jobs[key] = {
                "status": "running",
                "started_at": datetime.now().isoformat(),
                "cancel_requested": False,
                "details": details or {},
            }
            self._persist_job(sid, job_type)
            return True

    def get_start_rejection_reason(self, sid: str, job_type: str) -> str | None:
        with self._lock:
            return self._start_rejections.get((sid, job_type))

    def complete(self, sid: str, job_type: str, status="completed", details=None):
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key, {})
            current.update({"status": status, "finished_at": datetime.now().isoformat()})
            if details:
                merged = dict(current.get("details", {}))
                merged.update(details)
                current["details"] = merged
            self._jobs[key] = current
            self._persist_job(sid, job_type)

    def update(self, sid: str, job_type: str, details=None, **fields):
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key)
            if not current:
                return
            current.update(fields)
            if details:
                merged = dict(current.get("details", {}))
                merged.update(details)
                current["details"] = merged
            self._jobs[key] = current
            self._persist_job(sid, job_type)

    def cancel(self, sid: str, job_type: str) -> bool:
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key)
            if not current or current.get("status") != "running":
                return False
            current["cancel_requested"] = True
            current["status"] = "cancelling"
            current["cancel_requested_at"] = datetime.now().isoformat()
            self._jobs[key] = current

            process = self._processes.get(key)
            if process:
                try:
                    _signal_scan_process(process, signal.SIGTERM)
                except Exception:
                    logger.exception("Failed to terminate subprocess for %s", key)
            self._persist_job(sid, job_type)
            return True

    def is_cancelled(self, sid: str, job_type: str) -> bool:
        with self._lock:
            job = self._jobs.get((sid, job_type))
            return bool(job and job.get("cancel_requested"))

    def attach_process(self, sid: str, job_type: str, process: subprocess.Popen):
        with self._lock:
            if self._shutting_down:
                raise RuntimeError("Scanner is shutting down")
            self._processes[(sid, job_type)] = process

    def clear_process(self, sid: str, job_type: str):
        with self._lock:
            self._processes.pop((sid, job_type), None)

    def terminate_all(self, *, grace_seconds: float = 2.0) -> int:
        """Terminate every tracked child process. Returns the count signalled.

        Called by the shutdown reaper so a crash or SIGTERM does not leave
        orphaned nmap/arp-scan processes behind.
        """
        with self._lock:
            self._shutting_down = True
            processes = list(self._processes.items())
            self._processes.clear()

        signalled = []
        for key, process in processes:
            try:
                if _scan_process_group_alive(process):
                    _signal_scan_process(process, signal.SIGTERM)
                    signalled.append(process)
            except Exception:
                logger.exception("Failed to terminate subprocess for %s", key)

        deadline = time.monotonic() + max(0.0, grace_seconds)
        while signalled and time.monotonic() < deadline:
            if not any(_scan_process_group_alive(process) for process in signalled):
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        for process in signalled:
            try:
                if _scan_process_group_alive(process):
                    _signal_scan_process(process, signal.SIGKILL)
            except Exception:
                logger.exception("Failed to kill stubborn scan process group %s", process.pid)
        return len(signalled)

    def get(self, sid: str, job_type: str):
        with self._lock:
            job = self._jobs.get((sid, job_type))
            return dict(job) if job else None

    def snapshot(self):
        with self._lock:
            jobs = []
            for (sid, job_type), job in self._jobs.items():
                jobs.append(
                    {
                        "sid": sid,
                        "job_type": job_type,
                        "status": job.get("status"),
                        "started_at": job.get("started_at"),
                        "finished_at": job.get("finished_at"),
                        "details": dict(job.get("details", {})),
                        "cancel_requested": bool(job.get("cancel_requested")),
                        "disconnected": bool(job.get("disconnected")),
                    }
                )

            active_jobs = [
                job for job in jobs if job.get("status") in {"running", "cancelling"}
            ]
            return {
                "has_active_jobs": bool(active_jobs),
                "active_jobs": active_jobs,
                "jobs": jobs,
            }

    def mark_disconnected(self, sid: str):
        with self._lock:
            for key in list(self._start_rejections):
                if key[0] == sid:
                    self._start_rejections.pop(key, None)
            for key, job in list(self._jobs.items()):
                if key[0] != sid:
                    continue
                if job.get("status") == "running":
                    job["disconnected"] = True
                    job["disconnected_at"] = datetime.now().isoformat()
                    self._jobs[key] = job
                else:
                    self._jobs.pop(key, None)

    def clear_if_disconnected(self, sid: str, job_type: str):
        with self._lock:
            key = (sid, job_type)
            job = self._jobs.get(key)
            if job and job.get("disconnected"):
                self._jobs.pop(key, None)
            self._processes.pop(key, None)


def ensure_job_not_cancelled(job_registry, sid: str, job_type: str):
    """Stop the current workflow if cancellation was requested."""
    if job_registry.is_cancelled(sid, job_type):
        raise RuntimeError(f"{job_type} cancelled")


def run_cancellable_command(
    job_registry,
    cmd,
    sid=None,
    job_type=None,
    timeout=None,
):
    """Run a subprocess that can be cancelled via the job registry."""
    start = datetime.now()
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name == "posix",
    )
    process._nmapui_process_group = os.name == "posix"
    try:
        if sid and job_type:
            job_registry.attach_process(sid, job_type, process)
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.2)
                if sid and job_type and job_registry.is_cancelled(sid, job_type):
                    raise RuntimeError(f"{job_type} cancelled")
                break
            except subprocess.TimeoutExpired:
                if timeout is not None and (datetime.now() - start).total_seconds() > timeout:
                    _signal_scan_process(process, signal.SIGTERM)
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        _signal_scan_process(process, signal.SIGKILL)
                        try:
                            stdout, stderr = process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            stdout = stderr = None
                    raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
                if sid and job_type and job_registry.is_cancelled(sid, job_type):
                    _signal_scan_process(process, signal.SIGTERM)
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        _signal_scan_process(process, signal.SIGKILL)
                        try:
                            stdout, stderr = process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            stdout = stderr = None
                    raise RuntimeError(f"{job_type} cancelled")

        return subprocess.CompletedProcess(
            args=cmd, returncode=process.returncode, stdout=stdout, stderr=stderr
        )
    finally:
        try:
            if _scan_process_group_alive(process):
                _signal_scan_process(process, signal.SIGTERM)
                deadline = time.monotonic() + 2
                while _scan_process_group_alive(process) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if _scan_process_group_alive(process):
                    _signal_scan_process(process, signal.SIGKILL)
        except Exception:
            logger.exception("Failed to clean up scan subprocess group")
        if sid and job_type:
            job_registry.clear_process(sid, job_type)
