from functools import wraps
import threading

from flask_socketio import emit


_adapter_publication_lock = threading.RLock()


def job_publication_lock(job_registry):
    """Real registries own a lock; legacy registry adapters share a fallback."""
    return getattr(job_registry, "status_publication_lock", _adapter_publication_lock)


def serialize_job_publication(job_registry):
    """Order snapshot selection, replay and enqueue across status producers.

    Acquire before registry/broadcaster reads. Their internal locks are released
    before emission; mutations never acquire this lock while holding their own.
    Reentrancy allows bootstrap/preferred-status helpers to call the publisher.
    """
    def decorate(function):
        @wraps(function)
        def publish(*args, **kwargs):
            with job_publication_lock(job_registry):
                return function(*args, **kwargs)
        return publish
    return decorate


def safe_emit(event, data=None):
    """Emit a Socket.IO event only if in a request context."""
    try:
        if data is None:
            emit(event)
        else:
            emit(event, data)
    except RuntimeError:
        pass


def emit_to_client(socketio, sid: str, event: str, data=None):
    """Emit a Socket.IO event to a single connected client."""
    if data is None:
        socketio.emit(event, to=sid)
    else:
        socketio.emit(event, data, to=sid)


def emit_job_status(socketio, job_registry, sid: str, job_type: str):
    """Publish the current status for a client job."""
    with job_publication_lock(job_registry):
        payload = job_registry.get(sid, job_type) or {"status": "idle", "details": {}}
        payload["job_type"] = job_type
        emit_to_client(socketio, sid, "job_status", payload)


def update_job_progress(
    socketio,
    job_registry,
    sid: str,
    job_type: str,
    phase: str,
    message=None,
    progress=None,
    details=None,
):
    """Update the current phase/progress for a client job and publish it."""
    payload = {"phase": phase}
    if message is not None:
        payload["message"] = message
    if progress is not None:
        payload["progress"] = progress
    if details:
        payload.update(details)

    job_registry.update(sid, job_type, details=payload)
    emit_job_status(socketio, job_registry, sid, job_type)
