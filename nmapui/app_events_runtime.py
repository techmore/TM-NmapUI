from nmapui.events import (
    emit_job_status as nmapui_emit_job_status,
    emit_to_client as nmapui_emit_to_client,
    safe_emit as nmapui_safe_emit,
    update_job_progress as nmapui_update_job_progress,
)
from nmapui.jobs import (
    ensure_job_not_cancelled as nmapui_ensure_job_not_cancelled,
    run_cancellable_command as nmapui_run_cancellable_command,
)


def safe_emit(event, data=None):
    return nmapui_safe_emit(event, data)


def emit_to_client(*, socketio, sid, event, data=None):
    return nmapui_emit_to_client(socketio, sid, event, data)


def emit_job_status(*, socketio, job_registry, sid, job_type):
    return nmapui_emit_job_status(socketio, job_registry, sid, job_type)


def update_job_progress(
    *,
    socketio,
    job_registry,
    sid,
    job_type,
    phase,
    message=None,
    progress=None,
    details=None,
):
    return nmapui_update_job_progress(
        socketio,
        job_registry,
        sid,
        job_type,
        phase,
        message=message,
        progress=progress,
        details=details,
    )


def ensure_job_not_cancelled(*, job_registry, sid, job_type, on_pause=None):
    return nmapui_ensure_job_not_cancelled(job_registry, sid, job_type, on_pause=on_pause)


def run_cancellable_command(
    *,
    job_registry,
    cmd,
    sid=None,
    job_type=None,
    timeout=None,
):
    return nmapui_run_cancellable_command(
        job_registry,
        cmd,
        sid=sid,
        job_type=job_type,
        timeout=timeout,
    )
