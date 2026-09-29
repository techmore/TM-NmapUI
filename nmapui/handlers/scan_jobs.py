from flask import request
from flask_socketio import emit

from nmapui.auth import require_socket_auth


def register_scan_job_handlers(socketio, deps):
    broadcaster = deps.get("broadcaster")
    validate_target = deps["validate_target"]
    rate_limiter = deps["rate_limiter"]
    job_registry = deps["job_registry"]
    emit_job_status = deps["emit_job_status"]
    set_last_scan_target_state = deps["set_last_scan_target_state"]
    start_scan_task = deps["start_scan_task"]
    generate_report_task = deps["generate_report_task"]
    generate_pdf_from_saved_task = deps.get("generate_pdf_from_saved_task")

    def _start_scan_core(data, extra=None):
        payload = dict(extra or {})
        if isinstance(data, dict):
            payload.update(data)
        else:
            payload["target"] = str(data) if data else ""
        target = payload.get("target", "")

        if not isinstance(target, str):
            target = str(target)

        is_valid, error_msg = validate_target(target)
        if not is_valid:
            emit("scan_error", f"Invalid target: {error_msg}")
            return

        try:
            can_scan, rate_msg = rate_limiter.can_scan(request.sid)
        except TypeError:
            can_scan, rate_msg = rate_limiter.can_scan()
        if not can_scan:
            emit("scan_error", rate_msg)
            return

        if not job_registry.start(request.sid, "scan", {"target": target}):
            reason = (
                job_registry.get_start_rejection_reason(request.sid, "scan")
                if hasattr(job_registry, "get_start_rejection_reason")
                else None
            )
            emit("scan_error", reason or "A scan is already running for this client")
            emit_job_status(request.sid, "scan")
            return

        set_last_scan_target_state(value=target, sid=request.sid)
        if broadcaster is not None:
            broadcaster.start_job(request.sid)
        try:
            rate_limiter.record_scan(request.sid)
        except TypeError:
            rate_limiter.record_scan()
        emit_job_status(request.sid, "scan")
        socketio.start_background_task(start_scan_task, request.sid, target)

    # Legacy event names emitted by the frontend buttons (quick/complete/dragnet).
    @socketio.on("start_quick_scan")
    @require_socket_auth()
    def start_quick_scan(data):
        _start_scan_core(data)

    @socketio.on("start_complete_scan")
    @require_socket_auth()
    def start_complete_scan(data):
        _start_scan_core(data)

    @socketio.on("start_dragnet_scan")
    @require_socket_auth()
    def start_dragnet_scan(data):
        _start_scan_core(data)

    @socketio.on("start_scan")
    @require_socket_auth()
    def start_scan(data):
        _start_scan_core(data)

    @socketio.on("generate_report")
    @require_socket_auth()
    def generate_report_event(data):
        if not isinstance(data, dict):
            emit("report_error", {"error": "Invalid report request"})
            return

        if not job_registry.start(
            request.sid,
            "report",
            {
                "target": data.get("target"),
                "customer_name": data.get("customer_name"),
                "chunked": bool(data.get("chunked", True)),
            },
        ):
            reason = (
                job_registry.get_start_rejection_reason(request.sid, "report")
                if hasattr(job_registry, "get_start_rejection_reason")
                else None
            )
            emit(
                "report_error",
                {"error": reason or "A report job is already running for this client"},
            )
            emit_job_status(request.sid, "report")
            return

        if broadcaster is not None:
            broadcaster.start_job(request.sid, job_type="report")
        emit_job_status(request.sid, "report")
        socketio.start_background_task(generate_report_task, request.sid, data)

    if generate_pdf_from_saved_task is not None:
        @socketio.on("generate_pdf_from_saved")
        @require_socket_auth()
        def generate_pdf_from_saved_event(data):
            if not isinstance(data, dict):
                emit("report_error", {"error": "Invalid PDF request"})
                return

            socketio.start_background_task(generate_pdf_from_saved_task, request.sid, data)
