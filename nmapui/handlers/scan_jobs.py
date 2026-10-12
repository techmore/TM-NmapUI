from flask import request
from flask_socketio import emit

from nmapui.auth import require_socket_auth
from nmapui.daedalus_commands import command_id_from_payload, begin_command, emit_command_result, report_scan_completion


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

    runtime_store = deps.get("runtime_store")
    emit_to_client = deps.get("emit_to_client") or (lambda sid, event, data=None: socketio.emit(event, data, to=sid))
    receipt_deps = {"broadcaster": broadcaster, "emit_to_client": emit_to_client, "runtime_store": runtime_store}
    if hasattr(job_registry, "add_completion_listener"):
        job_registry.add_completion_listener(lambda sid, job_type, job: report_scan_completion(sid=sid, job=job, **receipt_deps) if job_type == "scan" else None)

    def _start_scan_core(data, extra=None):
        try:
            command_id = command_id_from_payload(data, sid=request.sid, broadcaster=broadcaster)
        except ValueError:
            emit("scan_error", "Invalid Daedalus command identifier")
            return
        if not begin_command(command_id=command_id, owner_sid=request.sid, action="start_scan", **receipt_deps):
            return
        def fail_command(message):
            emit_command_result(command_id=command_id, owner_sid=request.sid, status="failed", result=message, **receipt_deps)
        payload = dict(extra or {})
        if isinstance(data, dict):
            payload.update(data)
        else:
            payload["target"] = str(data) if data else ""
        if "skip_host_discovery" in payload and type(payload["skip_host_discovery"]) is not bool:
            fail_command("The skip_host_discovery option must be a JSON boolean.")
            emit("scan_error", "Invalid scan option: skip_host_discovery must be a JSON boolean")
            return
        scan_task_kwargs = (
            {"skip_host_discovery_override": payload["skip_host_discovery"]}
            if "skip_host_discovery" in payload
            else {}
        )
        target = payload.get("target", "")

        if not isinstance(target, str):
            target = str(target)

        is_valid, error_msg = validate_target(target)
        if not is_valid:
            fail_command("The scan target was rejected.")
            emit("scan_error", f"Invalid target: {error_msg}")
            return

        try:
            can_scan, rate_msg = rate_limiter.can_scan(request.sid)
        except TypeError:
            can_scan, rate_msg = rate_limiter.can_scan()
        if not can_scan:
            fail_command(str(rate_msg)[:500] if rate_msg else "The scan request was rate limited.")
            emit("scan_error", rate_msg)
            return

        if not job_registry.start(request.sid, "scan", {"target": target, **({"daedalus_command_id": command_id, "daedalus_command_namespace": broadcaster.get_bridge_namespace(request.sid)} if command_id else {})}):
            reason = (
                job_registry.get_start_rejection_reason(request.sid, "scan")
                if hasattr(job_registry, "get_start_rejection_reason")
                else None
            )
            fail_command("The scanner could not start this scan because another job is active or capacity is unavailable.")
            emit("scan_error", reason or "A scan is already running for this client")
            emit_job_status(request.sid, "scan")
            return

        set_last_scan_target_state(value=target, sid=request.sid)
        if broadcaster is not None:
            broadcaster.start_job(request.sid, source_job_id=job_registry.get(request.sid, "scan").get("source_job_id"))
        try:
            rate_limiter.record_scan(request.sid)
        except TypeError:
            rate_limiter.record_scan()
        emit_job_status(request.sid, "scan")
        try:
            task_args = (request.sid, target)
            if "skip_host_discovery_override" in scan_task_kwargs:
                task_args += (scan_task_kwargs["skip_host_discovery_override"],)
            socketio.start_background_task(start_scan_task, *task_args)
        except Exception:
            job_registry.complete(request.sid, "scan", status="failed", details={"error": "Scan task could not be scheduled"})
            if broadcaster is not None:
                broadcaster.end_job(request.sid, job_type="scan")
            emit("scan_error", "Scan task could not be scheduled")

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
            broadcaster.start_job(request.sid, job_type="report", source_job_id=job_registry.get(request.sid, "report").get("source_job_id"))
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
