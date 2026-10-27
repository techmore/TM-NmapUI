from datetime import datetime

from flask import request
from flask_socketio import emit
from nmapui.events import serialize_job_publication
from nmapui.auth import require_socket_auth
from nmapui.daedalus_commands import command_id_from_payload, begin_command, emit_command_result, report_scan_completion


def register_history_handlers(socketio, deps):
    get_most_recent_scan_xml = deps["get_most_recent_scan_xml"]
    customer_fingerprinter = deps["customer_fingerprinter"]
    scans_dir = deps["scans_dir"]
    sanitize_customer_dir_name = deps["sanitize_customer_dir_name"]
    parse_scan_xml_for_assets = deps["parse_scan_xml_for_assets"]
    get_versions = deps["get_versions"]
    emit_job_status = deps["emit_job_status"]
    job_registry = deps["job_registry"]
    emit_to_client = deps["emit_to_client"]
    release_client_state = deps.get("release_client_state")
    rate_limiter = deps.get("rate_limiter")
    broadcaster = deps.get("broadcaster")
    logger = deps["logger"]
    runtime_store = deps.get("runtime_store")

    @serialize_job_publication(job_registry)
    def emit_preferred_job_status(target_sid, job_type):
        owner_sid = broadcaster.find_active_owner(job_type) if broadcaster else None
        if owner_sid and owner_sid != target_sid:
            job = job_registry.get(owner_sid, job_type)
            if job and job.get("status") in {"running", "cancelling"}:
                emit_to_client(
                    target_sid,
                    "job_status",
                    {**job, "job_type": job_type},
                )
                return
        emit_job_status(target_sid, job_type)

    @socketio.on("check_resumable_scan")
    @require_socket_auth()
    def check_resumable_scan_event(data):
        customer_id = data.get("customer_id")
        max_days = data.get("max_days", 7)

        if not customer_id or customer_id == "unknown":
            emit("resumable_scan_check", {"available": False})
            return

        xml_path, metadata = get_most_recent_scan_xml(
            customer_id,
            customers=customer_fingerprinter.customers,
            scans_dir=scans_dir,
            sanitize_customer_dir_name=sanitize_customer_dir_name,
            max_days=max_days,
            runtime_store=runtime_store,
        )

        if xml_path and metadata:
            scan_time = datetime.fromisoformat(metadata.get("timestamp"))
            age_seconds = (datetime.now() - scan_time).total_seconds()
            age_days = int(age_seconds / (24 * 3600))
            assets = parse_scan_xml_for_assets(xml_path)
            total_vulns = sum(len(asset.get("vulnerabilities", [])) for asset in assets)

            emit(
                "resumable_scan_check",
                {
                    "available": True,
                    "scan_date": metadata.get("timestamp"),
                    "target": metadata.get("target"),
                    "duration": "N/A",
                    "total_hosts": len(assets),
                    "total_vulnerabilities": total_vulns,
                    "age_days": age_days,
                    "age_seconds": int(age_seconds),
                },
            )
        else:
            emit("resumable_scan_check", {"available": False})

    @socketio.on("resume_from_last_scan")
    @require_socket_auth()
    def resume_from_last_scan_event(data):
        customer_id = data.get("customer_id")
        max_days = data.get("max_days", 7)

        if not customer_id:
            emit("resume_scan_error", {"error": "No customer ID provided"})
            return

        xml_path, metadata = get_most_recent_scan_xml(
            customer_id,
            customers=customer_fingerprinter.customers,
            scans_dir=scans_dir,
            sanitize_customer_dir_name=sanitize_customer_dir_name,
            max_days=max_days,
            runtime_store=runtime_store,
        )

        if not xml_path:
            emit("resume_scan_error", {"error": "No recent scan found"})
            return

        assets = parse_scan_xml_for_assets(xml_path)
        if not assets:
            emit("resume_scan_error", {"error": "No assets found in scan"})
            return

        metadata = metadata or {}
        total_vulns = sum(len(asset.get("vulnerabilities", [])) for asset in assets)
        total_exploits = sum(
            len([v for v in asset.get("vulnerabilities", []) if v.get("is_exploit")])
            for asset in assets
        )
        scan_time = datetime.fromisoformat(
            metadata.get("timestamp", datetime.now().isoformat())
        )
        age_seconds = (datetime.now() - scan_time).total_seconds()
        age_days = int(age_seconds / (24 * 3600))

        emit(
            "scan_results",
            {
                "hosts": assets,
                "total": len(assets),
                "is_historical": True,
                "scan_date": metadata.get("timestamp", datetime.now().isoformat()),
                "target": metadata.get("target", "unknown"),
                "age_days": age_days,
                "total_vulnerabilities": total_vulns,
                "total_exploits": total_exploits,
            },
        )

        if age_days == 0:
            age_str = "today"
        elif age_days == 1:
            age_str = "yesterday"
        else:
            age_str = f"{age_days} days ago"

        emit(
            "scan_feedback",
            f"Loaded {len(assets)} assets from scan {age_str} ({total_vulns} vulnerabilities, {total_exploits} exploits)",
        )

    @socketio.on("get_versions")
    @require_socket_auth()
    def get_versions_event():
        emit("versions", get_versions())

    @socketio.on("get_job_status")
    @require_socket_auth()
    def get_job_status_event():
        emit_preferred_job_status(request.sid, "scan")
        emit_preferred_job_status(request.sid, "report")

    def request_job_cancellation(job_type, command_id=None, source_job_id=None):
        receipt_deps = {"broadcaster": broadcaster, "emit_to_client": emit_to_client, "runtime_store": runtime_store}
        if job_type not in {"scan", "report"} or command_id is not None and job_type != "scan":
            emit_command_result(command_id=command_id, owner_sid=request.sid, status="failed", result="Invalid scan cancellation request.", **receipt_deps)
            emit("scan_error", "Invalid job type")
            return
        owner_sid = request.sid
        if command_id is not None and broadcaster:
            namespace = broadcaster.get_bridge_namespace(request.sid)
            candidates = [job["sid"] for job in job_registry.snapshot()["active_jobs"] if job.get("job_type") == "scan" and (job.get("details") or {}).get("daedalus_command_namespace") == namespace]
            owner_sid = (request.sid if request.sid in candidates else candidates[0]) if candidates else (broadcaster.find_active_owner("scan") or request.sid)
        if source_job_id is not None and command_id is None:
            if broadcaster and broadcaster.is_bridge_client(request.sid):
                emit("scan_error", "Bridge cancellation requires a command identifier")
                return
            observed_owner = broadcaster.find_active_owner(job_type) if broadcaster else None
            observed = job_registry.get(observed_owner, job_type) if observed_owner else None
            if not observed or observed.get("source_job_id") != source_job_id:
                emit("scan_error", "This scan is no longer active; refresh its status")
                return
            owner_sid = observed_owner
        current = job_registry.get(owner_sid, job_type)
        if command_id is not None:
            if not current or current.get("status") not in {"running", "cancelling"}:
                emit_command_result(command_id=command_id, owner_sid=request.sid, status="succeeded", result="No running scan needed cancellation.", **receipt_deps)
                return
            namespace = broadcaster.get_bridge_namespace(request.sid)
            original_namespace = (current.get("details") or {}).get("daedalus_command_namespace")
            if original_namespace is not None and original_namespace != namespace:
                emit_command_result(command_id=command_id, owner_sid=request.sid, status="failed", result="The active scan belongs to a different bridge control session.", **receipt_deps)
                return
            identifiers = list((current.get("details") or {}).get("daedalus_cancel_commands", []))
            if len(identifiers) >= 10:
                emit_command_result(command_id=command_id, owner_sid=request.sid, status="failed", result="The pending scan cancellation receipt limit was reached.", **receipt_deps)
                return
            identifiers.append({"command_id": command_id, "command_namespace": namespace})
            job_registry.update(owner_sid, job_type, details={"daedalus_cancel_commands": identifiers})
        cancelled = job_registry.cancel(owner_sid, job_type, expected_source_job_id=source_job_id)
        if command_id is not None:
            current = job_registry.get(owner_sid, job_type)
            if current:
                report_scan_completion(sid=owner_sid, job=current, **receipt_deps)
        if not cancelled:
            emit_to_client(request.sid, "job_cancelled", {"job_type": job_type, "message": "No running job to cancel"})
            emit_job_status(owner_sid, job_type)
            return
        emit_job_status(owner_sid, job_type)
        emit_to_client(request.sid, "job_cancelled", {"job_type": job_type, "message": f"Cancelling {job_type} job..."})

    @socketio.on("cancel_job")
    @require_socket_auth()
    def cancel_job_event(data):
        try:
            command_id = command_id_from_payload(data, sid=request.sid, broadcaster=broadcaster)
        except ValueError:
            emit("scan_error", "Invalid Daedalus command identifier")
            return
        if not begin_command(command_id=command_id, owner_sid=request.sid, action="cancel_scan", broadcaster=broadcaster, emit_to_client=emit_to_client, runtime_store=runtime_store):
            return
        job_type = data.get("job_type") if isinstance(data, dict) else None
        request_job_cancellation(job_type, command_id, data.get("source_job_id") if isinstance(data, dict) else None)

    @socketio.on("stop_scan")
    @require_socket_auth()
    def stop_scan_event():
        # Preserve the original UI event for cached clients during upgrades.
        request_job_cancellation("scan")

    pause_failure_messages = {
        "no_job": "No scan is running, so there is nothing to {action}.",
        "not_running": "That scan is no longer running, so it cannot be {action}d.",
        "stale_job": "This scan is no longer active; refresh its status.",
        "already_paused": "The scan is already paused.",
        "not_paused": "The scan is not paused.",
        "unsupported": "Pausing scans is not supported on this platform; use Stop to cancel.",
    }

    def request_job_pause_change(job_type, *, resume, source_job_id=None):
        """Pause or resume a job on behalf of any connected tab.

        The job registry is the source of truth. Whatever the outcome, the
        current status is re-broadcast so every open tab (and a tab that raced
        another) converges on the real state.
        """
        action = "resume" if resume else "pause"
        if job_type not in {"scan", "report"} or (source_job_id is not None and not isinstance(source_job_id, str)):
            emit("scan_error", "Invalid job type")
            return
        owner_sid = request.sid
        bridge_namespace = (
            broadcaster.get_bridge_namespace(request.sid)
            if broadcaster and broadcaster.is_bridge_client(request.sid) else None
        )
        if bridge_namespace is not None:
            # A reconnected bridge has a new SID; prefer its enrollment's job
            # instead of the first scan another enrollment happens to own.
            candidates = [
                job["sid"] for job in job_registry.snapshot()["active_jobs"]
                if job.get("job_type") == job_type
                and (job.get("details") or {}).get("daedalus_command_namespace") == bridge_namespace
            ]
            if candidates:
                owner_sid = request.sid if request.sid in candidates else candidates[0]
        current = job_registry.get(owner_sid, job_type)
        if not current or current.get("status") != "running":
            observed_owner = broadcaster.find_active_owner(job_type) if broadcaster else None
            if observed_owner and job_registry.get(observed_owner, job_type):
                owner_sid = observed_owner
        current = job_registry.get(owner_sid, job_type)
        original_namespace = ((current or {}).get("details") or {}).get("daedalus_command_namespace")
        if (broadcaster and broadcaster.is_bridge_client(request.sid)
                and original_namespace is not None and original_namespace != bridge_namespace):
            emit_to_client(request.sid, "scan_error", "The active scan belongs to a different bridge control session.")
            return
        change = job_registry.resume if resume else job_registry.pause
        ok, reason = change(owner_sid, job_type, expected_source_job_id=source_job_id)
        emit_job_status(owner_sid, job_type)
        if not ok:
            emit_to_client(request.sid, "scan_feedback", pause_failure_messages.get(reason, f"Could not {action} the scan.").format(action=action))

    @socketio.on("pause_job")
    @require_socket_auth()
    def pause_job_event(data=None):
        data = data if isinstance(data, dict) else {}
        request_job_pause_change(data.get("job_type", "scan"), resume=False, source_job_id=data.get("source_job_id"))

    @socketio.on("resume_job")
    @require_socket_auth()
    def resume_job_event(data=None):
        data = data if isinstance(data, dict) else {}
        request_job_pause_change(data.get("job_type", "scan"), resume=True, source_job_id=data.get("source_job_id"))

    @socketio.on("disconnect")
    def disconnect_event():
        logger.info("Client disconnected: %s", request.sid)
        job_registry.mark_disconnected(request.sid)
        if rate_limiter:
            rate_limiter.remove_client(request.sid)
        if broadcaster:
            broadcaster.unsubscribe(request.sid)
        if release_client_state:
            release_client_state(request.sid)
