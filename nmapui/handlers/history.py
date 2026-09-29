from datetime import datetime

from flask import request
from flask_socketio import emit
from nmapui.auth import require_socket_auth


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

    def request_job_cancellation(job_type):
        if job_type not in {"scan", "report"}:
            emit("scan_error", "Invalid job type")
            return

        if not job_registry.cancel(request.sid, job_type):
            emit_to_client(
                request.sid,
                "job_cancelled",
                {"job_type": job_type, "message": "No running job to cancel"},
            )
            emit_job_status(request.sid, job_type)
            return

        emit_job_status(request.sid, job_type)
        emit_to_client(
            request.sid,
            "job_cancelled",
            {"job_type": job_type, "message": f"Cancelling {job_type} job..."},
        )

    @socketio.on("cancel_job")
    @require_socket_auth()
    def cancel_job_event(data):
        job_type = data.get("job_type") if isinstance(data, dict) else None
        request_job_cancellation(job_type)

    @socketio.on("stop_scan")
    @require_socket_auth()
    def stop_scan_event():
        # Preserve the original UI event for cached clients during upgrades.
        request_job_cancellation("scan")

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
