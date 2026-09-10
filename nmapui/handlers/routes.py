from datetime import datetime, timezone

from flask import (
    after_this_request,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
)
from nmapui.auth import (
    auth_uses_insecure_defaults,
    check_auth,
    clear_session_cookie,
    require_auth,
    request_is_local_ui,
    session_username,
    set_session_cookie,
)
from nmapui.handlers.scans import delete_scan_artifacts
from nmapui.reporting import _resolve_artifact_file_path, build_artifact_downloads
from nmapui.runtime_history import (
    backfill_runtime_history_artifacts,
    build_compare_result,
    build_history_rows,
    normalize_runtime_report_row,
)
from nmapui.runtime_log import append_runtime_log
from nmapui.runtime_db import (
    DEFAULT_CUSTOMER_SCAN_HISTORY_RETENTION,
    DEFAULT_RUNTIME_LOG_RETENTION,
)


def _get_runtime_artifact(runtime_store, scan_path):
    if runtime_store is None or not hasattr(runtime_store, "get_report_artifact"):
        return None
    return runtime_store.get_report_artifact(scan_path)


def _build_runtime_db_download_name() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"nmapui-runtime-{timestamp}.sqlite3"


def _send_runtime_artifact(*, runtime_store, scans_dir, scan_path, artifact_key, default_name, download_name=None, as_attachment=False):
    artifact = _get_runtime_artifact(runtime_store, scan_path)
    if artifact is None:
        return "Report artifact not found", 404

    artifact_path = _resolve_artifact_file_path(
        scans_dir=scans_dir,
        scan_path=scan_path,
        stored_path=artifact.get(artifact_key),
        default_name=default_name,
    )
    if not artifact_path.exists():
        return "Report artifact not found", 404

    kwargs = {"as_attachment": as_attachment}
    if download_name:
        kwargs["download_name"] = download_name
    return send_file(artifact_path, **kwargs)


def register_core_routes(app, deps):
    build_liveness_payload = deps["build_liveness_payload"]
    build_readiness_payload = deps["build_readiness_payload"]
    get_app_version = deps["get_app_version"]
    get_default_interface_cached = deps["get_default_interface_cached"]
    get_versions = deps["get_versions"]
    job_registry = deps["job_registry"]
    runtime_store = deps.get("runtime_store")
    settings_state = deps["settings_state"]
    startup_state = deps["startup_state"]
    get_auto_scan_thread = deps["get_auto_scan_thread"]
    upload_report_artifacts_to_google_drive = deps.get("upload_report_artifacts_to_google_drive")
    customer_fingerprinter = deps.get("customer_fingerprinter")

    def append_runtime_log_safe(*, category, level, message, payload=None):
        if runtime_store is None or not hasattr(runtime_store, "append_log"):
            return
        append_runtime_log(
            runtime_store=runtime_store,
            category=category,
            level=level,
            message=message,
            payload=payload or {},
        )

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Browser login that issues a long-lived session cookie.

        Kept separate from the API so an unattended appliance can authenticate
        once and keep working for months without re-prompting.
        """
        error = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            if check_auth(username, password):
                target = request.args.get("next") or "/"
                if not target.startswith("/") or target.startswith("//"):
                    target = "/"
                return set_session_cookie(make_response(redirect(target)), username)
            error = "Invalid credentials"
        elif auth_uses_insecure_defaults():
            error = (
                "Authentication is not configured. Set NMAPUI_USERNAME and "
                "NMAPUI_PASSWORD (or NMAPUI_ALLOW_DEFAULT_CREDENTIALS=true for a "
                "local-only install) before signing in."
            )
        return render_template("login.html", error=error), (401 if error and request.method == "POST" else 200)

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        return clear_session_cookie(make_response(redirect("/login")))

    @app.route("/api/session/status")
    @require_auth
    def session_status():
        username = session_username()
        return jsonify(
            {
                "authenticated": bool(username) or request_is_local_ui(),
                "username": username,
                "local_trust": request_is_local_ui(),
                "auth_configured": not auth_uses_insecure_defaults(),
            }
        )

    @app.route("/api/socket-token")
    def socket_token():
        """Loopback-only token for authenticating the Socket.IO handshake."""
        from flask import jsonify, request as flask_request

        remote = flask_request.remote_addr or ""
        if remote not in {"127.0.0.1", "::1"}:
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"token": deps["socket_auth_token"]})

    @app.route("/api/health")
    def health_check():
        return jsonify(
            build_liveness_payload(
                app_version=get_app_version(),
                default_interface=get_default_interface_cached(),
                auto_scan_thread_alive=bool(
                    get_auto_scan_thread() and get_auto_scan_thread().is_alive()
                ),
                tool_versions=get_versions(),
            )
        )

    @app.route("/api/health/live")
    def health_live():
        return health_check()

    @app.route("/api/health/ready")
    def health_ready():
        payload, status_code = build_readiness_payload(
            startup_state=startup_state,
            app_version=get_app_version(),
            default_interface=get_default_interface_cached(),
            auto_scan_thread_alive=bool(
                get_auto_scan_thread() and get_auto_scan_thread().is_alive()
            ),
            tool_versions=get_versions(),
        )
        return jsonify(payload), status_code

    @app.route("/api/runtime/status")
    def runtime_status():
        snapshot = job_registry.snapshot()
        active_jobs = snapshot["active_jobs"]
        return jsonify(
            {
                "has_active_jobs": snapshot["has_active_jobs"],
                "active_job_types": sorted(
                    {job.get("job_type") for job in active_jobs if job.get("job_type")}
                ),
                "active_jobs": active_jobs,
            }
        )

    @app.route("/api/runtime/settings-summary")
    def runtime_settings_summary():
        scan_rules = settings_state.get("scan_rules", {})
        reports = settings_state.get("reports", {})
        sync = settings_state.get("sync", {})
        max_scan_minutes = int(scan_rules.get("max_scan_minutes", 120) or 120)
        maintenance_backfill = {}
        maintenance_retention = {}
        persisted_counts = {
            "report_artifacts": 0,
            "customer_scan_history": 0,
            "runtime_logs": 0,
        }
        if runtime_store is not None and hasattr(runtime_store, "get_runtime_snapshot"):
            maintenance_backfill = (
                runtime_store.get_runtime_snapshot("maintenance_backfill_status") or {}
            )
            maintenance_retention = (
                runtime_store.get_runtime_snapshot("maintenance_retention_status") or {}
            )
        if runtime_store is not None:
            if hasattr(runtime_store, "count_report_artifacts"):
                persisted_counts["report_artifacts"] = runtime_store.count_report_artifacts()
            if hasattr(runtime_store, "count_customer_scan_history"):
                persisted_counts["customer_scan_history"] = runtime_store.count_customer_scan_history()
            if hasattr(runtime_store, "count_runtime_logs"):
                persisted_counts["runtime_logs"] = runtime_store.count_runtime_logs()
        return jsonify(
            {
                "scan_only_mode": bool(scan_rules.get("scan_only_mode", False)),
                "max_scan_minutes": max_scan_minutes,
                "excluded_targets_count": len(scan_rules.get("excluded_targets", [])),
                "target_profiles_count": len(settings_state.get("target_profiles", [])),
                "reports_save_to_desktop": bool(reports.get("save_to_desktop", False)),
                "google_drive_enabled": bool(
                    (sync.get("google_drive") or {}).get("enabled", False)
                ),
                "remote_sync_enabled": bool(
                    (sync.get("remote_sync") or {}).get("enabled", False)
                ),
                "tool_versions": get_versions(),
                "maintenance_backfill": maintenance_backfill,
                "maintenance_retention": maintenance_retention,
                "persisted_counts": persisted_counts,
            }
        )

    @app.route("/api/runtime/logs")
    def runtime_logs():
        category = None
        if runtime_store is not None:
            category = request.args.get("category") or None
            limit_value = request.args.get("limit", "200")
            try:
                limit = max(1, min(int(limit_value), 1000))
            except ValueError:
                limit = 200
            return jsonify(
                {
                    "entries": runtime_store.get_recent_logs(
                        category=category,
                        limit=limit,
                    )
                }
            )
        return jsonify({"entries": []})

    @app.route("/api/runtime/export")
    @require_auth
    def runtime_export():
        if runtime_store is None or not hasattr(runtime_store, "export_snapshot"):
            return jsonify({"success": False, "error": "Runtime database is not configured"}), 400
        export_path = runtime_store.export_snapshot()

        @after_this_request
        def cleanup_export(response):
            try:
                export_path.unlink(missing_ok=True)
            except OSError:
                pass
            return response

        return send_file(
            export_path,
            as_attachment=True,
            download_name=_build_runtime_db_download_name(),
            mimetype="application/x-sqlite3",
        )

    @app.route("/api/runtime/reports")
    @require_auth
    def runtime_reports():
        if runtime_store is None:
            return jsonify({"reports": []})

        reports = [
            normalize_runtime_report_row(
                artifact,
                customer_fingerprinter=customer_fingerprinter,
            )
            for artifact in runtime_store.list_report_artifacts()
        ]
        return jsonify({"reports": reports})

    @app.route("/api/runtime/reports/<path:scan_path>/html")
    @require_auth
    def runtime_report_html(scan_path):
        artifact = _get_runtime_artifact(runtime_store, scan_path)
        download_name = None
        if artifact is not None:
            download_name = build_artifact_downloads(
                dict(artifact.get("payload", {}) or {}),
                customer_fingerprinter=customer_fingerprinter,
            ).get("html")
        wants_download = request.args.get("download") == "1"
        return _send_runtime_artifact(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            scan_path=scan_path,
            artifact_key="html_path",
            default_name="scan_web.html",
            download_name=download_name if wants_download else None,
            as_attachment=wants_download,
        )

    @app.route("/api/runtime/reports/<path:scan_path>/pdf")
    @require_auth
    def runtime_report_pdf(scan_path):
        artifact = _get_runtime_artifact(runtime_store, scan_path)
        download_name = "Nmap_Audit_Report.pdf"
        if artifact is not None:
            download_name = build_artifact_downloads(
                dict(artifact.get("payload", {}) or {}),
                customer_fingerprinter=customer_fingerprinter,
            ).get("pdf", download_name)
        return _send_runtime_artifact(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            scan_path=scan_path,
            artifact_key="pdf_path",
            default_name="scan_report.pdf",
            download_name=download_name,
            as_attachment=True,
        )

    @app.route("/api/runtime/reports/<path:scan_path>/xml")
    @require_auth
    def runtime_report_xml(scan_path):
        artifact = _get_runtime_artifact(runtime_store, scan_path)
        download_name = "Nmap_Raw_Data.xml"
        if artifact is not None:
            download_name = build_artifact_downloads(
                dict(artifact.get("payload", {}) or {}),
                customer_fingerprinter=customer_fingerprinter,
            ).get("xml", download_name)
        return _send_runtime_artifact(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            scan_path=scan_path,
            artifact_key="xml_path",
            default_name="scan.xml",
            download_name=download_name,
            as_attachment=True,
        )

    @app.route("/api/runtime/reports/<path:scan_path>/upload/google-drive", methods=["POST"])
    @require_auth
    def runtime_report_google_drive_upload(scan_path):
        if upload_report_artifacts_to_google_drive is None:
            return jsonify({"success": False, "error": "Google Drive upload is not configured"}), 400

        artifact = _get_runtime_artifact(runtime_store, scan_path)
        payload = dict(artifact.get("payload", {}) or {}) if artifact else {}
        file_paths = []
        for artifact_key, default_name in (
            ("html_path", "scan_web.html"),
            ("pdf_path", "scan_report.pdf"),
            ("xml_path", "scan.xml"),
        ):
            artifact_path = _resolve_artifact_file_path(
                scans_dir=deps.get("scans_dir"),
                scan_path=scan_path,
                stored_path=artifact.get(artifact_key) if artifact else None,
                default_name=default_name,
            )
            if artifact_path.exists():
                file_paths.append(artifact_path)

        if not file_paths:
            return jsonify({"success": False, "error": "No report artifacts found for upload"}), 404

        append_runtime_log_safe(
            category="google_drive",
            level="INFO",
            message="Manual Google Drive upload started",
            payload={
                "scan_path": scan_path,
                "file_count": len(file_paths),
            },
        )
        result = upload_report_artifacts_to_google_drive(
            scan_path=scan_path,
            file_paths=file_paths,
            metadata=payload,
            settings_state=settings_state,
        )
        if result.get("success"):
            append_runtime_log_safe(
                category="google_drive",
                level="INFO",
                message="Manual Google Drive upload completed",
                payload={
                    "scan_path": scan_path,
                    "file_count": len(file_paths),
                    "status": result.get("status", ""),
                },
            )
        else:
            append_runtime_log_safe(
                category="google_drive",
                level="ERROR",
                message="Manual Google Drive upload failed",
                payload={
                    "scan_path": scan_path,
                    "file_count": len(file_paths),
                    "error": result.get("error", "Unknown upload failure"),
                },
            )
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/runtime/history")
    @require_auth
    def runtime_history():
        history = build_history_rows(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            logger=deps.get("logger"),
            customer_fingerprinter=customer_fingerprinter,
        )
        return jsonify({"history": history})

    @app.route("/api/runtime/history/<path:scan_path>", methods=["DELETE"])
    @require_auth
    def runtime_history_delete(scan_path):
        payload, status_code = delete_scan_artifacts(
            path=scan_path,
            scans_dir=deps.get("scans_dir"),
            resolve_scan_path=deps.get("resolve_scan_path"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            logger=deps.get("logger"),
            runtime_store=runtime_store,
        )
        return jsonify(payload), status_code

    @app.route("/api/runtime/maintenance/backfill", methods=["POST"])
    @require_auth
    def runtime_backfill():
        backfilled = backfill_runtime_history_artifacts(
            runtime_store=runtime_store,
            scans_dir=deps.get("scans_dir"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            logger=deps.get("logger"),
        )
        last_run_at = datetime.now(timezone.utc).isoformat()
        if runtime_store is not None and hasattr(runtime_store, "upsert_runtime_snapshot"):
            runtime_store.upsert_runtime_snapshot(
                "maintenance_backfill_status",
                {
                    "last_run_at": last_run_at,
                    "last_backfilled": backfilled,
                },
            )
        return jsonify(
            {
                "success": True,
                "backfilled": backfilled,
                "last_run_at": last_run_at,
            }
        )

    @app.route("/api/runtime/maintenance/retention", methods=["POST"])
    @require_auth
    def runtime_retention():
        if runtime_store is None or not hasattr(runtime_store, "apply_retention_policies"):
            return jsonify({"success": False, "error": "Runtime database is not configured"}), 400

        payload = request.get_json(silent=True) or {}
        runtime_logs_keep_latest = payload.get(
            "runtime_logs_keep_latest",
            DEFAULT_RUNTIME_LOG_RETENTION,
        )
        customer_history_keep_latest = payload.get(
            "customer_history_keep_latest",
            DEFAULT_CUSTOMER_SCAN_HISTORY_RETENTION,
        )
        compact = bool(payload.get("compact", True))

        result = runtime_store.apply_retention_policies(
            runtime_logs_keep_latest=runtime_logs_keep_latest,
            customer_history_keep_latest=customer_history_keep_latest,
            compact=compact,
        )
        last_run_at = datetime.now(timezone.utc).isoformat()
        retention_snapshot = {
            "last_run_at": last_run_at,
            **result,
        }
        if hasattr(runtime_store, "upsert_runtime_snapshot"):
            runtime_store.upsert_runtime_snapshot(
                "maintenance_retention_status",
                retention_snapshot,
            )
        return jsonify(
            {
                "success": True,
                **retention_snapshot,
            }
        )

    @app.route("/api/runtime/history/compare")
    @require_auth
    def runtime_history_compare():
        base_path = str(request.args.get("base_path", "") or "").strip()
        current_path = str(request.args.get("current_path", "") or "").strip()
        if not base_path or not current_path:
            return jsonify({"success": False, "error": "Both base_path and current_path are required"}), 400

        payload, error, status_code = build_compare_result(
            runtime_store=runtime_store,
            resolve_scan_path=deps.get("resolve_scan_path"),
            load_json_document=deps.get("load_json_document"),
            normalize_scan_metadata_document=deps.get("normalize_scan_metadata_document"),
            base_path=base_path,
            current_path=current_path,
        )
        if payload is None:
            return jsonify({"success": False, "error": error}), status_code
        return jsonify(payload)
