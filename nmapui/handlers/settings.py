from flask import jsonify, request
from html import escape

from nmapui.auto_monitor import build_auto_monitor_rule_status
from nmapui.auth import require_auth
from nmapui.settings import (
    SETTINGS_STATE_LOCK,
    normalize_settings_document,
    preserve_auto_monitor_progress,
)


def register_settings_routes(app, deps):
    settings_state = deps["settings_state"]
    save_settings = deps["save_settings"]
    validate_google_drive = deps["validate_google_drive"]
    validate_remote_sync = deps["validate_remote_sync"]
    get_customer_name = deps.get("get_customer_name")
    get_google_drive_auth_status = deps["get_google_drive_auth_status"]
    build_google_drive_auth_url = deps["build_google_drive_auth_url"]
    exchange_google_drive_auth_code = deps["exchange_google_drive_auth_code"]
    ensure_google_drive_reports_folder = deps["ensure_google_drive_reports_folder"]
    save_google_drive_credentials = deps["save_google_drive_credentials"]
    disconnect_google_drive = deps["disconnect_google_drive"]
    upload_latest_report_to_google_drive = deps.get("upload_latest_report_to_google_drive")

    @app.route("/api/settings")
    @require_auth
    def get_settings():
        with SETTINGS_STATE_LOCK:
            remote_sync = (settings_state.get("sync") or {}).get("remote_sync") or {}
            normalized = normalize_settings_document(
                settings_state,
                customer_name_lookup=get_customer_name,
                # The encrypted key is intentionally absent from the settings
                # document. Preserve its server-owned presence bit when
                # normalizing this already-loaded in-memory state.
                remote_sync_api_key_configured=bool(
                    remote_sync.get("api_key_configured", False)
                ),
            )
        return jsonify(normalized)

    @app.route("/api/settings", methods=["POST"])
    @require_auth
    def update_settings():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid settings payload"}), 400

        try:
            with SETTINGS_STATE_LOCK:
                candidate = preserve_auto_monitor_progress(payload, settings_state)
                normalized = save_settings(candidate)
                settings_state.clear()
                settings_state.update(normalized)
        except Exception:
            app.logger.exception("Failed to save settings")
            return jsonify({"success": False, "error": "Could not save settings"}), 500
        return jsonify({"success": True, "settings": normalized})

    @app.route("/api/settings/auto-monitor")
    @require_auth
    def get_auto_monitor_settings():
        with SETTINGS_STATE_LOCK:
            normalized = normalize_settings_document(
                settings_state,
                customer_name_lookup=get_customer_name,
            )
        auto_monitor = normalized.get("auto_monitor", {})
        return jsonify(
            {
                "defaults": auto_monitor.get("defaults", {}),
                "rules": [
                    build_auto_monitor_rule_status(rule)
                    for rule in auto_monitor.get("rules", [])
                ],
            }
        )

    @app.route("/api/settings/validate/google-drive", methods=["POST"])
    @require_auth
    def validate_google_drive_settings_route():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid settings payload"}), 400

        result = validate_google_drive(folder_id=payload.get("folder_id", ""))
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/settings/validate/remote-sync", methods=["POST"])
    @require_auth
    def validate_remote_sync_settings_route():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid settings payload"}), 400

        result = validate_remote_sync(
            endpoint=payload.get("endpoint", ""),
            api_key=payload.get("api_key", ""),
        )
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/settings/google-drive/status")
    @require_auth
    def google_drive_status_route():
        return jsonify(get_google_drive_auth_status())

    @app.route("/api/settings/google-drive/auth-url")
    @require_auth
    def google_drive_auth_url_route():
        redirect_uri = request.host_url.rstrip("/") + "/api/settings/google-drive/callback"
        result = build_google_drive_auth_url(redirect_uri=redirect_uri)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/settings/google-drive/credentials", methods=["POST"])
    @require_auth
    def google_drive_credentials_route():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or "credentials" not in payload:
            return jsonify({"success": False, "error": "Invalid credentials payload"}), 400
        result = save_google_drive_credentials(payload.get("credentials"))
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    @app.route("/api/settings/google-drive/callback")
    def google_drive_callback_route():
        code = request.args.get("code", "")
        state = request.args.get("state", "")
        # Reflected values are HTML-escaped to prevent XSS (#197).
        error = escape(request.args.get("error", ""))
        if error:
            return (
                "<html><body><h3>Google Drive connection failed</h3>"
                f"<p>{error}</p></body></html>",
                400,
            )
        try:
            result = exchange_google_drive_auth_code(code=code, state=state)
            if not result.get("success"):
                return (
                    "<html><body><h3>Google Drive connection failed</h3>"
                    f"<p>{escape(str(result.get('error', 'Unknown error')))}</p></body></html>",
                    400,
                )
            folder_result = ensure_google_drive_reports_folder()
            with SETTINGS_STATE_LOCK:
                normalized = normalize_settings_document(settings_state)
                google_drive_state = normalized.get("sync", {}).get("google_drive", {})
                if folder_result.get("success"):
                    google_drive_state.update(
                        {
                            "enabled": True,
                            "folder_id": folder_result.get("folder_id", ""),
                            "status": "Connected",
                        }
                    )
                else:
                    failure_reason = folder_result.get("error", "Folder setup failed")
                    google_drive_state.update(
                        {
                            "enabled": False,
                            "status": f"Connected (folder setup failed: {failure_reason})",
                        }
                    )
                normalized["sync"]["google_drive"] = google_drive_state
                normalized = save_settings(normalized)
                settings_state.clear()
                settings_state.update(normalized)
            message = "Google Drive connected."
            backfill_result = None
            if folder_result.get("success") and upload_latest_report_to_google_drive is not None:
                backfill_result = upload_latest_report_to_google_drive()
            if folder_result.get("success"):
                message = "Google Drive connected. Reports will sync to nmapui-reports."
                if isinstance(backfill_result, dict):
                    if backfill_result.get("attempted") and backfill_result.get("success"):
                        message += " Latest completed report was uploaded."
                    elif backfill_result.get("attempted") and not backfill_result.get("success"):
                        message += (
                            " Latest completed report upload failed. "
                            f"{backfill_result.get('error', 'Check Logs for details.')}"
                        )
                    elif backfill_result.get("error"):
                        message += (
                            " No saved report was uploaded automatically. "
                            f"{backfill_result.get('error')}"
                        )
            else:
                message = (
                    "Google Drive connected, but the default folder could not be created. "
                    f"{folder_result.get('error', 'Check Settings to finish setup.')}"
                )
            return f"<html><body><h3>{message}</h3><p>You can close this window and return to NmapUI.</p></body></html>"
        except Exception as exc:
            app.logger.exception("Google Drive callback failed")
            return (
                "<html><body><h3>Google Drive connection failed</h3>"
                f"<p>Unexpected callback error: {escape(str(exc))}</p></body></html>",
                500,
            )

    @app.route("/api/settings/google-drive/disconnect", methods=["POST"])
    @require_auth
    def google_drive_disconnect_route():
        return jsonify(disconnect_google_drive())
