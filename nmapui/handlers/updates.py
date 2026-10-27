import subprocess

from flask import request
from flask_socketio import emit
from nmapui.auth import require_socket_auth
from nmapui.daedalus_commands import command_id_from_payload, begin_command, emit_command_result


def register_update_handlers(socketio, deps):
    check_for_updates = deps["check_for_updates"]
    idle_state_manager = deps["idle_state_manager"]
    logger = deps["logger"]

    broadcaster = deps.get("broadcaster")
    receipt_deps = {"broadcaster": broadcaster, "runtime_store": deps.get("runtime_store"), "emit_to_client": deps.get("emit_to_client") or (lambda sid, event, data=None: socketio.emit(event, data, to=sid))}

    @socketio.on("check_app_updates")
    @require_socket_auth()
    def check_app_updates_event(data=None):
        try:
            command_id = command_id_from_payload(data, sid=request.sid, broadcaster=broadcaster)
        except ValueError:
            emit("update_error", {"message": "Invalid Daedalus command identifier"})
            return
        if not begin_command(command_id=command_id, owner_sid=request.sid, action="check_nmapui_updates", **receipt_deps):
            return
        try:
            update_info = check_for_updates(operator_requested=True)
            if isinstance(update_info, dict):
                available = update_info.get("available", False)
                if not (available and update_info.get("manual_check_only")):
                    idle_state_manager.set_update_available(bool(available), update_info)
                emit("app_update_available", update_info)
            else:
                idle_state_manager.set_update_available(False)
                emit("app_update_available", {"available": False})
            failed = not isinstance(update_info, dict) or bool(update_info.get("error") or update_info.get("disabled"))
            emit_command_result(command_id=command_id, owner_sid=request.sid, status="failed" if failed else "succeeded", result="NmapUI update checking was disabled or unavailable." if failed else "NmapUI release-channel check completed.", **receipt_deps)
        except Exception:
            logger.exception("Update availability check failed")
            emit_command_result(command_id=command_id, owner_sid=request.sid, status="failed", result="NmapUI update availability check failed.", **receipt_deps)
            emit("update_error", {"message": "NmapUI update availability check failed"})

    @socketio.on("perform_app_update")
    @require_socket_auth()
    def perform_app_update_event():
        try:
            update_info = check_for_updates()
            download_url = None
            message = None
            if (
                isinstance(update_info, dict)
                and update_info.get("available")
            ):
                download_url = update_info.get("download_url") or update_info.get("release_url")
                asset_name = update_info.get("asset_name")
                if asset_name:
                    message = f"Opening installer download for {asset_name}..."
                else:
                    message = "Opening release download page..."
            else:
                download_url = "https://github.com/techmore/TM-NmapUI/releases"
                message = "Opening releases page..."

            emit("update_status", {"message": message})
            socketio.sleep(1)
            subprocess.run(["open", str(download_url)], check=False)

            emit(
                "update_status",
                {
                    "message": "Manual install required. Download the installer, complete installation, then relaunch NmapUI."
                },
            )
            emit(
                "update_complete",
                {
                    "message": "Installer page opened. Finish the update manually and relaunch NmapUI.",
                    "manual_install": True,
                    "download_url": download_url,
                },
            )
        except Exception as exc:
            logger.error("Update failed: %s", exc)
            emit("update_error", {"message": f"Failed to open download: {str(exc)}"})

    @socketio.on("cancel_auto_update")
    @require_socket_auth()
    def cancel_auto_update_event():
        idle_state_manager.cancel_countdown()
        emit("hide_auto_update_banner")

    @socketio.on("start_auto_update_countdown")
    @require_socket_auth()
    def start_auto_update_countdown_event():
        idle_state_manager.start_countdown()
