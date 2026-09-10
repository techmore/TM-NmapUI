import subprocess

from flask_socketio import emit
from nmapui.auth import require_socket_auth


def register_update_handlers(socketio, deps):
    check_for_updates = deps["check_for_updates"]
    idle_state_manager = deps["idle_state_manager"]
    logger = deps["logger"]

    @socketio.on("check_app_updates")
    @require_socket_auth()
    def check_app_updates_event():
        update_info = check_for_updates()
        if isinstance(update_info, dict):
            available = update_info.get("available", False)
            idle_state_manager.set_update_available(bool(available), update_info)
            emit("app_update_available", update_info)
        else:
            idle_state_manager.set_update_available(False)
            emit("app_update_available", {"available": False})

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
