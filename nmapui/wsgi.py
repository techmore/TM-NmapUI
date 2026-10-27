"""Single-worker Gunicorn entry point for supervised host installations."""

from app import app
from app import log_auth_posture, start_auto_scan_thread, startup_checks
from nmapui.auth import get_session_secret

application = app


# Gunicorn imports this module in its worker when preload is disabled. Keep one
# worker: Socket.IO connections and the in-memory job registry are process-local.
log_auth_posture()
get_session_secret()
startup_checks(quick=False)
start_auto_scan_thread()
