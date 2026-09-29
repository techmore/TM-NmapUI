from datetime import datetime
import os
import socket

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

from .runtime import env_flag


DEFAULT_RUNTIME_PORT = 9000
RUNTIME_PORT_SEARCH_LIMIT = 20


def get_allowed_origins(*, port=None):
    """Return the explicit CORS allowlist for HTTP and Socket.IO."""
    configured = os.environ.get("NMAPUI_ALLOWED_ORIGINS", "").strip()
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    selected_port = int(port or os.environ.get("NMAPUI_PORT", str(DEFAULT_RUNTIME_PORT)))
    return [
        f"http://127.0.0.1:{selected_port}",
        f"http://localhost:{selected_port}",
        f"http://[::1]:{selected_port}",
    ]


def _is_port_available(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def select_runtime_port(host, requested_port, *, explicit=False):
    """Pick a runtime port, honoring explicit requests and otherwise falling back."""
    if explicit:
        if not _is_port_available(host, requested_port):
            raise RuntimeError(
                f"Requested NmapUI port {requested_port} is already in use on {host}"
            )
        return requested_port

    for candidate in range(requested_port, requested_port + RUNTIME_PORT_SEARCH_LIMIT):
        if _is_port_available(host, candidate):
            return candidate

    raise RuntimeError(
        "Unable to find an available local runtime port "
        f"between {requested_port} and {requested_port + RUNTIME_PORT_SEARCH_LIMIT - 1}"
    )


def build_runtime_options(argv, *, selected_port=None):
    """Build server runtime options from argv and environment."""
    host = os.environ.get("NMAPUI_HOST", "127.0.0.1")
    requested_port = int(os.environ.get("NMAPUI_PORT", str(DEFAULT_RUNTIME_PORT)))
    explicit_port = bool(os.environ.get("NMAPUI_PORT", "").strip())
    resolved_port = (
        int(selected_port)
        if selected_port is not None
        else select_runtime_port(host, requested_port, explicit=explicit_port)
    )
    return {
        "quick_mode": "--quick" in argv or "-q" in argv,
        "host": host,
        "port": resolved_port,
        "requested_port": requested_port,
        "port_auto_selected": resolved_port != requested_port,
        "debug": env_flag("NMAPUI_DEBUG", default=False),
        "allow_unsafe_werkzeug": env_flag(
            "NMAPUI_ALLOW_UNSAFE_WERKZEUG", default=False
        ),
    }


def create_web_app(import_name, *, port=None):
    """Create the Flask app and Socket.IO server with the default CORS policy."""
    allowed_origins = get_allowed_origins(port=port)
    app = Flask(import_name)
    socketio = SocketIO(app, cors_allowed_origins=allowed_origins)
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})
    return app, socketio


def begin_startup_state(startup_state, *, quick):
    """Reset startup-state tracking for a new startup attempt."""
    startup_state["startup_complete"] = False
    startup_state["dependency_checks_skipped"] = bool(quick)
    startup_state["dependencies_ok"] = False
    startup_state["traceroute_initialized"] = False
    startup_state["last_started_at"] = datetime.now().isoformat()
    startup_state["errors"] = []
    return startup_state


def complete_startup_state(startup_state, *, traceroute_initialized):
    """Mark startup as fully initialized."""
    startup_state["traceroute_initialized"] = bool(traceroute_initialized)
    startup_state["startup_complete"] = True
    return startup_state


def run_socketio_server(socketio, app, runtime_options):
    """Run the Socket.IO server using the normalized runtime options."""
    socketio.run(
        app,
        host=runtime_options["host"],
        port=runtime_options["port"],
        debug=runtime_options["debug"],
        allow_unsafe_werkzeug=(
            runtime_options["debug"] or runtime_options["allow_unsafe_werkzeug"]
        ),
    )
