import base64
import ipaddress
import os
from functools import wraps

from flask import jsonify, request
from flask_socketio import emit


DEFAULT_AUTH_USERNAME = "admin"
DEFAULT_AUTH_PASSWORD = "nmapui123"


def get_auth_credentials():
    return (
        os.environ.get("NMAPUI_USERNAME", DEFAULT_AUTH_USERNAME),
        os.environ.get("NMAPUI_PASSWORD", DEFAULT_AUTH_PASSWORD),
    )


def default_credentials_allowed():
    """Acknowledgement applies only to a loopback-bound, trusted local UI."""
    acknowledged = os.environ.get("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "").strip().lower() in {
        "1", "true", "yes", "on",
    }
    if not acknowledged or not local_ui_trusted():
        return False
    bind_host = os.environ.get("NMAPUI_HOST", "127.0.0.1").strip()
    if bind_host.startswith("[") and bind_host.endswith("]"):
        bind_host = bind_host[1:-1]
    if bind_host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind_host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def local_ui_trusted():
    return os.environ.get("NMAPUI_TRUST_LOCAL_UI", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def request_is_local_ui():
    if not local_ui_trusted():
        return False

    host = (request.host or "").split(":", 1)[0].lower()
    remote_addr = (request.remote_addr or "").lower()
    origin = (request.headers.get("Origin") or "").lower()

    allowed_hosts = {"127.0.0.1", "localhost"}
    local_remote_addrs = {"127.0.0.1", "::1", "localhost"}

    def is_loopback_remote_addr(value):
        if value in local_remote_addrs:
            return True
        try:
            address = ipaddress.ip_address(value)
            if address.is_loopback:
                return True
            if getattr(address, "ipv4_mapped", None) is not None:
                return address.ipv4_mapped.is_loopback
            return False
        except ValueError:
            return False

    def origin_is_local_ui(value):
        if not value:
            return True
        return any(token in value for token in ("127.0.0.1", "localhost"))

    if not is_loopback_remote_addr(remote_addr):
        return False

    if host and host not in allowed_hosts:
        return False

    if not origin_is_local_ui(origin):
        return False

    return True


def auth_uses_insecure_defaults():
    username, password = get_auth_credentials()
    return (
        not username.strip()
        or not password.strip()
        or (password == DEFAULT_AUTH_PASSWORD and not default_credentials_allowed())
    )


def check_auth(username, password):
    """Validate credentials."""
    if auth_uses_insecure_defaults():
        return False

    expected_username, expected_password = get_auth_credentials()
    return username == expected_username and password == expected_password


def log_auth_posture():
    """Emit startup warnings about the active authentication posture."""
    import logging as _logging
    _log = _logging.getLogger(__name__)

    if local_ui_trusted():
        _log.warning(
            "SECURITY: NMAPUI_TRUST_LOCAL_UI is ON — all localhost connections "
            "bypass authentication. Set NMAPUI_TRUST_LOCAL_UI=false to enforce "
            "credentials for every connection."
        )
    if auth_uses_insecure_defaults():
        _log.warning(
            "SECURITY: No credentials configured. Set NMAPUI_USERNAME and "
            "NMAPUI_PASSWORD environment variables, or enable "
            "NMAPUI_ALLOW_DEFAULT_CREDENTIALS=true to acknowledge the default "
            "credentials (admin / nmapui123)."
        )
    elif not local_ui_trusted():
        username, _ = get_auth_credentials()
        _log.info("Auth active — username: %s", username)


def require_auth(f):
    """Decorator to require HTTP Basic Auth for Flask routes."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if request_is_local_ui():
            return f(*args, **kwargs)
        if not auth or not check_auth(auth.username, auth.password):
            if auth_uses_insecure_defaults():
                return jsonify({"error": "Authentication is not configured securely"}), 503
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


def require_socket_auth():
    """Decorator to require HTTP Basic Auth context for Socket.IO events."""

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth = request.authorization
            if request_is_local_ui():
                return f(*args, **kwargs)
            if not auth:
                header = request.headers.get("Authorization", "")
                if header.startswith("Basic "):
                    try:
                        decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
                        username, password = decoded.split(":", 1)
                        if check_auth(username, password):
                            return f(*args, **kwargs)
                    except Exception:
                        pass
                if auth_uses_insecure_defaults():
                    emit("auth_error", {"error": "Authentication is not configured securely"})
                    return None
                emit("auth_error", {"error": "Unauthorized"})
                return None

            if not check_auth(auth.username, auth.password):
                if auth_uses_insecure_defaults():
                    emit("auth_error", {"error": "Authentication is not configured securely"})
                    return None
                emit("auth_error", {"error": "Unauthorized"})
                return None
            return f(*args, **kwargs)

        return wrapped

    return decorator
