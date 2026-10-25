import base64
import ipaddress
import os
from functools import wraps
from urllib.parse import urlsplit

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


def _url_origin(value, *, allow_path=False):
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (not allow_path and (parsed.path or parsed.query))
        ):
            return None
        port = parsed.port
        if port == 0:
            return None
        return parsed.scheme, parsed.hostname, port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def browser_request_origin_allowed():
    """Validate browser mutations while preserving headerless Basic API clients."""
    expected = _url_origin(request.host_url.rstrip("/"))
    allowed = {
        origin
        for value in os.environ.get("NMAPUI_ALLOWED_ORIGINS", "").split(",")
        if (origin := _url_origin(value.strip())) is not None
    }
    if expected is not None:
        allowed.add(expected)
    origin = request.headers.get("Origin")
    if origin is not None:
        return _url_origin(origin) in allowed
    referer = request.headers.get("Referer")
    if referer is not None:
        return _url_origin(referer, allow_path=True) in allowed
    return (request.headers.get("Sec-Fetch-Site") or "").strip().lower() != "cross-site"


def request_is_local_ui():
    if not local_ui_trusted():
        return False
    allowed_hosts = {"127.0.0.1", "localhost", "::1"}
    host_origin = _url_origin(request.host_url.rstrip("/"))
    if host_origin is None or host_origin[1] not in allowed_hosts:
        return False
    remote_addr = (request.remote_addr or "").lower()
    try:
        address = ipaddress.ip_address(remote_addr)
        loopback = address.is_loopback or bool(getattr(address, "ipv4_mapped", None) and address.ipv4_mapped.is_loopback)
    except ValueError:
        loopback = remote_addr == "localhost"
    if not loopback:
        return False
    if (request.headers.get("Sec-Fetch-Site") or "").strip().lower() == "cross-site":
        return False
    origin = request.headers.get("Origin")
    if origin is not None:
        parsed = _url_origin(origin)
        return parsed is not None and parsed[1] in allowed_hosts
    referer = request.headers.get("Referer")
    if referer is not None:
        parsed = _url_origin(referer, allow_path=True)
        return parsed is not None and parsed[1] in allowed_hosts
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
        def authenticated_call():
            if request.method not in {"GET", "HEAD", "OPTIONS"} and not browser_request_origin_allowed():
                return jsonify({"error": "Request origin is not allowed"}), 403
            return f(*args, **kwargs)

        auth = request.authorization
        if request_is_local_ui():
            return authenticated_call()
        if not auth or not check_auth(auth.username, auth.password):
            if auth_uses_insecure_defaults():
                return jsonify({"error": "Authentication is not configured securely"}), 503
            return jsonify({"error": "Unauthorized"}), 401
        return authenticated_call()

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
