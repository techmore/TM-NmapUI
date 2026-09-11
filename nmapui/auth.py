import base64
import hmac
import ipaddress
import os
from functools import wraps

from flask import jsonify, redirect, request
from flask_socketio import emit

from nmapui import session as session_module
from nmapui.paths import SESSION_SECRET_FILE


DEFAULT_AUTH_USERNAME = "admin"
DEFAULT_AUTH_PASSWORD = "nmapui123"

_session_secret_cache = None


def get_session_secret():
    """Return (and lazily create) the persisted session signing key."""
    global _session_secret_cache
    if _session_secret_cache is None:
        _session_secret_cache = session_module.load_or_create_secret(SESSION_SECRET_FILE)
    return _session_secret_cache


def session_username():
    """Return the username for a valid session cookie, else None."""
    token = request.cookies.get(session_module.SESSION_COOKIE, "")
    if not token:
        return None
    return session_module.verify_token(get_session_secret(), token)


def wants_html():
    """True when the caller is a browser navigating, not an API client."""
    if request.path.startswith("/api/"):
        return False
    accept = (request.headers.get("Accept") or "").lower()
    return "text/html" in accept or "*/*" in accept


def get_auth_credentials():
    return (
        os.environ.get("NMAPUI_USERNAME", DEFAULT_AUTH_USERNAME),
        os.environ.get("NMAPUI_PASSWORD", DEFAULT_AUTH_PASSWORD),
    )


def default_credentials_allowed():
    return os.environ.get("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


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
        username == DEFAULT_AUTH_USERNAME
        and password == DEFAULT_AUTH_PASSWORD
        and not default_credentials_allowed()
    )


def check_auth(username, password):
    """Validate credentials."""
    if auth_uses_insecure_defaults():
        return False

    expected_username, expected_password = get_auth_credentials()
    return hmac.compare_digest(username, expected_username) and hmac.compare_digest(
        password, expected_password
    )


def set_session_cookie(response, username):
    """Attach a long-lived signed session cookie to a response."""
    response.set_cookie(
        session_module.SESSION_COOKIE,
        session_module.issue_token(get_session_secret(), username),
        max_age=session_module.SESSION_TTL_SECONDS,
        httponly=True,
        samesite="Lax",
        path="/",
    )
    return response


def clear_session_cookie(response):
    response.delete_cookie(session_module.SESSION_COOKIE, path="/")
    return response


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
    """Decorator requiring a session cookie or HTTP Basic Auth."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if request_is_local_ui():
            return f(*args, **kwargs)
        # A long-lived session cookie is the normal browser path; Basic auth
        # remains for API clients and scripts.
        if session_username():
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            if auth_uses_insecure_defaults():
                return jsonify({"error": "Authentication is not configured securely"}), 503
            if wants_html():
                return redirect("/login")
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


def _basic_credentials_valid():
    """Validate the request's Basic credentials, from either source Flask uses."""
    auth = request.authorization
    if auth and check_auth(auth.username, auth.password):
        return True

    header = (request.headers.get("Authorization") or "").strip()
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
            username, password = decoded.split(":", 1)
            if check_auth(username, password):
                return True
        except Exception:
            return False
    return False


def socket_authorized():
    """True when the current Socket.IO handshake may proceed.

    The loopback handshake token is CSRF protection, not a credential: any
    local process can fetch it.  This is the actual gate.
    """
    if request_is_local_ui():
        return True
    if session_username():
        return True
    return _basic_credentials_valid()


def require_socket_auth():
    """Decorator to require an authenticated session for Socket.IO events."""

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if socket_authorized():
                return f(*args, **kwargs)
            if auth_uses_insecure_defaults():
                emit("auth_error", {"error": "Authentication is not configured securely"})
                return None
            emit("auth_error", {"error": "Unauthorized"})
            return None

        return wrapped

    return decorator
