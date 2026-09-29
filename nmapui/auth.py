import base64
import hmac
import ipaddress
import json
import os
from functools import wraps
from urllib.parse import urlsplit

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


def _session_signing_secret():
    """Bind sessions to the active login credentials so rotation revokes them."""
    username, password = get_auth_credentials()
    credentials = json.dumps(
        (username, password), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(
        get_session_secret(),
        b"nmapui-session-auth-v1\0" + credentials,
        digestmod="sha256",
    ).digest()


def _secure_session_cookies_enabled():
    value = os.environ.get("NMAPUI_COOKIE_SECURE", "false").strip().lower()
    return request.is_secure or value in {"1", "true", "yes", "on"}


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
    """Protect browser mutations; headerless API clients still authenticate normally.

    SameSite cookies do not isolate different ports or same-site subdomains.
    Compare browser origins with the requested app origin and explicitly
    configured frontend origins before allowing a state-changing request.
    """
    scheme = "https" if _secure_session_cookies_enabled() else "http"
    expected = _url_origin(f"{scheme}://{request.host}")
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
    return (request.headers.get("Sec-Fetch-Site") or "").lower() != "cross-site"


def session_username():
    """Return the username for a valid session cookie, else None."""
    token = request.cookies.get(session_module.SESSION_COOKIE, "")
    if not token:
        return None
    return session_module.verify_token(_session_signing_secret(), token)


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
    """Permit the built-in password only for acknowledged loopback-local mode."""
    acknowledged = os.environ.get("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not acknowledged or not local_ui_trusted():
        return False

    bind_host = str(os.environ.get("NMAPUI_HOST", "127.0.0.1") or "127.0.0.1").strip()
    if bind_host.startswith("[") and bind_host.endswith("]"):
        bind_host = bind_host[1:-1]
    if bind_host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind_host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def local_ui_trusted():
    # The appliance is loopback-only by default, so local browser access needs
    # no separate account. Remote peers never pass request_is_local_ui(). Set
    # this to false when local processes should also need credentials.
    return os.environ.get("NMAPUI_TRUST_LOCAL_UI", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def request_is_local_ui():
    if not local_ui_trusted():
        return False

    try:
        host = urlsplit(f"http://{request.host or ''}").hostname
    except ValueError:
        return False
    remote_addr = (request.remote_addr or "").lower()
    origin = request.headers.get("Origin") or ""

    allowed_hosts = {"127.0.0.1", "localhost", "::1"}
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

    def url_is_local_ui(value, *, serialized_origin):
        try:
            parsed = urlsplit(value)
            valid = (
                parsed.scheme in {"http", "https"}
                and parsed.hostname in allowed_hosts
                and parsed.username is None
                and parsed.password is None
                and parsed.port != 0
            )
            # Browsers send Origin as a serialized origin, not an arbitrary
            # URL. Referer may contain a path but still needs a local host.
            return valid and (
                not serialized_origin
                or (not parsed.path and not parsed.query and not parsed.fragment)
            )
        except ValueError:
            return False

    if not is_loopback_remote_addr(remote_addr):
        return False

    if host and host not in allowed_hosts:
        return False

    if (request.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
        return False

    if origin and not url_is_local_ui(origin, serialized_origin=True):
        return False

    referer = request.headers.get("Referer") or ""
    if not origin and referer and not url_is_local_ui(referer, serialized_origin=False):
        return False

    return True


def auth_uses_insecure_defaults():
    username, password = get_auth_credentials()
    if not username.strip() or not password.strip():
        return True
    return password == DEFAULT_AUTH_PASSWORD and not default_credentials_allowed()


def check_auth(username, password):
    """Validate credentials."""
    if auth_uses_insecure_defaults() or not isinstance(username, str) or not isinstance(password, str):
        return False

    expected_username, expected_password = get_auth_credentials()
    return hmac.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8")) and hmac.compare_digest(
        password.encode("utf-8"), expected_password.encode("utf-8")
    )


def set_session_cookie(response, username):
    """Attach a long-lived signed session cookie to a response."""
    response.set_cookie(
        session_module.SESSION_COOKIE,
        session_module.issue_token(_session_signing_secret(), username),
        max_age=session_module.SESSION_TTL_SECONDS,
        httponly=True,
        secure=_secure_session_cookies_enabled(),
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
        if local_ui_trusted():
            _log.info("Remote authentication is not configured; non-loopback requests will be rejected.")
        else:
            _log.warning(
                "SECURITY: Authentication credentials are empty or use the "
                "built-in default password. Set non-empty NMAPUI_USERNAME and "
                "NMAPUI_PASSWORD values; only enable "
                "NMAPUI_ALLOW_DEFAULT_CREDENTIALS=true when intentionally "
                "accepting the default password for a local-only install."
            )
    elif not local_ui_trusted():
        username, _ = get_auth_credentials()
        _log.info("Auth active — username: %s", username)


def require_auth(f):
    """Decorator requiring a session cookie or HTTP Basic Auth."""

    @wraps(f)
    def decorated(*args, **kwargs):
        def authenticated_call():
            if request.method not in {"GET", "HEAD", "OPTIONS"} and not browser_request_origin_allowed():
                return jsonify({"error": "Request origin is not allowed"}), 403
            return f(*args, **kwargs)

        if request_is_local_ui():
            return authenticated_call()
        # A long-lived session cookie is the normal browser path; Basic auth
        # remains for API clients and scripts.
        if session_username():
            return authenticated_call()
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            if auth_uses_insecure_defaults():
                return jsonify({"error": "Authentication is not configured securely"}), 503
            if wants_html():
                return redirect("/login")
            return jsonify({"error": "Unauthorized"}), 401
        return authenticated_call()

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
