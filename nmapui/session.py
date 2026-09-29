"""Long-lived signed sessions for the appliance UI.

The product runs for a year at a time without a human present, so a browser
must not be asked to re-authenticate constantly.  HTTP Basic auth prompts again
after a browser restart; this module issues a signed, expiring cookie instead,
so one login lasts about 13 months.

The signing key is generated once and persisted with 0600 permissions in the
data directory.  Tokens are HMAC-SHA256 over a compact JSON payload, compared
with ``hmac.compare_digest``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

from .private_storage import load_or_create_private_bytes

SESSION_COOKIE = "nmapui_session"
# ~13 months: comfortably longer than the one-year unattended target.
SESSION_TTL_SECONDS = 400 * 24 * 60 * 60

_SECRET_BYTES = 32


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def load_or_create_secret(secret_path: Path) -> bytes:
    """Return one durable signing key, or fail closed if it cannot be stored."""
    return load_or_create_private_bytes(
        secret_path,
        lambda: secrets.token_bytes(_SECRET_BYTES),
        minimum_size=_SECRET_BYTES,
    )


def issue_token(secret: bytes, username: str, *, now=None, ttl=SESSION_TTL_SECONDS) -> str:
    """Issue a signed session token for ``username``."""
    issued = int(now if now is not None else time.time())
    payload = json.dumps(
        {"u": username, "iat": issued, "exp": issued + int(ttl)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(secret, payload, hashlib.sha256).digest()
    return f"{_b64e(payload)}.{_b64e(signature)}"


def verify_token(secret: bytes, token: str, *, now=None):
    """Return the username for a valid, unexpired token, else ``None``."""
    if not token or "." not in token:
        return None

    payload_part, signature_part = token.split(".", 1)
    try:
        payload = _b64d(payload_part)
        signature = _b64d(signature_part)
    except Exception:
        return None

    expected = hmac.new(secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        data = json.loads(payload)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    expires_at = data.get("exp")
    current = int(now if now is not None else time.time())
    if not isinstance(expires_at, int) or expires_at <= current:
        return None

    username = data.get("u")
    return username if isinstance(username, str) and username else None
