import base64
import hashlib
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

from cryptography.fernet import Fernet, InvalidToken

from .google_drive_upload import upload_file

from .private_storage import (
    atomic_replace_private_bytes,
    load_or_create_private_bytes,
    load_private_bytes,
)


GOOGLE_DRIVE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_DRIVE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
GOOGLE_DRIVE_FILES_ENDPOINT = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"
_TOKEN_LOCK = threading.RLock()


def _serialized_tokens(function):
    """Serialize token read/modify/write operations in the single-worker server."""
    @wraps(function)
    def locked(*args, **kwargs):
        with _TOKEN_LOCK:
            return function(*args, **kwargs)
    return locked


def _format_google_drive_error(payload: dict) -> str:
    if not isinstance(payload, dict):
        return "Unknown error"
    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("status") or "Google Drive API error"
        reasons = []
        for entry in error.get("errors", []) or []:
            if isinstance(entry, dict) and entry.get("reason"):
                reasons.append(entry["reason"])
        if reasons:
            unique = ", ".join(sorted(set(reasons)))
            return f"{message} ({unique})"
        return message
    if isinstance(error, str):
        return error
    return payload.get("error_description") or payload.get("message") or "Unknown error"


def _response_json(response) -> dict:
    try:
        payload = response.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _token_lifetime(payload):
    if not isinstance(payload.get("access_token"), str) or not payload["access_token"]:
        raise ValueError("Missing access token")
    if str(payload.get("token_type", "Bearer")).lower() != "bearer":
        raise ValueError("Unsupported token type")
    expires_in = int(payload.get("expires_in", 3600))
    if not 0 < expires_in <= 86400:
        raise ValueError("Invalid token lifetime")
    if "scope" in payload and GOOGLE_DRIVE_SCOPE not in str(payload["scope"]).split():
        raise ValueError("Drive file access was not granted")
    return expires_in


def _authorized_request(*, method, url, credentials_path, token_path, key_path, requests_module, **kwargs):
    """Retry one rejected Bearer token without duplicating non-401 writes."""
    headers = kwargs.pop("headers", {})
    for force_refresh in (False, True):
        token = ensure_google_drive_access_token(
            credentials_path=credentials_path, token_path=token_path, key_path=key_path,
            requests_module=requests_module, force_refresh=force_refresh,
        )
        response = getattr(requests_module, method)(
            url, headers={**headers, "Authorization": f"Bearer {token}"}, **kwargs,
        )
        if response.status_code != 401:
            return response
    return response


ENCRYPTED_TOKEN_SCHEMA_VERSION = 1


def _load_json_file(path: Path, default):
    try:
        return json.loads(load_private_bytes(path).decode("utf-8"))
    except (OSError, ValueError):
        return default


def _save_json_file(path: Path, payload: dict) -> None:
    atomic_replace_private_bytes(path, json.dumps(payload, indent=2).encode("utf-8"))


def _load_or_create_encryption_key(key_path: Path) -> bytes:
    return load_or_create_private_bytes(
        key_path, Fernet.generate_key, normalize=bytes.strip
    )


def _load_encrypted_token_payload(token_path: Path, key_path: Path):
    if not token_path.exists():
        return None
    payload = _load_json_file(token_path, {})
    if not isinstance(payload, dict) or "ciphertext" not in payload:
        return None

    ciphertext = payload.get("ciphertext")
    if not ciphertext:
        return {}

    key = load_private_bytes(key_path, normalize=bytes.strip)
    decrypted = Fernet(key).decrypt(str(ciphertext).encode("utf-8"))
    decoded = json.loads(decrypted.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def load_google_drive_credentials(credentials_path: Path) -> dict:
    payload = _load_json_file(credentials_path, {})
    if not isinstance(payload, dict):
        return {}
    if "installed" in payload:
        payload = payload["installed"]
    elif "web" in payload:
        payload = payload["web"]
    return payload if isinstance(payload, dict) else {}


def save_google_drive_credentials(credentials_path: Path, payload: dict) -> dict:
    if not isinstance(payload, dict):
        return {"success": False, "error": "Invalid credentials payload"}
    credentials = payload.get("installed", payload.get("web", payload))
    if not isinstance(credentials, dict) or any(
        not isinstance(credentials.get(key), str) or not credentials[key].strip()
        for key in ("client_id", "client_secret")
    ):
        return {"success": False, "error": "Import a valid desktop or web OAuth client credentials JSON."}
    _save_json_file(credentials_path, payload)
    return {"success": True, "status": "Google Drive credentials saved"}


@_serialized_tokens
def load_google_drive_token_state(token_path: Path, key_path: Path | None = None) -> dict:
    key_path = key_path or token_path.with_suffix(".key")
    try:
        encrypted_payload = _load_encrypted_token_payload(token_path, key_path)
    except (InvalidToken, ValueError, OSError):
        return {}
    if encrypted_payload is not None:
        return encrypted_payload

    payload = _load_json_file(token_path, {})
    if not isinstance(payload, dict):
        return {}
    if payload:
        save_google_drive_token_state(token_path, payload, key_path=key_path)
    return payload


@_serialized_tokens
def save_google_drive_token_state(token_path: Path, payload: dict, key_path: Path | None = None) -> dict:
    key_path = key_path or token_path.with_suffix(".key")
    key = _load_or_create_encryption_key(key_path)
    encrypted_payload = Fernet(key).encrypt(json.dumps(payload).encode("utf-8")).decode("utf-8")
    _save_json_file(
        token_path,
        {
            "schema_version": ENCRYPTED_TOKEN_SCHEMA_VERSION,
            "ciphertext": encrypted_payload,
        },
    )
    return payload


@_serialized_tokens
def clear_google_drive_token_state(token_path: Path, key_path: Path | None = None) -> None:
    if token_path.exists():
        token_path.unlink()
    key_path = key_path or token_path.with_suffix(".key")
    if key_path.exists():
        key_path.unlink()


def build_google_drive_auth_status(*, credentials_path: Path, token_path: Path, key_path: Path | None = None) -> dict:
    credentials = load_google_drive_credentials(credentials_path)
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    has_refresh_token = bool(token_state.get("refresh_token"))
    has_access_token = bool(token_state.get("access_token")) and not _token_is_expired(token_state)
    expires_at = token_state.get("expires_at")
    configured = bool(credentials.get("client_id") and credentials.get("client_secret"))
    if has_refresh_token or has_access_token:
        status = "Connected"
    elif configured:
        status = "Not connected"
    else:
        status = "OAuth credentials missing. Import credentials.json to enable Google Drive."
    return {
        "configured": configured,
        "connected": has_refresh_token or has_access_token,
        "expires_at": expires_at,
        "status": status,
    }


def _build_code_verifier() -> str:
    return secrets.token_urlsafe(48)


def _build_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


@_serialized_tokens
def build_google_drive_auth_url(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    redirect_uri: str,
) -> dict:
    credentials = load_google_drive_credentials(credentials_path)
    if not credentials.get("client_id") or not credentials.get("client_secret"):
        return {
            "success": False,
            "error": "Google Drive OAuth credentials file not found. Upload your credentials.json from the Google Cloud Console.",
        }

    state = secrets.token_urlsafe(24)
    code_verifier = _build_code_verifier()
    code_challenge = _build_code_challenge(code_verifier)
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    token_state["pending_auth"] = {
        "state": state,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    save_google_drive_token_state(token_path, token_state, key_path=key_path)

    query = urlencode(
        {
            "client_id": credentials["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": GOOGLE_DRIVE_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return {"success": True, "auth_url": f"{GOOGLE_DRIVE_AUTH_ENDPOINT}?{query}"}


@_serialized_tokens
def exchange_google_drive_auth_code(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    code: str,
    state: str,
    requests_module,
) -> dict:
    credentials = load_google_drive_credentials(credentials_path)
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    pending_auth = token_state.get("pending_auth") or {}
    if (not isinstance(pending_auth, dict) or not isinstance(state, str) or not state
            or not secrets.compare_digest(str(pending_auth.get("state", "")).encode(), state.encode())):
        return {"success": False, "error": "Invalid or expired Google Drive auth state."}

    try:
        created_at = datetime.fromisoformat(pending_auth.get("created_at", ""))
        age = datetime.now(timezone.utc) - created_at
        valid = (timedelta(seconds=-60) <= age <= timedelta(minutes=10)
                 and bool(pending_auth.get("code_verifier")) and bool(code))
    except (TypeError, ValueError):
        valid = False
    # Consume before contacting Google: retries/replays need a fresh auth flow.
    token_state.pop("pending_auth", None)
    save_google_drive_token_state(token_path, token_state, key_path=key_path)
    if not valid:
        return {"success": False, "error": "Google Drive auth state has expired. Please restart the auth flow."}

    try:
        response = requests_module.post(
            GOOGLE_DRIVE_TOKEN_ENDPOINT,
            data={
                "client_id": credentials.get("client_id", ""),
                "client_secret": credentials.get("client_secret", ""),
                "code": code,
                "code_verifier": pending_auth.get("code_verifier", ""),
                "grant_type": "authorization_code",
                "redirect_uri": pending_auth.get("redirect_uri", ""),
            },
            timeout=10,
        )
    except Exception:
        return {"success": False, "error": "Failed to reach Google Drive token endpoint. Please restart the auth flow."}
    payload = _response_json(response)
    if response.status_code >= 400 or "access_token" not in payload:
        return {
            "success": False,
            "error": payload.get("error_description")
            or payload.get("error")
            or f"Failed to exchange Google Drive auth code (HTTP {response.status_code}).",
        }

    try:
        expires_in = _token_lifetime(payload)
    except (TypeError, ValueError):
        return {"success": False, "error": "Google Drive returned an invalid token or did not grant file access. Reconnect in Settings."}
    token_state.update(
        {
            "access_token": payload.get("access_token"),
            # A new consent may select a different account. Never reuse the
            # previous account's refresh token with this account's access token.
            "refresh_token": payload.get("refresh_token"),
            "scope": payload.get("scope", GOOGLE_DRIVE_SCOPE),
            "token_type": payload.get("token_type", "Bearer"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        }
    )
    token_state.pop("pending_auth", None)
    save_google_drive_token_state(token_path, token_state, key_path=key_path)
    return {"success": True, "status": "Google Drive connected"}


def _token_is_expired(token_state: dict) -> bool:
    expires_at = token_state.get("expires_at")
    if not expires_at:
        return True
    try:
        expiry = datetime.fromisoformat(expires_at)
        if expiry.tzinfo is None:
            return True
    except (ValueError, TypeError):
        return True
    return expiry <= (datetime.now(timezone.utc) + timedelta(minutes=1))


@_serialized_tokens
def ensure_google_drive_access_token(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
    force_refresh: bool = False,
) -> str:
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    access_token = token_state.get("access_token")
    if access_token and not force_refresh and not _token_is_expired(token_state):
        return access_token

    refresh_token = token_state.get("refresh_token")
    if not refresh_token:
        raise RuntimeError("Google Drive is not connected.")

    credentials = load_google_drive_credentials(credentials_path)
    try:
        response = requests_module.post(
            GOOGLE_DRIVE_TOKEN_ENDPOINT,
            data={
                "client_id": credentials.get("client_id", ""),
                "client_secret": credentials.get("client_secret", ""),
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=10,
        )
    except Exception:
        raise RuntimeError("Failed to refresh Google Drive access token. Please retry.") from None
    payload = _response_json(response)
    if response.status_code >= 400 or "access_token" not in payload:
        if payload.get("error") == "invalid_grant":
            for key in ("access_token", "refresh_token", "expires_at", "scope", "token_type"):
                token_state.pop(key, None)
            save_google_drive_token_state(token_path, token_state, key_path=key_path)
            raise RuntimeError("Google Drive authorization expired or was revoked. Reconnect in Settings.")
        raise RuntimeError(
            payload.get("error_description")
            or payload.get("error")
            or f"Failed to refresh Google Drive access token (HTTP {response.status_code})."
        )

    try:
        expires_in = _token_lifetime(payload)
    except (TypeError, ValueError):
        raise RuntimeError("Google Drive returned an invalid access token. Reconnect in Settings.") from None
    token_state.update(
        {
            "access_token": payload.get("access_token"),
            "token_type": payload.get("token_type", "Bearer"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        }
    )
    save_google_drive_token_state(token_path, token_state, key_path=key_path)
    return token_state["access_token"]


@_serialized_tokens
def disconnect_google_drive(
    *,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
) -> dict:
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    token = token_state.get("refresh_token") or token_state.get("access_token")
    revoked = not bool(token)
    if token:
        try:
            response = requests_module.post(
                GOOGLE_DRIVE_REVOKE_ENDPOINT,
                data={"token": token},
                timeout=10,
            )
            revoked = response.status_code == 200 or (
                response.status_code == 400 and _response_json(response).get("error") == "invalid_token"
            )
        except Exception:
            pass
    clear_google_drive_token_state(token_path, key_path=key_path)
    return {"success": True, "status": "Google Drive disconnected", "revoked": revoked,
            **({"warning": "Local tokens removed. Google revocation could not be confirmed; remove access in your Google Account."} if not revoked else {})}


def upload_files_to_google_drive(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    file_paths: list[Path],
    folder_id: str,
    file_name_map: dict[str, str] | None = None,
    requests_module,
) -> dict:
    def get_token(force_refresh):
        return ensure_google_drive_access_token(
            credentials_path=credentials_path, token_path=token_path,
            key_path=key_path, requests_module=requests_module, force_refresh=force_refresh,
        )
    uploaded = []
    for file_path in file_paths:
        override_name = (file_name_map or {}).get(str(file_path))
        try:
            payload = upload_file(
                file_path=file_path, name=override_name or file_path.name, folder_id=folder_id,
                requests_module=requests_module, get_access_token=get_token,
            )
        except (OSError, RuntimeError) as exc:
            return {"success": False, "uploaded": uploaded, "error": str(exc),
                    "status": f"Uploaded {len(uploaded)} of {len(file_paths)} file(s); upload incomplete"}
        uploaded.append(payload)

    return {
        "success": True,
        "uploaded": uploaded,
        "status": f"Uploaded {len(uploaded)} file(s) to Google Drive",
    }


def ensure_google_drive_reports_folder(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
    folder_name: str = "nmapui-reports",
) -> dict:
    escaped_name = folder_name.replace("\\", "\\\\").replace("'", "\\'")
    query = (
        "mimeType='application/vnd.google-apps.folder' "
        f"and name='{escaped_name}' and trashed=false"
    )
    try:
        response = _authorized_request(
            method="get", url=GOOGLE_DRIVE_FILES_ENDPOINT,
            credentials_path=credentials_path, token_path=token_path, key_path=key_path,
            requests_module=requests_module,
            params={"q": query, "fields": "files(id,name)"},
            timeout=10,
        )
    except Exception:
        return {"success": False, "error": "Failed to query Drive folder. Check the connection or reconnect in Settings."}
    payload = _response_json(response)
    if response.status_code >= 400:
        error_detail = _format_google_drive_error(payload)
        return {
            "success": False,
            "error": f"Failed to query Drive folder (HTTP {response.status_code}): {error_detail}",
        }

    files = payload.get("files") or []
    if files:
        folder_id = files[0].get("id")
        if folder_id:
            return {"success": True, "folder_id": folder_id, "status": "Drive folder ready"}
        return {"success": False, "error": "Google Drive did not confirm the reports folder ID."}

    try:
        create_response = _authorized_request(
            method="post", url=GOOGLE_DRIVE_FILES_ENDPOINT,
            credentials_path=credentials_path, token_path=token_path, key_path=key_path,
            requests_module=requests_module, headers={"Content-Type": "application/json"},
            json={"name": folder_name, "mimeType": GOOGLE_DRIVE_FOLDER_MIME},
            timeout=10,
        )
    except Exception:
        return {"success": False, "error": "Failed to create Drive folder. Check the connection or reconnect in Settings."}
    create_payload = _response_json(create_response)
    if create_response.status_code >= 400:
        error_detail = _format_google_drive_error(create_payload)
        return {
            "success": False,
            "error": f"Failed to create Drive folder (HTTP {create_response.status_code}): {error_detail}",
        }
    if not create_payload.get("id"):
        return {"success": False, "error": "Google Drive did not confirm the created folder ID."}
    return {
        "success": True,
        "folder_id": create_payload.get("id"),
        "status": "Drive folder created",
    }


def create_google_drive_folder(
    *,
    name: str,
    parent_id: str | None,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
) -> dict:
    payload = {"name": name, "mimeType": GOOGLE_DRIVE_FOLDER_MIME}
    if parent_id:
        payload["parents"] = [parent_id]
    try:
        response = _authorized_request(
            method="post", url=GOOGLE_DRIVE_FILES_ENDPOINT,
            credentials_path=credentials_path, token_path=token_path, key_path=key_path,
            requests_module=requests_module, headers={"Content-Type": "application/json"},
            json=payload,
            params={"supportsAllDrives": "true", "fields": "id,name"},
            timeout=10,
        )
    except Exception:
        return {"success": False, "error": "Failed to create Drive folder. Check the connection or reconnect in Settings."}
    create_payload = _response_json(response)
    if response.status_code >= 400:
        error_detail = _format_google_drive_error(create_payload)
        return {
            "success": False,
            "error": f"Failed to create Drive folder (HTTP {response.status_code}): {error_detail}",
        }
    if not create_payload.get("id"):
        return {"success": False, "error": "Google Drive did not confirm the created folder ID."}
    return {
        "success": True,
        "folder_id": create_payload.get("id"),
        "status": "Drive folder created",
    }
