"""Bounded-memory Drive v3 uploads with server-confirmed transfer recovery."""

import mimetypes
import os
import re
import time
from urllib.parse import urlsplit


UPLOAD_ENDPOINT = "https://www.googleapis.com/upload/drive/v3/files"
CHUNK_BYTES = 8 * 1024 * 1024  # Non-final chunks must be multiples of 256 KiB.
MAX_FAILURES = 4


def _payload(response):
    try:
        value = response.json()
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _retryable(response):
    if response.status_code == 429 or 500 <= response.status_code <= 599:
        return True
    error = _payload(response).get("error")
    reasons = (error.get("errors") or []) if isinstance(error, dict) else []
    return response.status_code == 403 and any(
        isinstance(item, dict) and item.get("reason") in {"rateLimitExceeded", "userRateLimitExceeded"}
        for item in reasons
    )


def _session_url(value):
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname == "www.googleapis.com"
                 and parsed.port in (None, 443) and not parsed.username and not parsed.password
                 and parsed.path == "/upload/drive/v3/files" and not parsed.fragment)
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise RuntimeError("Google Drive returned an invalid upload session URL.")
    return value


def upload_file(*, file_path, name, folder_id, requests_module, get_access_token):
    """Resume transient failures within this call; never restart a completed file.

    Session URLs are credential-like and must never appear in user-facing errors.
    No upload bytes or Bearer tokens follow redirects to a different endpoint.
    """
    token = get_access_token(False)
    content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"

    def send(method, url, **kwargs):
        nonlocal token
        headers = kwargs.pop("headers", {})
        for attempt in range(2):
            response = getattr(requests_module, method)(
                url, headers={**headers, "Authorization": f"Bearer {token}"},
                timeout=(10, 60), allow_redirects=False, **kwargs,
            )
            if response.status_code != 401 or attempt:
                return response
            token = get_access_token(True)

    def retry(failures):
        if failures >= MAX_FAILURES:
            raise RuntimeError(f"Google Drive upload interrupted for {name}; retry the upload.")
        time.sleep(min(2 ** (failures - 1), 4))

    metadata = {"name": name, "mimeType": content_type}
    if folder_id:
        metadata["parents"] = [folder_id]
    # Keep the same open descriptor across stat, transmission and retries.
    with file_path.open("rb") as source:
        original = os.fstat(source.fileno())
        size = original.st_size

        def verify_source():
            current = os.fstat(source.fileno())
            if (current.st_size, current.st_mtime_ns) != (size, original.st_mtime_ns):
                raise RuntimeError(f"File changed during Google Drive upload: {name}.")
        failures = 0
        while True:
            try:
                response = send(
                    "post", UPLOAD_ENDPOINT,
                    params={"uploadType": "resumable", "fields": "id,name,webViewLink,size", "supportsAllDrives": "true"},
                    json=metadata,
                    headers={"Content-Type": "application/json; charset=UTF-8",
                             "X-Upload-Content-Type": content_type, "X-Upload-Content-Length": str(size)},
                )
            except Exception:
                failures += 1
                retry(failures)
                continue
            if not _retryable(response):
                break
            failures += 1
            retry(failures)
        if response.status_code not in (200, 201):
            raise RuntimeError(f"Google Drive could not start upload for {name} (HTTP {response.status_code}).")
        session = _session_url(response.headers.get("Location", ""))
        offset, failures, probing, sent_through = 0, 0, False, 0
        while True:
            verify_source()
            source.seek(offset)
            chunk = b"" if probing else source.read(min(CHUNK_BYTES, size - offset))
            if not probing and not chunk and offset < size:
                raise RuntimeError(f"File changed during Google Drive upload: {name}.")
            if not probing:
                sent_through = max(sent_through, offset + len(chunk))
            content_range = f"bytes */{size}" if probing or not size else f"bytes {offset}-{offset + len(chunk) - 1}/{size}"
            try:
                response = send(
                    "put", session, data=chunk,
                    headers={"Content-Type": content_type, "Content-Length": str(len(chunk)),
                             "Content-Range": content_range},
                )
            except Exception:
                failures += 1
                retry(failures)
                probing = True
                continue
            if response.status_code in (200, 201):
                verify_source()
                if sent_through < size:
                    raise RuntimeError("Google Drive confirmed completion before the entire file was sent.")
                result = _payload(response)
                if not isinstance(result.get("id"), str) or not result["id"]:
                    raise RuntimeError("Google Drive did not confirm the uploaded file ID.")
                if "size" in result and str(result["size"]) != str(size):
                    raise RuntimeError("Google Drive returned an unexpected uploaded file size.")
                return result
            if response.status_code == 308:
                received = response.headers.get("Range", "")
                match = re.fullmatch(r"bytes=0-(\d+)", received) if received else None
                if received and not match:
                    raise RuntimeError("Google Drive returned an invalid upload byte range.")
                confirmed = int(match[1]) + 1 if match else 0
                maximum = size if probing else offset + len(chunk)
                if not offset <= confirmed <= maximum or confirmed >= size:
                    raise RuntimeError("Google Drive returned an inconsistent upload byte range.")
                if confirmed == offset:
                    failures += 1
                    retry(failures)
                else:
                    failures = 0
                offset, probing = confirmed, False
                continue
            if _retryable(response):
                failures += 1
                retry(failures)
                probing = True
                continue
            # Do not automatically create a second file after an expired session.
            # A caller can retry explicitly; successful earlier files are retained.
            raise RuntimeError(f"Google Drive upload failed for {name} (HTTP {response.status_code}).")
