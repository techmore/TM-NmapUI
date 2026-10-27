from pathlib import Path
import json
import os

import pytest

from nmapui import private_storage

from nmapui.google_drive import (
    build_google_drive_auth_status,
    build_google_drive_auth_url,
    clear_google_drive_token_state,
    ensure_google_drive_access_token,
    exchange_google_drive_auth_code,
    load_google_drive_token_state,
    save_google_drive_credentials,
    save_google_drive_token_state,
    upload_files_to_google_drive,
    disconnect_google_drive,
    create_google_drive_folder,
    load_google_drive_credentials,
)


def write_credentials(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '{"installed":{"client_id":"client-123","client_secret":"secret-456"}}'
    )


def test_build_google_drive_auth_url_persists_pending_state(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    write_credentials(credentials_path)

    result = build_google_drive_auth_url(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        redirect_uri="http://127.0.0.1:9000/api/settings/google-drive/callback",
    )

    assert result["success"] is True
    assert "accounts.google.com" in result["auth_url"]
    token_file_payload = json.loads(token_path.read_text())
    assert "ciphertext" in token_file_payload
    assert "pending_auth" not in token_file_payload
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    assert token_state["pending_auth"]["state"]
    assert token_state["pending_auth"]["code_verifier"]
    assert key_path.exists()
    assert oct(token_path.stat().st_mode & 0o777) == "0o600"
    assert oct(key_path.stat().st_mode & 0o777) == "0o600"


def test_google_drive_credentials_are_written_owner_only(tmp_path):
    credentials_path = tmp_path / "credentials.json"

    result = save_google_drive_credentials(
        credentials_path,
        {"installed": {"client_id": "client", "client_secret": "private-secret"}},
    )

    assert result["success"] is True
    assert credentials_path.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".credentials.json.*.tmp"))


def test_existing_google_drive_credentials_are_hardened_when_read(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    write_credentials(credentials_path)
    credentials_path.chmod(0o644)

    status = build_google_drive_auth_status(
        credentials_path=credentials_path,
        token_path=tmp_path / "tokens.json",
    )

    assert status["configured"] is True
    assert credentials_path.stat().st_mode & 0o777 == 0o600


def test_failed_google_drive_token_write_preserves_previous_token(tmp_path, monkeypatch):
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    save_google_drive_token_state(
        token_path, {"access_token": "existing"}, key_path=key_path
    )

    def fail_sync(_file_descriptor):
        raise OSError("sync failed")

    monkeypatch.setattr(private_storage.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="sync failed"):
        save_google_drive_token_state(
            token_path, {"access_token": "replacement"}, key_path=key_path
        )

    assert load_google_drive_token_state(token_path, key_path=key_path) == {
        "access_token": "existing"
    }
    assert not list(tmp_path.glob(".tokens.json.*.tmp"))


def test_missing_google_drive_key_is_not_silently_recreated_on_read(tmp_path):
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    save_google_drive_token_state(
        token_path, {"access_token": "existing"}, key_path=key_path
    )
    encrypted = token_path.read_bytes()
    key_path.unlink()

    assert load_google_drive_token_state(token_path, key_path=key_path) == {}
    assert not key_path.exists()
    assert token_path.read_bytes() == encrypted


def test_exchange_google_drive_auth_code_saves_tokens(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    write_credentials(credentials_path)
    auth_result = build_google_drive_auth_url(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        redirect_uri="http://127.0.0.1:9000/api/settings/google-drive/callback",
    )
    token_state = load_google_drive_token_state(token_path, key_path=key_path)

    class ResponseStub:
        status_code = 200

        @staticmethod
        def json():
            return {
                "access_token": "access-123",
                "refresh_token": "refresh-456",
                "expires_in": 3600,
                "token_type": "Bearer",
            }

    class RequestsStub:
        @staticmethod
        def post(url, data=None, timeout=None):
            assert data["code"] == "code-123"
            return ResponseStub()

    result = exchange_google_drive_auth_code(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        code="code-123",
        state=token_state["pending_auth"]["state"],
        requests_module=RequestsStub,
    )

    assert auth_result["success"] is True
    assert result == {"success": True, "status": "Google Drive connected"}
    saved = load_google_drive_token_state(token_path, key_path=key_path)
    assert saved["access_token"] == "access-123"
    assert saved["refresh_token"] == "refresh-456"
    assert "pending_auth" not in saved
    assert "access-123" not in token_path.read_text()


def test_exchange_google_drive_auth_code_handles_request_failure(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    write_credentials(credentials_path)
    build_google_drive_auth_url(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        redirect_uri="http://127.0.0.1:9000/api/settings/google-drive/callback",
    )
    token_state = load_google_drive_token_state(token_path, key_path=key_path)

    class RequestsStub:
        @staticmethod
        def post(url, data=None, timeout=None):
            raise RuntimeError("network down")

    result = exchange_google_drive_auth_code(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        code="code-123",
        state=token_state["pending_auth"]["state"],
        requests_module=RequestsStub,
    )

    assert result["success"] is False
    assert "Failed to reach Google Drive token endpoint" in result["error"]


def test_ensure_google_drive_access_token_refreshes_expired_token(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    write_credentials(credentials_path)
    save_google_drive_token_state(
        token_path,
        {"refresh_token": "refresh-456", "access_token": "stale", "expires_at": "2020-01-01T00:00:00+00:00"},
        key_path=key_path,
    )

    class ResponseStub:
        status_code = 200

        @staticmethod
        def json():
            return {"access_token": "fresh-123", "expires_in": 3600, "token_type": "Bearer"}

    class RequestsStub:
        @staticmethod
        def post(url, data=None, timeout=None):
            assert data["grant_type"] == "refresh_token"
            return ResponseStub()

    token = ensure_google_drive_access_token(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        requests_module=RequestsStub,
    )

    assert token == "fresh-123"


def test_upload_files_to_google_drive_posts_each_file(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    file_path = tmp_path / "report.pdf"
    write_credentials(credentials_path)
    save_google_drive_token_state(
        token_path,
        {"access_token": "access-123", "expires_at": "2099-01-01T00:00:00+00:00"},
        key_path=key_path,
    )
    file_path.write_bytes(b"pdf-data")
    uploaded_names = []

    class ResponseStub:
        status_code = 200

        def __init__(self, name):
            self.name = name

        def json(self):
            return {"id": f"id-{self.name}", "name": self.name}

    class RequestsStub:
        @staticmethod
        def post(url, headers=None, json=None, params=None, timeout=None, allow_redirects=None):
            uploaded_names.append(json["name"])
            assert json["parents"] == ["folder-123"]
            assert json["mimeType"] == "application/pdf"
            assert params["uploadType"] == "resumable"
            assert allow_redirects is False
            response = ResponseStub(json["name"])
            response.headers = {"Location": "https://www.googleapis.com/upload/drive/v3/files?upload_id=test"}
            return response

        @staticmethod
        def put(url, headers=None, data=None, timeout=None, allow_redirects=None):
            assert data == b"pdf-data"
            assert headers["Content-Range"] == "bytes 0-7/8"
            assert allow_redirects is False
            return ResponseStub("report.pdf")

    result = upload_files_to_google_drive(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        file_paths=[file_path],
        folder_id="folder-123",
        requests_module=RequestsStub,
    )

    assert result["success"] is True
    assert uploaded_names == ["report.pdf"]


def test_upload_files_to_google_drive_does_not_use_read_bytes(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    file_path = tmp_path / "report.pdf"
    write_credentials(credentials_path)
    save_google_drive_token_state(
        token_path,
        {"access_token": "access-123", "expires_at": "2099-01-01T00:00:00+00:00"},
        key_path=key_path,
    )
    file_path.write_bytes(b"pdf-data")

    original_read_bytes = Path.read_bytes

    def fail_read_bytes(self):
        if self == file_path:
            raise AssertionError("upload path should stream files instead of calling read_bytes()")
        return original_read_bytes(self)

    Path.read_bytes = fail_read_bytes
    try:
        class ResponseStub:
            status_code = 200
            headers = {"Location": "https://www.googleapis.com/upload/drive/v3/files?upload_id=test"}

            @staticmethod
            def json():
                return {"id": "id-report.pdf", "name": "report.pdf"}

        class RequestsStub:
            @staticmethod
            def post(url, **kwargs):
                return ResponseStub()

            @staticmethod
            def put(url, data=None, **kwargs):
                assert data == b"pdf-data"
                return ResponseStub()

        result = upload_files_to_google_drive(
            credentials_path=credentials_path,
            token_path=token_path,
            key_path=key_path,
            file_paths=[file_path],
            folder_id="folder-123",
            requests_module=RequestsStub,
        )
    finally:
        Path.read_bytes = original_read_bytes

    assert result["success"] is True


def test_build_google_drive_auth_status_reports_connected_token(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    write_credentials(credentials_path)
    save_google_drive_token_state(
        token_path,
        {"refresh_token": "refresh-456"},
        key_path=key_path,
    )

    status = build_google_drive_auth_status(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
    )

    assert status["configured"] is True
    assert status["connected"] is True


def test_build_google_drive_auth_status_reports_missing_credentials(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"

    status = build_google_drive_auth_status(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
    )

    assert status["configured"] is False
    assert status["connected"] is False
    assert status["status"] == "OAuth credentials missing. Import credentials.json to enable Google Drive."


def test_load_google_drive_token_state_migrates_plaintext_file(tmp_path):
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    plaintext = {"refresh_token": "refresh-456", "access_token": "access-123"}
    token_path.write_text(json.dumps(plaintext))

    loaded = load_google_drive_token_state(token_path, key_path=key_path)

    assert loaded == plaintext
    persisted = json.loads(token_path.read_text())
    assert "ciphertext" in persisted
    assert "access-123" not in token_path.read_text()
    assert key_path.exists()


def test_clear_google_drive_token_state_removes_token_and_key(tmp_path):
    token_path = tmp_path / "tokens.json"
    key_path = tmp_path / "tokens.key"
    save_google_drive_token_state(
        token_path,
        {"refresh_token": "refresh-456"},
        key_path=key_path,
    )

    clear_google_drive_token_state(token_path, key_path=key_path)

    assert not token_path.exists()
    assert not key_path.exists()


@pytest.mark.parametrize("timestamp", [None, "", "invalid", "2099-01-01T00:00:00+00:00", "2026-01-01T00:00:00"])
def test_invalid_oauth_timestamp_cannot_exchange_and_is_consumed(tmp_path, timestamp):
    token_path = tmp_path / "tokens.json"
    save_google_drive_token_state(token_path, {
        "pending_auth": {"state": "nonce", "created_at": timestamp, "code_verifier": "verifier"},
    })

    class NoNetwork:
        @staticmethod
        def post(*args, **kwargs):
            pytest.fail("Invalid state must not reach Google")

    result = exchange_google_drive_auth_code(
        credentials_path=tmp_path / "credentials.json", token_path=token_path,
        code="code", state="nonce", requests_module=NoNetwork,
    )
    assert not result["success"]
    assert "pending_auth" not in load_google_drive_token_state(token_path)


def test_oauth_callback_is_single_use_and_does_not_mix_google_accounts(tmp_path):
    from datetime import datetime, timezone

    token_path = tmp_path / "tokens.json"
    save_google_drive_token_state(token_path, {
        "refresh_token": "old-account-refresh",
        "pending_auth": {"state": "nonce", "created_at": datetime.now(timezone.utc).isoformat(), "code_verifier": "verifier"},
    })
    calls = []

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"access_token": "new-account-access", "expires_in": 3600}

    class Transport:
        @staticmethod
        def post(*args, **kwargs):
            calls.append(kwargs)
            return Response()

    kwargs = dict(credentials_path=tmp_path / "credentials.json", token_path=token_path,
                  code="code", state="nonce", requests_module=Transport)
    assert exchange_google_drive_auth_code(**kwargs)["success"]
    assert not exchange_google_drive_auth_code(**kwargs)["success"]
    assert len(calls) == 1
    assert not load_google_drive_token_state(token_path).get("refresh_token")


def test_revoked_refresh_grant_is_no_longer_reported_connected(tmp_path):
    token_path = tmp_path / "tokens.json"
    credentials_path = tmp_path / "credentials.json"
    write_credentials(credentials_path)
    save_google_drive_token_state(token_path, {"refresh_token": "revoked"})

    class Response:
        status_code = 400

        @staticmethod
        def json():
            return {"error": "invalid_grant"}

    class Transport:
        @staticmethod
        def post(*args, **kwargs):
            return Response()

    with pytest.raises(RuntimeError, match="revoked"):
        ensure_google_drive_access_token(credentials_path=credentials_path, token_path=token_path, requests_module=Transport)
    assert not build_google_drive_auth_status(credentials_path=credentials_path, token_path=token_path)["connected"]


@pytest.mark.parametrize("expiry", [None, "bad", "2020-01-01T00:00:00", "2020-01-01T00:00:00+00:00", 123])
def test_expired_or_malformed_access_only_state_is_disconnected(tmp_path, expiry):
    token_path = tmp_path / "tokens.json"
    save_google_drive_token_state(token_path, {"access_token": "old", "expires_at": expiry})
    assert not build_google_drive_auth_status(credentials_path=tmp_path / "credentials.json", token_path=token_path)["connected"]


def test_concurrent_uploads_share_one_token_refresh(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    token_path = tmp_path / "tokens.json"
    save_google_drive_token_state(token_path, {"refresh_token": "refresh"})
    barrier, calls = Barrier(2), []

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"access_token": "fresh", "expires_in": 3600}

    class Transport:
        @staticmethod
        def post(*args, **kwargs):
            calls.append(kwargs)
            return Response()

    def get_token():
        barrier.wait(timeout=5)
        return ensure_google_drive_access_token(credentials_path=tmp_path / "credentials.json", token_path=token_path, requests_module=Transport)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(get_token) for _ in range(2)]
        assert [future.result(timeout=5) for future in futures] == ["fresh", "fresh"]
    assert len(calls) == 1


def test_disconnect_puts_token_in_body_and_reports_unconfirmed_revocation(tmp_path):
    token_path = tmp_path / "tokens.json"
    save_google_drive_token_state(token_path, {"refresh_token": "private"})

    class Transport:
        @staticmethod
        def post(url, data=None, timeout=None):
            assert "private" not in url
            assert data == {"token": "private"}
            raise OSError("offline")

    result = disconnect_google_drive(token_path=token_path, requests_module=Transport)
    assert result["success"] and not result["revoked"] and result["warning"]
    assert not token_path.exists()
    assert not token_path.with_suffix(".key").exists()


def test_folder_unauthorized_response_refreshes_once_and_requires_id(tmp_path):
    token_path = tmp_path / "tokens.json"
    save_google_drive_token_state(token_path, {"access_token": "old", "refresh_token": "refresh", "expires_at": "2099-01-01T00:00:00+00:00"})
    calls = []

    class Response:
        def __init__(self, status_code, payload):
            self.status_code, self.payload = status_code, payload

        def json(self):
            return self.payload

    class Transport:
        @staticmethod
        def post(url, **kwargs):
            if url.endswith("/token"):
                return Response(200, {"access_token": "fresh", "expires_in": 3600})
            calls.append(kwargs["headers"]["Authorization"])
            return Response(401 if len(calls) == 1 else 200, {})

    result = create_google_drive_folder(name="reports", parent_id=None, credentials_path=tmp_path / "credentials.json", token_path=token_path, requests_module=Transport)
    assert calls == ["Bearer old", "Bearer fresh"]
    assert not result["success"] and "folder ID" in result["error"]


@pytest.mark.parametrize("payload", [{}, {"installed": []}, {"web": {}}, {"client_id": 123, "client_secret": "secret"}])
def test_invalid_credentials_cannot_replace_existing_client(tmp_path, payload):
    path = tmp_path / "credentials.json"
    write_credentials(path)
    previous = path.read_text()
    assert not save_google_drive_credentials(path, payload)["success"]
    assert path.read_text() == previous


@pytest.mark.parametrize("payload", [{"installed": None}, {"installed": []}, [], {"web": None}])
def test_malformed_legacy_credentials_are_reported_unconfigured(tmp_path, payload):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps(payload))
    assert load_google_drive_credentials(path) == {}
    assert not build_google_drive_auth_status(credentials_path=path, token_path=tmp_path / "tokens.json")["configured"]
