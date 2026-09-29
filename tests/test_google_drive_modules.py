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
        def post(url, headers=None, files=None, timeout=None):
            uploaded_names.append(files["file"][0])
            assert hasattr(files["file"][1], "read")
            assert not isinstance(files["file"][1], (bytes, bytearray))
            return ResponseStub(files["file"][0])

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

            @staticmethod
            def json():
                return {"id": "id-report.pdf", "name": "report.pdf"}

        class RequestsStub:
            @staticmethod
            def post(url, headers=None, files=None, timeout=None):
                assert hasattr(files["file"][1], "read")
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
