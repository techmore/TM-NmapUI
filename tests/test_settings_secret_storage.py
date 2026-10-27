"""Private and crash-safe storage for the remote-sync token and its key."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import threading

import pytest

from nmapui import private_storage, settings


def test_remote_sync_key_and_secret_are_private_before_publication(tmp_path, monkeypatch):
    key_path = tmp_path / "remote-sync.key"
    secret_path = tmp_path / "remote-sync.json"
    observed = []
    original_link = os.link
    original_replace = os.replace

    def checked_link(source, destination, *args, **kwargs):
        if Path(destination) == key_path:
            observed.append("key")
            assert Path(source).stat().st_mode & 0o777 == 0o600
        return original_link(source, destination, *args, **kwargs)

    def checked_replace(source, destination, *args, **kwargs):
        if Path(destination) == secret_path:
            observed.append("secret")
            assert Path(source).stat().st_mode & 0o777 == 0o600
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(private_storage.os, "link", checked_link)
    monkeypatch.setattr(private_storage.os, "replace", checked_replace)

    settings.save_remote_sync_secret(
        secret_path=secret_path, key_path=key_path, api_key="private-token"
    )

    assert observed == ["key", "secret"]
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert secret_path.stat().st_mode & 0o777 == 0o600
    assert settings.load_remote_sync_secret(
        secret_path=secret_path, key_path=key_path
    ) == "private-token"


def test_concurrent_remote_sync_key_creation_uses_one_published_key(tmp_path, monkeypatch):
    key_path = tmp_path / "remote-sync.key"
    original_generate_key = settings.Fernet.generate_key
    barrier = threading.Barrier(4)

    def generate_together():
        barrier.wait(timeout=5)
        return original_generate_key()

    monkeypatch.setattr(settings.Fernet, "generate_key", staticmethod(generate_together))

    with ThreadPoolExecutor(max_workers=4) as executor:
        keys = list(executor.map(settings._load_or_create_encryption_key, [key_path] * 4))

    assert len(set(keys)) == 1
    assert key_path.read_bytes().strip() == keys[0]
    assert not list(tmp_path.glob(".remote-sync.key.*.tmp"))


def test_failed_remote_sync_secret_write_keeps_existing_token(tmp_path, monkeypatch):
    key_path = tmp_path / "remote-sync.key"
    secret_path = tmp_path / "remote-sync.json"
    settings.save_remote_sync_secret(
        secret_path=secret_path, key_path=key_path, api_key="existing-token"
    )

    def fail_sync(_file_descriptor):
        raise OSError("sync failed")

    monkeypatch.setattr(private_storage.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="sync failed"):
        settings.save_remote_sync_secret(
            secret_path=secret_path, key_path=key_path, api_key="replacement-token"
        )

    assert settings.load_remote_sync_secret(
        secret_path=secret_path, key_path=key_path
    ) == "existing-token"
    assert not list(tmp_path.glob(".remote-sync.json.*.tmp"))


def test_remote_sync_secret_refuses_symlinked_key(tmp_path):
    key_path = tmp_path / "remote-sync.key"
    target = tmp_path / "outside.key"
    target.write_bytes(b"untouched")
    key_path.symlink_to(target)
    secret_path = tmp_path / "remote-sync.json"

    with pytest.raises(ValueError, match="symlinked"):
        settings.save_remote_sync_secret(
            secret_path=secret_path, key_path=key_path, api_key="private-token"
        )

    assert target.read_bytes() == b"untouched"
    assert not secret_path.exists()


def test_missing_remote_sync_key_is_not_silently_recreated_on_read(tmp_path):
    key_path = tmp_path / "remote-sync.key"
    secret_path = tmp_path / "remote-sync.json"
    settings.save_remote_sync_secret(
        secret_path=secret_path, key_path=key_path, api_key="private-token"
    )
    encrypted = secret_path.read_bytes()
    key_path.unlink()

    assert settings.load_remote_sync_secret(
        secret_path=secret_path, key_path=key_path
    ) == ""
    assert not key_path.exists()
    assert secret_path.read_bytes() == encrypted


def test_existing_remote_sync_secret_is_hardened_when_read(tmp_path):
    key_path = tmp_path / "remote-sync.key"
    secret_path = tmp_path / "remote-sync.json"
    settings.save_remote_sync_secret(
        secret_path=secret_path, key_path=key_path, api_key="private-token"
    )
    secret_path.chmod(0o644)

    assert settings.load_remote_sync_secret(
        secret_path=secret_path, key_path=key_path
    ) == "private-token"
    assert secret_path.stat().st_mode & 0o777 == 0o600
