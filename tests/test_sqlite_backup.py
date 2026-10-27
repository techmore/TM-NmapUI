"""WAL-safe database migration snapshots for the macOS build."""

import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys


BACKUP_SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "sqlite_backup.py"


def _backup(source: Path, destination: Path):
    return subprocess.run(
        [sys.executable, str(BACKUP_SCRIPT), "--source", str(source), "--destination", str(destination)],
        text=True, capture_output=True, timeout=10,
    )


def _load_backup_module():
    spec = importlib.util.spec_from_file_location("nmapui_sqlite_backup_test", BACKUP_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_backup_includes_committed_rows_still_in_wal(tmp_path):
    source = tmp_path / "runtime.sqlite3"
    destination = tmp_path / "snapshot.sqlite3"
    writer = sqlite3.connect(source)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT)")
        writer.commit()
        writer.execute("INSERT INTO scans(target) VALUES (?)", ("192.0.2.1",))
        writer.commit()
        assert Path(f"{source}-wal").stat().st_size > 0

        result = _backup(source, destination)
        assert result.returncode == 0, result.stderr
        assert destination.stat().st_mode & 0o777 == 0o600
        with sqlite3.connect(destination) as snapshot:
            assert snapshot.execute("SELECT target FROM scans").fetchall() == [("192.0.2.1",)]
            assert snapshot.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
    finally:
        writer.close()


def test_backup_replaces_existing_sqlite_through_sqlite_not_file_copy(tmp_path):
    source = tmp_path / "snapshot.sqlite3"
    destination = tmp_path / "installed.sqlite3"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE scans (target TEXT)")
        conn.execute("INSERT INTO scans(target) VALUES ('198.51.100.2')")
    with sqlite3.connect(destination) as conn:
        conn.execute("CREATE TABLE scans (target TEXT)")
        conn.execute("INSERT INTO scans(target) VALUES ('old')")

    result = _backup(source, destination)

    assert result.returncode == 0, result.stderr
    with sqlite3.connect(destination) as conn:
        assert conn.execute("SELECT target FROM scans").fetchall() == [("198.51.100.2",)]


def test_backup_rejects_same_database_and_symlinked_destination(tmp_path):
    source = tmp_path / "source.sqlite3"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE scans (target TEXT)")
    link = tmp_path / "link.sqlite3"
    link.symlink_to(source)
    hardlink = tmp_path / "hardlink.sqlite3"
    hardlink.hardlink_to(source)

    same = _backup(source, source)
    linked = _backup(source, link)
    hardlinked = _backup(source, hardlink)

    assert same.returncode != 0
    assert "must differ" in same.stderr
    assert linked.returncode != 0
    assert "symlinked" in linked.stderr
    assert hardlinked.returncode != 0
    assert "must differ" in hardlinked.stderr


def test_failed_backup_does_not_leave_new_destination(tmp_path):
    source = tmp_path / "corrupt.sqlite3"
    source.write_bytes(b"not a SQLite database")
    destination = tmp_path / "new.sqlite3"

    result = _backup(source, destination)

    assert result.returncode != 0
    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()


def test_corrupt_source_does_not_replace_existing_database(tmp_path):
    source = tmp_path / "corrupt.sqlite3"
    source.write_bytes(b"not a SQLite database")
    destination = tmp_path / "existing.sqlite3"
    with sqlite3.connect(destination) as conn:
        conn.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        conn.execute("INSERT INTO marker VALUES ('keep-existing-data')")

    result = _backup(source, destination)

    assert result.returncode != 0
    with sqlite3.connect(destination) as conn:
        assert conn.execute("SELECT value FROM marker").fetchone() == (
            "keep-existing-data",
        )


def test_failed_snapshot_does_not_replace_existing_database(tmp_path):
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "existing.sqlite3"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE scans (target TEXT)")
        conn.execute("INSERT INTO scans VALUES ('192.0.2.10')")
    with sqlite3.connect(destination) as conn:
        conn.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        conn.execute("INSERT INTO marker VALUES ('keep-existing-data')")

    backup_module = _load_backup_module()

    def fail_after_partial_snapshot(_source, snapshot):
        snapshot.write_bytes(b"partial database snapshot")
        raise OSError("injected snapshot failure")

    backup_module._create_snapshot = fail_after_partial_snapshot
    try:
        backup_module.backup_sqlite(source, destination)
    except OSError as exc:
        assert "injected snapshot failure" in str(exc)
    else:
        raise AssertionError("snapshot failure should be reported")

    with sqlite3.connect(destination) as conn:
        assert conn.execute("SELECT value FROM marker").fetchone() == (
            "keep-existing-data",
        )
    assert list(tmp_path.glob(".existing.sqlite3.backup-*.sqlite3")) == []


def test_backup_refuses_destination_with_live_wal_sidecars(tmp_path):
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "active.sqlite3"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE scans (target TEXT)")
        conn.execute("INSERT INTO scans VALUES ('192.0.2.11')")

    writer = sqlite3.connect(destination)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        writer.execute("INSERT INTO marker VALUES ('active-database')")
        writer.commit()
        assert Path(f"{destination}-wal").is_file()

        result = _backup(source, destination)

        assert result.returncode != 0
        assert "stop the service and retry" in result.stderr
        assert writer.execute("SELECT value FROM marker").fetchone() == (
            "active-database",
        )
    finally:
        writer.close()
