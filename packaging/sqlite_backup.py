"""Copy a live SQLite database through its backup API, including WAL commits."""

from __future__ import annotations

import argparse
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile


def _create_snapshot(source: Path, snapshot: Path) -> None:
    source_uri = source.as_uri() + "?mode=ro"
    with closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as source_conn:
        source_check = source_conn.execute("PRAGMA quick_check(1)").fetchone()
        if source_check is None or source_check[0] != "ok":
            raise sqlite3.DatabaseError(f"SQLite source failed integrity check: {source_check}")
        with closing(sqlite3.connect(snapshot, timeout=30)) as snapshot_conn:
            source_conn.backup(snapshot_conn)
            result = snapshot_conn.execute("PRAGMA quick_check(1)").fetchone()
            if result is None or result[0] != "ok":
                raise sqlite3.DatabaseError(f"SQLite backup failed integrity check: {result}")


def _has_sidecar(path: Path) -> bool:
    return any(
        candidate.exists() or candidate.is_symlink()
        for candidate in (Path(f"{path}-wal"), Path(f"{path}-shm"))
    )


def backup_sqlite(source: Path, destination: Path) -> None:
    source = Path(source).resolve(strict=True)
    destination = Path(destination).absolute()
    if not source.is_file():
        raise ValueError(f"SQLite source is not a regular file: {source}")
    if destination.is_symlink():
        raise ValueError(f"Refusing symlinked SQLite destination: {destination}")
    if source == destination.resolve(strict=False) or (
        destination.exists() and source.samefile(destination)
    ):
        raise ValueError("SQLite source and destination must differ")
    if not destination.parent.is_dir():
        raise ValueError(f"SQLite destination directory is missing: {destination.parent}")
    if _has_sidecar(destination):
        raise ValueError(
            "Refusing SQLite destination with WAL sidecars; stop the service and retry"
        )

    descriptor, snapshot_name = tempfile.mkstemp(
        prefix=f".{destination.name}.backup-",
        suffix=".sqlite3",
        dir=destination.parent,
    )
    os.close(descriptor)
    snapshot = Path(snapshot_name)
    try:
        _create_snapshot(source, snapshot)
        snapshot.chmod(0o600)
        with snapshot.open("rb") as snapshot_file:
            os.fsync(snapshot_file.fileno())
        os.replace(snapshot, destination)
        directory_fd = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        for suffix in ("", "-wal", "-shm"):
            Path(f"{snapshot}{suffix}").unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    backup_sqlite(args.source, args.destination)


if __name__ == "__main__":
    main()
