"""Atomic, owner-only files for long-lived service secrets."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Callable


def write_private_temp(path: Path, contents: bytes) -> Path:
    """Write and sync a unique 0600 temporary file beside its destination."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            os.fchmod(temp_file.fileno(), 0o600)
            temp_file.write(contents)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        return temp_path
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def atomic_replace_private_bytes(path: Path, contents: bytes) -> None:
    """Replace one file without exposing partial or permissive content."""
    path = Path(path)
    temp_path = write_private_temp(path, contents)
    try:
        temp_path.replace(path)
    finally:
        temp_path.unlink(missing_ok=True)
    path.chmod(0o600)


def load_or_create_private_bytes(
    path: Path,
    create_bytes: Callable[[], bytes],
    *,
    normalize: Callable[[bytes], bytes] | None = None,
    minimum_size: int = 0,
) -> bytes:
    """Publish a new key only if absent; concurrent creators read the winner."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"Refusing symlinked private file: {path}")
    if not path.exists():
        temp_path = write_private_temp(path, create_bytes())
        try:
            try:
                os.link(temp_path, path)
            except FileExistsError:
                pass
        finally:
            temp_path.unlink(missing_ok=True)
    return load_private_bytes(path, normalize=normalize, minimum_size=minimum_size)


def load_private_bytes(
    path: Path,
    *,
    normalize: Callable[[bytes], bytes] | None = None,
    minimum_size: int = 0,
) -> bytes:
    """Read a protected existing file without creating a replacement."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"Refusing symlinked private file: {path}")
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise ValueError(f"Private file is not a regular file: {path}")
    path.chmod(0o600)
    result = path.read_bytes()
    if normalize is not None:
        result = normalize(result)
    if len(result) < minimum_size:
        raise ValueError(f"Private file is too short: {path}")
    return result
