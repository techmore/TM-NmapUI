"""Copy only the Flask runtime into a service-owned release directory.

Installers run this as root before switching their `current` symlink. The
checkout, tests, build outputs and mutable data never become service code.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys


RUNTIME_FILES = (
    "app.py",
    "persistence.py",
    "customer_fingerprint.py",
    "customer_fingerprint_matcher.py",
    "customer_fingerprint_store.py",
    "google_drive.py",
    "VERSION",
    "nmap-modern.xsl",
    "nmap-pdf-olive-legacy.xsl",
    "nmap-vulners/LICENSE",
    "nmap-vulners/vulners.nse",
    "config/auto_scan_config.example.json",
    "config/customers_example.yaml",
)
RUNTIME_DIRS = ("nmapui", "templates", "static")
PRIVILEGED_ASSETS = (
    ("nmap-vulners/vulners.nse", "vulners.nse"),
    ("nmap-modern.xsl", "nmap-modern.xsl"),
    ("nmap-pdf-olive-legacy.xsl", "nmap-pdf-olive-legacy.xsl"),
)


def _reject_code_symlinks(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Service code cannot be a symlink: {path}")
    if path.is_dir():
        for child in path.iterdir():
            _reject_code_symlinks(child)


def _harden_permissions(path: Path) -> None:
    if path.is_symlink():
        return
    if path.is_dir():
        path.chmod(0o755)
        for child in path.iterdir():
            _harden_permissions(child)
    else:
        executable = bool(stat.S_IMODE(path.stat().st_mode) & 0o111)
        path.chmod(0o755 if executable else 0o644)


def verify_root_interpreter(venv_python: Path) -> Path:
    """Reject a root service whose base Python can be changed by another user."""
    interpreter = Path(venv_python).resolve(strict=True)
    for path in (interpreter, *interpreter.parents):
        details = path.stat()
        if details.st_uid != 0 or stat.S_IMODE(details.st_mode) & 0o022:
            raise ValueError(f"Root service Python path is not root-owned and read-only: {path}")
    return interpreter


def verify_root_executable(executable: Path) -> Path:
    """Reject tools whose command path, symlink, target, or parents are writable by users."""
    command_path = Path(os.path.abspath(executable))
    resolved = command_path.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"Service tool is not executable: {command_path}")
    _verify_root_owned_path(command_path)
    _verify_root_owned_path(resolved)
    if sys.platform == "darwin":
        _verify_macho_dependencies(resolved, seen=set())
    return resolved


def verify_root_file(file_path: Path) -> Path:
    """Verify a service configuration file and all path components are protected."""
    file_path = Path(os.path.abspath(file_path))
    resolved = file_path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"Service path is not a regular file: {file_path}")
    _verify_root_owned_path(file_path)
    _verify_root_owned_path(resolved)
    return resolved


def _verify_root_owned_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        details = candidate.lstat()
        if details.st_uid != 0 or (not stat.S_ISLNK(details.st_mode) and stat.S_IMODE(details.st_mode) & 0o022):
            raise ValueError(f"Service tool path is not root-owned and read-only: {candidate}")


def _verify_macho_dependencies(binary: Path, *, seen: set[Path]) -> None:
    if binary in seen:
        return
    seen.add(binary)
    result = subprocess.run(
        ["/usr/bin/otool", "-L", str(binary)],
        capture_output=True, text=True, check=False, timeout=15,
    )
    if result.returncode != 0:
        raise ValueError(f"Cannot inspect service tool libraries: {binary}")
    for line in result.stdout.splitlines()[1:]:
        dependency = line.strip().split(" (", 1)[0]
        if not dependency:
            continue
        if dependency.startswith("@"):
            raise ValueError(f"Unresolved service tool library path: {dependency}")
        if not dependency.startswith("/"):
            raise ValueError(f"Non-absolute service tool library path: {dependency}")
        if dependency.startswith(("/usr/lib/", "/System/Library/")):
            continue  # SIP-protected Apple system libraries may live in dyld cache.
        dependency_path = Path(dependency)
        _verify_root_owned_path(dependency_path)
        resolved_dependency = dependency_path.resolve(strict=True)
        _verify_root_owned_path(resolved_dependency)
        _verify_macho_dependencies(resolved_dependency, seen=seen)


def verify_root_nmap_data_dir(directory: Path) -> Path:
    """Reject writable NSE scripts/databases that a privileged scan would load."""
    directory = Path(os.path.abspath(directory))
    resolved = directory.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"Nmap data path is not a directory: {directory}")
    _verify_root_owned_path(directory)
    _verify_root_owned_path(resolved)
    for required in ("scripts", "nselib", "nmap-services", "nmap-os-db"):
        if not (resolved / required).exists():
            raise ValueError(f"Incomplete Nmap data directory: {resolved / required}")
    for item in resolved.rglob("*"):
        if item.is_symlink():
            target = item.resolve(strict=True)
            if target != resolved and resolved not in target.parents:
                raise ValueError(f"Nmap data symlink escapes the protected directory: {item}")
            _verify_root_owned_path(target)
        _verify_root_owned_path(item)
    return resolved


def stage_runtime(source: Path, destination: Path) -> Path:
    source = Path(source).resolve()
    destination = Path(destination).resolve(strict=False)
    if destination == source or source in destination.parents:
        raise ValueError("Release destination must be outside the source checkout")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Release already exists: {destination}")

    for name in (*RUNTIME_FILES, *RUNTIME_DIRS):
        item = source / name
        _reject_code_symlinks(item)
        if not item.exists():
            raise FileNotFoundError(f"Missing runtime source: {item}")
    venv = source / ".venv"
    if not (venv / "bin" / "python").is_file():
        raise FileNotFoundError(f"Missing service virtual environment: {venv}")

    destination.mkdir(parents=True, mode=0o755)
    try:
        for name in RUNTIME_FILES:
            (destination / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, destination / name)
        for name in RUNTIME_DIRS:
            shutil.copytree(
                source / name,
                destination / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        asset_dir = destination / "privileged-assets"
        asset_dir.mkdir()
        for source_name, asset_name in PRIVILEGED_ASSETS:
            shutil.copy2(source / source_name, asset_dir / asset_name)
        shutil.copytree(
            venv,
            destination / ".venv",
            symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        for path in (destination / ".venv").rglob("*"):
            if path.is_symlink():
                target = path.resolve(strict=False)
                if target == source or source in target.parents:
                    raise ValueError(f"Virtualenv link still points into the checkout: {path}")
        # Public deployment identity, not an authentication secret. Installers
        # compare it with readiness so another process on the port cannot pass.
        (destination / "release_id").write_text(secrets.token_hex(16) + "\n", encoding="ascii")
        _harden_permissions(destination)
        if not (destination / ".venv" / "bin" / "python").is_file():
            raise RuntimeError("Staged Python interpreter is not usable")
    except Exception:
        shutil.rmtree(destination)
        raise
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--verify-root-interpreter", action="store_true")
    parser.add_argument("--verify-root-executable", action="append", type=Path, default=[])
    parser.add_argument("--verify-root-file", action="append", type=Path, default=[])
    parser.add_argument("--verify-root-nmap-data-dir", action="append", type=Path, default=[])
    args = parser.parse_args()
    if args.verify_root_interpreter:
        verify_root_interpreter(args.source / ".venv" / "bin" / "python")
    for executable in args.verify_root_executable:
        verify_root_executable(executable)
    for file_path in args.verify_root_file:
        verify_root_file(file_path)
    for directory in args.verify_root_nmap_data_dir:
        verify_root_nmap_data_dir(directory)
    if args.destination is not None:
        stage_runtime(args.source, args.destination)
    elif not args.verify_root_interpreter and not args.verify_root_executable and not args.verify_root_file and not args.verify_root_nmap_data_dir:
        parser.error("--destination or a verification option is required")


if __name__ == "__main__":
    main()
