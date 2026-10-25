#!/usr/bin/env python3
"""Read-only preflight: a build cannot establish ownership of an earlier runtime."""

import os
from pathlib import Path
import subprocess
import sys


class ActiveBundleError(RuntimeError):
    pass


def _processes() -> dict[int, str]:
    result = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,comm="], capture_output=True, text=True, timeout=5, check=True)
    return {int(pid): command for line in result.stdout.splitlines() if line.strip()
            for pid, command in [line.strip().split(None, 1)]}


def _working_directories() -> dict[int, str]:
    if sys.platform == "darwin":
        result = subprocess.run(["/usr/sbin/lsof", "-nP", "-d", "cwd", "-Fpn"],
                                capture_output=True, text=True, timeout=5, check=True)
        directories = {}
        pid = None
        for line in result.stdout.splitlines():
            if line.startswith("p") and line[1:].isdigit():
                pid = int(line[1:])
            elif line.startswith("n") and pid is not None:
                directories[pid] = line[1:]
        return directories
    if sys.platform.startswith("linux"):
        directories = {}
        for process in Path("/proc").iterdir():
            if process.name.isdigit():
                try:
                    directories[int(process.name)] = os.readlink(process / "cwd")
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    continue
        return directories
    raise ActiveBundleError("Cannot inspect active bundles on this platform")


def _inside(path: str, bundle: Path) -> bool:
    # ps/lsof already identify filesystem paths. Do not resolve unrelated
    # processes' paths (which may traverse unavailable network mounts).
    resolved = Path(os.path.normpath(path))
    return resolved.is_absolute() and (resolved == bundle or bundle in resolved.parents)


def assert_bundles_stopped(paths: list[str]) -> None:
    bundles = {candidate for path in paths if Path(path).exists()
               for candidate in (Path(path).resolve(), Path(os.path.abspath(path)))}
    if not bundles:
        return
    processes = _processes()
    for bundle in bundles:
        marker = bundle / "Contents/Resources/nmapui-runtime.pid"
        if marker.exists():
            value = marker.read_text(encoding="ascii").strip()
            if not value.isdigit() or int(value) <= 1:
                raise ActiveBundleError(f"unverified runtime marker in {bundle}")
            if int(value) in processes:
                # A stale/reused PID is reason to refuse, never authority to signal.
                raise ActiveBundleError(f"live runtime marker PID {value} in {bundle}")
        for pid, executable in processes.items():
            if _inside(executable, bundle):
                raise ActiveBundleError(f"active executable PID {pid} in {bundle}")
    # Catch children running a system Python/interpreter from the bundle even
    # when their original parent exited or the runtime marker is missing.
    for pid, directory in _working_directories().items():
        for bundle in bundles:
            if _inside(directory, bundle):
                raise ActiveBundleError(f"active working directory PID {pid} in {bundle}")


if __name__ == "__main__":
    try:
        assert_bundles_stopped(sys.argv[1:])
    except (ActiveBundleError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"ERROR: Refusing to replace active or unverified bundle: {error}. "
                 "Quit this copy of NmapUI and retry. Review stale markers manually; "
                 "the build never signals processes or removes scanner locks.")
