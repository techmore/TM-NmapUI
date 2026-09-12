"""Privilege handling for scan commands.

The appliance runs unattended for long stretches, so it must never block on a
password prompt.  Every privileged invocation therefore uses ``sudo -n``
(non-interactive): if passwordless sudo is not configured the command fails
immediately instead of waiting for a human, and the caller falls back to an
unprivileged connect scan.

This module is the single owner of two things that were previously duplicated
and buggy across the scan path:

* the argv **prefix** that grants privileges, and
* the **technique slot** (``-sS`` / ``-sT``) in the nmap command line.

Keeping the technique out of the option list is what prevents the old bug where
the unprivileged fallback overwrote ``--exclude`` and turned excluded hosts
into scan targets.
"""

from __future__ import annotations

import logging
import os
import shutil

logger = logging.getLogger(__name__)

SUDO = "sudo"
# Root-owned validating wrapper installed by packaging/macos/install-daemon.sh.
# When present it replaces raw `sudo -n nmap`, so sudoers never grants the
# scanner binaries directly.
DEFAULT_SCANNER_HELPER = "/usr/local/libexec/nmapui-privileged-scanner"

PERMISSION_DENIED_TOKENS = (
    "permission denied",
    "operation not permitted",
    "not permitted",
    "requires root",
    # `sudo -n` failures: never prompt, just report and fall back.
    "a password is required",
    "no tty present",
    "sudo:",
)


def scanner_helper_path() -> str:
    """Path to the privileged scanner wrapper, or "" when unavailable."""
    override = str(os.environ.get("NMAPUI_SCAN_HELPER", "") or "").strip()
    candidate = override or DEFAULT_SCANNER_HELPER
    try:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    except OSError:
        return ""
    return ""


def scanner_helper_installed() -> bool:
    return bool(scanner_helper_path())


def is_root() -> bool:
    """Return True when the current process is already privileged."""
    geteuid = getattr(os, "geteuid", None)
    return bool(callable(geteuid) and geteuid() == 0)


def sudo_available() -> bool:
    return shutil.which(SUDO) is not None


def privileged_prefix() -> list[str]:
    """Return the argv prefix that grants scan privileges.

    * root               -> ``[]`` (already privileged)
    * non-root + helper  -> ``["sudo", "-n", <helper>]`` (argv re-validated)
    * non-root + sudo    -> ``["sudo", "-n"]`` (development fallback)
    * otherwise          -> ``[]`` (unprivileged; caller must fall back)
    """
    if is_root():
        return []
    if not sudo_available():
        return []
    helper = scanner_helper_path()
    if helper:
        return [SUDO, "-n", helper]
    return [SUDO, "-n"]


def nmap_argv(
    technique: str,
    options,
    target: str,
    *,
    prefix=None,
) -> list[str]:
    """Build one nmap argv, owning the technique slot.

    ``options`` must not contain ``-sS``/``-sT``/``--exclude`` handling that
    depends on position; callers pass the full option list and may rebuild the
    command with a different technique without losing any flag.
    """
    if prefix is None:
        prefix = privileged_prefix()
    return [*prefix, "nmap", technique, *options, target]


def is_permission_denied(result) -> bool:
    """Detect a privilege failure so the caller can retry unprivileged."""
    combined = " ".join(
        str(part or "")
        for part in (
            getattr(result, "stdout", ""),
            getattr(result, "stderr", ""),
        )
    ).lower()
    return any(token in combined for token in PERMISSION_DENIED_TOKENS)
