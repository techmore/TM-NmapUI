"""Offline IEEE OUI lookup using the prefix database shipped with Nmap."""

from functools import lru_cache
import os
from pathlib import Path
import re
import shutil


_HEX = re.compile(r"^[0-9a-fA-F]{12}$")


def _normalized_mac(mac):
    source = str(mac or "")
    if re.search(r"[^0-9a-fA-F:\-.\s]", source):
        return ""
    value = re.sub(r"[:.\-\s]", "", source)
    return value.upper() if _HEX.fullmatch(value) else ""


def is_locally_administered_mac(mac):
    """Return whether a MAC uses the locally-administered address bit."""
    normalized = _normalized_mac(mac)
    return bool(normalized) and bool(int(normalized[:2], 16) & 0x02)


def is_globally_administered_unicast_mac(mac):
    """Return whether a MAC can be used for hardware-vendor identification."""
    normalized = _normalized_mac(mac)
    return bool(normalized) and not bool(int(normalized[:2], 16) & 0x03)


def _candidate_database_paths():
    directories = []
    for value in os.environ.get("NMAPDIR", "").split(os.pathsep):
        if value:
            directories.append(Path(value).expanduser())

    nmap_binary = shutil.which("nmap")
    if nmap_binary:
        binary = Path(nmap_binary).resolve()
        directories.extend(parent / "share" / "nmap" for parent in binary.parents)

    directories.extend((
        Path("/usr/share/nmap"),
        Path("/usr/local/share/nmap"),
        Path("/opt/homebrew/share/nmap"),
        Path("/usr/local/opt/nmap/share/nmap"),
    ))

    seen = set()
    for directory in directories:
        candidate = directory / "nmap-mac-prefixes"
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            yield candidate


def _find_database_path():
    return next((path for path in _candidate_database_paths() if path.is_file()), None)


@lru_cache(maxsize=8)
def _load_prefixes(database_path):
    prefixes = {}
    try:
        lines = Path(database_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return prefixes

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        prefix, vendor = parts
        prefix = prefix.strip().upper()
        vendor = vendor.strip()
        if 6 <= len(prefix) <= 12 and re.fullmatch(r"[0-9A-F]+", prefix) and vendor:
            prefixes[prefix] = vendor
    return prefixes


def lookup_mac_vendor(mac, *, database_path=None):
    """Look up a globally administered MAC in Nmap's local OUI database.

    Locally administered and multicast addresses are excluded because their
    prefix cannot reliably identify the hardware manufacturer.
    """
    normalized = _normalized_mac(mac)
    if not normalized:
        return ""
    if not is_globally_administered_unicast_mac(normalized):
        return ""

    path = Path(database_path) if database_path else _find_database_path()
    if path is None:
        return ""
    prefixes = _load_prefixes(str(path))
    for length in sorted({len(prefix) for prefix in prefixes}, reverse=True):
        vendor = prefixes.get(normalized[:length])
        if vendor:
            return vendor
    return ""
