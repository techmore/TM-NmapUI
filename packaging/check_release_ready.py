"""Verify that a ready HTTP response belongs to the staged service release."""

from __future__ import annotations

import argparse
from http.client import HTTPConnection, HTTPException
import ipaddress
import json
from pathlib import Path


def _probe_host(bind_host: str) -> str:
    host = str(bind_host or "127.0.0.1").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.is_unspecified:
        return "127.0.0.1" if address.version == 4 else "::1"
    return host


def check_release_ready(
    release: Path,
    port: int,
    *,
    host: str = "127.0.0.1",
    timeout: float = 5,
) -> bool:
    if not 1 <= port <= 65535:
        return False
    try:
        expected = (release / "release_id").read_text(encoding="ascii").strip()
        if len(expected) != 32 or any(char not in "0123456789abcdef" for char in expected):
            return False
        # A direct connection avoids proxy environment state. Wildcard binds
        # are probed through loopback; interface-specific binds use that address.
        connection = HTTPConnection(_probe_host(host), port, timeout=timeout)
        try:
            connection.request("GET", "/api/health/ready")
            response = connection.getresponse()
            if response.status != 200:
                return False
            payload = json.load(response)
        finally:
            connection.close()
        return payload.get("ready") is True and payload.get("release_id") == expected
    except (OSError, HTTPException, UnicodeError, ValueError, TypeError, KeyError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    raise SystemExit(
        0 if check_release_ready(args.release, args.port, host=args.host) else 1
    )


if __name__ == "__main__":
    main()
