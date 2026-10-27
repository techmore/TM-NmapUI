"""Fail before deployment when persisted service paths disagree with the installer."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
POSITIVE_LIMIT_RE = re.compile(r"^[1-9][0-9]{0,9}$")
MAX_SERVICE_LIMIT = 2_147_483_647
ALLOWED_SETTINGS = frozenset(
    {
        "NMAPUI_DATA_DIR",
        "NMAPUI_LOG_DIR",
        "NMAPUI_HOST",
        "NMAPUI_PORT",
        "NMAPUI_ALLOWED_ORIGINS",
        "NMAPUI_TRUST_LOCAL_UI",
        "NMAPUI_COOKIE_SECURE",
        "NMAPUI_MAX_CONCURRENT_JOBS",
        "NMAPUI_RUNTIME_LOGS_KEEP_LATEST",
        "NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST",
        "NMAPUI_FINISHED_JOBS_KEEP_LATEST",
        "NMAPUI_ALLOW_UNSAFE_WERKZEUG",
        "NMAPUI_STARTUP_TRACEROUTE",
        "NMAPUI_ENABLE_NETWORK_FINGERPRINT",
        "NMAPUI_ENABLE_UPDATE_CHECK",
        "NMAPUI_ENABLE_VULNERS",
        "NMAPUI_USERNAME",
        "NMAPUI_PASSWORD",
        "NMAPUI_PRIVILEGED_ASSETS",
        "PLAYWRIGHT_BROWSERS_PATH",
    }
)


def validate_service_env(
    path: Path,
    *,
    expected_data: str,
    expected_log: str,
    expected_browser: str,
) -> None:
    values: dict[str, str] = {}
    required = {
        "NMAPUI_DATA_DIR": expected_data,
        "NMAPUI_LOG_DIR": expected_log,
        "PLAYWRIGHT_BROWSERS_PATH": expected_browser,
    }
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip() or raw_line.startswith("#"):
            continue
        name, separator, value = raw_line.partition("=")
        if not separator or not KEY_RE.fullmatch(name):
            raise ValueError(f"Invalid service setting at {path}:{line_number}")
        if name not in ALLOWED_SETTINGS:
            raise ValueError(f"Unsupported service setting {name} at {path}:{line_number}")
        if name in values:
            raise ValueError(f"Duplicate service setting {name} at {path}:{line_number}")
        values[name] = value

    for name, expected in required.items():
        if values.get(name) != expected:
            raise ValueError(f"{name} must equal {expected!r} in {path}; found {values.get(name)!r}")
    port = values.get("NMAPUI_PORT", "9000")
    if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
        raise ValueError(f"NMAPUI_PORT must be a number from 1 to 65535 in {path}")
    limit_settings = (
        "NMAPUI_MAX_CONCURRENT_JOBS",
        "NMAPUI_RUNTIME_LOGS_KEEP_LATEST",
        "NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST",
        "NMAPUI_FINISHED_JOBS_KEEP_LATEST",
    )
    for name in limit_settings:
        if name not in values:
            continue
        value = values[name]
        if not POSITIVE_LIMIT_RE.fullmatch(value) or int(value) > MAX_SERVICE_LIMIT:
            raise ValueError(
                f"{name} must be a positive integer no greater than "
                f"{MAX_SERVICE_LIMIT} in {path}"
            )
    boolean_settings = (
        "NMAPUI_TRUST_LOCAL_UI",
        "NMAPUI_COOKIE_SECURE",
        "NMAPUI_ALLOW_UNSAFE_WERKZEUG",
        "NMAPUI_STARTUP_TRACEROUTE",
        "NMAPUI_ENABLE_NETWORK_FINGERPRINT",
        "NMAPUI_ENABLE_UPDATE_CHECK",
        "NMAPUI_ENABLE_VULNERS",
    )
    for name in boolean_settings:
        if name in values and values[name].strip().lower() not in {
            "true", "false", "1", "0", "yes", "no", "on", "off"
        }:
            raise ValueError(f"{name} must be a boolean value in {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--browser", required=True)
    args = parser.parse_args()
    try:
        validate_service_env(
            args.file,
            expected_data=args.data,
            expected_log=args.log,
            expected_browser=args.browser,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(1, f"Invalid NmapUI service credentials: {exc}\n")


if __name__ == "__main__":
    main()
