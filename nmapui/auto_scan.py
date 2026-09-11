import json
import logging
from datetime import datetime, timedelta
import re
from pathlib import Path

from .paths import (
    AUTO_SCAN_CONFIG_EXAMPLE_FILE,
    AUTO_SCAN_CONFIG_FILE,
    LEGACY_AUTO_SCAN_CONFIG_FILE,
)


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write JSON atomically to avoid partial-write corruption on crash."""
    import json as _json
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    tmp_path.write_text(_json.dumps(payload, indent=2))
    tmp_path.replace(path)


logger = logging.getLogger(__name__)

DEFAULT_AUTO_SCAN_CONFIG = {
    "enabled": False,
    "start_time": "01:00",
    "end_time": "06:00",
    "last_run": None,
}

AUTO_SCAN_ALLOWED_KEYS = {"enabled", "start_time", "end_time", "last_run"}


def _parse_time_of_day(value: str) -> tuple[int, int]:
    try:
        hour_text, minute_text = str(value or "00:00").split(":", 1)
        return int(hour_text), int(minute_text)
    except (ValueError, AttributeError):
        logger.warning("Invalid time-of-day value %r, defaulting to 00:00", value)
        return 0, 0


def get_next_auto_scan_run(config: dict, *, now: datetime | None = None) -> datetime | None:
    """Return the next scheduled scan start time for the current auto-scan config."""
    if not isinstance(config, dict) or not config.get("enabled"):
        return None

    now = now or datetime.now()
    start_hour, start_minute = _parse_time_of_day(str(config.get("start_time") or "01:00"))
    end_hour, end_minute = _parse_time_of_day(str(config.get("end_time") or "06:00"))

    start_today = now.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
    end_today = now.replace(hour=end_hour, minute=end_minute, second=0, microsecond=0)
    if start_today <= end_today:
        within_window = start_today <= now <= end_today
    else:
        within_window = now >= start_today or now <= end_today

    if within_window:
        return start_today + timedelta(days=1)
    if now <= start_today:
        return start_today
    return start_today + timedelta(days=1)


def build_auto_scan_status_payload(
    config: dict,
    *,
    now: datetime | None = None,
    warning_window_seconds: int = 2 * 60 * 60,
) -> dict:
    """Return the canonical auto-scan status payload for API and Socket.IO clients."""
    payload = dict(config or {})
    next_run = get_next_auto_scan_run(payload, now=now)
    if next_run is None:
        payload["next_run"] = None
        payload["seconds_until_next_run"] = None
        payload["warning_active"] = False
        return payload

    now = now or datetime.now()
    seconds_until_next_run = max(int((next_run - now).total_seconds()), 0)
    payload["next_run"] = next_run.isoformat()
    payload["seconds_until_next_run"] = seconds_until_next_run
    payload["warning_active"] = 0 < seconds_until_next_run <= warning_window_seconds
    return payload


def migrate_legacy_auto_scan_config() -> bool:
    """Move schedule state out of the app bundle into the data dir.

    Returns True when a legacy file was migrated.  Safe to call repeatedly.
    """
    if AUTO_SCAN_CONFIG_FILE.exists() or not LEGACY_AUTO_SCAN_CONFIG_FILE.exists():
        return False
    try:
        payload = json.loads(LEGACY_AUTO_SCAN_CONFIG_FILE.read_text())
    except Exception as exc:
        logger.warning(
            "Could not migrate legacy auto scan config from %s: %s",
            LEGACY_AUTO_SCAN_CONFIG_FILE,
            exc,
        )
        return False
    if not isinstance(payload, dict):
        return False
    try:
        AUTO_SCAN_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(AUTO_SCAN_CONFIG_FILE, payload)
    except Exception as exc:
        logger.error("Failed to write migrated auto scan config: %s", exc)
        return False
    logger.info(
        "Migrated auto scan config from %s to %s",
        LEGACY_AUTO_SCAN_CONFIG_FILE,
        AUTO_SCAN_CONFIG_FILE,
    )
    return True


def load_auto_scan_config(target_config: dict) -> None:
    """Load auto scan configuration into a mutable target mapping."""
    migrate_legacy_auto_scan_config()
    for config_file in (AUTO_SCAN_CONFIG_FILE, AUTO_SCAN_CONFIG_EXAMPLE_FILE):
        if not config_file.exists():
            continue
        try:
            target_config.update(json.loads(config_file.read_text()))
            return
        except Exception as exc:
            logger.warning("Failed to load auto scan config from %s: %s", config_file, exc)


def save_auto_scan_config(source_config: dict) -> None:
    """Persist auto scan configuration using an atomic write."""
    try:
        AUTO_SCAN_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(AUTO_SCAN_CONFIG_FILE, source_config)
    except Exception as exc:
        logger.error("Failed to save auto scan config: %s", exc)


def validate_auto_scan_config_update(config) -> tuple[bool, str | None]:
    """Validate a partial auto-scan config update payload."""
    if not isinstance(config, dict):
        return False, "Invalid JSON payload"

    unknown_keys = sorted(set(config) - AUTO_SCAN_ALLOWED_KEYS)
    if unknown_keys:
        return (
            False,
            f"Unknown configuration keys: {', '.join(unknown_keys)}",
        )

    if "enabled" in config and not isinstance(config["enabled"], bool):
        return False, "'enabled' must be a boolean"

    time_pattern = re.compile(r"^\d{2}:\d{2}$")
    for field in ("start_time", "end_time"):
        if field not in config:
            continue
        value = config[field]
        if not isinstance(value, str) or not time_pattern.match(value):
            return False, f"'{field}' must use HH:MM format"

    if "last_run" in config and config["last_run"] is not None:
        if not isinstance(config["last_run"], str):
            return False, "'last_run' must be an ISO string"
        try:
            datetime.fromisoformat(config["last_run"])
        except ValueError:
            return False, "'last_run' must be a valid ISO timestamp"

    return True, None


def should_run_auto_scan(
    config: dict,
    *,
    now: datetime,
    startup_at: datetime,
    startup_grace_seconds: int,
) -> bool:
    """Check if auto scan should run now."""
    if not config["enabled"]:
        return False

    startup_elapsed = (now - startup_at).total_seconds()
    if startup_elapsed < startup_grace_seconds:
        logger.info(
            "Auto scan suppressed during startup grace period (%ss remaining)",
            int(startup_grace_seconds - startup_elapsed),
        )
        return False

    current_time = now.strftime("%H:%M")
    start = config["start_time"]
    end = config["end_time"]

    if start <= end:
        return start <= current_time <= end
    return current_time >= start or current_time <= end
