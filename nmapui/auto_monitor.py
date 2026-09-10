from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta
from typing import Any
import uuid


AUTO_MONITOR_ALLOWED_RECURRENCES = {
    "daily",
    "weekly",
    "biweekly",
    "monthly",
    "quarterly",
}
AUTO_MONITOR_ALLOWED_SCAN_MODES = {"complete_pdf"}
WEEKDAY_NAMES = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
]
WEEKDAY_TO_INDEX = {name: index for index, name in enumerate(WEEKDAY_NAMES)}
DEFAULT_AUTO_MONITOR_DEFAULTS = {
    "enabled_by_default": False,
    "recurrence": "weekly",
    "day_of_week": "sunday",
    "time": "01:00",
    "scan_mode": "complete_pdf",
}


def _normalize_time(value: Any, *, fallback: str = "01:00") -> str:
    text = str(value or fallback).strip()
    if len(text) != 5 or text[2] != ":":
        return fallback
    try:
        hour = int(text[:2])
        minute = int(text[3:])
    except ValueError:
        return fallback
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return fallback
    return f"{hour:02d}:{minute:02d}"


def _normalize_day_of_week(value: Any, *, fallback: str = "sunday") -> str:
    text = str(value or fallback).strip().lower()
    return text if text in WEEKDAY_TO_INDEX else fallback


def _normalize_datetime_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        return ""


def normalize_auto_monitor_defaults(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    recurrence = str(
        value.get("recurrence", DEFAULT_AUTO_MONITOR_DEFAULTS["recurrence"]) or ""
    ).strip().lower()
    if recurrence not in AUTO_MONITOR_ALLOWED_RECURRENCES:
        recurrence = DEFAULT_AUTO_MONITOR_DEFAULTS["recurrence"]
    scan_mode = str(
        value.get("scan_mode", DEFAULT_AUTO_MONITOR_DEFAULTS["scan_mode"]) or ""
    ).strip().lower()
    if scan_mode not in AUTO_MONITOR_ALLOWED_SCAN_MODES:
        scan_mode = DEFAULT_AUTO_MONITOR_DEFAULTS["scan_mode"]
    return {
        "enabled_by_default": bool(
            value.get(
                "enabled_by_default",
                DEFAULT_AUTO_MONITOR_DEFAULTS["enabled_by_default"],
            )
        ),
        "recurrence": recurrence,
        "day_of_week": _normalize_day_of_week(
            value.get("day_of_week", DEFAULT_AUTO_MONITOR_DEFAULTS["day_of_week"]),
            fallback=DEFAULT_AUTO_MONITOR_DEFAULTS["day_of_week"],
        ),
        "time": _normalize_time(
            value.get("time", DEFAULT_AUTO_MONITOR_DEFAULTS["time"]),
            fallback=DEFAULT_AUTO_MONITOR_DEFAULTS["time"],
        ),
        "scan_mode": scan_mode,
    }


def normalize_auto_monitor_rule(
    rule: Any,
    *,
    defaults: dict[str, Any] | None = None,
    customer_name_lookup=None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now()
    defaults = normalize_auto_monitor_defaults(defaults)
    rule = rule if isinstance(rule, dict) else {}
    recurrence = str(rule.get("recurrence", defaults["recurrence"]) or "").strip().lower()
    if recurrence not in AUTO_MONITOR_ALLOWED_RECURRENCES:
        recurrence = defaults["recurrence"]
    scan_mode = str(rule.get("scan_mode", defaults["scan_mode"]) or "").strip().lower()
    if scan_mode not in AUTO_MONITOR_ALLOWED_SCAN_MODES:
        scan_mode = defaults["scan_mode"]
    customer_id = str(rule.get("customer_id", "") or "").strip()
    customer_name = str(rule.get("customer_name", "") or "").strip()
    if not customer_name and callable(customer_name_lookup):
        customer_name = str(customer_name_lookup(customer_id) or "").strip()
    return {
        "id": str(rule.get("id") or uuid.uuid4().hex[:12]),
        "customer_id": customer_id,
        "customer_name": customer_name,
        "enabled": bool(rule.get("enabled", defaults["enabled_by_default"])),
        "recurrence": recurrence,
        "day_of_week": _normalize_day_of_week(
            rule.get("day_of_week", defaults["day_of_week"]),
            fallback=defaults["day_of_week"],
        ),
        "time": _normalize_time(
            rule.get("time", defaults["time"]),
            fallback=defaults["time"],
        ),
        "scan_mode": scan_mode,
        "target": str(rule.get("target", "") or "").strip(),
        "public_ip": str(rule.get("public_ip", "") or "").strip(),
        "last_run": _normalize_datetime_text(rule.get("last_run")),
        "anchor_date": _normalize_datetime_text(
            rule.get("anchor_date") or rule.get("created_at") or now.isoformat()
        ),
        "created_at": _normalize_datetime_text(rule.get("created_at") or now.isoformat()),
        "updated_at": _normalize_datetime_text(rule.get("updated_at") or now.isoformat()),
    }


def normalize_auto_monitor_settings(
    value: Any,
    *,
    customer_name_lookup=None,
) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    defaults = normalize_auto_monitor_defaults(value.get("defaults"))
    rules = []
    seen = set()
    for entry in value.get("rules") or []:
        normalized = normalize_auto_monitor_rule(
            entry,
            defaults=defaults,
            customer_name_lookup=customer_name_lookup,
        )
        if not normalized["customer_id"] or normalized["id"] in seen:
            continue
        seen.add(normalized["id"])
        rules.append(normalized)
    return {"defaults": defaults, "rules": rules}


def build_default_auto_monitor_rule(
    *,
    customer_id: str,
    customer_name: str,
    public_ip: str = "",
    target: str = "",
    defaults: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now()
    defaults = normalize_auto_monitor_defaults(defaults)
    return normalize_auto_monitor_rule(
        {
            "customer_id": customer_id,
            "customer_name": customer_name,
            "enabled": defaults["enabled_by_default"],
            "recurrence": defaults["recurrence"],
            "day_of_week": defaults["day_of_week"],
            "time": defaults["time"],
            "scan_mode": defaults["scan_mode"],
            "target": target,
            "public_ip": public_ip,
            "anchor_date": now.isoformat(),
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        },
        defaults=defaults,
        now=now,
    )


def _parse_anchor(rule: dict[str, Any], *, now: datetime) -> datetime:
    anchor = _normalize_datetime_text(rule.get("anchor_date") or rule.get("created_at"))
    return datetime.fromisoformat(anchor) if anchor else now


def _next_daily_run(rule: dict[str, Any], *, now: datetime) -> datetime:
    hour, minute = map(int, rule["time"].split(":"))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return candidate if candidate > now else candidate + timedelta(days=1)


def _next_weekly_run(rule: dict[str, Any], *, now: datetime, interval_weeks: int) -> datetime:
    target_weekday = WEEKDAY_TO_INDEX.get(rule["day_of_week"], 6)
    hour, minute = map(int, rule["time"].split(":"))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    candidate += timedelta(days=(target_weekday - candidate.weekday()) % 7)
    if candidate <= now:
        candidate += timedelta(days=7)
    if interval_weeks <= 1:
        return candidate

    anchor = _parse_anchor(rule, now=now)
    anchor_week_start = (anchor - timedelta(days=anchor.weekday())).date()
    while True:
        candidate_week_start = (candidate - timedelta(days=candidate.weekday())).date()
        weeks_between = (candidate_week_start - anchor_week_start).days // 7
        if weeks_between >= 0 and weeks_between % interval_weeks == 0:
            return candidate
        candidate += timedelta(days=7)


def _shift_months(base: datetime, months: int) -> datetime:
    year = base.year + ((base.month - 1 + months) // 12)
    month = ((base.month - 1 + months) % 12) + 1
    day = min(base.day, monthrange(year, month)[1])
    return base.replace(year=year, month=month, day=day)


def _next_monthly_run(rule: dict[str, Any], *, now: datetime, interval_months: int) -> datetime:
    anchor = _parse_anchor(rule, now=now)
    hour, minute = map(int, rule["time"].split(":"))
    candidate = anchor.replace(hour=hour, minute=minute, second=0, microsecond=0)
    while candidate <= now:
        candidate = _shift_months(candidate, interval_months)
    return candidate


def get_next_auto_monitor_run(
    rule: dict[str, Any], *, now: datetime | None = None
) -> datetime | None:
    now = now or datetime.now()
    if not isinstance(rule, dict) or not rule.get("enabled"):
        return None
    recurrence = str(rule.get("recurrence") or "").strip().lower()
    if recurrence == "daily":
        return _next_daily_run(rule, now=now)
    if recurrence == "weekly":
        return _next_weekly_run(rule, now=now, interval_weeks=1)
    if recurrence == "biweekly":
        return _next_weekly_run(rule, now=now, interval_weeks=2)
    if recurrence == "monthly":
        return _next_monthly_run(rule, now=now, interval_months=1)
    if recurrence == "quarterly":
        return _next_monthly_run(rule, now=now, interval_months=3)
    return None


def _parse_last_run(value: Any) -> datetime | None:
    text = _normalize_datetime_text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _previous_daily_run(rule: dict[str, Any], *, now: datetime) -> datetime:
    hour, minute = map(int, rule["time"].split(":"))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate > now:
        candidate -= timedelta(days=1)
    return candidate


def _previous_weekly_run(
    rule: dict[str, Any], *, now: datetime, interval_weeks: int
) -> datetime | None:
    target_weekday = WEEKDAY_TO_INDEX.get(rule["day_of_week"], 6)
    hour, minute = map(int, rule["time"].split(":"))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    candidate -= timedelta(days=(candidate.weekday() - target_weekday) % 7)
    if candidate > now:
        candidate -= timedelta(days=7)
    if interval_weeks <= 1:
        return candidate

    anchor = _parse_anchor(rule, now=now)
    if candidate < anchor:
        return None
    anchor_week_start = (anchor - timedelta(days=anchor.weekday())).date()
    while candidate >= anchor:
        candidate_week_start = (candidate - timedelta(days=candidate.weekday())).date()
        weeks_between = (candidate_week_start - anchor_week_start).days // 7
        if weeks_between % interval_weeks == 0:
            return candidate
        candidate -= timedelta(days=7)
    return None


def _previous_monthly_run(
    rule: dict[str, Any], *, now: datetime, interval_months: int
) -> datetime | None:
    """Most recent anchor-aligned monthly occurrence at or before ``now``.

    Occurrences are generated forward from the anchor so the anchor's
    day-of-month is preserved (stepping back from today would use today's day).
    """
    anchor = _parse_anchor(rule, now=now)
    hour, minute = map(int, rule["time"].split(":"))
    candidate = anchor.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate > now:
        return None
    # Bounded so a clock jump cannot loop forever.
    for _ in range(2400):
        following = _shift_months(candidate, interval_months)
        if following > now:
            break
        candidate = following
    return candidate


def get_previous_auto_monitor_run(
    rule: dict[str, Any], *, now: datetime | None = None
) -> datetime | None:
    """Return the most recent scheduled occurrence at or before ``now``.

    This is what makes catch-up possible: after sleep, reboot or a long scan the
    missed slot is still in the past, so the rule stays due until it has run.
    """
    now = now or datetime.now()
    if not isinstance(rule, dict) or not rule.get("enabled"):
        return None
    recurrence = str(rule.get("recurrence") or "").strip().lower()
    if recurrence == "daily":
        return _previous_daily_run(rule, now=now)
    if recurrence == "weekly":
        return _previous_weekly_run(rule, now=now, interval_weeks=1)
    if recurrence == "biweekly":
        return _previous_weekly_run(rule, now=now, interval_weeks=2)
    if recurrence == "monthly":
        return _previous_monthly_run(rule, now=now, interval_months=1)
    if recurrence == "quarterly":
        return _previous_monthly_run(rule, now=now, interval_months=3)
    return None


def build_auto_monitor_rule_status(
    rule: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now()
    next_run = get_next_auto_monitor_run(rule, now=now)
    payload = dict(rule)
    payload["next_run"] = next_run.isoformat() if next_run else None
    payload["seconds_until_next_run"] = (
        max(int((next_run - now).total_seconds()), 0) if next_run else None
    )
    return payload


def get_due_auto_monitor_rules(
    auto_monitor_settings: dict[str, Any],
    *,
    now: datetime,
    startup_at: datetime,
    startup_grace_seconds: int,
) -> list[dict[str, Any]]:
    """Return enabled rules whose most recent scheduled slot has not run.

    Due-ness is derived from the persisted ``last_run`` rather than from a
    one-minute window, so a slot missed while the Mac was asleep or off is
    picked up (once) on the next tick instead of being skipped silently.
    """
    if (now - startup_at).total_seconds() < startup_grace_seconds:
        return []

    due = []
    for rule in (auto_monitor_settings or {}).get("rules") or []:
        if not rule.get("enabled"):
            continue
        slot = get_previous_auto_monitor_run(rule, now=now)
        if slot is None:
            continue
        last_run = _parse_last_run(rule.get("last_run"))
        if last_run is None or last_run < slot:
            due.append(rule)
    return due
