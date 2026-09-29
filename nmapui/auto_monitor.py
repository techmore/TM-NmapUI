from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
from typing import Any
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


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
    "timezone": "",
}


def _normalize_timezone(value: Any, *, fallback: str = "") -> str:
    name = str(value or "").strip()
    if not name:
        return fallback
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return fallback
    return name


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
        "timezone": _normalize_timezone(value.get("timezone")),
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
        "timezone": _normalize_timezone(
            rule.get("timezone", defaults["timezone"]),
            fallback=defaults["timezone"],
        ),
        "target": str(rule.get("target", "") or "").strip(),
        "public_ip": str(rule.get("public_ip", "") or "").strip(),
        "last_run": _normalize_datetime_text(rule.get("last_run")),
        "anchor_date": _normalize_datetime_text(
            rule.get("anchor_date") or rule.get("created_at") or now.isoformat()
        ),
        "created_at": _normalize_datetime_text(
            rule.get("created_at") or rule.get("anchor_date") or now.isoformat()
        ),
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
            "timezone": defaults["timezone"],
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


def _parse_creation(rule: dict[str, Any], *, now: datetime) -> datetime:
    created = _normalize_datetime_text(rule.get("created_at") or rule.get("anchor_date"))
    return datetime.fromisoformat(created) if created else now


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


def _aware_schedule_candidates(rule: dict[str, Any], *, now: datetime) -> list[datetime]:
    """Create nearby occurrences in the rule's timezone.

    A nonexistent spring-forward time is moved to the first corresponding
    valid time after the jump. An ambiguous fall-back time runs on its first
    occurrence. Comparisons below use UTC so Python's same-zone fold handling
    cannot treat two distinct instants as equal.
    """
    zone = ZoneInfo(rule["timezone"])
    now_local = now.astimezone(zone)
    wall_now = now_local.replace(tzinfo=None)
    hour, minute = map(int, rule["time"].split(":"))
    recurrence = str(rule.get("recurrence") or "").lower()
    anchor = _parse_anchor(rule, now=wall_now)
    if anchor.tzinfo is not None:
        anchor = anchor.astimezone(zone).replace(tzinfo=None)
    wall_slots = []

    if recurrence == "daily":
        wall_slots = [
            (wall_now + timedelta(days=delta)).replace(
                hour=hour, minute=minute, second=0, microsecond=0
            )
            for delta in range(-2, 3)
        ]
    elif recurrence in {"weekly", "biweekly"}:
        interval_weeks = 1 if recurrence == "weekly" else 2
        anchor_week_start = (anchor - timedelta(days=anchor.weekday())).date()
        for delta in range(-21, 22):
            day = (wall_now + timedelta(days=delta)).date()
            if day.weekday() != WEEKDAY_TO_INDEX.get(rule["day_of_week"], 6):
                continue
            weeks = (day - anchor_week_start).days // 7
            if recurrence == "biweekly" and (weeks < 0 or weeks % interval_weeks):
                continue
            wall_slots.append(datetime.combine(day, datetime.min.time()).replace(hour=hour, minute=minute))
    elif recurrence in {"monthly", "quarterly"}:
        interval_months = 1 if recurrence == "monthly" else 3
        month_delta = (wall_now.year - anchor.year) * 12 + wall_now.month - anchor.month
        near_index = max(0, month_delta // interval_months)
        for index in range(max(0, near_index - 2), near_index + 4):
            wall_slots.append(
                _shift_months(anchor, index * interval_months).replace(
                    hour=hour, minute=minute, second=0, microsecond=0
                )
            )

    occurrences = []
    for wall in wall_slots:
        candidate = wall.replace(tzinfo=zone, fold=0)
        round_trip = candidate.astimezone(timezone.utc).astimezone(zone)
        if round_trip.replace(tzinfo=None) != wall:
            candidate = round_trip
        occurrences.append(candidate)
    return occurrences


def _nearest_aware_run(rule: dict[str, Any], *, now: datetime, next_run: bool) -> datetime | None:
    now_utc = now.astimezone(timezone.utc)
    candidates = _aware_schedule_candidates(rule, now=now)
    if next_run:
        future = [item for item in candidates if item.astimezone(timezone.utc) > now_utc]
        return min(future, key=lambda item: item.astimezone(timezone.utc)) if future else None
    previous = [item for item in candidates if item.astimezone(timezone.utc) <= now_utc]
    return max(previous, key=lambda item: item.astimezone(timezone.utc)) if previous else None


def _next_monthly_run(rule: dict[str, Any], *, now: datetime, interval_months: int) -> datetime:
    anchor = _parse_anchor(rule, now=now)
    hour, minute = map(int, rule["time"].split(":"))
    first = anchor.replace(hour=hour, minute=minute, second=0, microsecond=0)
    months_since_anchor = (now.year - anchor.year) * 12 + now.month - anchor.month
    occurrence_index = max(0, months_since_anchor // interval_months)
    candidate = _shift_months(first, occurrence_index * interval_months)
    while candidate <= now:
        occurrence_index += 1
        candidate = _shift_months(first, occurrence_index * interval_months)
    return candidate


def get_next_auto_monitor_run(
    rule: dict[str, Any], *, now: datetime | None = None
) -> datetime | None:
    now = now or datetime.now()
    if not isinstance(rule, dict) or not rule.get("enabled"):
        return None
    if rule.get("timezone"):
        return _nearest_aware_run(rule, now=now, next_run=True)
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
    first = anchor.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if first > now:
        return None
    months_since_anchor = (now.year - anchor.year) * 12 + now.month - anchor.month
    occurrence_index = max(0, months_since_anchor // interval_months)
    candidate = _shift_months(first, occurrence_index * interval_months)
    if candidate > now:
        occurrence_index -= 1
        candidate = _shift_months(first, occurrence_index * interval_months)
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
    slot = None
    if rule.get("timezone"):
        slot = _nearest_aware_run(rule, now=now, next_run=False)
    else:
        recurrence = str(rule.get("recurrence") or "").strip().lower()
        if recurrence == "daily":
            slot = _previous_daily_run(rule, now=now)
        elif recurrence == "weekly":
            slot = _previous_weekly_run(rule, now=now, interval_weeks=1)
        elif recurrence == "biweekly":
            slot = _previous_weekly_run(rule, now=now, interval_weeks=2)
        elif recurrence == "monthly":
            slot = _previous_monthly_run(rule, now=now, interval_months=1)
        elif recurrence == "quarterly":
            slot = _previous_monthly_run(rule, now=now, interval_months=3)
    if slot is None:
        return None

    # A newly created rule must not catch up a slot that predates its creation.
    # The recurrence anchor can intentionally predate creation to align a
    # biweekly or monthly cadence, so it is not the activation boundary.
    # Compare aware slots as instants across DST folds; legacy naive schedules
    # continue using the host's local wall clock.
    created = _parse_creation(rule, now=now)
    if slot.tzinfo is not None:
        if created.tzinfo is None:
            created = created.replace(tzinfo=ZoneInfo(rule["timezone"]))
        return slot if slot.astimezone(timezone.utc) >= created.astimezone(timezone.utc) else None
    if created.tzinfo is not None:
        created = created.astimezone().replace(tzinfo=None)
    return slot if slot >= created else None


def build_auto_monitor_rule_status(
    rule: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now()
    next_run = get_next_auto_monitor_run(rule, now=now)
    payload = dict(rule)
    payload["next_run"] = next_run.isoformat() if next_run else None
    payload["seconds_until_next_run"] = (
        max(
            int(
                (
                    next_run.astimezone(timezone.utc) - now.astimezone(timezone.utc)
                    if next_run.tzinfo is not None
                    else next_run - now
                ).total_seconds()
            ),
            0,
        ) if next_run else None
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
        if last_run is not None and slot.tzinfo is not None:
            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=ZoneInfo(rule["timezone"]))
            last_run = last_run.astimezone(timezone.utc)
            slot = slot.astimezone(timezone.utc)
        elif last_run is not None and last_run.tzinfo is not None:
            last_run = last_run.astimezone().replace(tzinfo=None)
        if last_run is None or last_run < slot:
            due.append(rule)
    return due
