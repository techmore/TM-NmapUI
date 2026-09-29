from datetime import datetime, timezone

from nmapui.auto_monitor import (
    build_auto_monitor_rule_status,
    build_default_auto_monitor_rule,
    get_due_auto_monitor_rules,
    get_next_auto_monitor_run,
    get_previous_auto_monitor_run,
    normalize_auto_monitor_settings,
)
from nmapui.auto_scan_runtime import execute_auto_monitor_rule


def test_normalize_auto_monitor_settings_applies_defaults_and_filters_invalid_rules():
    settings = normalize_auto_monitor_settings(
        {
            "defaults": {"recurrence": "weekly", "day_of_week": "sunday", "time": "01:00"},
            "rules": [
                {"customer_id": "cust-1", "customer_name": "Acme", "enabled": True},
                {"customer_id": "", "customer_name": "Missing"},
            ],
        }
    )

    assert settings["defaults"]["recurrence"] == "weekly"
    assert len(settings["rules"]) == 1
    assert settings["rules"][0]["day_of_week"] == "sunday"
    assert settings["rules"][0]["time"] == "01:00"


def test_get_next_auto_monitor_run_supports_weekly_and_biweekly():
    weekly_rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "weekly", "day_of_week": "sunday", "time": "01:00"},
        now=datetime(2026, 3, 15, 0, 0),
    )
    weekly_rule["enabled"] = True

    biweekly_rule = dict(weekly_rule)
    biweekly_rule["recurrence"] = "biweekly"
    biweekly_rule["anchor_date"] = "2026-03-15T00:00:00"

    assert get_next_auto_monitor_run(
        weekly_rule, now=datetime(2026, 3, 15, 0, 30)
    ).isoformat() == "2026-03-15T01:00:00"
    assert get_next_auto_monitor_run(
        biweekly_rule, now=datetime(2026, 3, 16, 0, 0)
    ).isoformat() == "2026-03-29T01:00:00"


def test_get_due_auto_monitor_rules_returns_enabled_rule_when_next_run_has_arrived():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 14, 0, 0),
    )
    rule["enabled"] = True

    due = get_due_auto_monitor_rules(
        {"rules": [rule]},
        now=datetime(2026, 3, 14, 1, 0),
        startup_at=datetime(2026, 3, 14, 0, 0),
        startup_grace_seconds=0,
    )

    assert due == [rule]


def test_new_daily_rule_does_not_catch_up_a_slot_before_creation():
    created = datetime(2026, 3, 14, 12, 0)
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=created,
    )
    rule["enabled"] = True

    assert get_previous_auto_monitor_run(rule, now=created) is None
    assert get_due_auto_monitor_rules(
        {"rules": [rule]}, now=created, startup_at=created,
        startup_grace_seconds=0,
    ) == []
    assert get_next_auto_monitor_run(rule, now=created) == datetime(2026, 3, 15, 1, 0)


def test_new_weekly_rule_does_not_catch_up_a_slot_before_creation():
    created = datetime(2026, 3, 16, 12, 0)  # Monday after the 01:00 slot.
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "weekly", "day_of_week": "monday", "time": "01:00"},
        now=created,
    )
    rule["enabled"] = True

    assert get_previous_auto_monitor_run(rule, now=created) is None
    assert get_next_auto_monitor_run(rule, now=created) == datetime(2026, 3, 23, 1, 0)


def test_older_cadence_anchor_does_not_make_precreation_slot_due():
    created = datetime(2026, 3, 14, 12, 0)
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=created,
    )
    rule["enabled"] = True
    rule["anchor_date"] = "2026-03-01T00:00:00"

    assert get_previous_auto_monitor_run(rule, now=created) is None
    assert get_due_auto_monitor_rules(
        {"rules": [rule]}, now=created, startup_at=created,
        startup_grace_seconds=0,
    ) == []


def test_legacy_rule_uses_persisted_anchor_when_creation_is_missing():
    settings = normalize_auto_monitor_settings({
        "defaults": {"recurrence": "daily", "time": "01:00"},
        "rules": [{
            "id": "legacy-rule", "customer_id": "cust-1", "enabled": True,
            "anchor_date": "2026-03-01T00:00:00",
        }],
    })
    rule = settings["rules"][0]

    assert rule["created_at"] == "2026-03-01T00:00:00"
    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 3, 14, 12, 0)
    ) == datetime(2026, 3, 14, 1, 0)


def test_new_timezone_rule_does_not_catch_up_spring_gap_before_creation():
    created = datetime(2026, 3, 8, 7, 40, tzinfo=timezone.utc)
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "02:30", "timezone": "America/New_York"},
        now=created,
    )
    rule["enabled"] = True

    assert get_previous_auto_monitor_run(rule, now=created) is None
    assert get_due_auto_monitor_rules(
        {"rules": [rule]}, now=created, startup_at=created,
        startup_grace_seconds=0,
    ) == []


def test_build_auto_monitor_rule_status_includes_next_run():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 14, 0, 0),
    )
    rule["enabled"] = True

    status = build_auto_monitor_rule_status(rule, now=datetime(2026, 3, 14, 0, 30))

    assert status["next_run"] == "2026-03-14T01:00:00"
    assert status["seconds_until_next_run"] == 1800


def test_previous_daily_run_returns_the_slot_already_passed():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 10, 0, 0),
    )
    rule["enabled"] = True

    # 01:00 has not happened yet today, so the previous slot is yesterday's.
    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 3, 14, 0, 30)
    ) == datetime(2026, 3, 13, 1, 0)
    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 3, 14, 1, 0)
    ) == datetime(2026, 3, 14, 1, 0)


def test_missed_slot_is_caught_up_once_after_downtime():
    """The Mac was off for three days; the daily rule must run, exactly once."""
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 10, 0, 0),
    )
    rule["enabled"] = True
    rule["last_run"] = "2026-03-10T01:00:00"

    # Boot on 2026-03-13 at 09:00: the 01:00 slot is long overdue.
    shared = {"rules": [rule]}
    first_tick = get_due_auto_monitor_rules(
        shared,
        now=datetime(2026, 3, 13, 9, 0),
        startup_at=datetime(2026, 3, 13, 8, 0),
        startup_grace_seconds=0,
    )
    assert first_tick == [rule]

    # After the run records last_run, the same slot is no longer due.
    rule["last_run"] = "2026-03-13T09:00:01"
    assert (
        get_due_auto_monitor_rules(
            shared,
            now=datetime(2026, 3, 13, 9, 1),
            startup_at=datetime(2026, 3, 13, 8, 0),
            startup_grace_seconds=0,
        )
        == []
    )


def test_rule_is_not_due_when_last_run_is_after_the_slot():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 14, 0, 0),
    )
    rule["enabled"] = True
    rule["last_run"] = "2026-03-14T01:00:05"

    assert (
        get_due_auto_monitor_rules(
            {"rules": [rule]},
            now=datetime(2026, 3, 14, 12, 0),
            startup_at=datetime(2026, 3, 14, 0, 0),
            startup_grace_seconds=0,
        )
        == []
    )


def test_startup_grace_suppresses_catch_up():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 1, 0, 0),
    )
    rule["enabled"] = True
    rule["last_run"] = "2026-03-01T01:00:00"

    assert (
        get_due_auto_monitor_rules(
            {"rules": [rule]},
            now=datetime(2026, 3, 14, 9, 0),
            startup_at=datetime(2026, 3, 14, 9, 0),
            startup_grace_seconds=300,
        )
        == []
    )


def test_weekly_catch_up_finds_the_most_recent_occurrence():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "weekly", "day_of_week": "sunday", "time": "02:00"},
        now=datetime(2026, 3, 1, 0, 0),
    )
    rule["enabled"] = True
    rule["last_run"] = "2026-03-01T02:00:00"

    # Sunday 2026-03-15 02:00 has passed; now it is Tuesday 2026-03-17.
    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 3, 17, 12, 0)
    ) == datetime(2026, 3, 15, 2, 0)
    assert get_due_auto_monitor_rules(
        {"rules": [rule]},
        now=datetime(2026, 3, 17, 12, 0),
        startup_at=datetime(2026, 3, 17, 0, 0),
        startup_grace_seconds=0,
    ) == [rule]


def test_previous_monthly_run_preserves_the_anchor_day_of_month():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "monthly", "time": "02:00"},
        now=datetime(2026, 1, 20, 0, 0),
    )
    rule["enabled"] = True

    # Occurrences follow the anchor's day (20th), not today's day.
    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 3, 1, 0, 30)
    ) == datetime(2026, 2, 20, 2, 0)
    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 3, 25, 0, 0)
    ) == datetime(2026, 3, 20, 2, 0)
    # Before the first occurrence there is nothing to catch up.
    assert get_previous_auto_monitor_run(rule, now=datetime(2026, 1, 20, 1, 0)) is None


def test_previous_quarterly_run_steps_three_months():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "quarterly", "time": "02:00"},
        now=datetime(2026, 1, 10, 0, 0),
    )
    rule["enabled"] = True

    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 8, 1, 0, 0)
    ) == datetime(2026, 7, 10, 2, 0)


def test_legacy_monthly_schedule_does_not_drift_after_short_month():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "monthly", "time": "01:00"},
        now=datetime(2026, 1, 31, 12, 0),
    )
    rule["enabled"] = True

    assert get_previous_auto_monitor_run(
        rule, now=datetime(2026, 3, 1, 12, 0)
    ) == datetime(2026, 2, 28, 1, 0)
    assert get_next_auto_monitor_run(
        rule, now=datetime(2026, 3, 1, 12, 0)
    ) == datetime(2026, 3, 31, 1, 0)


def test_spring_forward_schedule_moves_missing_local_time_after_gap():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "02:30", "timezone": "America/New_York"},
        now=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    rule["enabled"] = True
    now = datetime(2026, 3, 8, 7, 10, tzinfo=timezone.utc)

    next_run = get_next_auto_monitor_run(rule, now=now)
    status = build_auto_monitor_rule_status(rule, now=now)

    assert next_run.isoformat() == "2026-03-08T03:30:00-04:00"
    assert status["seconds_until_next_run"] == 20 * 60
    assert get_previous_auto_monitor_run(rule, now=now).isoformat() == "2026-03-07T02:30:00-05:00"


def test_fall_back_schedule_runs_once_on_first_ambiguous_occurrence():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:30", "timezone": "America/New_York"},
        now=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )
    rule["enabled"] = True
    now = datetime(2026, 11, 1, 6, 10, tzinfo=timezone.utc)
    slot = get_previous_auto_monitor_run(rule, now=now)
    assert slot.isoformat() == "2026-11-01T01:30:00-04:00"

    rule["last_run"] = "2026-11-01T05:45:00+00:00"
    assert get_due_auto_monitor_rules(
        {"rules": [rule]},
        now=now,
        startup_at=datetime(2026, 11, 1, 4, tzinfo=timezone.utc),
        startup_grace_seconds=0,
    ) == []


def test_monthly_timezone_schedule_reuses_original_anchor_day():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "monthly", "time": "01:00", "timezone": "America/New_York"},
        now=datetime(2026, 1, 31, 12, tzinfo=timezone.utc),
    )
    rule["enabled"] = True
    assert get_next_auto_monitor_run(
        rule,
        now=datetime(2026, 3, 1, 12, tzinfo=timezone.utc),
    ).isoformat() == "2026-03-31T01:00:00-04:00"


def test_auto_monitor_records_last_run_only_after_successful_report():
    rule = {"id": "rule-1", "customer_id": "cust-1", "customer_name": "Acme", "target": "127.0.0.1"}
    settings_state = {"auto_monitor": {"rules": [rule]}}
    saved = []

    class Registry:
        status = "idle"

        def start(self, sid, job_type, details=None):
            self.status = "running"
            return True

        def complete(self, sid, job_type, status="completed"):
            self.status = status

        def get(self, sid, job_type):
            return {"status": self.status}

    registry = Registry()
    deps = {
        "rule": rule,
        "logger": __import__("logging").getLogger(__name__),
        "network_key": {},
        "rate_limiter": type("Limiter", (), {"can_scan": lambda self, sid: (True, None), "record_scan": lambda self, sid: None})(),
        "validate_target": lambda target: (True, None),
        "job_registry": registry,
        "emit_job_status": lambda sid, job_type: None,
        "generate_report_task": lambda sid, payload: registry.complete(sid, "report", status="failed"),
        "set_current_customer_state": lambda value, sid=None: None,
        "set_last_scan_target_state": lambda value, sid=None: None,
        "settings_state": settings_state,
        "save_settings": lambda value: saved.append(value),
    }

    assert execute_auto_monitor_rule(deps=deps) is False
    assert saved == []
    assert not settings_state["auto_monitor"]["rules"][0].get("last_run")

    deps["generate_report_task"] = lambda sid, payload: registry.complete(sid, "report")
    assert execute_auto_monitor_rule(deps=deps) is True
    assert saved[0]["auto_monitor"]["rules"][0]["last_run"].endswith("+00:00")
