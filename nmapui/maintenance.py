"""Daily, bounded maintenance for the runtime database."""

from datetime import datetime, timezone
import os
import re

from nmapui.runtime_db import (
    DEFAULT_CUSTOMER_SCAN_HISTORY_RETENTION,
    DEFAULT_FINISHED_JOB_RETENTION,
    DEFAULT_RUNTIME_LOG_RETENTION,
)

_RETENTION_SETTINGS = (
    ("NMAPUI_RUNTIME_LOGS_KEEP_LATEST", DEFAULT_RUNTIME_LOG_RETENTION),
    ("NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST", DEFAULT_CUSTOMER_SCAN_HISTORY_RETENTION),
    ("NMAPUI_FINISHED_JOBS_KEEP_LATEST", DEFAULT_FINISHED_JOB_RETENTION),
)
_MAX_RETENTION_LIMIT = 2_147_483_647


def _retention_limit(setting, default, logger):
    raw_value = os.environ.get(setting)
    if raw_value is None:
        return default
    if not re.fullmatch(r"[1-9][0-9]{0,9}", raw_value):
        logger.warning("Ignoring invalid %s; using default %s", setting, default)
        return default
    value = int(raw_value)
    if value > _MAX_RETENTION_LIMIT:
        logger.warning("Ignoring out-of-range %s; using default %s", setting, default)
        return default
    return value


def run_daily_runtime_maintenance(*, runtime_store, logger, now=None):
    if runtime_store is None:
        return None

    now = now or datetime.now(timezone.utc)
    run_date = now.astimezone(timezone.utc).date().isoformat()
    previous = runtime_store.get_runtime_snapshot("automatic_retention_status") or {}
    if previous.get("run_date") == run_date:
        return None

    logs_setting, logs_default = _RETENTION_SETTINGS[0]
    history_setting, history_default = _RETENTION_SETTINGS[1]
    jobs_setting, jobs_default = _RETENTION_SETTINGS[2]
    logs_keep_latest = _retention_limit(logs_setting, logs_default, logger)
    history_keep_latest = _retention_limit(history_setting, history_default, logger)
    jobs_keep_latest = _retention_limit(jobs_setting, jobs_default, logger)
    retention = runtime_store.apply_retention_policies(
        runtime_logs_keep_latest=logs_keep_latest,
        customer_history_keep_latest=history_keep_latest,
        compact=False,
    )
    jobs = runtime_store.prune_finished_jobs(
        keep_latest=jobs_keep_latest,
    )
    result = {
        "run_date": run_date,
        "last_run_at": now.astimezone(timezone.utc).isoformat(),
        "finished_jobs_keep_latest": jobs_keep_latest,
        **retention,
        **jobs,
    }
    runtime_store.upsert_runtime_snapshot("automatic_retention_status", result)
    logger.info(
        "Automatic runtime retention removed %s logs, %s history rows, %s jobs and %s job events",
        result["deleted_runtime_logs"],
        result["deleted_customer_scan_history"],
        result["deleted_jobs"],
        result["deleted_job_events"],
    )
    return result
