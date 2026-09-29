from datetime import datetime, timezone

from nmapui.auto_monitor import normalize_auto_monitor_settings
from nmapui.auto_scan import AUTO_SCAN_CONFIG_LOCK
from nmapui.settings import SETTINGS_STATE_LOCK

AUTO_SCAN_SID = "__auto_scan__"


def execute_auto_scan(*, deps):
    """Run a scheduled scan server-side.

    Earlier revisions emitted a ``trigger_generate_report`` Socket.IO event from
    the scheduler thread.  ``flask_socketio.emit`` requires a request context,
    so that call always raised ``RuntimeError`` and was swallowed by
    ``safe_emit``; nothing in the codebase listened for the event either.  The
    outcome was a scheduled "scan" that recorded ``last_run`` and logged success
    while never running nmap. This now mirrors ``execute_auto_monitor_rule`` and
    executes a real report job through ``generate_report_task``.
    """
    auto_scan_config = deps["auto_scan_config"]
    current_customer = deps["current_customer"]
    get_last_scan_target = deps["get_last_scan_target"]
    logger = deps["logger"]
    network_key = deps["network_key"]
    rate_limiter = deps["rate_limiter"]
    safe_emit = deps["safe_emit"]
    save_auto_scan_config = deps["save_auto_scan_config"]
    validate_target = deps["validate_target"]
    job_registry = deps["job_registry"]
    emit_job_status = deps["emit_job_status"]
    generate_report_task = deps["generate_report_task"]
    set_current_customer_state = deps["set_current_customer_state"]
    set_last_scan_target_state = deps["set_last_scan_target_state"]

    target = get_last_scan_target() or network_key.get("cidr", "192.168.1.0/24")

    if not target:
        logger.warning("No target available for auto scan")
        safe_emit("auto_scan_error", {"error": "No target configured"})
        return

    is_valid, error_msg = validate_target(target)
    if not is_valid:
        logger.error("Auto scan validation failed: %s", error_msg)
        safe_emit("auto_scan_error", {"error": error_msg})
        return

    can_scan, rate_msg = rate_limiter.can_scan(AUTO_SCAN_SID)
    if not can_scan:
        logger.warning("Auto scan rate limited: %s", rate_msg)
        safe_emit("auto_scan_error", {"error": rate_msg})
        return

    customer_name = current_customer.get("name", "Unknown").split(" (")[0]
    logger.info(
        "Executing auto scan for target: %s, customer: %s",
        target,
        customer_name,
    )

    if not job_registry.start(
        AUTO_SCAN_SID,
        "report",
        {
            "target": target,
            "customer_name": customer_name,
            "chunked": False,
            "auto_scan": True,
        },
    ):
        logger.info(
            "Skipping auto scan because a report job is already running for %s",
            AUTO_SCAN_SID,
        )
        return

    rate_limiter.record_scan(AUTO_SCAN_SID)
    set_current_customer_state(
        {
            "id": current_customer.get("id", "unknown"),
            "name": customer_name,
            "confidence": 1.0,
            "metadata": {"auto_scan": True},
        },
        sid=AUTO_SCAN_SID,
    )
    set_last_scan_target_state(target, sid=AUTO_SCAN_SID)
    emit_job_status(AUTO_SCAN_SID, "report")

    try:
        generate_report_task(
            AUTO_SCAN_SID,
            {
                "target": target,
                "customer_name": customer_name,
                "chunked": False,
                "auto_scan": True,
            },
        )
    except Exception as exc:
        logger.error("Auto scan failed to start for target %s: %s", target, exc)
        job_registry.complete(AUTO_SCAN_SID, "report", status="failed")
        emit_job_status(AUTO_SCAN_SID, "report")
        safe_emit("auto_scan_error", {"error": str(exc)})
        return

    job = job_registry.get(AUTO_SCAN_SID, "report")
    if not job or job.get("status") != "completed":
        logger.warning("Auto scan did not complete successfully for target %s", target)
        return False

    try:
        with AUTO_SCAN_CONFIG_LOCK:
            auto_scan_config["last_run"] = datetime.now().isoformat()
            save_auto_scan_config(auto_scan_config)
    except Exception:
        logger.exception("Auto scan completed but its last-run timestamp could not be saved")
        return False
    logger.info("Auto scan completed for target: %s", target)
    return True


def execute_auto_monitor_rule(*, deps):
    rule = deps["rule"]
    logger = deps["logger"]
    network_key = deps["network_key"]
    rate_limiter = deps["rate_limiter"]
    validate_target = deps["validate_target"]
    job_registry = deps["job_registry"]
    emit_job_status = deps["emit_job_status"]
    generate_report_task = deps["generate_report_task"]
    set_current_customer_state = deps["set_current_customer_state"]
    set_last_scan_target_state = deps["set_last_scan_target_state"]
    settings_state = deps["settings_state"]
    save_settings = deps["save_settings"]

    target = str(
        rule.get("target") or rule.get("public_ip") or network_key.get("cidr") or ""
    ).strip()
    if not target:
        logger.warning("Auto-monitor rule %s has no target", rule.get("id"))
        return

    is_valid, error_msg = validate_target(target)
    if not is_valid:
        logger.warning(
            "Auto-monitor target invalid for rule %s: %s",
            rule.get("id"),
            error_msg,
        )
        return

    can_scan, rate_msg = rate_limiter.can_scan(AUTO_SCAN_SID)
    if not can_scan:
        logger.warning(
            "Auto-monitor rate limited for rule %s: %s",
            rule.get("id"),
            rate_msg,
        )
        return

    if not job_registry.start(
        AUTO_SCAN_SID,
        "report",
        {
            "target": target,
            "customer_name": rule.get("customer_name"),
            "chunked": False,
            "auto_monitor_rule_id": rule.get("id"),
        },
    ):
        logger.info(
            "Skipping auto-monitor rule %s because a report job is already running",
            rule.get("id"),
        )
        return

    rate_limiter.record_scan(AUTO_SCAN_SID)
    set_current_customer_state(
        {
            "id": rule.get("customer_id", "unknown"),
            "name": rule.get("customer_name", "Unknown"),
            "confidence": 1.0,
            "metadata": {"auto_monitor": True, "rule_id": rule.get("id")},
        },
        sid=AUTO_SCAN_SID,
    )
    set_last_scan_target_state(target, sid=AUTO_SCAN_SID)
    emit_job_status(AUTO_SCAN_SID, "report")
    try:
        generate_report_task(
            AUTO_SCAN_SID,
            {
                "target": target,
                "customer_name": rule.get("customer_name", "Unknown"),
                "chunked": False,
                "auto_scan": True,
                "auto_monitor": True,
                "auto_monitor_rule_id": rule.get("id"),
            },
        )
    except Exception:
        logger.exception("Auto-monitor rule %s failed", rule.get("id"))
        job_registry.complete(AUTO_SCAN_SID, "report", status="failed")
        emit_job_status(AUTO_SCAN_SID, "report")
        return False

    job = job_registry.get(AUTO_SCAN_SID, "report")
    if not job or job.get("status") != "completed":
        logger.warning("Auto-monitor rule %s did not complete successfully", rule.get("id"))
        return False

    with SETTINGS_STATE_LOCK:
        auto_monitor = normalize_auto_monitor_settings(
            (settings_state or {}).get("auto_monitor", {})
        )
        for entry in auto_monitor.get("rules", []):
            if entry.get("id") == rule.get("id"):
                entry["last_run"] = datetime.now(timezone.utc).isoformat()
                entry["updated_at"] = entry["last_run"]
                break
        settings_state["auto_monitor"] = auto_monitor
        try:
            save_settings(settings_state)
        except Exception:
            logger.exception("Auto-monitor rule %s completed but its last-run timestamp could not be saved", rule.get("id"))
            return False
    return True
