from datetime import datetime, timezone
import threading

from flask import jsonify, request
from flask_socketio import emit

from nmapui.auto_monitor import get_due_auto_monitor_rules, normalize_auto_monitor_settings
from nmapui.auto_scan import (
    AUTO_SCAN_CONFIG_LOCK,
    build_auto_scan_status_payload,
    validate_auto_scan_config_update as default_validate_auto_scan_config_update,
)
from nmapui.auth import require_auth, require_socket_auth
from nmapui.paths import AUTO_SCAN_SCHEDULER_LOCK_FILE
from nmapui.settings import SETTINGS_STATE_LOCK

try:
    import fcntl
except ImportError:  # pragma: no cover - only used on non-POSIX runtimes
    fcntl = None


def register_auto_scan_handlers(app, socketio, deps):
    auto_scan_config = deps["auto_scan_config"]
    save_auto_scan_config = deps["save_auto_scan_config"]
    validate_auto_scan_config_update = deps.get(
        "validate_auto_scan_config_update",
        default_validate_auto_scan_config_update,
    )
    logger = deps["logger"]

    @socketio.on("update_auto_scan")
    @require_socket_auth()
    def update_auto_scan_event(data):
        is_valid, error = validate_auto_scan_config_update(data)
        if not is_valid:
            emit("auto_scan_error", {"error": error})
            return

        try:
            with AUTO_SCAN_CONFIG_LOCK:
                updated_config = {**auto_scan_config, **data}
                save_auto_scan_config(updated_config)
                auto_scan_config.update(updated_config)
                status_payload = build_auto_scan_status_payload(updated_config)
        except Exception:
            logger.exception("Failed to save auto-scan configuration")
            emit("auto_scan_error", {"error": "Could not save auto-scan settings"})
            return
        emit("auto_scan_status", status_payload, broadcast=True)
        logger.info("Auto scan updated: %s", auto_scan_config)

    @app.route("/api/auto_scan/status")
    @require_auth
    def get_auto_scan_status():
        with AUTO_SCAN_CONFIG_LOCK:
            status_payload = build_auto_scan_status_payload(dict(auto_scan_config))
        return jsonify(status_payload)

    @app.route("/api/auto_scan/update", methods=["POST"])
    @require_auth
    def update_auto_scan():
        config = request.get_json(silent=True)
        is_valid, error = validate_auto_scan_config_update(config)
        if not is_valid:
            return jsonify({"success": False, "error": error}), 400

        try:
            with AUTO_SCAN_CONFIG_LOCK:
                updated_config = {**auto_scan_config, **config}
                save_auto_scan_config(updated_config)
                auto_scan_config.update(updated_config)
        except Exception:
            logger.exception("Failed to save auto-scan configuration")
            return jsonify({"success": False, "error": "Could not save auto-scan settings"}), 500
        logger.info("Auto scan config updated: %s", auto_scan_config)
        return jsonify({"success": True})


def auto_scan_loop(
    *,
    socketio,
    auto_scan_config,
    settings_state=None,
    should_run_auto_scan,
    startup_at,
    startup_grace_seconds,
    execute_auto_scan,
    execute_auto_monitor_rule=None,
    maintenance_task=None,
    logger,
):
    """Background loop to check and execute auto scans."""
    last_check_minute = None
    last_maintenance_date = None
    worker_running = threading.Event()

    def run_due_work(run_auto_scan, due_rules, run_maintenance, maintenance_date):
        nonlocal last_maintenance_date
        try:
            if run_maintenance:
                try:
                    maintenance_task()
                    last_maintenance_date = maintenance_date
                except Exception:
                    logger.exception("Automatic runtime maintenance failed")
            if run_auto_scan:
                try:
                    with AUTO_SCAN_CONFIG_LOCK:
                        current_auto_scan = dict(auto_scan_config)
                    if current_auto_scan.get("enabled") and should_run_auto_scan(
                        current_auto_scan,
                        now=datetime.now(),
                        startup_at=startup_at,
                        startup_grace_seconds=startup_grace_seconds,
                    ):
                        execute_auto_scan()
                    else:
                        logger.info("Skipping queued auto scan after its settings changed")
                except Exception:
                    logger.exception("Automatic scan failed")
            if execute_auto_monitor_rule is not None:
                for rule in due_rules:
                    try:
                        with SETTINGS_STATE_LOCK:
                            current_settings = normalize_auto_monitor_settings(
                                (settings_state or {}).get("auto_monitor", {})
                            )
                        current_due = get_due_auto_monitor_rules(
                            current_settings,
                            now=datetime.now(),
                            startup_at=startup_at,
                            startup_grace_seconds=startup_grace_seconds,
                        )
                        current_rule = next(
                            (entry for entry in current_due if entry.get("id") == rule.get("id")),
                            None,
                        )
                        if current_rule is None:
                            logger.info("Skipping queued auto-monitor rule %s after its settings changed", rule.get("id"))
                            continue
                        execute_auto_monitor_rule(current_rule)
                    except Exception:
                        logger.exception("Auto-monitor rule %s failed", rule.get("id"))
        finally:
            worker_running.clear()

    while True:
        try:
            now = datetime.now()
            current_minute = now.strftime("%Y-%m-%d %H:%M")
            if current_minute != last_check_minute:
                last_check_minute = current_minute
                with AUTO_SCAN_CONFIG_LOCK:
                    auto_scan_snapshot = dict(auto_scan_config)
                run_auto_scan = should_run_auto_scan(
                    auto_scan_snapshot,
                    now=now,
                    startup_at=startup_at,
                    startup_grace_seconds=startup_grace_seconds,
                )
                if run_auto_scan:
                    last_run = auto_scan_snapshot.get("last_run")
                    if last_run:
                        try:
                            last_run_time = datetime.fromisoformat(last_run)
                            elapsed = (
                                (now.astimezone(timezone.utc) - last_run_time.astimezone(timezone.utc)).total_seconds()
                                if last_run_time.tzinfo is not None
                                else (now - last_run_time).total_seconds()
                            )
                            if 0 <= elapsed < 3600:
                                run_auto_scan = False
                        except (TypeError, ValueError):
                            logger.warning("Ignoring invalid auto-scan last_run: %r", last_run)

                with SETTINGS_STATE_LOCK:
                    auto_monitor_settings = normalize_auto_monitor_settings(
                        (settings_state or {}).get("auto_monitor", {})
                    )
                due_rules = get_due_auto_monitor_rules(
                    auto_monitor_settings,
                    now=now,
                    startup_at=startup_at,
                    startup_grace_seconds=startup_grace_seconds,
                )
                run_maintenance = (
                    maintenance_task is not None
                    and now.date() != last_maintenance_date
                )
                if (run_auto_scan or due_rules or run_maintenance) and not worker_running.is_set():
                    worker_running.set()
                    try:
                        socketio.start_background_task(
                            run_due_work,
                            run_auto_scan,
                            due_rules,
                            run_maintenance,
                            now.date(),
                        )
                    except Exception:
                        worker_running.clear()
                        raise
        except Exception as exc:
            logger.error("Auto scan loop error: %s", exc)

        socketio.sleep(60)


def acquire_auto_scan_scheduler_lock(*, lock_file=AUTO_SCAN_SCHEDULER_LOCK_FILE):
    """Acquire a non-blocking process lock for the scheduler, or return None."""
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_file.open("a+", encoding="utf-8")

    if fcntl is None:
        return handle

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None

    handle.seek(0)
    handle.truncate()
    handle.write(f"{threading.get_native_id()}\n")
    handle.flush()
    return handle


def start_auto_scan_thread(
    *,
    thread_ref,
    socketio,
    auto_scan_config,
    settings_state=None,
    should_run_auto_scan,
    startup_at,
    startup_grace_seconds,
    execute_auto_scan,
    execute_auto_monitor_rule=None,
    maintenance_task=None,
    logger,
    acquire_scheduler_lock=acquire_auto_scan_scheduler_lock,
):
    """Start the auto-scan worker once per process."""
    if thread_ref["thread"] and thread_ref["thread"].is_alive():
        return

    lock_handle = thread_ref.get("lock_handle")
    if lock_handle is None:
        lock_handle = acquire_scheduler_lock()
        if lock_handle is None:
            logger.info("Skipping auto-scan worker startup; another process owns the scheduler")
            return
        thread_ref["lock_handle"] = lock_handle

    thread_ref["thread"] = threading.Thread(
        target=auto_scan_loop,
        kwargs={
            "socketio": socketio,
            "auto_scan_config": auto_scan_config,
            "settings_state": settings_state,
            "should_run_auto_scan": should_run_auto_scan,
            "startup_at": startup_at,
            "startup_grace_seconds": startup_grace_seconds,
            "execute_auto_scan": execute_auto_scan,
            "execute_auto_monitor_rule": execute_auto_monitor_rule,
            "maintenance_task": maintenance_task,
            "logger": logger,
        },
        daemon=True,
    )
    thread_ref["thread"].start()
