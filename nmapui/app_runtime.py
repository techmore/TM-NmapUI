import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path

from nmapui.auto_scan_runtime import execute_auto_scan as execute_auto_scan_impl
from nmapui.handlers.auto_scan import start_auto_scan_thread as handler_start_auto_scan_thread
from nmapui.startup_checks import run_startup_checks


def execute_auto_scan(*, deps):
    return execute_auto_scan_impl(deps=deps)


def startup_checks(*, deps, quick=False):
    run_startup_checks(deps, quick=quick)


def start_auto_scan_thread(
    *,
    auto_scan_thread,
    socketio,
    auto_scan_config,
    settings_state,
    should_run_auto_scan,
    startup_at,
    startup_grace_seconds,
    execute_auto_scan,
    execute_auto_monitor_rule,
    maintenance_task=None,
    logger,
):
    thread_ref = {"thread": auto_scan_thread}
    handler_start_auto_scan_thread(
        thread_ref=thread_ref,
        socketio=socketio,
        auto_scan_config=auto_scan_config,
        settings_state=settings_state,
        should_run_auto_scan=should_run_auto_scan,
        startup_at=startup_at,
        startup_grace_seconds=startup_grace_seconds,
        execute_auto_scan=execute_auto_scan,
        execute_auto_monitor_rule=execute_auto_monitor_rule,
        maintenance_task=maintenance_task,
        logger=logger,
    )
    return thread_ref["thread"]


def _resolve_log_dir(base_dir: Path) -> Path:
    override = str(os.environ.get("NMAPUI_LOG_DIR", "") or "").strip()
    preferred = (
        Path(override).expanduser()
        if override
        else Path.home() / "Library" / "Application Support" / "NmapUI" / "logs"
    )
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        return preferred
    except OSError:
        fallback = base_dir / "logs"
        fallback.mkdir(exist_ok=True)
        return fallback


def configure_root_logging(*, base_dir):
    root_logger = logging.getLogger()
    if getattr(root_logger, "_nmapui_configured", False):
        return

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root_logger.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    log_dir = _resolve_log_dir(base_dir)
    file_handler = RotatingFileHandler(
        log_dir / "nmapui.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    root_logger._nmapui_configured = True


def run_server(
    *,
    argv=None,
    runtime_options=None,
    build_runtime_options,
    log_auth_posture,
    startup_checks,
    start_auto_scan_thread,
    run_socketio_server,
    socketio,
    app,
    sys_module,
):
    runtime_options = runtime_options or build_runtime_options(argv or sys_module.argv)
    quick_mode = runtime_options["quick_mode"]
    if runtime_options.get("port_auto_selected"):
        logging.getLogger(__name__).warning(
            "Default runtime port %s was unavailable; using %s instead",
            runtime_options.get("requested_port"),
            runtime_options["port"],
        )

    log_auth_posture()
    startup_checks(quick=quick_mode)
    start_auto_scan_thread()
    run_socketio_server(socketio, app, runtime_options)
