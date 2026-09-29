from typing import Any

from nmapui.paths import BASE_DIR


def _release_id() -> str | None:
    marker = BASE_DIR / "release_id"
    if not marker.is_file():
        return None
    return marker.read_text(encoding="ascii").strip() or None


def build_liveness_payload(
    *,
    app_version: str,
    default_interface: str,
    auto_scan_thread_alive: bool,
    tool_versions: dict[str, Any],
) -> dict[str, Any]:
    """Build a lightweight liveness payload for smoke tests."""
    return {
        "status": "ok",
        "app_version": app_version,
        "default_interface": default_interface,
        "auto_scan_thread_alive": auto_scan_thread_alive,
        "tool_versions": tool_versions,
    }


def build_readiness_payload(
    *,
    startup_state: dict[str, Any],
    app_version: str,
    default_interface: str,
    auto_scan_thread_alive: bool,
    tool_versions: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    """Build a readiness/diagnostics payload and matching HTTP status."""
    startup_complete = bool(startup_state.get("startup_complete"))
    dependency_checks_skipped = bool(startup_state.get("dependency_checks_skipped"))
    dependencies_ok = bool(startup_state.get("dependencies_ok"))
    recovery = dict(startup_state.get("recovery") or {})
    recovery_ok = bool(recovery.get("ok", True))
    traceroute_initialized = bool(startup_state.get("traceroute_initialized"))
    startup_errors = list(startup_state.get("errors", []))

    # A scanner on an isolated network need not reach the public traceroute
    # target. Topology discovery is diagnostic, not a prerequisite for scans.
    ready = (
        startup_complete
        and (dependency_checks_skipped or dependencies_ok)
        and auto_scan_thread_alive
        and recovery_ok
    )
    status_code = 200 if ready else 503

    payload = {
        "status": "ready" if ready else "degraded",
        "ready": ready,
        "release_id": _release_id(),
        "app_version": app_version,
        "default_interface": default_interface,
        "auto_scan_thread_alive": auto_scan_thread_alive,
        "tool_versions": tool_versions,
        "startup": {
            "startup_complete": startup_complete,
            "dependency_checks_skipped": dependency_checks_skipped,
            "dependencies_ok": dependencies_ok,
            "traceroute_initialized": traceroute_initialized,
            "last_started_at": startup_state.get("last_started_at"),
            "errors": startup_errors,
            "recovery": recovery,
        },
    }
    return payload, status_code
