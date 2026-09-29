from datetime import datetime
import os

from nmapui.client_state import DEFAULT_CUSTOMER, DEFAULT_NETWORK_KEY


def _load_runtime_defaults(runtime_store):
    customer = dict(DEFAULT_CUSTOMER)
    network_key = dict(DEFAULT_NETWORK_KEY)
    last_scan_target = None

    if runtime_store is None:
        return customer, network_key, last_scan_target

    saved_customer = runtime_store.get_runtime_snapshot("current_customer")
    if isinstance(saved_customer, dict) and saved_customer:
        customer.update(saved_customer)

    saved_network_key = runtime_store.get_runtime_snapshot("network_key")
    if isinstance(saved_network_key, dict) and saved_network_key:
        network_key.update(saved_network_key)

    saved_last_scan_target = runtime_store.get_runtime_snapshot("last_scan_target")
    if isinstance(saved_last_scan_target, dict):
        last_scan_target = saved_last_scan_target.get("value")

    return customer, network_key, last_scan_target


def create_runtime_services(
    *,
    default_auto_scan_config,
    rate_limiter_cls,
    job_registry_cls,
    client_state_registry_cls,
    tool_version_registry_cls,
    startup_state_factory,
    idle_state_manager,
    runtime_store=None,
):
    current_customer, network_key, last_scan_target = _load_runtime_defaults(runtime_store)
    client_state_registry = client_state_registry_cls(
        default_customer=current_customer,
        default_network_key=network_key,
    )
    client_state_registry.set_default_last_scan_target(last_scan_target)

    return {
        "network_key": network_key,
        "idle_state_manager": idle_state_manager,
        "customer_fingerprinter": None,
        "current_customer": current_customer,
        "last_scan_target": last_scan_target,
        "auto_scan_config": dict(default_auto_scan_config),
        "auto_scan_thread": None,
        "auto_scan_startup_at": datetime.now(),
        "auto_scan_startup_grace_seconds": 300,
        "rate_limiter": rate_limiter_cls(max_scans_per_hour=10, cooldown_seconds=300),
        "job_registry": _build_job_registry(job_registry_cls, runtime_store),
        "client_state_registry": client_state_registry,
        "tool_versions": tool_version_registry_cls(),
        "startup_state": startup_state_factory(),
        "runtime_store": runtime_store,
    }


def _build_job_registry(job_registry_cls, runtime_store):
    raw_limit = str(os.environ.get("NMAPUI_MAX_CONCURRENT_JOBS", "2") or "2").strip()
    try:
        max_active_jobs = max(1, int(raw_limit))
    except ValueError:
        max_active_jobs = 2
    try:
        return job_registry_cls(
            runtime_store=runtime_store,
            max_active_jobs=max_active_jobs,
        )
    except TypeError:
        try:
            return job_registry_cls(runtime_store=runtime_store)
        except TypeError:
            return job_registry_cls()
