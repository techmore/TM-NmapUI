from nmapui.app_state_runtime import (
    get_report_counts as get_report_counts_runtime,
    load_current_assignment as load_current_assignment_runtime,
    save_current_assignment as save_current_assignment_runtime,
    save_customers_config as save_customers_config_runtime,
)
from nmapui.app_runtime import (
    execute_auto_scan as execute_auto_scan_runtime,
    start_auto_scan_thread as start_auto_scan_thread_runtime,
)
from nmapui.auto_scan_runtime import execute_auto_monitor_rule as execute_auto_monitor_rule_runtime
from nmapui.app_events_runtime import safe_emit as safe_emit_runtime
from nmapui.traceroute_runtime import (
    build_traceroute_deps,
    run_traceroute as run_traceroute_runtime,
)


def build_state_bindings(
    *,
    current_assignment_file,
    current_customer,
    scans_dir,
    normalize_current_assignment_document,
    normalize_scan_metadata_document,
    load_json_document,
    save_json_document,
    save_yaml_document,
    get_customer_fingerprinter,
    merge_customer_metadata,
    client_state_registry,
    get_current_customer_state,
    logger,
):
    def get_report_counts():
        return get_report_counts_runtime(
            scans_dir=scans_dir,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
        )

    def save_customers_config():
        save_customers_config_runtime(
            get_customer_fingerprinter=get_customer_fingerprinter,
            save_yaml_document=save_yaml_document,
            logger=logger,
        )

    def save_current_assignment(sid=None):
        save_current_assignment_runtime(
            current_assignment_file=current_assignment_file,
            get_current_customer_state=get_current_customer_state,
            save_json_document=save_json_document,
            logger=logger,
            sid=sid,
        )

    def load_current_assignment():
        return load_current_assignment_runtime(
            current_assignment_file=current_assignment_file,
            current_customer=current_customer,
            normalize_current_assignment_document=normalize_current_assignment_document,
            load_json_document=load_json_document,
            get_customer_fingerprinter=get_customer_fingerprinter,
            merge_customer_metadata=merge_customer_metadata,
            client_state_registry=client_state_registry,
            logger=logger,
        )

    return {
        "get_report_counts": get_report_counts,
        "save_customers_config": save_customers_config,
        "save_current_assignment": save_current_assignment,
        "load_current_assignment": load_current_assignment,
    }


def build_traceroute_bindings(
    *,
    emit_to_client,
    safe_emit,
    get_client_state,
    socketio_sleep,
    logger,
    is_private_ip,
    requests,
    set_network_key_state,
    get_customer_fingerprinter,
    merge_customer_metadata,
    set_current_customer_state,
    get_current_customer_state,
    runtime_store=None,
):
    def traceroute_deps():
        return build_traceroute_deps(
            emit_to_client=emit_to_client,
            safe_emit=safe_emit,
            get_client_state=get_client_state,
            socketio_sleep=socketio_sleep,
            logger=logger,
            is_private_ip=is_private_ip,
            requests=requests,
            set_network_key_state=set_network_key_state,
            get_customer_fingerprinter=get_customer_fingerprinter,
            merge_customer_metadata=merge_customer_metadata,
            set_current_customer_state=set_current_customer_state,
            get_current_customer_state=get_current_customer_state,
            runtime_store=runtime_store,
        )

    def run_traceroute(target="1.1.1.1", sid=None):
        return run_traceroute_runtime(target=target, sid=sid, deps=traceroute_deps())

    return {
        "traceroute_deps": traceroute_deps,
        "run_traceroute": run_traceroute,
    }


def build_runtime_bindings(
    *,
    build_execute_auto_scan_deps,
    build_execute_auto_monitor_rule_deps,
    auto_scan_config,
    get_current_customer,
    get_last_scan_target,
    logger,
    get_network_key,
    rate_limiter,
    save_auto_scan_config,
    validate_target,
    auto_scan_thread,
    socketio,
    should_run_auto_scan,
    startup_at,
    startup_grace_seconds,
    current_assignment_loader,
    set_current_customer,
    settings_state,
    save_settings,
    job_registry,
    emit_job_status,
    set_current_customer_state,
    set_last_scan_target_state,
    generate_report_task_provider,
):
    def safe_emit(event, data=None):
        return safe_emit_runtime(event, data)

    def execute_auto_scan():
        return execute_auto_scan_runtime(
            deps=build_execute_auto_scan_deps(
                auto_scan_config=auto_scan_config,
                current_customer=get_current_customer(),
                get_last_scan_target=get_last_scan_target,
                logger=logger,
                network_key=get_network_key(),
                rate_limiter=rate_limiter,
                safe_emit=safe_emit,
                save_auto_scan_config=save_auto_scan_config,
                validate_target=validate_target,
                job_registry=job_registry,
                emit_job_status=emit_job_status,
                generate_report_task=generate_report_task_provider(),
                set_current_customer_state=set_current_customer_state,
                set_last_scan_target_state=set_last_scan_target_state,
            )
        )

    def execute_auto_monitor_rule(rule):
        return execute_auto_monitor_rule_runtime(
            deps=build_execute_auto_monitor_rule_deps(
                rule=rule,
                logger=logger,
                network_key=get_network_key(),
                rate_limiter=rate_limiter,
                validate_target=validate_target,
                job_registry=job_registry,
                emit_job_status=emit_job_status,
                generate_report_task=generate_report_task_provider(),
                set_current_customer_state=set_current_customer_state,
                set_last_scan_target_state=set_last_scan_target_state,
                settings_state=settings_state,
                save_settings=save_settings,
            )
        )

    thread_ref = {"thread": auto_scan_thread}

    def start_auto_scan_thread():
        thread_ref["thread"] = start_auto_scan_thread_runtime(
            auto_scan_thread=thread_ref["thread"],
            socketio=socketio,
            auto_scan_config=auto_scan_config,
            settings_state=settings_state,
            should_run_auto_scan=should_run_auto_scan,
            startup_at=startup_at,
            startup_grace_seconds=startup_grace_seconds,
            execute_auto_scan=execute_auto_scan,
            execute_auto_monitor_rule=execute_auto_monitor_rule,
            logger=logger,
        )
        return thread_ref["thread"]

    def get_auto_scan_thread():
        return thread_ref["thread"]

    def load_current_assignment():
        set_current_customer(current_assignment_loader())

    return {
        "safe_emit": safe_emit,
        "execute_auto_scan": execute_auto_scan,
        "execute_auto_monitor_rule": execute_auto_monitor_rule,
        "start_auto_scan_thread": start_auto_scan_thread,
        "get_auto_scan_thread": get_auto_scan_thread,
        "load_current_assignment": load_current_assignment,
    }
