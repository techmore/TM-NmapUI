from nmapui.handlers.auto_scan import register_auto_scan_handlers
from nmapui.handlers.connections import register_connection_handlers
from nmapui.handlers.customers import register_customer_handlers
from nmapui.handlers.history import register_history_handlers
from nmapui.handlers.routes import register_core_routes
from nmapui.handlers.runtime_info import register_runtime_info_handlers
from nmapui.handlers.scan_jobs import register_scan_job_handlers
from nmapui.handlers.scans import register_scan_routes
from nmapui.handlers.settings import register_settings_routes
from nmapui.handlers.updates import register_update_handlers


def build_execute_auto_scan_deps(
    *,
    auto_scan_config,
    current_customer,
    get_last_scan_target,
    logger,
    network_key,
    rate_limiter,
    safe_emit,
    save_auto_scan_config,
    validate_target,
    job_registry,
    emit_job_status,
    generate_report_task,
    set_current_customer_state,
    set_last_scan_target_state,
):
    return {
        "auto_scan_config": auto_scan_config,
        "current_customer": current_customer,
        "get_last_scan_target": get_last_scan_target,
        "logger": logger,
        "network_key": network_key,
        "rate_limiter": rate_limiter,
        "safe_emit": safe_emit,
        "save_auto_scan_config": save_auto_scan_config,
        "validate_target": validate_target,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
        "generate_report_task": generate_report_task,
        "set_current_customer_state": set_current_customer_state,
        "set_last_scan_target_state": set_last_scan_target_state,
    }


def build_execute_auto_monitor_rule_deps(
    *,
    rule,
    logger,
    network_key,
    rate_limiter,
    validate_target,
    job_registry,
    emit_job_status,
    generate_report_task,
    set_current_customer_state,
    set_last_scan_target_state,
    settings_state,
    save_settings,
):
    return {
        "rule": rule,
        "logger": logger,
        "network_key": network_key,
        "rate_limiter": rate_limiter,
        "validate_target": validate_target,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
        "generate_report_task": generate_report_task,
        "set_current_customer_state": set_current_customer_state,
        "set_last_scan_target_state": set_last_scan_target_state,
        "settings_state": settings_state,
        "save_settings": save_settings,
    }


def build_scan_task_deps(
    *,
    broadcaster,
    emit_job_status,
    emit_to_client,
    ensure_job_not_cancelled,
    get_client_state,
    idle_state_manager,
    identify_gateway_firewall_targets,
    job_registry,
    logger,
    run_arp_scan,
    run_cancellable_command,
    settings_state,
    socketio_sleep,
    update_job_progress,
    vulners_script,
    runtime_store,
):
    return {
        "broadcaster": broadcaster,
        "emit_to_client": emit_to_client,
        "get_client_state": get_client_state,
        "ensure_job_not_cancelled": ensure_job_not_cancelled,
        "idle_state_manager": idle_state_manager,
        "update_job_progress": update_job_progress,
        "socketio_sleep": socketio_sleep,
        "run_cancellable_command": run_cancellable_command,
        "run_arp_scan": run_arp_scan,
        "identify_gateway_firewall_targets": identify_gateway_firewall_targets,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
        "logger": logger,
        "runtime_store": runtime_store,
        "settings_state": settings_state,
        "vulners_script": vulners_script,
    }


def build_report_task_deps(
    *,
    broadcaster,
    current_customer,
    customer_fingerprinter,
    runtime_store,
    emit_job_status,
    emit_to_client,
    extract_scan_statistics,
    get_app_version,
    get_client_state,
    idle_state_manager,
    job_registry,
    merge_nmap_xml_files,
    network_key,
    pdf_stylesheet,
    run_nmap_with_xml_output,
    sanitize_customer_dir_name,
    save_scan_metadata,
    scans_dir,
    settings_state,
    upload_report_artifacts_to_google_drive,
    socketio_sleep,
    split_subnet_into_chunks,
    stylesheet,
    update_job_progress,
    validate_target,
    web_stylesheet,
    convert_html_to_pdf,
    convert_xml_to_html,
    create_scan_folder,
):
    return {
        "job_registry": job_registry,
        "broadcaster": broadcaster,
        "idle_state_manager": idle_state_manager,
        "emit_job_status": emit_job_status,
        "emit_to_client": emit_to_client,
        "update_job_progress": update_job_progress,
        "validate_target": validate_target,
        "split_subnet_into_chunks": split_subnet_into_chunks,
        "create_scan_folder": create_scan_folder,
        "scans_dir": scans_dir,
        "settings_state": settings_state,
        "upload_report_artifacts_to_google_drive": upload_report_artifacts_to_google_drive,
        "sanitize_customer_dir_name": sanitize_customer_dir_name,
        "run_nmap_with_xml_output": run_nmap_with_xml_output,
        "merge_nmap_xml_files": merge_nmap_xml_files,
        "socketio_sleep": socketio_sleep,
        "convert_xml_to_html": convert_xml_to_html,
        "convert_html_to_pdf": convert_html_to_pdf,
        "web_stylesheet": web_stylesheet,
        "pdf_stylesheet": pdf_stylesheet,
        "stylesheet": stylesheet,
        "get_app_version": get_app_version,
        "save_scan_metadata": save_scan_metadata,
        "get_client_state": get_client_state,
        "network_key": network_key,
        "current_customer": current_customer,
        "extract_scan_statistics": extract_scan_statistics,
        "customer_fingerprinter": customer_fingerprinter,
        "runtime_store": runtime_store,
    }


def build_saved_pdf_task_deps(
    *,
    broadcaster,
    convert_html_to_pdf,
    convert_xml_to_html,
    emit_job_status,
    emit_to_client,
    find_latest_saved_scan_for_pdf,
    get_app_version,
    get_client_state,
    job_registry,
    logger,
    pdf_stylesheet,
    runtime_store,
    scans_dir,
    socketio_sleep,
    web_stylesheet,
):
    return {
        "job_registry": job_registry,
        "broadcaster": broadcaster,
        "emit_job_status": emit_job_status,
        "emit_to_client": emit_to_client,
        "get_client_state": get_client_state,
        "find_latest_saved_scan_for_pdf": find_latest_saved_scan_for_pdf,
        "convert_xml_to_html": convert_xml_to_html,
        "convert_html_to_pdf": convert_html_to_pdf,
        "get_app_version": get_app_version,
        "logger": logger,
        "scans_dir": scans_dir,
        "socketio_sleep": socketio_sleep,
        "web_stylesheet": web_stylesheet,
        "pdf_stylesheet": pdf_stylesheet,
        "runtime_store": runtime_store,
    }


def build_startup_check_deps(
    *,
    auto_scan_config,
    begin_startup_state,
    check_arp_scan,
    check_nmap,
    check_vulners,
    complete_startup_state,
    get_app_version,
    get_default_interface_cached,
    get_versions,
    load_auto_scan_config,
    load_current_assignment,
    logger,
    network_key,
    runtime_store,
    run_traceroute,
    safe_emit,
    startup_state,
    tool_versions,
    vulners_script,
):
    return {
        "begin_startup_state": begin_startup_state,
        "check_arp_scan": check_arp_scan,
        "check_nmap": check_nmap,
        "check_vulners": check_vulners,
        "complete_startup_state": complete_startup_state,
        "get_app_version": get_app_version,
        "get_default_interface_cached": get_default_interface_cached,
        "get_versions": get_versions,
        "load_auto_scan_config": load_auto_scan_config,
        "load_current_assignment": load_current_assignment,
        "logger": logger,
        "network_key": network_key,
        "runtime_store": runtime_store,
        "run_traceroute": run_traceroute,
        "safe_emit": safe_emit,
        "startup_state": startup_state,
        "tool_versions": tool_versions,
        "auto_scan_config": auto_scan_config,
        "vulners_script": vulners_script,
    }


def build_auto_scan_handler_deps(
    *,
    auto_scan_config,
    save_auto_scan_config,
    validate_auto_scan_config_update,
    logger,
):
    return {
        "auto_scan_config": auto_scan_config,
        "save_auto_scan_config": save_auto_scan_config,
        "validate_auto_scan_config_update": validate_auto_scan_config_update,
        "logger": logger,
    }


def build_scan_routes_deps(
    *,
    scans_dir,
    resolve_scan_path,
    load_json_document,
    normalize_scan_metadata_document,
    logger,
    runtime_store,
    customer_fingerprinter,
):
    return {
        "scans_dir": scans_dir,
        "resolve_scan_path": resolve_scan_path,
        "load_json_document": load_json_document,
        "normalize_scan_metadata_document": normalize_scan_metadata_document,
        "logger": logger,
        "runtime_store": runtime_store,
        "customer_fingerprinter": customer_fingerprinter,
    }


def build_history_handler_deps(
    *,
    get_most_recent_scan_xml,
    customer_fingerprinter,
    scans_dir,
    sanitize_customer_dir_name,
    parse_scan_xml_for_assets,
    get_versions,
    emit_job_status,
    job_registry,
    emit_to_client,
    rate_limiter,
    broadcaster,
    release_client_state,
    logger,
    runtime_store,
):
    return {
        "get_most_recent_scan_xml": get_most_recent_scan_xml,
        "customer_fingerprinter": customer_fingerprinter,
        "scans_dir": scans_dir,
        "sanitize_customer_dir_name": sanitize_customer_dir_name,
        "parse_scan_xml_for_assets": parse_scan_xml_for_assets,
        "get_versions": get_versions,
        "emit_job_status": emit_job_status,
        "job_registry": job_registry,
        "emit_to_client": emit_to_client,
        "rate_limiter": rate_limiter,
        "broadcaster": broadcaster,
        "release_client_state": release_client_state,
        "logger": logger,
        "runtime_store": runtime_store,
    }


def build_update_handler_deps(*, check_for_updates, idle_state_manager, logger):
    return {
        "check_for_updates": check_for_updates,
        "idle_state_manager": idle_state_manager,
        "logger": logger,
    }


def build_connection_handler_deps(
    *,
    broadcaster,
    emit_to_client,
    get_client_state,
    job_registry,
    logger,
    runtime_store,
    set_current_customer_state,
    set_last_scan_target_state,
    set_network_key_state,
    auto_scan_config,
    socket_auth_token=None,
):
    return {
        "broadcaster": broadcaster,
        "emit_to_client": emit_to_client,
        "get_client_state": get_client_state,
        "job_registry": job_registry,
        "logger": logger,
        "runtime_store": runtime_store,
        "set_current_customer_state": set_current_customer_state,
        "set_last_scan_target_state": set_last_scan_target_state,
        "set_network_key_state": set_network_key_state,
        "auto_scan_config": auto_scan_config,
        "socket_auth_token": socket_auth_token or "",
    }


def build_core_routes_deps(
    *,
    build_liveness_payload,
    build_readiness_payload,
    get_app_version,
    get_default_interface_cached,
    get_versions,
    job_registry,
    load_json_document,
    normalize_scan_metadata_document,
    resolve_scan_path,
    runtime_store,
    scans_dir,
    settings_state,
    startup_state,
    get_auto_scan_thread,
    upload_report_artifacts_to_google_drive,
    customer_fingerprinter,
    socket_auth_token=None,
):
    return {
        "build_liveness_payload": build_liveness_payload,
        "build_readiness_payload": build_readiness_payload,
        "get_app_version": get_app_version,
        "get_default_interface_cached": get_default_interface_cached,
        "get_versions": get_versions,
        "job_registry": job_registry,
        "load_json_document": load_json_document,
        "normalize_scan_metadata_document": normalize_scan_metadata_document,
        "resolve_scan_path": resolve_scan_path,
        "runtime_store": runtime_store,
        "scans_dir": scans_dir,
        "settings_state": settings_state,
        "startup_state": startup_state,
        "get_auto_scan_thread": get_auto_scan_thread,
        "upload_report_artifacts_to_google_drive": upload_report_artifacts_to_google_drive,
        "customer_fingerprinter": customer_fingerprinter,
        "socket_auth_token": socket_auth_token or "",
    }


def build_settings_routes_deps(
    *,
    settings_state,
    save_settings,
    get_customer_name,
    validate_google_drive,
    validate_remote_sync,
    get_google_drive_auth_status,
    build_google_drive_auth_url,
    exchange_google_drive_auth_code,
    ensure_google_drive_reports_folder,
    save_google_drive_credentials,
    disconnect_google_drive,
    upload_latest_report_to_google_drive=None,
):
    return {
        "settings_state": settings_state,
        "save_settings": save_settings,
        "get_customer_name": get_customer_name,
        "validate_google_drive": validate_google_drive,
        "validate_remote_sync": validate_remote_sync,
        "get_google_drive_auth_status": get_google_drive_auth_status,
        "build_google_drive_auth_url": build_google_drive_auth_url,
        "exchange_google_drive_auth_code": exchange_google_drive_auth_code,
        "ensure_google_drive_reports_folder": ensure_google_drive_reports_folder,
        "save_google_drive_credentials": save_google_drive_credentials,
        "disconnect_google_drive": disconnect_google_drive,
        "upload_latest_report_to_google_drive": upload_latest_report_to_google_drive,
    }


def build_customer_handler_deps(
    *,
    get_customer_fingerprinter,
    network_key,
    get_current_customer,
    set_current_customer,
    merge_customer_metadata,
    save_current_assignment,
    save_customers_config,
    normalize_scan_metadata_document,
    load_json_document,
    save_json_document,
    logger,
):
    return {
        "get_customer_fingerprinter": get_customer_fingerprinter,
        "network_key": network_key,
        "get_current_customer": get_current_customer,
        "set_current_customer": set_current_customer,
        "merge_customer_metadata": merge_customer_metadata,
        "save_current_assignment": save_current_assignment,
        "save_customers_config": save_customers_config,
        "normalize_scan_metadata_document": normalize_scan_metadata_document,
        "load_json_document": load_json_document,
        "save_json_document": save_json_document,
        "logger": logger,
    }


def build_runtime_info_handler_deps(
    *,
    calculate_cidr,
    get_client_state,
    get_default_interface_cached,
    get_report_counts,
    logger,
    netifaces,
    requests,
    run_traceroute,
):
    return {
        "calculate_cidr": calculate_cidr,
        "get_client_state": get_client_state,
        "get_default_interface_cached": get_default_interface_cached,
        "get_report_counts": get_report_counts,
        "logger": logger,
        "netifaces": netifaces,
        "requests": requests,
        "run_traceroute": run_traceroute,
    }


def build_scan_job_handler_deps(
    *,
    validate_target,
    rate_limiter,
    job_registry,
    emit_job_status,
    set_last_scan_target_state,
    start_scan_task,
    generate_report_task,
    generate_pdf_from_saved_task,
    broadcaster,
):
    return {
        "validate_target": validate_target,
        "rate_limiter": rate_limiter,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
        "set_last_scan_target_state": set_last_scan_target_state,
        "start_scan_task": start_scan_task,
        "generate_report_task": generate_report_task,
        "generate_pdf_from_saved_task": generate_pdf_from_saved_task,
        "broadcaster": broadcaster,
    }


def register_shared_handlers(
    *,
    app,
    socketio,
    auto_scan_handler_deps,
    scan_routes_deps,
    history_handler_deps,
    update_handler_deps,
    connection_handler_deps,
    core_routes_deps,
    customer_handler_deps,
    runtime_info_handler_deps,
    scan_job_handler_deps,
    settings_routes_deps,
):
    register_auto_scan_handlers(app, socketio, auto_scan_handler_deps)
    register_scan_routes(app, scan_routes_deps)
    register_history_handlers(socketio, history_handler_deps)
    register_update_handlers(socketio, update_handler_deps)
    register_connection_handlers(socketio, connection_handler_deps)
    register_core_routes(app, core_routes_deps)
    register_customer_handlers(socketio, customer_handler_deps)
    register_runtime_info_handlers(socketio, runtime_info_handler_deps)
    register_scan_job_handlers(socketio, scan_job_handler_deps)
    register_settings_routes(app, settings_routes_deps)
