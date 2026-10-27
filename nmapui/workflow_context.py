from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any


def _require_keys(deps, keys):
    missing = [key for key in keys if key not in deps]
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise TypeError(f"Missing workflow dependencies: {missing_list}")


@dataclass(slots=True)
class ScanWorkflowContext:
    get_client_state: Any
    ensure_job_not_cancelled: Any
    idle_state_manager: Any
    update_job_progress: Any
    emit_to_client: Any
    socketio_sleep: Any
    run_cancellable_command: Any
    run_arp_scan: Any
    identify_gateway_firewall_targets: Any
    start_deep_scan: Any
    job_registry: Any
    emit_job_status: Any
    logger: Any
    vulners_script: Path
    cve_pattern: Any
    port_info_regex: Any
    ip_regex: Any
    hostname_regex: Any
    host_status_regex: Any
    open_port_regex: Any
    nmap_done_regex: Any
    ip_sort_key: Any
    settings_state: Any = None
    on_job_end: Any = None


@dataclass(slots=True)
class ReportWorkflowContext:
    job_registry: Any
    idle_state_manager: Any
    emit_job_status: Any
    emit_to_client: Any
    update_job_progress: Any
    validate_target: Any
    split_subnet_into_chunks: Any
    create_scan_folder: Any
    scans_dir: Path
    sanitize_customer_dir_name: Any
    run_nmap_with_xml_output: Any
    merge_nmap_xml_files: Any
    socketio_sleep: Any
    convert_xml_to_html: Any
    convert_html_to_pdf: Any
    stylesheet: Any
    get_app_version: Any
    save_scan_metadata: Any
    get_client_state: Any
    network_key: Any
    current_customer: Any
    extract_scan_statistics: Any
    customer_fingerprinter: Any
    runtime_store: Any = None
    settings_state: Any = None
    upload_report_artifacts_to_google_drive: Any = None
    web_stylesheet: Any = None
    pdf_stylesheet: Any = None
    on_job_end: Any = None


def build_scan_workflow_context(deps):
    _require_keys(
        deps,
        [
            "get_client_state",
            "ensure_job_not_cancelled",
            "idle_state_manager",
            "update_job_progress",
            "emit_to_client",
            "socketio_sleep",
            "run_cancellable_command",
            "run_arp_scan",
            "identify_gateway_firewall_targets",
            "start_deep_scan",
            "job_registry",
            "emit_job_status",
            "logger",
            "vulners_script",
            "ip_sort_key",
        ],
    )
    return ScanWorkflowContext(
        get_client_state=deps["get_client_state"],
        ensure_job_not_cancelled=deps["ensure_job_not_cancelled"],
        idle_state_manager=deps["idle_state_manager"],
        update_job_progress=deps["update_job_progress"],
        emit_to_client=deps["emit_to_client"],
        socketio_sleep=deps["socketio_sleep"],
        run_cancellable_command=deps["run_cancellable_command"],
        run_arp_scan=deps["run_arp_scan"],
        identify_gateway_firewall_targets=deps["identify_gateway_firewall_targets"],
        start_deep_scan=deps["start_deep_scan"],
        job_registry=deps["job_registry"],
        emit_job_status=deps["emit_job_status"],
        logger=deps["logger"],
        vulners_script=deps["vulners_script"],
        cve_pattern=re.compile(
            r"CVE-\d{4}-\d+\s+(\d+\.\d+)\s+(https://vulners\.com/cve/CVE-\d{4}-\d+)"
        ),
        port_info_regex=re.compile(r"(\d+)/(?:tcp|udp)\s+([\w|]+)\s+(.*)"),
        ip_regex=re.compile(r"Nmap scan report for .*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        hostname_regex=re.compile(
            r"Nmap scan report for ([^ ]+) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)"
        ),
        host_status_regex=re.compile(r"Host is (up|down) \(([\d.]+s latency\))"),
        open_port_regex=re.compile(r"(\d+)/(?:tcp|udp)\s+([\w|]+)\s+(\w+)"),
        nmap_done_regex=re.compile(
            r"Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds"
        ),
        ip_sort_key=deps["ip_sort_key"],
        settings_state=deps.get("settings_state"),
        on_job_end=deps.get("on_job_end"),
    )


def build_report_workflow_context(deps):
    _require_keys(
        deps,
        [
            "job_registry",
            "idle_state_manager",
            "emit_job_status",
            "emit_to_client",
            "update_job_progress",
            "validate_target",
            "split_subnet_into_chunks",
            "create_scan_folder",
            "scans_dir",
            "sanitize_customer_dir_name",
            "run_nmap_with_xml_output",
            "merge_nmap_xml_files",
            "socketio_sleep",
            "convert_xml_to_html",
            "convert_html_to_pdf",
            "stylesheet",
            "get_app_version",
            "save_scan_metadata",
            "get_client_state",
            "network_key",
            "current_customer",
            "extract_scan_statistics",
            "customer_fingerprinter",
        ],
    )
    return ReportWorkflowContext(
        job_registry=deps["job_registry"],
        idle_state_manager=deps["idle_state_manager"],
        emit_job_status=deps["emit_job_status"],
        emit_to_client=deps["emit_to_client"],
        update_job_progress=deps["update_job_progress"],
        validate_target=deps["validate_target"],
        split_subnet_into_chunks=deps["split_subnet_into_chunks"],
        create_scan_folder=deps["create_scan_folder"],
        scans_dir=deps["scans_dir"],
        sanitize_customer_dir_name=deps["sanitize_customer_dir_name"],
        run_nmap_with_xml_output=deps["run_nmap_with_xml_output"],
        merge_nmap_xml_files=deps["merge_nmap_xml_files"],
        socketio_sleep=deps["socketio_sleep"],
        convert_xml_to_html=deps["convert_xml_to_html"],
        convert_html_to_pdf=deps["convert_html_to_pdf"],
        stylesheet=deps["stylesheet"],
        get_app_version=deps["get_app_version"],
        save_scan_metadata=deps["save_scan_metadata"],
        get_client_state=deps["get_client_state"],
        network_key=deps["network_key"],
        current_customer=deps["current_customer"],
        extract_scan_statistics=deps["extract_scan_statistics"],
        customer_fingerprinter=deps["customer_fingerprinter"],
        runtime_store=deps.get("runtime_store"),
        settings_state=deps.get("settings_state"),
        upload_report_artifacts_to_google_drive=deps.get("upload_report_artifacts_to_google_drive"),
        web_stylesheet=deps.get("web_stylesheet"),
        pdf_stylesheet=deps.get("pdf_stylesheet"),
        on_job_end=deps.get("on_job_end"),
    )
