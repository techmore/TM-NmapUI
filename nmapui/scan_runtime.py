import copy
import ipaddress

from nmapui.workflow_context import build_scan_workflow_context
from nmapui.workflows import (
    start_deep_scan as workflow_start_deep_scan,
    start_scan_task as workflow_start_scan_task,
)


def make_broadcast_emit(*, owner_sid, broadcaster, emit_to_client, job_type="scan", runtime_store=None):
    """Fan events out to all subscribed tabs while recording replay state."""

    source_job_id = broadcaster.get_source_job_id(owner_sid, job_type=job_type)

    def _emit(sid, event, data=None):
        nonlocal source_job_id
        if source_job_id is None:
            source_job_id = broadcaster.get_source_job_id(owner_sid, job_type=job_type)
        source_event = broadcaster.record(owner_sid, event, data, job_type=job_type, source_job_id=source_job_id)
        if runtime_store is not None:
            runtime_store.append_job_event(
                job_id=f"source-job:{source_event['source_job_id']}" if source_event.get("source_job_id") else f"{owner_sid}:{job_type}",
                owner_sid=owner_sid,
                job_type=job_type,
                event_name=event,
                payload=source_event["payload"],
                source_event=source_event,
            )
        for sub_sid in broadcaster.get_subscribers(owner_sid, job_type=job_type):
            if hasattr(broadcaster, "is_bridge_client") and broadcaster.is_bridge_client(sub_sid):
                emit_to_client(sub_sid, "daedalus_event", copy.deepcopy(source_event))
            else:
                emit_to_client(sub_sid, event, copy.deepcopy(source_event["payload"]))

    return _emit


def start_scan_task(
    *,
    sid,
    target,
    skip_host_discovery_override=None,
    broadcaster,
    emit_to_client,
    get_client_state,
    ensure_job_not_cancelled,
    idle_state_manager,
    update_job_progress,
    socketio_sleep,
    run_cancellable_command,
    run_arp_scan,
    identify_gateway_firewall_targets,
    job_registry,
    emit_job_status,
    logger,
    settings_state,
    vulners_script,
    runtime_store=None,
):
    wrapped_emit = make_broadcast_emit(
        owner_sid=sid,
        broadcaster=broadcaster,
        emit_to_client=emit_to_client,
        job_type="scan",
        runtime_store=runtime_store,
    )
    original_run_arp_scan = run_arp_scan

    context = build_scan_workflow_context(
        {
            "get_client_state": get_client_state,
            "ensure_job_not_cancelled": ensure_job_not_cancelled,
            "idle_state_manager": idle_state_manager,
            "update_job_progress": update_job_progress,
            "emit_to_client": wrapped_emit,
            "socketio_sleep": socketio_sleep,
            "run_cancellable_command": run_cancellable_command,
            "run_arp_scan": lambda target, interface=None, sid=None: original_run_arp_scan(
                target,
                interface=interface,
                sid=sid,
                emit_to_client_override=wrapped_emit,
            ),
            "identify_gateway_firewall_targets": identify_gateway_firewall_targets,
            "start_deep_scan": workflow_start_deep_scan,
            "job_registry": job_registry,
            "emit_job_status": emit_job_status,
            "logger": logger,
            "settings_state": settings_state,
            "vulners_script": vulners_script,
            "ip_sort_key": ipaddress.IPv4Address,
            "on_job_end": lambda: broadcaster.end_job(sid, job_type="scan"),
        }
    )
    try:
        return workflow_start_scan_task(context, sid, target, skip_host_discovery_override=skip_host_discovery_override)
    except Exception:
        # Initialization can fail before the workflow's own try/finally begins.
        # Resolve this job's receipt rather than leaving an accepted command open.
        job_registry.complete(sid, "scan", status="failed", details={"error": "Scan workflow initialization failed"})
        broadcaster.end_job(sid, job_type="scan")
        job_registry.clear_if_disconnected(sid, "scan")
        logger.exception("Scan workflow initialization failed")
        return None
