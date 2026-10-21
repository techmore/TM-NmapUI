from nmapui.app_client_state_runtime import (
    get_client_state as get_client_state_runtime,
    get_current_customer_state as get_current_customer_state_runtime,
    release_client_state as release_client_state_runtime,
    set_current_customer_state as set_current_customer_state_runtime,
    set_last_scan_target_state as set_last_scan_target_state_runtime,
    set_network_key_state as set_network_key_state_runtime,
)
from nmapui.app_events_runtime import (
    emit_job_status as emit_job_status_runtime,
    emit_to_client as emit_to_client_runtime,
    ensure_job_not_cancelled as ensure_job_not_cancelled_runtime,
    run_cancellable_command as run_cancellable_command_runtime,
    update_job_progress as update_job_progress_runtime,
)
from nmapui.runtime_log import append_runtime_log
from nmapui.scan_runtime import make_broadcast_emit


def _log_runtime_event(runtime_store, event, data=None):
    if runtime_store is None:
        return

    if event == "scan_feedback":
        message = data if isinstance(data, str) else (data or {}).get("message", str(data))
        append_runtime_log(
            runtime_store=runtime_store,
            category="scan",
            level="INFO",
            message=message,
            payload=data if isinstance(data, dict) else {"message": message},
        )
    elif event == "report_complete":
        append_runtime_log(
            runtime_store=runtime_store,
            category="report",
            level="INFO",
            message="Report generation completed",
            payload=data or {},
        )
    elif event == "report_error":
        append_runtime_log(
            runtime_store=runtime_store,
            category="report",
            level="ERROR",
            message=(data or {}).get("error", "Report generation failed"),
            payload=data or {},
        )
    elif event == "update_status":
        append_runtime_log(
            runtime_store=runtime_store,
            category="update",
            level="INFO",
            message=(data or {}).get("message", str(data)),
            payload=data or {},
        )
    elif event == "update_error":
        append_runtime_log(
            runtime_store=runtime_store,
            category="update",
            level="ERROR",
            message=(data or {}).get("message", str(data)),
            payload=data or {},
        )


def build_event_helpers(*, socketio, job_registry, broadcaster=None, runtime_store=None):
    def emit_to_client(sid, event, data=None):
        result = emit_to_client_runtime(socketio=socketio, sid=sid, event=event, data=data)
        _log_runtime_event(runtime_store, event, data)
        return result

    def emit_job_status(sid, job_type):
        targets = {sid}
        if broadcaster is not None and hasattr(broadcaster, "get_subscribers"):
            targets |= set(broadcaster.get_subscribers(sid, job_type=job_type))

        payload = job_registry.get(sid, job_type) or {"status": "idle", "details": {}}
        payload["job_type"] = job_type
        result = None
        if broadcaster is not None and payload.get("source_job_id"):
            # The registry owns this run UUID; establish a slot for alternate
            # workflow entry points only when one has not already been started.
            if broadcaster.get_source_job_id(sid, job_type=job_type) != payload["source_job_id"]:
                broadcaster.start_job(sid, job_type=job_type, source_job_id=payload["source_job_id"])
            make_broadcast_emit(owner_sid=sid, broadcaster=broadcaster, emit_to_client=emit_to_client,
                                job_type=job_type, runtime_store=runtime_store)(sid, "job_status", payload)
            targets = set()
        for target_sid in targets:
            result = emit_to_client_runtime(
                socketio=socketio,
                sid=target_sid,
                event="job_status",
                data=payload,
            )
        append_runtime_log(
            runtime_store=runtime_store,
            category="job",
            level="INFO",
            message=f"[{job_type}] {payload.get('status', 'idle')}",
            payload={
                "job_type": job_type,
                "status": payload.get("status", "idle"),
                "details": dict(payload.get("details", {})),
            },
        )
        return result

    def update_job_progress(
        sid,
        job_type,
        phase,
        message=None,
        progress=None,
        details=None,
    ):
        # Progress must use the same durable, grouped source-envelope path as
        # start/completion status. Raw browser events are not bridge evidence.
        payload = {"phase": phase}
        if message is not None:
            payload["message"] = message
        if progress is not None:
            payload["progress"] = progress
        if details:
            payload.update(details)
        job_registry.update(sid, job_type, details=payload)
        return emit_job_status(sid, job_type)

    def ensure_job_not_cancelled(sid, job_type):
        return ensure_job_not_cancelled_runtime(
            job_registry=job_registry,
            sid=sid,
            job_type=job_type,
            # A pause that takes effect at this checkpoint is published to every
            # open tab so they stop showing the scan as actively running.
            on_pause=lambda: emit_job_status(sid, job_type),
        )

    def run_cancellable_command(cmd, sid=None, job_type=None, timeout=None):
        return run_cancellable_command_runtime(
            job_registry=job_registry,
            cmd=cmd,
            sid=sid,
            job_type=job_type,
            timeout=timeout,
        )

    return {
        "emit_to_client": emit_to_client,
        "emit_job_status": emit_job_status,
        "update_job_progress": update_job_progress,
        "ensure_job_not_cancelled": ensure_job_not_cancelled,
        "run_cancellable_command": run_cancellable_command,
    }


def build_client_state_helpers(
    *,
    client_state_registry,
    get_current_customer,
    get_network_key,
    get_last_scan_target,
    set_default_customer,
    set_default_network_key,
    set_default_last_scan_target,
    runtime_store=None,
):
    def persist_snapshot(key, payload):
        if runtime_store is None:
            return
        runtime_store.upsert_runtime_snapshot(key, payload)

    def get_client_state(*, sid=None):
        return get_client_state_runtime(
            sid=sid,
            client_state_registry=client_state_registry,
            current_customer=get_current_customer(),
            network_key=get_network_key(),
            last_scan_target=get_last_scan_target(),
        )

    def get_current_customer_state(sid=None):
        return get_current_customer_state_runtime(
            sid=sid,
            get_client_state=get_client_state,
        )

    def set_current_customer_state(value, sid=None):
        result = set_current_customer_state_runtime(
            value=value,
            sid=sid,
            client_state_registry=client_state_registry,
            set_default_customer=set_default_customer,
            sync_default_state=(
                (lambda customer: (set_default_customer(customer), client_state_registry.set_default_customer(customer)))
                if sid is not None
                else None
            ),
        )
        persist_snapshot("current_customer", result)
        return result

    def set_network_key_state(value, sid=None):
        result = set_network_key_state_runtime(
            value=value,
            sid=sid,
            client_state_registry=client_state_registry,
            set_default_network_key=set_default_network_key,
            sync_default_state=(
                (lambda key: (set_default_network_key(key), client_state_registry.set_default_network_key(key)))
                if sid is not None
                else None
            ),
        )
        persist_snapshot("network_key", result)
        return result

    def set_last_scan_target_state(value, sid=None):
        result = set_last_scan_target_state_runtime(
            value=value,
            sid=sid,
            client_state_registry=client_state_registry,
            set_default_last_scan_target=set_default_last_scan_target,
            sync_default_state=(
                (lambda target: (set_default_last_scan_target(target), client_state_registry.set_default_last_scan_target(target)))
                if sid is not None
                else None
            ),
        )
        persist_snapshot("last_scan_target", {"value": result})
        return result

    def release_client_state(sid):
        return release_client_state_runtime(
            sid=sid,
            client_state_registry=client_state_registry,
        )

    return {
        "get_client_state": get_client_state,
        "get_current_customer_state": get_current_customer_state,
        "set_current_customer_state": set_current_customer_state,
        "set_network_key_state": set_network_key_state,
        "set_last_scan_target_state": set_last_scan_target_state,
        "release_client_state": release_client_state,
    }
