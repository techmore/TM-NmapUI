"""Typed command receipts for authenticated Daedalus bridge sessions.

No command payload is executable. Receipts have separate durable job records,
so browser scan events and reconnect replay cannot claim another command's result.
"""
from __future__ import annotations

import re
import threading
import uuid
from datetime import datetime, timezone

_LOCK = threading.RLock()
NAMESPACE = re.compile(r"[a-f0-9]{24}\Z")


def command_id_from_payload(data, *, sid, broadcaster):
    if not broadcaster or not hasattr(broadcaster, "is_bridge_client") or not broadcaster.is_bridge_client(sid):
        return None
    if not isinstance(data, dict) or "daedalus_command_id" not in data:
        return None
    namespace = broadcaster.get_bridge_namespace(sid) if hasattr(broadcaster, "get_bridge_namespace") else None
    if not isinstance(namespace, str) or not NAMESPACE.fullmatch(namespace) or data.get("daedalus_command_namespace") != namespace:
        raise ValueError("Invalid Daedalus command namespace")
    command_id = data["daedalus_command_id"]
    if not isinstance(command_id, int) or isinstance(command_id, bool) or not 0 < command_id < 2**63:
        raise ValueError("Invalid Daedalus command identifier")
    return command_id


def _job_id(command_id, command_namespace):
    return f"daedalus-command:{command_namespace}:{command_id}"


def emit_command_result(*, command_id, owner_sid, status, result, broadcaster, emit_to_client, runtime_store=None, action=None, command_namespace=None):
    if command_id is None:
        return
    namespace = command_namespace or (broadcaster.get_bridge_namespace(owner_sid) if broadcaster and hasattr(broadcaster, "get_bridge_namespace") else None)
    if not isinstance(namespace, str) or not NAMESPACE.fullmatch(namespace):
        return
    with _LOCK:
        saved = runtime_store.get_job(_job_id(command_id, namespace)) if runtime_store is not None else None
        if saved and saved.get("status") in {"completed", "failed"}:
            return
        payload = {"command_id": command_id, "command_namespace": namespace, "status": status, "result": str(result)[:1000]}
        envelope = {"client_event_id": str(uuid.uuid4()), "occurred_at": datetime.now(timezone.utc).isoformat(), "event_name": "daedalus_command_result", "payload": payload}
        if runtime_store is not None:
            local_status = {"accepted": "running", "succeeded": "completed", "failed": "failed"}[status]
            command = {"command_id": command_id, "command_namespace": namespace, "action": action or (saved or {}).get("payload", {}).get("action")}
            runtime_store.record_daedalus_command_receipt(job_id=_job_id(command_id, namespace), owner_sid=owner_sid, status=local_status, command=command, source_event=envelope)
        recipients = broadcaster.get_bridge_clients(namespace) if broadcaster is not None and hasattr(broadcaster, "get_bridge_clients") else {owner_sid}
        for sid in recipients:
            emit_to_client(sid, "daedalus_event", envelope)


def begin_command(*, command_id, owner_sid, action, broadcaster, emit_to_client, runtime_store=None):
    if command_id is None:
        return True
    namespace = broadcaster.get_bridge_namespace(owner_sid)
    with _LOCK:
        saved = runtime_store.get_job(_job_id(command_id, namespace)) if runtime_store is not None else None
        if saved:
            for event in runtime_store.list_job_events(job_id=_job_id(command_id, namespace)):
                envelope = event.get("source_event")
                if envelope:
                    emit_to_client(owner_sid, "daedalus_event", envelope)
            return False
        emit_command_result(command_id=command_id, owner_sid=owner_sid, action=action, status="accepted", result="Command received by the local NmapUI service.", broadcaster=broadcaster, emit_to_client=emit_to_client, runtime_store=runtime_store)
        return True


def report_scan_completion(*, sid, job, broadcaster, emit_to_client, runtime_store=None):
    details = job.get("details") or {}
    status = job.get("status")
    if status not in {"completed", "failed", "cancelled", "interrupted"}:
        return
    completed_message = "Scan workflow completed."
    host_count = details.get("host_count")
    if isinstance(host_count, int) and not isinstance(host_count, bool) and host_count >= 0:
        completed_message = f"Scan workflow completed with {host_count} discovered or explicitly selected hosts."
    emit_command_result(command_id=details.get("daedalus_command_id"), owner_sid=sid, status="succeeded" if status == "completed" else "failed", result=completed_message if status == "completed" else "Scan workflow was cancelled or failed.", broadcaster=broadcaster, emit_to_client=emit_to_client, runtime_store=runtime_store, command_namespace=details.get("daedalus_command_namespace"))
    for cancel_command in details.get("daedalus_cancel_commands", []):
        command_id = cancel_command["command_id"]
        emit_command_result(command_id=command_id, owner_sid=sid, status="succeeded" if status in {"cancelled", "completed"} else "failed", result="The selected scan is no longer running." if status in {"cancelled", "completed"} else "The selected scan failed while cancellation was pending.", broadcaster=broadcaster, emit_to_client=emit_to_client, runtime_store=runtime_store, command_namespace=cancel_command["command_namespace"])
