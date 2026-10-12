from flask import request
import uuid
from datetime import datetime, timedelta, timezone
from nmapui.auth import require_socket_auth, socket_authorized
from nmapui.daedalus_commands import emit_command_result, NAMESPACE
from nmapui.auto_scan import build_auto_scan_status_payload


def get_app_version_safe():
    import os as _os
    version_file = _os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))),
        "VERSION",
    )
    try:
        with open(version_file) as fh:
            return fh.read().strip() or "unknown"
    except OSError:
        return "unknown"


def _load_persisted_source_state(runtime_store):
    if runtime_store is None:
        return None

    current_customer = runtime_store.get_runtime_snapshot("current_customer")
    network_key = runtime_store.get_runtime_snapshot("network_key")
    last_scan_target = runtime_store.get_runtime_snapshot("last_scan_target")
    if isinstance(last_scan_target, dict):
        last_scan_target = last_scan_target.get("value")

    if current_customer is None and network_key is None and last_scan_target is None:
        return None

    return {
        "current_customer": current_customer
        or {"id": "unknown", "name": "Unknown Network", "confidence": 0.0},
        "network_key": network_key
        or {
            "target": "1.1.1.1",
            "total_hops": 0,
            "private_hops": [],
            "public_hops": [],
            "exit_ip": None,
        },
        "last_scan_target": last_scan_target,
    }


def _load_persisted_active_job(runtime_store):
    if runtime_store is None or not hasattr(runtime_store, "list_jobs"):
        return None
    jobs = runtime_store.list_jobs(statuses=("running", "cancelling"), limit=1)
    if not jobs:
        return None
    job = jobs[0]
    payload = dict(job.get("payload", {}))
    details = dict(payload.get("details", {}))
    return {
        "job_id": job["job_id"],
        "job_type": job["job_type"],
        "status": job["status"],
        "details": details,
        "cancel_requested": bool(payload.get("cancel_requested")),
        "started_at": payload.get("started_at") or job.get("created_at"),
        "finished_at": payload.get("finished_at"),
        "disconnected": bool(payload.get("disconnected")),
    }


def _load_persisted_job_events(runtime_store, job_id):
    if runtime_store is None or not hasattr(runtime_store, "list_job_events"):
        return []
    return runtime_store.list_job_events(job_id=job_id, limit=200)


def register_connection_handlers(socketio, deps):
    auto_scan_config = deps.get("auto_scan_config")
    broadcaster = deps["broadcaster"]
    emit_to_client = deps["emit_to_client"]
    get_client_state = deps["get_client_state"]
    job_registry = deps["job_registry"]
    logger = deps["logger"]
    runtime_store = deps.get("runtime_store")
    set_current_customer_state = deps["set_current_customer_state"]
    set_last_scan_target_state = deps["set_last_scan_target_state"]
    set_network_key_state = deps["set_network_key_state"]
    socket_auth_token = deps.get("socket_auth_token") or ""
    import os as _os
    auth_disabled = _os.environ.get("NMAPUI_SOCKET_AUTH_DISABLED", "").strip().lower() in {"1", "true", "yes"}

    @socketio.on("connect")
    def on_connect(auth=None):
        # Reject connections that did not present the loopback token (#210).
        # Test harnesses may disable the check explicitly via env flag.
        if socket_auth_token and not auth_disabled:
            if not (isinstance(auth, dict) and auth.get("token") == socket_auth_token):
                logger.warning(
                    "Rejected Socket.IO connection from %s without valid token.",
                    request.remote_addr or "unknown",
                )
                return False
        # The handshake token is CSRF protection, not a credential. Require a
        # real session (cookie or Basic) unless local trust is explicitly on,
        # otherwise any local process could fetch the token and read scan data.
        if not socket_authorized():
            logger.warning(
                "Rejected unauthenticated Socket.IO connection from %s.",
                request.remote_addr or "unknown",
            )
            return False
        new_sid = request.sid
        if hasattr(broadcaster, "register_client"):
            broadcaster.register_client(new_sid)
        bridge_client = bool(isinstance(auth, dict) and auth.get("daedalus_bridge") is True)
        if bridge_client and hasattr(broadcaster, "set_bridge_client"):
            command_namespace = auth.get("command_namespace")
            command_namespace = command_namespace if isinstance(command_namespace, str) and NAMESPACE.fullmatch(command_namespace) else None
            broadcaster.set_bridge_client(new_sid, command_namespace=command_namespace)
            emit_to_client(new_sid, "daedalus_protocol", {"version": 1, "command_results": command_namespace is not None, "source_job_metadata": True, "command_namespace": command_namespace})

        def replay_persisted_bridge_events():
            if not bridge_client or runtime_store is None or not hasattr(runtime_store, "list_jobs"):
                return
            # Recover terminal evidence that completed while the bridge was absent.
            for saved_job in reversed(runtime_store.list_jobs(limit=20)):
                if saved_job.get("job_type") == "command" and (saved_job.get("payload") or {}).get("command_namespace") != broadcaster.get_bridge_namespace(new_sid):
                    continue
                if saved_job.get("job_type") == "command" and saved_job.get("status") == "interrupted":
                    command_id = (saved_job.get("payload") or {}).get("command_id")
                    if isinstance(command_id, int) and not isinstance(command_id, bool):
                        emit_command_result(command_id=command_id, owner_sid=new_sid, status="failed", result="NmapUI restarted before this command completed.", broadcaster=broadcaster, emit_to_client=emit_to_client, runtime_store=runtime_store, command_namespace=(saved_job.get("payload") or {}).get("command_namespace"))
                if saved_job.get("status") not in {"running", "cancelling"}:
                    try:
                        updated = datetime.fromisoformat(str(saved_job["updated_at"]).replace("Z", "+00:00"))
                        updated = updated.replace(tzinfo=updated.tzinfo or timezone.utc)
                        if updated < datetime.now(timezone.utc) - timedelta(days=7):
                            continue
                    except (ValueError, KeyError):
                        continue
                for saved in _load_persisted_job_events(runtime_store, saved_job["job_id"]):
                    envelope = saved.get("source_event") or {
                        "client_event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"nmapui:{saved['job_id']}:{saved['id']}:{saved['created_at']}")),
                        "occurred_at": saved["created_at"],
                        "event_name": saved["event_name"], "payload": saved["payload"],
                    }
                    emit_to_client(new_sid, "daedalus_event", envelope)

        replay_persisted_bridge_events()
        active_job_type = None
        owner_sid = broadcaster.find_active_owner("scan")
        if owner_sid is not None:
            active_job_type = "scan"
        else:
            owner_sid = broadcaster.find_active_owner("report")
            if owner_sid is not None:
                active_job_type = "report"
        if owner_sid:
            source_state = get_client_state(sid=owner_sid)
        else:
            source_state = _load_persisted_source_state(runtime_store) or get_client_state()

        set_current_customer_state(value=source_state["current_customer"], sid=new_sid)
        set_network_key_state(value=source_state["network_key"], sid=new_sid)
        set_last_scan_target_state(
            value=source_state.get("last_scan_target"),
            sid=new_sid,
        )

        emit_to_client(new_sid, "customer_info", source_state["current_customer"])
        emit_to_client(new_sid, "network_key", source_state["network_key"])
        emit_to_client(
            new_sid,
            "client_state_snapshot",
            {"last_scan_target": source_state.get("last_scan_target")},
        )
        if auto_scan_config is not None:
            emit_to_client(new_sid, "auto_scan_status", build_auto_scan_status_payload(auto_scan_config))

        job = job_registry.get(owner_sid, active_job_type) if owner_sid else None
        is_scanning = bool(job and job.get("status") in ("running", "cancelling"))
        last_scan_target = source_state.get("last_scan_target") or ""
        network_key = source_state.get("network_key") or {}
        hops = network_key.get("hops", []) if isinstance(network_key, dict) else []
        auto_scan_payload = (
            build_auto_scan_status_payload(auto_scan_config) if auto_scan_config else {}
        )
        emit_to_client(new_sid, "sync_state", {
            "version": get_app_version_safe(),
            "hosts": [],
            "isScanning": is_scanning,
            "phase": (2 if active_job_type == "report" else 1) if is_scanning else None,
            "scanKind": "complete" if active_job_type == "report" else "quick",
            "target": last_scan_target,
            "autoScan": auto_scan_payload,
            "hops": hops,
        })
        emit_to_client(new_sid, "initial_data", {"autoScan": auto_scan_payload})

        if owner_sid is None:
            persisted_job = _load_persisted_active_job(runtime_store)
            if persisted_job is not None:
                persisted_job_id = persisted_job.pop("job_id", None)
                emit_to_client(new_sid, "job_status", persisted_job)
                if persisted_job_id and not bridge_client:
                    for event in _load_persisted_job_events(runtime_store, persisted_job_id):
                        emit_to_client(new_sid, event["event_name"], event["payload"])
            return

        job = job_registry.get(owner_sid, active_job_type)
        if not job or job.get("status") not in ("running", "cancelling"):
            broadcaster.end_job(owner_sid, job_type=active_job_type)
            return

        replay_buffer = broadcaster.get_replay_buffer(owner_sid, job_type=active_job_type)
        logger.info(
            "New tab %s joining active %s owned by %s — replaying %d events",
            new_sid,
            active_job_type,
            owner_sid,
            len(replay_buffer),
        )

        broadcaster.subscribe(owner_sid, new_sid, job_type=active_job_type)
        emit_to_client(new_sid, "job_status", {**job, "job_type": active_job_type})

        if bridge_client and hasattr(broadcaster, "get_bridge_replay_buffer"):
            for envelope in broadcaster.get_bridge_replay_buffer(owner_sid, job_type=active_job_type):
                emit_to_client(new_sid, "daedalus_event", envelope)
        else:
            for event, data in replay_buffer:
                emit_to_client(new_sid, event, data)

    @socketio.on("get_initial_data")
    @require_socket_auth()
    def on_get_initial_data():
        """Legacy protocol bridge (#230): re-send the sync snapshot when the frontend
        asks for it after wiring its listeners."""
        owner_sid = None
        active_job_type = None
        for job_type in ("scan", "report"):
            owner_sid = broadcaster.find_active_owner(job_type)
            if owner_sid is not None:
                active_job_type = job_type
                break

        source_state = (
            get_client_state(sid=owner_sid)
            if owner_sid
            else _load_persisted_source_state(runtime_store) or get_client_state()
        )

        job = job_registry.get(owner_sid, active_job_type) if owner_sid else None
        is_scanning = bool(job and job.get("status") in ("running", "cancelling"))
        last_scan_target = source_state.get("last_scan_target") or ""
        network_key = source_state.get("network_key") or {}
        hops = network_key.get("hops", []) if isinstance(network_key, dict) else []
        auto_scan_payload = (
            build_auto_scan_status_payload(auto_scan_config) if auto_scan_config else {}
        )

        emit_to_client(
            request.sid,
            "sync_state",
            {
                "version": get_app_version_safe(),
                "hosts": [],
                "isScanning": is_scanning,
                "phase": (2 if active_job_type == "report" else 1) if is_scanning else None,
                "scanKind": "complete" if active_job_type == "report" else "quick",
                "target": last_scan_target,
                "autoScan": auto_scan_payload,
                "hops": hops,
            },
        )
        emit_to_client(request.sid, "initial_data", {"autoScan": auto_scan_payload})

        # Replay buffered job events for late joiners.
        if owner_sid:
            for event, data in broadcaster.get_replay_buffer(owner_sid, job_type=active_job_type):
                emit_to_client(request.sid, event, data)
