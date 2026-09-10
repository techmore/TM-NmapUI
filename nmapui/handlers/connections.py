from flask import request
from nmapui.auth import require_socket_auth, socket_authorized
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

        # #237: ignore zombie jobs whose owner tab has disconnected.
        if owner_sid and owner_sid not in getattr(broadcaster, "_connected_sids", set()):
            _complete = getattr(job_registry, "complete", None)
            if callable(_complete):
                _complete(owner_sid, active_job_type or "scan", status="completed")
            broadcaster.end_job(owner_sid, job_type=active_job_type or "scan")
            job = None
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
            "phase": 1 if is_scanning else None,
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
                if persisted_job_id:
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
        # #237 follow-up: a job whose owner tab is gone is a zombie - it would
        # otherwise disable scan buttons for every future page load.
        if owner_sid and owner_sid not in getattr(broadcaster, "_connected_sids", set()):
            job = None
            _complete = getattr(job_registry, "complete", None)
            if callable(_complete):
                _complete(owner_sid, active_job_type or "scan", status="completed")
            broadcaster.end_job(owner_sid, job_type=active_job_type or "scan")
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
                "phase": 1 if is_scanning else None,
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
