import platform
import re
import subprocess

from nmapui.runtime import env_flag
from nmapui.runtime_log import append_runtime_log


def run_traceroute(target="1.1.1.1", *, sid=None, deps):
    emit_to_client = deps["emit_to_client"]
    safe_emit = deps["safe_emit"]
    get_client_state = deps["get_client_state"]
    socketio_sleep = deps["socketio_sleep"]
    logger = deps["logger"]
    is_private_ip = deps["is_private_ip"]
    requests = deps["requests"]
    set_network_key_state = deps["set_network_key_state"]
    get_customer_fingerprinter = deps["get_customer_fingerprinter"]
    merge_customer_metadata = deps["merge_customer_metadata"]
    set_current_customer_state = deps["set_current_customer_state"]
    get_current_customer_state = deps["get_current_customer_state"]
    runtime_store = deps.get("runtime_store")

    def emit_customer_event(event, data=None):
        if sid:
            emit_to_client(sid, event, data)
        else:
            safe_emit(event, data)

    state = get_client_state(sid=sid)
    active_network_key = dict(state["network_key"])
    active_customer = dict(state["current_customer"])

    if not env_flag("NMAPUI_ENABLE_NETWORK_FINGERPRINT", default=True):
        active_network_key.update(
            {
                "target": target,
                "hops": [],
                "private_hops": [],
                "public_hops": [],
                "total_hops": 0,
                "exit_ip": None,
                "public_ip": None,
                "error": "Network fingerprinting disabled by configuration",
            }
        )
        set_network_key_state(value=active_network_key, sid=sid)
        emit_customer_event(
            "customer_identification_progress",
            {"message": "Network fingerprinting is disabled by configuration."},
        )
        emit_customer_event("network_key", active_network_key)
        return active_network_key

    try:
        emit_customer_event("customer_identification_start")
        socketio_sleep(0)

        logger.info("Running traceroute to %s...", target)
        emit_customer_event(
            "customer_identification_progress",
            {"message": f"Running traceroute to {target}..."},
        )
        socketio_sleep(0)

        system = platform.system()
        if system == "Darwin":
            traceroute_cmd = ["traceroute", "-I", "-n", "-q", "1", target]
        else:
            traceroute_cmd = ["traceroute", "-n", "-I", "-q", "1", target]

        logger.info("Running traceroute: %s", " ".join(traceroute_cmd))
        output = subprocess.check_output(
            traceroute_cmd, stderr=subprocess.STDOUT, timeout=60
        ).decode("utf-8")

        active_network_key["raw"] = output
        active_network_key["target"] = target
        active_network_key["hops"] = []
        active_network_key["private_hops"] = []
        active_network_key["public_hops"] = []
        active_network_key.pop("error", None)

        hop_pattern = re.compile(r"^\s*(\d+)\s+(\S+)\s+(.+)$", re.MULTILINE)

        for match in hop_pattern.finditer(output):
            hop_num = int(match.group(1))
            ip_or_star = match.group(2)
            latencies = match.group(3)

            if ip_or_star == "*" or "traceroute" in ip_or_star.lower():
                continue

            latency_matches = re.findall(r"([\d.]+)\s*ms", latencies)
            avg_latency = None
            if latency_matches:
                avg_latency = round(
                    sum(float(lat) for lat in latency_matches) / len(latency_matches), 2
                )

            hop_data = {
                "hop": hop_num,
                "ip": ip_or_star,
                "latency_ms": avg_latency,
                "is_private": is_private_ip(ip_or_star),
            }

            active_network_key["hops"].append(hop_data)
            if hop_data["is_private"]:
                active_network_key["private_hops"].append(hop_data)
            else:
                active_network_key["public_hops"].append(hop_data)

        active_network_key["total_hops"] = len(active_network_key["hops"])
        if active_network_key["hops"]:
            active_network_key["exit_ip"] = active_network_key["hops"][-1]["ip"]

        if env_flag("NMAPUI_ENABLE_NETWORK_FINGERPRINT", default=True):
            try:
                active_network_key["public_ip"] = requests.get(
                    "https://api.ipify.org", timeout=5
                ).text
                logger.info("Detected public IP: %s", active_network_key["public_ip"])
            except Exception as exc:
                logger.warning("Could not detect public IP: %s", exc)
                active_network_key["public_ip"] = None
        else:
            active_network_key["public_ip"] = None

        set_network_key_state(value=active_network_key, sid=sid)

        logger.info(
            "Traceroute complete: %s hops, %s private, %s public",
            active_network_key["total_hops"],
            len(active_network_key["private_hops"]),
            len(active_network_key["public_hops"]),
        )
        emit_customer_event(
            "customer_identification_progress",
            {"message": f"Traceroute complete ({active_network_key['total_hops']} hops)"},
        )
        socketio_sleep(0)

        logger.info("Running customer identification...")
        emit_customer_event(
            "customer_identification_progress", {"message": "Identifying customer..."}
        )
        socketio_sleep(0)

        if not active_customer.get("manual_assignment"):
            fingerprinter = get_customer_fingerprinter()
            customer, confidence = fingerprinter.match_customer(active_network_key)
            if confidence > 0 and customer and customer.get("id") != "unknown":
                active_customer = {
                    "id": customer.get("id"),
                    "name": customer.get("name"),
                    "confidence": confidence,
                }
                active_customer = merge_customer_metadata(active_customer, customer)
                logger.info("Auto-detected customer: %s", active_customer["name"])
                save_customer = customer
            else:
                generated_customer = fingerprinter.ensure_generated_customer(
                    active_network_key
                )
                active_customer = {
                    "id": generated_customer.get("id"),
                    "name": generated_customer.get("name"),
                    "confidence": generated_customer.get("confidence", 0.35),
                }
                active_customer = merge_customer_metadata(
                    active_customer, generated_customer
                )
                logger.info(
                    "No customer match found, auto-created generated customer: %s",
                    active_customer["name"],
                )
                save_customer = generated_customer
                confidence = generated_customer.get("confidence", 0.35)
        else:
            logger.info("Preserving manual assignment: %s", active_customer["name"])
            if active_customer.get("id"):
                saved_customer = get_customer_fingerprinter().get_customer_by_id(
                    active_customer["id"]
                )
                if saved_customer:
                    active_customer = merge_customer_metadata(
                        active_customer, saved_customer
                    )
            save_customer = {
                "id": active_customer["id"],
                "name": active_customer["name"],
            }
            confidence = active_customer.get("confidence", 1.0)

        set_current_customer_state(value=active_customer, sid=sid)
        fingerprinter = get_customer_fingerprinter()
        fingerprinter.save_scan_result(active_network_key, save_customer, confidence)
        fingerprinter.save_traceroute_to_history(
            active_customer["id"],
            active_network_key,
            f"WAN: {active_network_key.get('public_ip', 'unknown')}",
        )

        emit_customer_event(
            "customer_identified",
            {
                "customer": get_current_customer_state(sid=sid),
                "match_method": getattr(
                    fingerprinter, "last_match_method", "unknown"
                ),
                "public_ip": active_network_key.get("public_ip"),
                "exit_ip": active_network_key.get("exit_ip"),
                "hop_count": active_network_key["total_hops"],
            },
        )

        emit_customer_event(
            "file_updated", {"file": "data/runtime.sqlite3", "action": "saved"}
        )
        emit_customer_event(
            "file_updated",
            {"file": "data/customer_traceroutes.json", "action": "saved"},
        )

        logger.info(
            "Customer identified: %s (confidence: %.2f)",
            active_customer["name"],
            confidence,
        )
        append_runtime_log(
            runtime_store=runtime_store,
            category="topology",
            level="INFO",
            message="Traceroute completed and customer identified",
            payload={
                "sid": sid,
                "target": target,
                "total_hops": active_network_key["total_hops"],
                "public_ip": active_network_key.get("public_ip"),
                "customer_id": active_customer.get("id"),
                "customer_name": active_customer.get("name"),
            },
        )

    except subprocess.TimeoutExpired:
        logger.error("Traceroute timed out")
        active_network_key["error"] = "Traceroute timed out"
        set_network_key_state(value=active_network_key, sid=sid)
        append_runtime_log(
            runtime_store=runtime_store,
            category="topology",
            level="ERROR",
            message="Traceroute timed out",
            payload={"sid": sid, "target": target},
        )
        emit_customer_event(
            "customer_identification_error", {"error": "Traceroute timed out"}
        )
    except Exception as exc:
        logger.error("Traceroute error: %s", exc)
        active_network_key["error"] = str(exc)
        set_network_key_state(value=active_network_key, sid=sid)
        append_runtime_log(
            runtime_store=runtime_store,
            category="topology",
            level="ERROR",
            message="Traceroute failed",
            payload={"sid": sid, "target": target, "error": str(exc)},
        )
        emit_customer_event("customer_identification_error", {"error": str(exc)})

    return active_network_key
