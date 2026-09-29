from datetime import datetime
import json
import os
from pathlib import Path

from flask import request
from flask_socketio import emit
from nmapui.auth import require_socket_auth


def _resolve_report_path(report_path: str):
    """Resolve a report path confined to SCANS_DIR, or None when outside.

    Accepts both a scans-relative path (what the UI sends) and an absolute path
    that already lives under the scans directory.
    """
    from nmapui.paths import SCANS_DIR, resolve_scan_path

    if not report_path:
        return None

    candidate = Path(str(report_path))
    if candidate.is_absolute():
        try:
            resolved = candidate.resolve()
            resolved.relative_to(SCANS_DIR.resolve())
        except (OSError, RuntimeError, ValueError):
            return None
        return resolved

    return resolve_scan_path(str(report_path))


def register_customer_handlers(socketio, deps):
    get_customer_fingerprinter = deps["get_customer_fingerprinter"]
    network_key = deps["network_key"]
    get_network_key = network_key if callable(network_key) else lambda sid=None: network_key
    get_current_customer = deps["get_current_customer"]
    set_current_customer = deps["set_current_customer"]
    merge_customer_metadata = deps["merge_customer_metadata"]
    save_current_assignment = deps["save_current_assignment"]
    save_customers_config = deps["save_customers_config"]
    normalize_scan_metadata_document = deps["normalize_scan_metadata_document"]
    load_json_document = deps["load_json_document"]
    save_json_document = deps["save_json_document"]
    logger = deps["logger"]

    @socketio.on("get_customer_info")
    @require_socket_auth()
    def get_customer_info_event():
        customer_fingerprinter = get_customer_fingerprinter()
        current_customer = get_current_customer()
        active_network_key = get_network_key(request.sid)
        if not current_customer.get("id") and not current_customer.get("manual_assignment"):
            customer, confidence = customer_fingerprinter.match_customer(active_network_key)
            if confidence > 0 and customer and customer.get("id") != "unknown":
                set_current_customer(
                    {
                        "id": customer.get("id"),
                        "name": customer.get("name"),
                        "confidence": confidence,
                        "metadata": customer.get("metadata", {}),
                    }
                )
                current_customer = get_current_customer()

        emit("customer_info", current_customer)

    @socketio.on("search_scan_history")
    @require_socket_auth()
    def search_scan_history_event(data):
        customer_fingerprinter = get_customer_fingerprinter()
        customer_id = data.get("customer_id")
        limit = data.get("limit", 50)
        try:
            history = customer_fingerprinter.get_scan_history(customer_id, limit)
            emit("scan_history_results", history)
        except Exception as exc:
            emit("scan_error", f"Search failed: {str(exc)}")

    @socketio.on("get_network_statistics")
    @require_socket_auth()
    def get_network_statistics_event():
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            history = customer_fingerprinter.get_scan_history(limit=1000)
            stats = {
                "total_scans": len(history),
                "unique_customers": len(set(h.get("customer_id", "unknown") for h in history)),
                "most_common_customer": None,
                "average_confidence": 0.0,
                "recent_scans": history[:10],
            }

            if history:
                customer_counts = {}
                for entry in history:
                    cust_id = entry.get("customer_id", "unknown")
                    customer_counts[cust_id] = customer_counts.get(cust_id, 0) + 1

                if customer_counts:
                    most_common_id = max(customer_counts.keys(), key=lambda key: customer_counts[key])
                    most_common_scan = next((h for h in history if h.get("customer_id") == most_common_id), None)
                    if most_common_scan:
                        stats["most_common_customer"] = {
                            "id": most_common_id,
                            "name": most_common_scan.get("customer_name", "Unknown"),
                            "count": customer_counts[most_common_id],
                        }

                confidences = [
                    h.get("confidence_score", 0)
                    for h in history
                    if h.get("confidence_score") is not None
                ]
                if confidences:
                    stats["average_confidence"] = sum(confidences) / len(confidences)

            emit("network_statistics", stats)
        except Exception as exc:
            emit("scan_error", f"Statistics failed: {str(exc)}")

    @socketio.on("add_customer")
    @require_socket_auth()
    def add_customer_event(data):
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            customer_data = {
                "name": data.get("name", "").strip(),
                "id": data.get("id", "").strip(),
                "description": data.get("description", "").strip(),
                "confidence": float(data.get("confidence", 0.7)),
                "networks": {
                    "public_ip": data.get("public_ip", "").strip() or "dynamic",
                    "private_ranges": [r.strip() for r in data.get("private_ranges", "").split(",") if r.strip()],
                    "exit_ips": [e.strip() for e in data.get("exit_ips", "").split(",") if e.strip()] or "dynamic",
                    "gateway_pattern": data.get("gateway_pattern", "").strip(),
                },
                "fingerprints": [
                    {
                        "type": data.get("connection_type", "direct").strip(),
                        "description": f"{data.get('connection_type', 'direct')} connection",
                        "hop_count": data.get("hop_count", "2-10").strip(),
                        "private_hop_pattern": [
                            {
                                "ip_pattern": data.get("gateway_pattern", "192.168.1.1").strip(),
                                "is_private": True,
                                "position": 1,
                            }
                        ],
                        "public_exit_pattern": [
                            {
                                "ip_pattern": data.get("exit_pattern", "*.*.*.*").strip(),
                                "is_private": False,
                                "position": 2,
                            }
                        ],
                        "latency_profile": {
                            "first_hop": data.get("first_hop_latency", "<5ms").strip(),
                            "exit_hop": data.get("exit_hop_latency", "5-100ms").strip(),
                            "total_time": data.get("total_latency", "<200ms").strip(),
                        },
                    }
                ],
                "metadata": {
                    "location": data.get("location", "Unknown").strip(),
                    "connection_type": [data.get("connection_type", "direct").strip()],
                    "isp": data.get("isp", "Unknown").strip(),
                    "network_size": data.get("network_size", "medium").strip(),
                    "last_updated": datetime.now().strftime("%Y-%m-%d"),
                },
            }

            if not customer_data["name"] or not customer_data["id"]:
                emit("customer_error", "Name and ID are required fields")
                return

            existing_ids = [c.get("id") for c in customer_fingerprinter.customers]
            if customer_data["id"] in existing_ids:
                emit("customer_error", f"Customer ID '{customer_data['id']}' already exists")
                return

            customer_fingerprinter.customers.append(customer_data)
            save_customers_config()
            emit(
                "customer_added",
                {
                    "success": True,
                    "customer": customer_data,
                    "message": f"Customer '{customer_data['name']}' added successfully",
                },
            )
        except ValueError as exc:
            emit("customer_error", f"Invalid data format: {str(exc)}")
        except Exception as exc:
            emit("customer_error", f"Failed to add customer: {str(exc)}")

    @socketio.on("update_customer")
    @require_socket_auth()
    def update_customer_event(data):
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            customer_id = data.get("customer_id", "").strip() or data.get("id", "").strip()
            if not customer_id:
                emit("customer_error", "Customer ID is required")
                return

            existing_customer = customer_fingerprinter.get_customer_by_id(customer_id)
            if not existing_customer:
                emit("customer_error", f"Customer '{customer_id}' not found")
                return

            existing_customer["name"] = data.get("name", existing_customer.get("name", "")).strip()
            existing_customer["id"] = data.get("id", existing_customer.get("id", "")).strip()
            existing_customer["description"] = data.get("description", existing_customer.get("description", "")).strip()
            existing_customer["confidence"] = float(data.get("confidence", existing_customer.get("confidence", 0.7)))

            networks = existing_customer.setdefault("networks", {})
            networks["public_ip"] = data.get("public_ip", networks.get("public_ip", "dynamic")).strip() or "dynamic"
            public_ip_value = data.get("public_ip", "").strip()
            if public_ip_value:
                public_ips = networks.setdefault("public_ips", [])
                if public_ip_value not in public_ips:
                    public_ips.append(public_ip_value)
            networks["private_ranges"] = [
                r.strip() for r in data.get("private_ranges", "").split(",") if r.strip()
            ]
            networks["exit_ips"] = [
                e.strip() for e in data.get("exit_ips", "").split(",") if e.strip()
            ] or "dynamic"
            networks["gateway_pattern"] = data.get("gateway_pattern", networks.get("gateway_pattern", "")).strip()

            metadata = existing_customer.setdefault("metadata", {})
            metadata["location"] = data.get("location", metadata.get("location", "Unknown")).strip()
            metadata["connection_type"] = [data.get("connection_type", "direct").strip()]
            metadata["isp"] = data.get("isp", metadata.get("isp", "Unknown")).strip()
            metadata["network_size"] = data.get("network_size", metadata.get("network_size", "medium")).strip()
            metadata["last_updated"] = datetime.now().strftime("%Y-%m-%d")

            fingerprints = existing_customer.setdefault("fingerprints", [{}])
            if not fingerprints:
                fingerprints.append({})
            fingerprints[0].update(
                {
                    "type": data.get("connection_type", fingerprints[0].get("type", "direct")).strip(),
                    "description": f"{data.get('connection_type', fingerprints[0].get('type', 'direct')).strip()} connection",
                    "hop_count": data.get("hop_count", fingerprints[0].get("hop_count", "2-10")).strip(),
                    "private_hop_pattern": [
                        {
                            "ip_pattern": data.get("gateway_pattern", networks.get("gateway_pattern", "192.168.1.1")).strip(),
                            "is_private": True,
                            "position": 1,
                        }
                    ],
                    "public_exit_pattern": [
                        {
                            "ip_pattern": data.get("exit_pattern", "*.*.*.*").strip(),
                            "is_private": False,
                            "position": 2,
                        }
                    ],
                    "latency_profile": {
                        "first_hop": data.get("first_hop_latency", "<5ms").strip(),
                        "exit_hop": data.get("exit_hop_latency", "5-100ms").strip(),
                        "total_time": data.get("total_latency", "<200ms").strip(),
                    },
                }
            )

            save_customers_config()
            emit(
                "customer_updated",
                {
                    "success": True,
                    "customer": existing_customer,
                    "message": f"Updated customer '{existing_customer['name']}'",
                },
            )
        except ValueError as exc:
            emit("customer_error", f"Invalid data format: {str(exc)}")
        except Exception as exc:
            emit("customer_error", f"Failed to update customer: {str(exc)}")

    @socketio.on("assign_customer")
    @require_socket_auth()
    def assign_customer_event(data):
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            customer_id = data.get("customer_id", "").strip()
            customer_name = data.get("customer_name", "").strip()
            if not customer_id:
                emit("customer_error", "Customer ID is required")
                return

            customer = None
            for existing in customer_fingerprinter.customers:
                if existing.get("id") == customer_id:
                    customer = existing
                    break

            if not customer:
                customer = {
                    "id": customer_id,
                    "name": customer_name or customer_id,
                    "description": "Manually assigned customer",
                    "confidence": 1.0,
                }

            set_current_customer(
                {
                    "id": customer.get("id", customer_id),
                    "name": customer.get("name", customer_name),
                    "confidence": 1.0,
                    "manual_assignment": True,
                }
            )
            save_current_assignment()
            emit(
                "customer_assigned",
                {
                    "success": True,
                    "customer": get_current_customer(),
                    "message": f"Assigned to '{get_current_customer()['name']}'",
                },
            )
        except Exception as exc:
            emit("customer_error", f"Failed to assign customer: {str(exc)}")

    @socketio.on("get_customers")
    @require_socket_auth()
    def get_customers_event():
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            customers = customer_fingerprinter.customers + [customer_fingerprinter.unknown_customer]
            logger.info("Sending %s customers to client", len(customers))
            emit("customers_list", customers)
        except Exception as exc:
            logger.error("Failed to get customers: %s", exc)
            emit("customer_error", f"Failed to get customers: {str(exc)}")

    @socketio.on("delete_customer")
    @require_socket_auth()
    def delete_customer_event(data):
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            customer_id = data.get("customer_id", "").strip()
            if not customer_id:
                emit("customer_error", "Customer ID is required")
                return

            original_length = len(customer_fingerprinter.customers)
            customer_fingerprinter.customers = [
                c for c in customer_fingerprinter.customers if c.get("id") != customer_id
            ]
            if len(customer_fingerprinter.customers) == original_length:
                emit("customer_error", f"Customer '{customer_id}' not found")
                return

            save_customers_config()
            emit(
                "customer_deleted",
                {
                    "success": True,
                    "customer_id": customer_id,
                    "message": f"Customer '{customer_id}' deleted successfully",
                },
            )
            logger.info("Customer '%s' deleted", customer_id)
        except Exception as exc:
            logger.error("Failed to delete customer: %s", exc)
            emit("customer_error", f"Failed to delete customer: {str(exc)}")

    @socketio.on("assign_report_to_customer")
    @require_socket_auth()
    def assign_report_to_customer_event(data):
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            report_path = data.get("report_path", "").strip()
            customer_id = data.get("customer_id", "").strip()
            label = data.get("label", "").strip()

            if not report_path:
                emit("customer_error", "Report path is required")
                return
            if not customer_id:
                emit("customer_error", "Customer ID is required")
                return

            # Confine the client-supplied path to the scans directory. This
            # handler writes metadata.json, so an unvalidated path let a caller
            # overwrite any metadata.json on the filesystem.
            resolved_report_path = _resolve_report_path(report_path)
            if resolved_report_path is None:
                logger.warning(
                    "Rejected report assignment outside the scans directory: %s",
                    report_path,
                )
                emit("customer_error", "Report path is outside the scans directory")
                return
            report_path = str(resolved_report_path)

            if not os.path.exists(report_path):
                emit("customer_error", f"Report not found at {report_path}")
                return

            customer = None
            for existing in customer_fingerprinter.customers:
                if existing.get("id") == customer_id:
                    customer = existing
                    break
            if not customer:
                emit("customer_error", f"Customer '{customer_id}' not found")
                return

            metadata_path = os.path.join(report_path, "metadata.json")
            if not os.path.exists(metadata_path):
                emit("customer_error", "Report metadata not found")
                return

            metadata = normalize_scan_metadata_document(
                load_json_document(Path(metadata_path), {})
            )
            metadata["customer_id"] = customer_id
            metadata["customer_name"] = customer.get("name")
            metadata["assigned_at"] = datetime.now().isoformat()
            if label:
                metadata["assignment_label"] = label
            save_json_document(Path(metadata_path), metadata)

            logger.info(
                "Report %s assigned to customer '%s' (%s)",
                report_path,
                customer.get("name"),
                customer_id,
            )
            emit(
                "report_assigned",
                {
                    "success": True,
                    "report_path": report_path,
                    "customer_id": customer_id,
                    "customer_name": customer.get("name"),
                    "message": f"Report assigned to '{customer.get('name')}'",
                },
            )
            emit("file_updated", {"file": metadata_path, "action": "updated"})
        except json.JSONDecodeError as exc:
            logger.error("Error reading report metadata: %s", exc)
            emit("customer_error", f"Error reading report metadata: {str(exc)}")
        except Exception as exc:
            logger.error("Failed to assign report to customer: %s", exc)
            emit("customer_error", f"Failed to assign report: {str(exc)}")

    @socketio.on("get_customer_traceroutes")
    @require_socket_auth()
    def get_customer_traceroutes_event(data):
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            customer_id = data.get("customer_id", "").strip()
            if not customer_id:
                emit("customer_error", "Customer ID is required")
                return

            if customer_id not in customer_fingerprinter.customer_traceroutes:
                emit("customer_traceroutes", {"customer_id": customer_id, "traceroutes": []})
                return

            traceroutes = customer_fingerprinter.customer_traceroutes[customer_id].get(
                "traceroutes", []
            )
            emit("customer_traceroutes", {"customer_id": customer_id, "traceroutes": traceroutes})
        except Exception as exc:
            logger.error("Failed to get customer traceroutes: %s", exc)
            emit("customer_error", f"Failed to get traceroutes: {str(exc)}")

    @socketio.on("add_labeled_public_ip")
    @require_socket_auth()
    def add_labeled_public_ip_event(data):
        try:
            customer_fingerprinter = get_customer_fingerprinter()
            customer_id = data.get("customer_id", "").strip()
            label = data.get("label", "").strip()
            ip_address = data.get("ip_address", "").strip()

            if not customer_id or not label or not ip_address:
                emit("customer_error", "Customer ID, label, and IP address are required")
                return

            customer = None
            for existing in customer_fingerprinter.customers:
                if existing.get("id") == customer_id:
                    customer = existing
                    break
            if not customer:
                emit("customer_error", f"Customer '{customer_id}' not found")
                return

            if "networks" not in customer:
                customer["networks"] = {}
            if "labeled_public_ips" not in customer["networks"]:
                customer["networks"]["labeled_public_ips"] = {}

            customer["networks"]["labeled_public_ips"][label] = {
                "address": ip_address,
                "added_at": datetime.now().isoformat(),
            }
            save_customers_config()
            logger.info(
                "Added labeled IP '%s' (%s) to customer '%s'",
                label,
                ip_address,
                customer.get("name"),
            )
            emit(
                "labeled_ip_added",
                {
                    "success": True,
                    "customer_id": customer_id,
                    "label": label,
                    "ip_address": ip_address,
                    "message": f"Labeled IP '{label}' added to '{customer.get('name')}'",
                },
            )
            emit("file_updated", {"file": str(customer_fingerprinter.config_path), "action": "updated"})
        except Exception as exc:
            logger.error("Failed to add labeled public IP: %s", exc)
            emit("customer_error", f"Failed to add labeled IP: {str(exc)}")
