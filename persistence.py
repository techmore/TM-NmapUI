import json
from pathlib import Path
from typing import Any

import yaml

from nmapui.private_storage import atomic_replace_private_bytes

CURRENT_ASSIGNMENT_SCHEMA_VERSION = 1
SCAN_METADATA_SCHEMA_VERSION = 1
SCAN_METADATA_INDEX_SCHEMA_VERSION = 1
SCAN_HISTORY_SCHEMA_VERSION = 1
TRACEROUTE_HISTORY_SCHEMA_VERSION = 1
CUSTOMER_CONFIG_SCHEMA_VERSION = "1.0"
SCAN_METADATA_INDEX_FILENAME = ".scan_metadata_index.json"


def sanitize_customer_dir_name(customer_name: str) -> str:
    import re

    return re.sub(r"[^\w\-]", "_", customer_name or "Unknown")


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text()
    except FileNotFoundError:
        return None


def _atomic_write_text(path: Path, content: str) -> None:
    atomic_replace_private_bytes(path, content.encode("utf-8"))


def load_json_document(path: Path, default: Any) -> Any:
    raw = _read_text(path)
    if raw is None:
        return default
    return json.loads(raw)


def save_json_document(path: Path, payload: Any) -> None:
    _atomic_write_text(path, json.dumps(payload, indent=2))


def load_yaml_document(path: Path, default: Any) -> Any:
    raw = _read_text(path)
    if raw is None:
        return default
    return yaml.safe_load(raw) or default


def save_yaml_document(path: Path, payload: Any) -> None:
    _atomic_write_text(path, yaml.dump(payload, default_flow_style=False, indent=2))


def normalize_customer(customer: Any) -> dict[str, Any]:
    customer = customer if isinstance(customer, dict) else {}
    metadata = customer.get("metadata")
    networks = customer.get("networks")
    fingerprints = customer.get("fingerprints")
    return {
        "name": str(customer.get("name", "") or ""),
        "id": str(customer.get("id", "") or ""),
        "description": str(customer.get("description", "") or ""),
        "confidence": float(customer.get("confidence", 0.0) or 0.0),
        "networks": networks if isinstance(networks, dict) else {},
        "fingerprints": fingerprints if isinstance(fingerprints, list) else [],
        "metadata": metadata if isinstance(metadata, dict) else {},
    }


def normalize_customer_config_document(document: Any) -> dict[str, Any]:
    document = document if isinstance(document, dict) else {}
    customers = document.get("customers")
    settings = document.get("settings")
    indexing = document.get("indexing")
    return {
        "version": str(document.get("version", CUSTOMER_CONFIG_SCHEMA_VERSION)),
        "description": str(
            document.get(
                "description", "Customer network fingerprinting database"
            )
        ),
        "settings": settings if isinstance(settings, dict) else {},
        "customers": [normalize_customer(customer) for customer in customers or []],
        "unknown_customer": normalize_customer(document.get("unknown_customer", {})),
        "indexing": indexing if isinstance(indexing, dict) else {},
    }


def normalize_current_assignment_document(document: Any) -> dict[str, Any]:
    document = document if isinstance(document, dict) else {}
    customer = document.get("customer")
    return {
        "schema_version": CURRENT_ASSIGNMENT_SCHEMA_VERSION,
        "timestamp": str(document.get("timestamp", "") or ""),
        "customer": customer if isinstance(customer, dict) else {},
    }


def normalize_scan_metadata_document(document: Any) -> dict[str, Any]:
    document = document if isinstance(document, dict) else {}
    files = document.get("files")
    customer_info = document.get("customer_info")
    network_key = document.get("network_key")
    status = document.get("status")
    failure_stage = document.get("failure_stage")
    failure_error = document.get("failure_error")
    completed_successfully = document.get("completed_successfully")
    diff_summary = document.get("diff_summary")
    return {
        "schema_version": int(
            document.get("schema_version", SCAN_METADATA_SCHEMA_VERSION)
        ),
        "customer_name": str(document.get("customer_name", "") or ""),
        "customer_id": str(document.get("customer_id", "") or ""),
        "target": str(document.get("target", "") or ""),
        "timestamp": str(document.get("timestamp", "") or ""),
        "date": str(document.get("date", "") or ""),
        "time": str(document.get("time", "") or ""),
        "scan_start_time": document.get("scan_start_time"),
        "scan_end_time": document.get("scan_end_time"),
        "duration_seconds": document.get("duration_seconds"),
        "duration_formatted": document.get("duration_formatted"),
        "network_key": network_key if isinstance(network_key, dict) else {},
        "customer_info": customer_info if isinstance(customer_info, dict) else {},
        "files": files if isinstance(files, dict) else {},
        "status": str(status or ""),
        "failure_stage": str(failure_stage or ""),
        "failure_error": str(failure_error or ""),
        "completed_successfully": completed_successfully
        if isinstance(completed_successfully, bool)
        else None,
        "diff_summary": diff_summary if isinstance(diff_summary, dict) else None,
        "diff_summary_computed": bool(document.get("diff_summary_computed", False)),
    }


def get_scan_metadata_index_path(scans_dir: Path) -> Path:
    return scans_dir / SCAN_METADATA_INDEX_FILENAME


def build_scan_metadata_index_entry(
    *, scans_dir: Path, metadata_path: Path, metadata: dict[str, Any]
) -> dict[str, Any]:
    scan_dir = metadata_path.parent
    rel_path = scan_dir.relative_to(scans_dir)
    return {
        "path": str(rel_path),
        "metadata": metadata,
        "has_html": (scan_dir / "scan_web.html").exists() or (scan_dir / "scan.html").exists(),
        "has_pdf": (scan_dir / "scan_report.pdf").exists(),
        "has_xml": (scan_dir / "scan.xml").exists(),
    }


def normalize_scan_metadata_index_document(document: Any) -> dict[str, Any]:
    document = document if isinstance(document, dict) else {}
    entries = document.get("entries")
    normalized_entries = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        normalized_entries.append(
            {
                "path": str(entry.get("path", "") or ""),
                "metadata": normalize_scan_metadata_document(entry.get("metadata", {})),
                "has_html": bool(entry.get("has_html", False)),
                "has_pdf": bool(entry.get("has_pdf", False)),
                "has_xml": bool(entry.get("has_xml", False)),
            }
        )
    normalized_entries.sort(
        key=lambda item: item["metadata"].get("timestamp", ""),
        reverse=True,
    )
    return {
        "schema_version": int(
            document.get("schema_version", SCAN_METADATA_INDEX_SCHEMA_VERSION)
        ),
        "entries": normalized_entries,
    }


def build_scan_metadata_index(
    scans_dir: Path,
    load_json_document,
    normalize_scan_metadata_document,
    *,
    logger=None,
):
    entries = []
    if scans_dir.exists():
        for metadata_path in scans_dir.glob("**/metadata.json"):
            try:
                metadata = normalize_scan_metadata_document(
                    load_json_document(metadata_path, {})
                )
                entries.append(
                    build_scan_metadata_index_entry(
                        scans_dir=scans_dir,
                        metadata_path=metadata_path,
                        metadata=metadata,
                    )
                )
            except Exception as exc:
                if logger is not None:
                    logger.error("Error reading metadata at %s: %s", metadata_path, exc)
    return normalize_scan_metadata_index_document({"entries": entries})


def load_scan_metadata_index(
    scans_dir: Path,
    load_json_document,
    normalize_scan_metadata_index_document,
):
    return normalize_scan_metadata_index_document(
        load_json_document(get_scan_metadata_index_path(scans_dir), {})
    )


def save_scan_metadata_index(scans_dir: Path, index_document: dict[str, Any]) -> None:
    save_json_document(
        get_scan_metadata_index_path(scans_dir),
        normalize_scan_metadata_index_document(index_document),
    )


def rebuild_scan_metadata_index(
    scans_dir: Path,
    load_json_document,
    normalize_scan_metadata_document,
    *,
    logger=None,
):
    index_document = build_scan_metadata_index(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_document,
        logger=logger,
    )
    save_scan_metadata_index(scans_dir, index_document)
    return index_document


def upsert_scan_metadata_index_entry(
    scans_dir: Path,
    scan_dir: Path,
    metadata: dict[str, Any],
    *,
    load_json_document=load_json_document,
):
    rel_path = str(scan_dir.relative_to(scans_dir))
    index_document = load_scan_metadata_index(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_index_document,
    )
    entry = build_scan_metadata_index_entry(
        scans_dir=scans_dir,
        metadata_path=scan_dir / "metadata.json",
        metadata=normalize_scan_metadata_document(metadata),
    )
    entries = [
        existing
        for existing in index_document["entries"]
        if existing.get("path") != rel_path
    ]
    entries.append(entry)
    save_scan_metadata_index(scans_dir, {"entries": entries})


def remove_scan_metadata_index_entry(
    scans_dir: Path,
    scan_dir: Path,
    *,
    load_json_document=load_json_document,
):
    rel_path = str(scan_dir.relative_to(scans_dir))
    index_document = load_scan_metadata_index(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_index_document,
    )
    entries = [
        entry
        for entry in index_document["entries"]
        if entry.get("path") != rel_path
    ]
    save_scan_metadata_index(scans_dir, {"entries": entries})


def normalize_scan_history_document(document: Any) -> dict[str, Any]:
    if isinstance(document, list):
        entries = document
    elif isinstance(document, dict):
        entries = document.get("entries", [])
    else:
        entries = []

    normalized_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        normalized_entries.append(
            {
                "timestamp": str(entry.get("timestamp", "") or ""),
                "customer_id": str(entry.get("customer_id", "unknown") or "unknown"),
                "customer_name": str(entry.get("customer_name", "Unknown") or "Unknown"),
                "confidence_score": entry.get("confidence_score"),
                "exit_ip": entry.get("exit_ip"),
                "hop_count": int(entry.get("hop_count", 0) or 0),
                "private_hop_count": int(entry.get("private_hop_count", 0) or 0),
                "public_hop_count": int(entry.get("public_hop_count", 0) or 0),
                "network_signature": str(entry.get("network_signature", "") or ""),
                "raw_traceroute": str(entry.get("raw_traceroute", "") or ""),
                "network_key": entry.get("network_key", {})
                if isinstance(entry.get("network_key"), dict)
                else {},
            }
        )

    return {
        "schema_version": SCAN_HISTORY_SCHEMA_VERSION,
        "entries": normalized_entries,
    }


def iter_scan_metadata_documents(
    scans_dir: Path,
    load_json_document,
    normalize_scan_metadata_document,
    *,
    logger=None,
):
    if not scans_dir.exists():
        return

    index_path = get_scan_metadata_index_path(scans_dir)
    if not index_path.exists():
        rebuild_scan_metadata_index(
            scans_dir,
            load_json_document,
            normalize_scan_metadata_document,
            logger=logger,
        )

    try:
        index_document = load_scan_metadata_index(
            scans_dir,
            load_json_document,
            normalize_scan_metadata_index_document,
        )
        for entry in index_document["entries"]:
            rel_path = entry.get("path")
            if not rel_path:
                continue
            yield scans_dir / rel_path / "metadata.json", entry.get("metadata", {})
        return
    except Exception:
        if logger is not None:
            logger.warning("Falling back to filesystem metadata traversal")

    for metadata_path in scans_dir.glob("**/metadata.json"):
        try:
            yield metadata_path, normalize_scan_metadata_document(
                load_json_document(metadata_path, {})
            )
        except Exception as exc:
            if logger is not None:
                logger.error("Error reading metadata at %s: %s", metadata_path, exc)


def normalize_traceroute_history_document(document: Any) -> dict[str, Any]:
    if isinstance(document, dict) and "customers" in document:
        customers = document.get("customers", {})
    elif isinstance(document, dict):
        customers = document
    else:
        customers = {}

    normalized_customers: dict[str, Any] = {}
    for customer_id, payload in customers.items():
        payload = payload if isinstance(payload, dict) else {}
        traceroutes = payload.get("traceroutes")
        normalized_traceroutes = []
        for traceroute in traceroutes or []:
            if not isinstance(traceroute, dict):
                continue
            normalized_traceroutes.append(
                {
                    "timestamp": str(traceroute.get("timestamp", "") or ""),
                    "public_ip": traceroute.get("public_ip"),
                    "exit_ip": traceroute.get("exit_ip"),
                    "hop_count": int(traceroute.get("hop_count", 0) or 0),
                    "network_signature": str(
                        traceroute.get("network_signature", "") or ""
                    ),
                    "label": str(traceroute.get("label", "") or ""),
                    "raw_traceroute": str(traceroute.get("raw_traceroute", "") or ""),
                }
            )
        normalized_customers[str(customer_id or "unknown")] = {
            "name": str(payload.get("name", customer_id or "unknown")),
            "traceroutes": normalized_traceroutes,
        }

    return {
        "schema_version": TRACEROUTE_HISTORY_SCHEMA_VERSION,
        "customers": normalized_customers,
    }
