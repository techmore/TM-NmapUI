from nmapui.reporting import (
    build_artifact_downloads,
    find_previous_scan_metadata,
    parse_scan_xml_for_assets,
    resolve_report_customer_identity,
    summarize_asset_differences,
)
from persistence import iter_scan_metadata_documents


def normalize_runtime_report_row(artifact, *, customer_fingerprinter=None):
    payload = dict(artifact.get("payload", {}) or {})
    resolved_identity = resolve_report_customer_identity(
        payload,
        customer_fingerprinter=customer_fingerprinter,
    )
    customer_name = resolved_identity["customer_name"]
    customer_id = resolved_identity["customer_id"]
    downloads = build_artifact_downloads(
        payload,
        customer_fingerprinter=customer_fingerprinter,
    )

    return {
        **payload,
        "customer_name": customer_name,
        "customer_id": customer_id,
        "downloads": downloads,
        "path": artifact["scan_path"],
        "has_html": bool(artifact.get("html_path")),
        "has_pdf": bool(artifact.get("pdf_path")),
        "has_xml": bool(artifact.get("xml_path")),
    }


def _backfill_runtime_artifact(runtime_store, scan_path, metadata, metadata_path):
    if runtime_store is None:
        return
    if not hasattr(runtime_store, "get_report_artifact") or not hasattr(
        runtime_store, "upsert_report_artifact"
    ):
        return
    if runtime_store.get_report_artifact(scan_path) is not None:
        return

    scan_dir = metadata_path.parent
    runtime_store.upsert_report_artifact(
        scan_path=scan_path,
        customer_id=str(metadata.get("customer_id", "") or ""),
        target=str(metadata.get("target", "") or ""),
        html_path="scan_web.html"
        if (scan_dir / "scan_web.html").exists()
        else ("scan.html" if (scan_dir / "scan.html").exists() else ""),
        pdf_path="scan_report.pdf" if (scan_dir / "scan_report.pdf").exists() else "",
        xml_path="scan.xml" if (scan_dir / "scan.xml").exists() else "",
        payload=dict(metadata),
    )


def backfill_runtime_history_artifacts(
    *,
    runtime_store,
    scans_dir,
    load_json_document,
    normalize_scan_metadata_document,
    logger,
):
    if (
        runtime_store is None
        or scans_dir is None
        or load_json_document is None
        or normalize_scan_metadata_document is None
    ):
        return 0

    backfilled = 0
    for metadata_path, data in iter_scan_metadata_documents(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_document,
        logger=logger,
    ):
        rel_path = str(metadata_path.parent.relative_to(scans_dir))
        if (
            hasattr(runtime_store, "get_report_artifact")
            and runtime_store.get_report_artifact(rel_path) is not None
        ):
            continue
        _backfill_runtime_artifact(runtime_store, rel_path, data, metadata_path)
        backfilled += 1

    return backfilled


def build_history_rows(
    *,
    runtime_store,
    scans_dir,
    load_json_document,
    normalize_scan_metadata_document,
    logger,
    customer_fingerprinter=None,
):
    history = []
    seen_paths = set()

    if runtime_store is not None:
        for artifact in runtime_store.list_report_artifacts():
            row = normalize_runtime_report_row(
                artifact,
                customer_fingerprinter=customer_fingerprinter,
            )
            history.append(row)
            seen_paths.add(row["path"])

    if (
        scans_dir is not None
        and load_json_document is not None
        and normalize_scan_metadata_document is not None
    ):
        for metadata_path, data in iter_scan_metadata_documents(
            scans_dir,
            load_json_document,
            normalize_scan_metadata_document,
            logger=logger,
        ):
            rel_path = str(metadata_path.parent.relative_to(scans_dir))
            if rel_path in seen_paths:
                continue
            if "customer_name" not in data:
                data["customer_name"] = data.get(
                    "customer", data.get("customer_id", "Unknown")
                )
            resolved_identity = resolve_report_customer_identity(
                data,
                customer_fingerprinter=customer_fingerprinter,
            )
            data["customer_name"] = resolved_identity["customer_name"]
            data["customer_id"] = resolved_identity["customer_id"]
            data["downloads"] = build_artifact_downloads(
                data,
                customer_fingerprinter=customer_fingerprinter,
            )
            data["path"] = rel_path
            data["has_html"] = (metadata_path.parent / "scan_web.html").exists() or (
                metadata_path.parent / "scan.html"
            ).exists()
            data["has_pdf"] = (metadata_path.parent / "scan_report.pdf").exists()
            data["has_xml"] = (metadata_path.parent / "scan.xml").exists()
            _backfill_runtime_artifact(runtime_store, rel_path, data, metadata_path)
            history.append(data)

    history.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    for scan in history:
        if scan.get("diff_summary") is not None or scan.get("diff_summary_computed"):
            continue

        previous = find_previous_scan_metadata(scan, history)
        if previous is None or scans_dir is None:
            continue

        current_xml = scans_dir / scan["path"] / "scan.xml"
        previous_xml = scans_dir / previous["path"] / "scan.xml"
        if not current_xml.exists() or not previous_xml.exists():
            continue

        try:
            diff_summary = summarize_asset_differences(
                parse_scan_xml_for_assets(current_xml),
                parse_scan_xml_for_assets(previous_xml),
            )
        except Exception as exc:
            if logger is not None:
                logger.error("Error building diff summary for %s: %s", scan["path"], exc)
            continue

        if diff_summary.get("has_changes"):
            scan["diff_summary"] = {
                **diff_summary,
                "baseline_path": previous["path"],
                "baseline_timestamp": previous.get("timestamp", ""),
            }

    return history


def load_runtime_compare_payload(
    *,
    runtime_store,
    resolve_scan_path,
    load_json_document,
    normalize_scan_metadata_document,
    scan_path,
):
    if runtime_store is not None and hasattr(runtime_store, "get_report_artifact"):
        artifact = runtime_store.get_report_artifact(scan_path)
        if artifact is not None:
            payload = dict(artifact.get("payload", {}) or {})
            payload["path"] = scan_path
            return payload

    if resolve_scan_path is None:
        return None

    scan_dir = resolve_scan_path(scan_path)
    if scan_dir is None:
        return None

    metadata_path = scan_dir / "metadata.json"
    if not metadata_path.exists():
        return None

    payload = normalize_scan_metadata_document(load_json_document(metadata_path, {}))
    payload["path"] = scan_path
    return payload


def build_compare_result(
    *,
    runtime_store,
    resolve_scan_path,
    load_json_document,
    normalize_scan_metadata_document,
    base_path,
    current_path,
):
    base_metadata = load_runtime_compare_payload(
        runtime_store=runtime_store,
        resolve_scan_path=resolve_scan_path,
        load_json_document=load_json_document,
        normalize_scan_metadata_document=normalize_scan_metadata_document,
        scan_path=base_path,
    )
    current_metadata = load_runtime_compare_payload(
        runtime_store=runtime_store,
        resolve_scan_path=resolve_scan_path,
        load_json_document=load_json_document,
        normalize_scan_metadata_document=normalize_scan_metadata_document,
        scan_path=current_path,
    )

    if base_metadata is None or current_metadata is None:
        return None, "Scan metadata not found", 404

    if str(base_metadata.get("customer_id", "") or "") != str(
        current_metadata.get("customer_id", "") or ""
    ):
        return None, "Scans must belong to the same customer", 400
    if str(base_metadata.get("target", "") or "") != str(
        current_metadata.get("target", "") or ""
    ):
        return None, "Scans must target the same network", 400

    base_assets = base_metadata.get("asset_snapshot")
    current_assets = current_metadata.get("asset_snapshot")

    if not isinstance(base_assets, list) or not isinstance(current_assets, list):
        if resolve_scan_path is None:
            return None, "Compare data unavailable", 404

        base_dir = resolve_scan_path(base_path)
        current_dir = resolve_scan_path(current_path)
        if base_dir is None or current_dir is None:
            return None, "Invalid scan path", 400

        base_xml = base_dir / "scan.xml"
        current_xml = current_dir / "scan.xml"
        if not base_xml.exists() or not current_xml.exists():
            return None, "Scan XML not found", 404

        base_assets = parse_scan_xml_for_assets(base_xml)
        current_assets = parse_scan_xml_for_assets(current_xml)

    diff_summary = summarize_asset_differences(current_assets, base_assets)
    return {
        "base_scan": {
            "path": base_path,
            "timestamp": base_metadata.get("timestamp"),
            "customer_name": base_metadata.get("customer_name"),
            "target": base_metadata.get("target"),
            "status": base_metadata.get("status"),
        },
        "current_scan": {
            "path": current_path,
            "timestamp": current_metadata.get("timestamp"),
            "customer_name": current_metadata.get("customer_name"),
            "target": current_metadata.get("target"),
            "status": current_metadata.get("status"),
        },
        "diff_summary": {
            **diff_summary,
            "baseline_path": base_path,
            "baseline_timestamp": base_metadata.get("timestamp", ""),
        },
    }, None, 200
