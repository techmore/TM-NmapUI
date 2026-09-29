from datetime import datetime
import re
import shutil

from flask import jsonify, make_response, request, send_file
from nmapui.auth import require_auth
from nmapui.reporting import (
    _resolve_artifact_file_path,
    build_artifact_downloads,
    report_content_security_policy,
    refresh_persisted_diff_summaries,
)
from nmapui.runtime_history import build_compare_result, build_history_rows
from persistence import remove_scan_metadata_index_entry


def _load_runtime_artifact_payload(runtime_store, path):
    if runtime_store is None or not hasattr(runtime_store, "get_report_artifact"):
        return None
    artifact = runtime_store.get_report_artifact(path)
    if artifact is None:
        return None
    return dict(artifact.get("payload", {}) or {})


def _resolve_runtime_artifact_path(*, runtime_store, scans_dir, scan_path, stored_path, default_name):
    if runtime_store is None:
        return scans_dir / scan_path / default_name
    return _resolve_artifact_file_path(
        scans_dir=scans_dir,
        scan_path=scan_path,
        stored_path=stored_path,
        default_name=default_name,
    )


def delete_scan_artifacts(
    *,
    path,
    scans_dir,
    resolve_scan_path,
    load_json_document,
    normalize_scan_metadata_document,
    logger,
    runtime_store,
):
    scan_dir = resolve_scan_path(path)
    if scan_dir is None or not scan_dir.exists():
        return {"success": False, "error": "Invalid path"}, 400

    try:
        metadata_path = scan_dir / "metadata.json"
        metadata = normalize_scan_metadata_document(
            load_json_document(metadata_path, {})
        ) if metadata_path.exists() else {}
        if runtime_store is not None and hasattr(runtime_store, "delete_report_artifact"):
            runtime_store.delete_report_artifact(path)
        shutil.rmtree(scan_dir)
        remove_scan_metadata_index_entry(scans_dir, scan_dir)
        refresh_persisted_diff_summaries(
            scans_dir,
            customer_id=metadata.get("customer_id"),
            target=metadata.get("target"),
            logger=logger,
            full_rebuild=True,
        )
        return {"success": True}, 200
    except Exception as exc:
        return {"success": False, "error": str(exc)}, 500


def _mark_legacy_scan_route(response):
    response = make_response(response)
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "runtime-api-preferred"
    response.headers["Link"] = '</api/runtime/history>; rel="successor-version"'
    return response


def register_scan_routes(app, deps):
    scans_dir = deps["scans_dir"]
    resolve_scan_path = deps["resolve_scan_path"]
    load_json_document = deps["load_json_document"]
    normalize_scan_metadata_document = deps["normalize_scan_metadata_document"]
    logger = deps["logger"]
    runtime_store = deps.get("runtime_store")
    customer_fingerprinter = deps.get("customer_fingerprinter")

    @app.route("/api/scans")
    @require_auth
    def list_scans():
        scans = build_history_rows(
            runtime_store=runtime_store,
            scans_dir=scans_dir,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
            logger=logger,
            customer_fingerprinter=customer_fingerprinter,
        )
        return _mark_legacy_scan_route(jsonify({"scans": scans}))

    @app.route("/api/scans/<path:path>/html")
    @require_auth
    def get_scan_html(path):
        scan_dir = resolve_scan_path(path)
        if scan_dir is None:
            return "Invalid path", 400

        artifact = runtime_store.get_report_artifact(path) if runtime_store is not None and hasattr(runtime_store, "get_report_artifact") else None
        html_path = _resolve_runtime_artifact_path(
            runtime_store=runtime_store,
            scans_dir=scans_dir,
            scan_path=path,
            stored_path=artifact.get("html_path") if artifact else None,
            default_name="scan_web.html",
        )
        if not html_path.exists():
            html_path = scan_dir / "scan.html"
        if not html_path.exists():
            return _mark_legacy_scan_route(("Report not found", 404))
        response = _mark_legacy_scan_route(send_file(html_path))
        response.headers["Content-Security-Policy"] = report_content_security_policy()
        return response

    @app.route("/api/scans/<path:path>/pdf")
    @require_auth
    def get_scan_pdf(path):
        scan_dir = resolve_scan_path(path)
        if scan_dir is None:
            return _mark_legacy_scan_route(("Invalid path", 400))

        artifact = runtime_store.get_report_artifact(path) if runtime_store is not None and hasattr(runtime_store, "get_report_artifact") else None
        pdf_path = _resolve_runtime_artifact_path(
            runtime_store=runtime_store,
            scans_dir=scans_dir,
            scan_path=path,
            stored_path=artifact.get("pdf_path") if artifact else None,
            default_name="scan_report.pdf",
        )
        if not pdf_path.exists():
            return _mark_legacy_scan_route(("PDF not found", 404))

        download_name = "Nmap_Audit_Report.pdf"
        artifact_payload = dict(artifact.get("payload", {}) or {}) if artifact else None
        if artifact_payload:
            download_name = build_artifact_downloads(
                artifact_payload,
                customer_fingerprinter=customer_fingerprinter,
            ).get("pdf", download_name)
        metadata_path = scan_dir / "metadata.json"
        if metadata_path.exists() and not artifact_payload:
            try:
                meta = normalize_scan_metadata_document(
                    load_json_document(metadata_path, {})
                )
                download_name = build_artifact_downloads(
                    meta,
                    customer_fingerprinter=customer_fingerprinter,
                ).get("pdf", download_name)
            except Exception as exc:
                logger.error("Error generating download name: %s", exc)

        return _mark_legacy_scan_route(
            send_file(pdf_path, as_attachment=True, download_name=download_name)
        )

    @app.route("/api/scans/<path:path>/xml")
    @require_auth
    def get_scan_xml(path):
        scan_dir = resolve_scan_path(path)
        if scan_dir is None:
            return _mark_legacy_scan_route(("Invalid path", 400))

        artifact = runtime_store.get_report_artifact(path) if runtime_store is not None and hasattr(runtime_store, "get_report_artifact") else None
        xml_path = _resolve_runtime_artifact_path(
            runtime_store=runtime_store,
            scans_dir=scans_dir,
            scan_path=path,
            stored_path=artifact.get("xml_path") if artifact else None,
            default_name="scan.xml",
        )
        if not xml_path.exists():
            return _mark_legacy_scan_route(("XML not found", 404))

        download_name = "Nmap_Raw_Data.xml"
        artifact_payload = dict(artifact.get("payload", {}) or {}) if artifact else None
        if artifact_payload:
            download_name = build_artifact_downloads(
                artifact_payload,
                customer_fingerprinter=customer_fingerprinter,
            ).get("xml", download_name)
        metadata_path = scan_dir / "metadata.json"
        if metadata_path.exists() and not artifact_payload:
            try:
                meta = normalize_scan_metadata_document(
                    load_json_document(metadata_path, {})
                )
                download_name = build_artifact_downloads(
                    meta,
                    customer_fingerprinter=customer_fingerprinter,
                ).get("xml", download_name)
            except Exception as exc:
                logger.error("Error generating download name: %s", exc)

        return _mark_legacy_scan_route(
            send_file(xml_path, as_attachment=True, download_name=download_name)
        )

    @app.route("/api/scans/<path:path>", methods=["DELETE"])
    @require_auth
    def delete_scan(path):
        payload, status_code = delete_scan_artifacts(
            path=path,
            scans_dir=scans_dir,
            resolve_scan_path=resolve_scan_path,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
            logger=logger,
            runtime_store=runtime_store,
        )
        return _mark_legacy_scan_route((jsonify(payload), status_code))

    @app.route("/api/scans/compare")
    @require_auth
    def compare_scans():
        base_path = str(request.args.get("base_path", "") or "").strip()
        current_path = str(request.args.get("current_path", "") or "").strip()
        if not base_path or not current_path:
            return _mark_legacy_scan_route(
                (jsonify({"success": False, "error": "Both base_path and current_path are required"}), 400)
            )

        payload, error, status_code = build_compare_result(
            runtime_store=runtime_store,
            resolve_scan_path=resolve_scan_path,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
            base_path=base_path,
            current_path=current_path,
        )
        if payload is None:
            return _mark_legacy_scan_route((jsonify({"success": False, "error": error}), status_code))
        return _mark_legacy_scan_route(jsonify({"success": True, **payload}))
