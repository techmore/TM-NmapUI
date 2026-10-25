"""Disposable strict-auth Flask wire fixture. No scanner, scheduler or user data."""
import hmac
import json
import os
import sys
import time
from flask import Flask, Response, jsonify, request
from werkzeug.serving import WSGIRequestHandler, make_server

app = Flask(__name__)
mode = os.environ.get("SHARED_FIXTURE_MODE", "valid")
scan_path = "Example customer/scan with spaces 雪"
pdf = b"%PDF-1.4\nfixture-report\n%%EOF\n"


@app.before_request
def strict_auth():
    if mode == "unavailable":
        return jsonify(error="Unavailable"), 503
    auth = request.authorization
    if not auth or not hmac.compare_digest((auth.username or "").encode(), b"fixture-user") or not hmac.compare_digest((auth.password or "").encode(), "fixture-contraseña-🔐".encode()):
        return jsonify(error="Unauthorized"), 401


def row():
    return dict(path=scan_path, timestamp="2026-10-25T12:00:00Z", target="127.0.0.1/32", customer_name="Example customer", status="completed", host_count=1, has_html=True, has_pdf=True, has_xml=True)


@app.get("/api/session/status")
def access():
    # Match the shared engine: valid Basic access need not create a browser session.
    return jsonify(authenticated=False, local_trust=False, auth_configured=True)


@app.get("/api/health/ready")
def health():
    return jsonify(ready=mode != "not-ready", status="ready" if mode != "not-ready" else "starting", app_version="v2026.10.25")


@app.get("/api/runtime/status")
def status():
    return jsonify(has_active_jobs=True, maintenance_active=False, active_jobs=[dict(job_type="scan", status="running", details=dict(target="127.0.0.1/32"))])


@app.get("/api/runtime/history")
def history():
    if mode == "bad-json":
        return Response("{broken", content_type="application/json")
    if mode == "oversized-json":
        return Response(b" " * (2 * 1024 * 1024 + 1), content_type="application/json")
    if mode == "streamed-json":
        return Response((b" " * 65536 for _ in range(33)), content_type="application/json")
    return jsonify(history=[row(), dict(path="runtime-job:public-id", job_id="public-id", record_type="scan_run", timestamp="2026-10-25T12:01:00Z", status="failed", target="127.0.0.2")])


@app.get("/api/runtime/reports")
def reports():
    if mode == "bad-schema":
        return jsonify(reports=None)
    result = row()
    if mode == "long":
        result["path"] = "A very long customer report folder " * 8 + "/" + "long scan name " * 8
        result["customer_name"] = "Long customer display name " * 7
        result["target"] = "Example recorded scan target " * 5
    return jsonify(reports=[result])


@app.get("/api/runtime/reports/<path:path>/<format>")
def artifact(path, format):
    if path != scan_path:
        return jsonify(error="Not found"), 404
    if mode == "redirect-report":
        return Response(status=302, headers={"Location": "/forbidden-redirect"})
    if format == "pdf":
        if mode == "large-pdf":
            return Response(b"%PDF-1.4\n" + b"x" * (4 * 1024 * 1024), content_type="application/pdf")
        if mode == "oversized-report":
            response = Response(pdf, content_type="application/pdf")
            response.headers["Content-Length"] = str(64 * 1024 * 1024 + 1)
            return response
        if mode == "slow-report":
            def chunks():
                yield b"%PDF-1.4\n"
                for _ in range(1024):
                    time.sleep(0.01)
                    yield b"x" * 65536
            return Response(chunks(), content_type="application/pdf")
        return Response(b"not-a-pdf" if mode == "bad-pdf" else pdf, content_type="application/pdf")
    if format == "xml":
        return Response('<?xml version="1.0"?><nmaprun><host/></nmaprun>', content_type="application/xml")
    if format == "html":
        response = Response("<!doctype html><html><head><title>Fixture</title></head><body>Report</body></html>", content_type="text/html")
        if mode != "bad-policy":
            response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'none'; base-uri 'none'; object-src 'none'"
        return response
    return jsonify(error="Not found"), 404


@app.get("/forbidden-redirect")
def forbidden_redirect():
    # If a client follows even a same-origin redirect, make its incorrect
    # success visible. Production clients must reject every redirect.
    return Response(pdf, content_type="application/pdf")


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


server = make_server("127.0.0.1", 0, app, request_handler=QuietHandler, threaded=True)
if mode == "delayed-ready":
    time.sleep(0.3)
print(json.dumps({"port": server.server_port}), flush=True)
server.serve_forever()
