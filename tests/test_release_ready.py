import importlib.util
import json
import threading
from io import BytesIO
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


CHECKER_PATH = Path(__file__).resolve().parents[1] / "packaging" / "check_release_ready.py"
SPEC = importlib.util.spec_from_file_location("nmapui_release_ready", CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class _Response(BytesIO):
    status = 200


class _Connection:
    payload = b'{"ready":true,"release_id":null}'
    expected_host = "127.0.0.1"

    def __init__(self, host, port, timeout):
        assert (host, port) == (self.expected_host, 9000)
        assert timeout == 5

    def request(self, method, path):
        assert (method, path) == ("GET", "/api/health/ready")

    def getresponse(self):
        return _Response(self.payload)

    def close(self):
        pass


def test_release_readiness_requires_matching_identity(tmp_path, monkeypatch):
    release = tmp_path / "release"
    release.mkdir()
    (release / "release_id").write_text("a" * 32 + "\n", encoding="ascii")
    monkeypatch.setattr(CHECKER, "HTTPConnection", _Connection)
    monkeypatch.setattr(
        _Connection,
        "payload",
        b'{"ready":true,"release_id":"' + b"a" * 32 + b'"}',
    )

    assert CHECKER.check_release_ready(release, 9000) is True

    monkeypatch.setattr(_Connection, "payload", b'{"ready":true,"release_id":null}')
    assert CHECKER.check_release_ready(release, 9000) is False


def test_release_readiness_rejects_invalid_marker_or_port(tmp_path, monkeypatch):
    release = tmp_path / "release"
    release.mkdir()
    (release / "release_id").write_text("not-a-release-id", encoding="ascii")
    monkeypatch.setattr(CHECKER, "HTTPConnection", _Connection)

    assert CHECKER.check_release_ready(release, 9000) is False
    assert CHECKER.check_release_ready(release, 0) is False


def test_release_readiness_uses_specific_bind_address(tmp_path, monkeypatch):
    release = tmp_path / "release"
    release.mkdir()
    release_id = "b" * 32
    (release / "release_id").write_text(release_id, encoding="ascii")
    monkeypatch.setattr(CHECKER, "HTTPConnection", _Connection)
    monkeypatch.setattr(_Connection, "expected_host", "192.0.2.10")
    monkeypatch.setattr(
        _Connection,
        "payload",
        b'{"ready":true,"release_id":"' + release_id.encode("ascii") + b'"}',
    )

    assert CHECKER.check_release_ready(release, 9000, host="192.0.2.10") is True


def test_release_readiness_maps_wildcard_binds_to_loopback(tmp_path, monkeypatch):
    release = tmp_path / "release"
    release.mkdir()
    release_id = "c" * 32
    (release / "release_id").write_text(release_id, encoding="ascii")
    monkeypatch.setattr(CHECKER, "HTTPConnection", _Connection)
    monkeypatch.setattr(_Connection, "expected_host", "127.0.0.1")
    monkeypatch.setattr(
        _Connection,
        "payload",
        b'{"ready":true,"release_id":"' + release_id.encode("ascii") + b'"}',
    )

    assert CHECKER.check_release_ready(release, 9000, host="0.0.0.0") is True


def test_release_readiness_maps_ipv6_wildcard_to_loopback():
    assert CHECKER._probe_host("::") == "::1"
    assert CHECKER._probe_host("[::]") == "::1"


def test_release_readiness_reaches_bound_address(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    release_id = "d" * 32
    (release / "release_id").write_text(release_id, encoding="ascii")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"ready": True, "release_id": release_id}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert CHECKER.check_release_ready(
            release, server.server_port, host="127.0.0.1"
        ) is True
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
