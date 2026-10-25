"""Disposable stdlib server testing redirect/challenge refusal, no engine."""
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

root = tempfile.TemporaryDirectory(prefix="nmapui-control-policy-")
mode = os.environ["NMAPUI_CONTROL_POLICY"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_GET(self):
        with (Path(root.name) / "requests.jsonl").open("a") as out:
            out.write(json.dumps({"path": self.path}) + "\n")
        if self.path == "/api/socket-token" and mode == "socket-redirect":
            self.send_response(200)
            body = b'{"token":"test-csrf-only"}'
        elif mode == "challenge":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="private-fixture"')
            body = b"challenge"
        elif self.path == "/decoy":
            self.send_response(200)
            body = b"redirect was incorrectly followed"
        else:
            self.send_response(302)
            self.send_header("Location", "/decoy")
            body = b"redirect"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LiteralLoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer's default bind performs reverse DNS even for 127.0.0.1.
        # This fixture has no hostname contract and must work without DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def forbidden_dns(*_args, **_kwargs):
    raise RuntimeError("The loopback policy fixture must never resolve DNS")


socket.getfqdn = forbidden_dns
server = LiteralLoopbackHTTPServer(("127.0.0.1", 0), Handler)
def stop(*_): raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
if mode == "delayed-ready": time.sleep(.3)
if mode == "heartbeat-ready":
    release = Path(os.environ["NMAPUI_CONTROL_READY_RELEASE"])
    deadline = time.monotonic() + 5
    while not release.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("MainActor could not release fixture readiness")
        time.sleep(.01)
print(json.dumps({"port": server.server_port, "root": root.name}), flush=True)
try: server.serve_forever()
finally:
    server.server_close()
    root.cleanup()
