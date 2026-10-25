"""Disposable stdlib server testing redirect/challenge refusal, no engine."""
import json
import os
from pathlib import Path
import signal
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


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
def stop(*_): raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
if mode == "delayed-ready": time.sleep(.3)
print(json.dumps({"port": server.server_port, "root": root.name}), flush=True)
try: server.serve_forever()
finally:
    server.server_close()
    root.cleanup()
