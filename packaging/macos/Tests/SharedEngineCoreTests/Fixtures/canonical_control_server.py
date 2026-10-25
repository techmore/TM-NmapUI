"""Owned Gunicorn + frozen canonical workflow + non-networking nmap executable.

No test HTTP/control routes or alternate backend workflow. IPC files observe the
owned fake scanner only. Strict HTTP AND Socket.IO auth are forced pre-import.
"""
import base64
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PIN = "911f83d837c6ea992f2592b4633c59e4a5c1ee29"

if os.environ.get("NMAPUI_CONTROL_FIXTURE_WORKER") == "1":
    sys.path.insert(0, os.environ["NMAPUI_SHARED_ENGINE_SOURCE"])
    import app as engine
    engine.settings_state["scan_rules"]["scan_only_mode"] = True
    # The actual handler, registry and cancellable subprocess workflow remain.
    def application(environ, start_response):
        root = Path(os.environ["NMAPUI_CONTROL_FIXTURE_ROOT"])
        with (root / "requests.jsonl").open("a") as out:
            out.write(json.dumps({"path": environ.get("PATH_INFO"), "query": environ.get("QUERY_STRING"),
                                  "cookie": environ.get("HTTP_COOKIE", "")}) + "\n")
        return engine.app(environ, start_response)
else:
    def main():
        source = Path(os.environ["NMAPUI_SHARED_ENGINE_SOURCE"]).resolve(strict=True)
        assert subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() == PIN
        assert not subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip()
        with tempfile.TemporaryDirectory(prefix="nmapui-shared-controls-") as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            fake = root / "bin/nmap"
            fake.write_text("#!" + sys.executable + "\n" + r'''
import json, os, pathlib, sys, time
if '--version' in sys.argv:
    print('Nmap version 7.98 (fixture, no networking)'); raise SystemExit(0)
root = pathlib.Path(os.environ['NMAPUI_CONTROL_FIXTURE_ROOT'])
parent = os.getppid()
with (root / 'invocations.jsonl').open('a') as out:
    out.write(json.dumps({'pid': os.getpid(), 'args': sys.argv[1:]}) + '\n')
deadline = time.monotonic() + 60
while not (root / 'release').exists():
    if os.getppid() != parent or time.monotonic() > deadline: raise SystemExit(2)
    time.sleep(.025)
print('Nmap scan report for 127.0.0.1\nHost is up (0.001s latency).\nNmap done: 1 IP address (1 host up) scanned in 0.01 seconds')
''')
            fake.chmod(0o700)
            # Fail closed if a future workflow accidentally requests privilege.
            for name in ("sudo", "arp-scan"):
                blocked = root / "bin" / name
                blocked.write_text("#!/bin/sh\necho 'fixture refuses privilege/network helper' >&2\nexit 97\n")
                blocked.chmod(0o700)
            (root / "data").mkdir()
            (root / "data/auto_scan_config.json").write_text('{"enabled":false}')
            listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(128)
            port = listener.getsockname()[1]
            env = {**os.environ,
                "PATH": str(root / "bin") + os.pathsep + os.environ.get("PATH", ""),
                "NMAPUI_CONTROL_FIXTURE_WORKER": "1", "NMAPUI_CONTROL_FIXTURE_ROOT": str(root),
                "NMAPUI_DATA_DIR": str(root / "data"), "NMAPUI_LOG_DIR": str(root / "logs"),
                "NMAPUI_SKIP_LEGACY_MIGRATION": "1", "NMAPUI_STARTUP_TRACEROUTE": "false",
                "NMAPUI_ENABLE_NETWORK_FINGERPRINT": "false", "NMAPUI_ENABLE_UPDATE_CHECK": "false",
                "NMAPUI_ENABLE_VULNERS": "false", "NMAPUI_TRUST_LOCAL_UI": "false",
                "GUNICORN_CMD_ARGS": "", "NMAPUI_PORT": str(port),
                "NMAPUI_SCAN_HELPER": str(root / "no-privileged-helper"),
                "NMAPUI_SOCKET_AUTH_DISABLED": "false", "NMAPUI_HOST": "127.0.0.1",
                "NMAPUI_USERNAME": "fixture-user", "NMAPUI_PASSWORD": "fixture-contraseña-🔐",
                "NMAPUI_COOKIE_SECURE": "false",
            }
            def stop(*_): raise SystemExit(0)
            signal.signal(signal.SIGTERM, stop)
            with (root / "server.log").open("w+") as log:
                process = subprocess.Popen([sys.executable, "-m", "gunicorn", "--bind", f"fd://{listener.fileno()}",
                    "--control-socket", str(root / "gunicorn.ctl"), "--workers", "1", "--threads", "8", "--timeout", "30", "--graceful-timeout", "2",
                    "--pythonpath", str(Path(__file__).parent), "canonical_control_server:application"],
                    env=env, cwd=source, pass_fds=(listener.fileno(),), stdout=log, stderr=log, start_new_session=True)
                listener.close()
                try:
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if process.poll() is not None: raise RuntimeError('Gunicorn exited: ' + (root / 'server.log').read_text()[-8000:])
                        try:
                            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health/live", timeout=.3)
                            break
                        except urllib.error.HTTPError as error:
                            if error.code == 401: break
                        except OSError: pass
                        time.sleep(.05)
                    else: raise RuntimeError('Gunicorn not live: ' + (root / 'server.log').read_text()[-8000:])
                    print(json.dumps({"port": port, "root": str(root)}), flush=True)
                    process.wait()
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try: process.wait(timeout=4)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=2)
                    # A failed test can leave a deliberately SIGSTOPped fake.
                    # Signal only recorded process-group leaders whose current
                    # argv still contains this fixture's unique executable path.
                    records = root / "invocations.jsonl"
                    if records.exists():
                        for line in records.read_text().splitlines():
                            pid = json.loads(line)["pid"]
                            args = subprocess.run(["ps", "-p", str(pid), "-o", "args="], capture_output=True, text=True).stdout
                            try:
                                if str(fake) in args and os.getpgid(pid) == pid:
                                    os.killpg(pid, signal.SIGCONT); os.killpg(pid, signal.SIGTERM)
                                    deadline = time.monotonic() + 1
                                    while time.monotonic() < deadline:
                                        try: os.kill(pid, 0)
                                        except ProcessLookupError: break
                                        time.sleep(.025)
                                    else:
                                        args = subprocess.run(["ps", "-p", str(pid), "-o", "args="], capture_output=True, text=True).stdout
                                        if str(fake) in args and os.getpgid(pid) == pid: os.killpg(pid, signal.SIGKILL)
                            except ProcessLookupError: pass
                    sys.stderr.write((root / "server.log").read_text()[-12000:])
    if __name__ == "__main__": main()
