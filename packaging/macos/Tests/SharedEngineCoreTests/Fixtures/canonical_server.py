"""Host the frozen shared app with its real auth/routes/SQLite store, isolated.

No scan commands, host service installation, or user data are accessed. Readiness
runs normal version/dependency checks; its process-local scheduler thread runs
with automatic scanning disabled.
"""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile

PIN = "911f83d837c6ea992f2592b4633c59e4a5c1ee29"
source = Path(os.environ["NMAPUI_SHARED_ENGINE_SOURCE"]).resolve(strict=True)
assert subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() == PIN
assert not subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip()
temporary = tempfile.TemporaryDirectory(prefix="nmapui-native-shared-fixture-")
def stop(*_):
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
root = Path(temporary.name)
os.environ.update({
    "NMAPUI_DATA_DIR": str(root / "data"), "NMAPUI_LOG_DIR": str(root / "logs"),
    "NMAPUI_SKIP_LEGACY_MIGRATION": "1", "NMAPUI_STARTUP_TRACEROUTE": "false",
    "NMAPUI_ENABLE_NETWORK_FINGERPRINT": "false", "NMAPUI_ENABLE_UPDATE_CHECK": "false",
    "NMAPUI_ENABLE_VULNERS": "false", "NMAPUI_TRUST_LOCAL_UI": "false",
    "NMAPUI_USERNAME": "fixture-user", "NMAPUI_PASSWORD": "fixture-contraseña-🔐",
    "NMAPUI_HOST": "127.0.0.1", "NMAPUI_COOKIE_SECURE": "false",
})
(root / "data").mkdir()
(root / "data/auto_scan_config.json").write_text(json.dumps({"enabled": False, "start_time": "01:00", "end_time": "06:00", "last_run": None}))
sys.path.insert(0, str(source))
with contextlib.redirect_stdout(sys.stderr):
    import app as engine
    from werkzeug.serving import WSGIRequestHandler, make_server
    engine.startup_checks(quick=False)
    engine.start_auto_scan_thread()
    path = "Example customer/scan with spaces 雪"
    folder = root / "data/scans" / path
    folder.mkdir(parents=True)
    (folder / "scan_report.pdf").write_bytes(b"%PDF-1.4\nfixture-report\n%%EOF\n")
    (folder / "scan.xml").write_text('''<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" version="7.98" startstr="Sun Oct 25 12:00:00 2026">
<scaninfo type="connect" protocol="tcp" numservices="1" services="443"/>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="fixture-host"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Fixture service" version="1.2"/></port></ports></host>
<runstats><finished timestr="Sun Oct 25 12:00:01 2026" elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>''')
    transformed = subprocess.run(["xsltproc", "--nonet", str(source / "nmap-modern.xsl"), str(folder / "scan.xml")], check=True, capture_output=True)
    (folder / "scan_web.html").write_bytes(transformed.stdout)
    from nmapui.reporting import _embed_report_assets
    _embed_report_assets(folder / "scan_web.html")
    engine.runtime_store.upsert_report_artifact(scan_path=path, customer_id="fixture-customer", target="127.0.0.1/32",
        html_path="scan_web.html", pdf_path="scan_report.pdf", xml_path="scan.xml",
        payload={"timestamp": "2026-10-25T12:00:00Z", "target": "127.0.0.1/32", "customer_id": "fixture-customer",
                 "customer_name": "Example customer", "host_count": 1, "status": "completed"})
    engine.runtime_store.upsert_job(job_id="fixture-completed-job", owner_sid="fixture", job_type="scan", status="completed",
                                   payload={"details": {"target": "127.0.0.1/32", "host_count": 1}})


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


server = make_server("127.0.0.1", 0, engine.app, request_handler=QuietHandler, threaded=True)
print(json.dumps({"port": server.server_port, "baselinePath": str(folder / "scan_web.html")}), flush=True)
try:
    server.serve_forever()
finally:
    server.server_close()
    temporary.cleanup()
