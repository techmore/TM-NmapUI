from datetime import datetime
import ipaddress
import logging
import os
import re
import shutil
import subprocess

from nmapui import privileged


logger = logging.getLogger(__name__)


def _is_permission_denied(result) -> bool:
    return privileged.is_permission_denied(result)


def get_nmap_scan_technique(force_unprivileged=False):
    """Choose a connect scan when the process is not running with root privileges."""
    if force_unprivileged:
        return "-sT"
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return "-sS"
    return "-sT"


def check_arp_scan():
    """Check if arp-scan is installed."""
    arp_path = shutil.which("arp-scan")
    if arp_path:
        try:
            version = (
                subprocess.check_output(
                    ["arp-scan", "--version"], stderr=subprocess.STDOUT
                )
                .decode()
                .split("\n")[0]
            )
            logger.info("Found: %s", version)
            return True
        except Exception:
            logger.info("Found: arp-scan (version unknown)")
            return True

    logger.warning("arp-scan not found. MAC/vendor detection will be disabled.")
    logger.info("  macOS:  brew install arp-scan")
    logger.info("  Ubuntu: sudo apt install arp-scan")
    return False


def check_nmap():
    """Ensure nmap is installed and return its version string.

    Returns ``None`` when nmap is unavailable instead of calling ``sys.exit``.
    Exiting here used to kill the whole process before the HTTP server bound,
    which made any missing-dependency restart an unrecoverable silent death for
    an unattended deployment.  Callers record the failure in startup state so
    ``/api/health/ready`` can report it.
    """
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        logger.error("nmap not found. Please install nmap:")
        logger.error("  macOS:  brew install nmap")
        logger.error("  Ubuntu: sudo apt install nmap")
        return None

    try:
        version = subprocess.check_output(["nmap", "--version"]).decode().split("\n")[0]
        logger.info("Found: %s", version)
        return version
    except Exception as exc:
        logger.error("Could not get nmap version: %s", exc)
        return None


def check_vulners(vulners_script):
    """Verify the bundled vulners NSE script is present.

    Returns ``True`` when usable.  A missing script degrades vulnerability
    detection but must not terminate the server (see ``check_nmap``).
    """
    if not vulners_script.exists():
        logger.error(
            "Vulners NSE script not found at %s. Run: git clone https://github.com/vulnersCom/nmap-vulners.git %s",
            vulners_script,
            vulners_script.parent,
        )
        return False

    vulners_dir = vulners_script.parent
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--oneline"],
            cwd=vulners_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Vulners script present (revision: %s)", result.stdout.strip())
        else:
            logger.info("Vulners script present at %s", vulners_script)
    except Exception:
        logger.info("Vulners script present at %s", vulners_script)

    return True


def create_scan_folder(customer_name, target, *, scans_dir, sanitize_customer_dir_name):
    """Create organized folder structure for a scan."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    time_str = datetime.now().strftime("%H%M%S")
    safe_customer = sanitize_customer_dir_name(customer_name)
    safe_target = re.sub(r"[^\w\.]", "_", target)

    folder_name = f"scan_{time_str}_{safe_target}"
    scan_dir = scans_dir / safe_customer / date_str / folder_name
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir


def run_quick_auto_scan(target, output_base):
    """Run a quick scan suitable for automated overnight scanning."""
    logger.info("Running auto scan on %s...", target)
    cmd = [
        "nmap",
        "-sS",
        "-T3",
        "--top-ports",
        "50",
        "-oA",
        str(output_base),
        target,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.error("Auto scan timed out after 120 seconds on %s", target)
        return False


def split_subnet_into_chunks(target):
    """Split large subnets into /29 chunks for manageable scanning."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses <= 8:
            return [target]

        chunks = []
        for subnet in network.subnets(new_prefix=29):
            if subnet.num_addresses > 0:
                chunks.append(str(subnet))
            if len(chunks) >= 2048:
                break
        return chunks[:2048]
    except ValueError:
        return [target]


def run_arp_scan(
    target,
    *,
    interface=None,
    sid=None,
    get_default_interface_cached,
    which,
    emit_to_client,
    socketio_emit,
    socketio_sleep,
    run_cancellable_command,
):
    if interface is None:
        interface = get_default_interface_cached()

    if not which("arp-scan"):
        logger.warning("arp-scan not found, skipping MAC/vendor detection")
        if sid:
            emit_to_client(
                sid, "scan_feedback", "arp-scan not found, skipping MAC/vendor detection"
            )
        else:
            socketio_emit(
                "scan_feedback", "arp-scan not found, skipping MAC/vendor detection"
            )
        return {}

    try:
        command_str = f"arp-scan {target} --interface {interface}"
        if sid:
            emit_to_client(sid, "scan_feedback", f"Executing: {command_str}")
        else:
            socketio_emit("scan_feedback", f"Executing: {command_str}")
        logger.info(command_str)
        socketio_sleep(0)

        result = run_cancellable_command(
            ["arp-scan", target, "--interface", interface],
            sid=sid,
            job_type="scan" if sid else None,
            timeout=30,
        )
        if result.returncode == 0:
            output = result.stdout
        else:
            if _is_permission_denied(result):
                message = (
                    "arp-scan requires elevated privileges; skipping MAC/vendor detection"
                )
                logger.warning(message)
                if sid:
                    emit_to_client(sid, "scan_feedback", message)
                else:
                    socketio_emit("scan_feedback", message)
                return {}
            output = result.stdout

        arp_data = {}
        arp_pattern = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)$")

        for line in output.splitlines():
            match = arp_pattern.match(line.strip())
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                vendor = match.group(3).strip()
                arp_data[ip] = {"mac": mac, "vendor": vendor}

        logger.info("ARP scan found %s hosts with MAC addresses", len(arp_data))
        return arp_data

    except FileNotFoundError:
        logger.warning("arp-scan not found, skipping MAC/vendor detection")
        return {}
    except RuntimeError as exc:
        if str(exc) == "scan cancelled":
            return {}
        logger.error("arp-scan error: %s", exc)
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("arp-scan timed out")
        return {}
    except Exception as exc:
        logger.error("arp-scan error: %s", exc)
        return {}


def run_nmap_with_xml_output(
    target,
    output_base,
    *,
    scan_type="comprehensive",
    sid=None,
    excluded_targets=None,
    scan_only_mode=False,
    force_privileged_scan=False,
    vulners_script,
    stylesheet_pdf,
    emit_to_client,
    socketio_emit,
    socketio_sleep,
    run_cancellable_command,
    timeout_seconds=None,
):
    """Run nmap with all formats output (-oA)."""
    # Precedence matters: an explicit unprivileged request must win over the
    # default privileged attempt, otherwise "scan only" mode silently becomes
    # a SYN scan (and contradicts the message shown to the operator).
    if scan_only_mode:
        scan_technique = "-sT"
    elif force_privileged_scan:
        scan_technique = "-sS"
    else:
        scan_technique = get_nmap_scan_technique(
            force_unprivileged=not (privileged.is_root() or privileged.sudo_available())
        )
    scan_prefix = privileged.privileged_prefix()
    excluded_targets = [
        str(item or "").strip() for item in (excluded_targets or []) if str(item or "").strip()
    ]

    if scan_type == "quick":
        logger.info("Running quick scan on %s...", target)
        if sid:
            emit_to_client(sid, "scan_feedback", f"Starting quick scan on {target}...")
        else:
            socketio_emit("scan_feedback", f"Starting quick scan on {target}...")
        options = ["-T3", "--top-ports", "100", "-oA", str(output_base)]
        timeout_seconds = int(timeout_seconds or 180)
    else:
        logger.info("Running comprehensive scan on %s...", target)
        message = (
            f"Starting comprehensive scan with vulnerability detection on {target} "
            "(may take 10+ minutes)..."
        )
        if sid:
            emit_to_client(sid, "scan_feedback", message)
        else:
            socketio_emit("scan_feedback", message)
        options = [
            "-Pn",
            "-T4",
            "-A",
            "-sC",
            "--script",
            str(vulners_script),
            "--stylesheet",
            str(stylesheet_pdf),
            "-oA",
            str(output_base),
        ]
        timeout_seconds = int(timeout_seconds or 7200)

    if excluded_targets:
        # Part of the shared option list, so the unprivileged fallback keeps it.
        options = ["--exclude", ",".join(excluded_targets), *options]

    cmd = privileged.nmap_argv(scan_technique, options, target, prefix=scan_prefix)

    cmd_str = " ".join(cmd)
    logger.info("Executing: %s", cmd_str)
    if sid:
        emit_to_client(sid, "scan_feedback", f"Command: {cmd_str}")
    else:
        socketio_emit("scan_feedback", f"Command: {cmd_str}")
    socketio_sleep(0)

    start_time = datetime.now()
    logger.info("Scan started at %s", start_time.strftime("%H:%M:%S"))
    if sid:
        emit_to_client(
            sid, "scan_feedback", f"Scan started at {start_time.strftime('%H:%M:%S')}"
        )
    else:
        socketio_emit(
            "scan_feedback", f"Scan started at {start_time.strftime('%H:%M:%S')}"
        )
    socketio_sleep(0)

    try:
        result = run_cancellable_command(
            cmd, sid=sid, job_type="report" if sid else None, timeout=timeout_seconds
        )
        if (
            (force_privileged_scan or scan_prefix)
            and result.returncode != 0
            and _is_permission_denied(result)
        ):
            logger.warning("Privileged scan denied; retrying with unprivileged connect scan")
            if sid:
                emit_to_client(
                    sid,
                    "scan_feedback",
                    "Privileged scan denied; retrying with unprivileged connect scan",
                )
            else:
                socketio_emit(
                    "scan_feedback",
                    "Privileged scan denied; retrying with unprivileged connect scan",
                )
            socketio_sleep(0)
            # Rebuild from the shared option list with no privilege prefix so
            # exclusions and every other flag survive the retry.
            fallback_cmd = privileged.nmap_argv(
                "-sT", options, target, prefix=[]
            )
            result = run_cancellable_command(
                fallback_cmd,
                sid=sid,
                job_type="report" if sid else None,
                timeout=timeout_seconds,
            )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info("Scan completed in %.1f seconds", duration)
        if sid:
            emit_to_client(
                sid, "scan_feedback", f"Scan completed in {duration:.1f} seconds"
            )
        else:
            socketio_emit("scan_feedback", f"Scan completed in {duration:.1f} seconds")
        socketio_sleep(0)

        if result.stdout:
            logger.info("Nmap stdout:\\n%s", result.stdout)
        if result.stderr:
            logger.warning("Nmap stderr:\\n%s", result.stderr)

        if result.returncode != 0:
            logger.error("Nmap failed with return code %s", result.returncode)
            message = f"❌ Nmap failed with return code {result.returncode}"
            if sid:
                emit_to_client(sid, "scan_feedback", message)
            else:
                socketio_emit("scan_feedback", message)
            socketio_sleep(0)

        return {"success": result.returncode == 0, "timeout": False}

    except RuntimeError as exc:
        if str(exc) == "report cancelled":
            if sid:
                emit_to_client(sid, "scan_feedback", "Report generation cancelled")
            return {"success": False, "timeout": False, "cancelled": True}
        raise
    except subprocess.TimeoutExpired:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        error_msg = (
            f"⏱️  Nmap scan TIMED OUT after {duration:.1f} seconds "
            f"(limit: {timeout_seconds}s / {timeout_seconds // 60}min) on {target}"
        )
        logger.error(error_msg)
        payload = {
            "error": (
                f"Scan timed out after {timeout_seconds // 60} minutes. "
                "Your network requires a longer scan time."
            ),
            "timeout": True,
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": duration,
        }
        if sid:
            emit_to_client(sid, "scan_feedback", error_msg)
            emit_to_client(sid, "report_error", payload)
        else:
            socketio_emit("scan_feedback", error_msg)
            socketio_emit("report_error", payload)
        socketio_sleep(0)
        return {
            "success": False,
            "timeout": True,
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": duration,
            "error": payload.get("error"),
        }
