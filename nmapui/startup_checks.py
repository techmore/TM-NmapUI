import subprocess

from nmapui.auto_scan import build_auto_scan_status_payload
from nmapui.runtime_log import append_runtime_log


def run_startup_checks(deps, quick=False):
    begin_startup_state = deps["begin_startup_state"]
    check_arp_scan = deps["check_arp_scan"]
    check_nmap = deps["check_nmap"]
    check_vulners = deps["check_vulners"]
    complete_startup_state = deps["complete_startup_state"]
    get_app_version = deps["get_app_version"]
    get_default_interface_cached = deps["get_default_interface_cached"]
    get_versions = deps["get_versions"]
    load_auto_scan_config = deps["load_auto_scan_config"]
    load_current_assignment = deps["load_current_assignment"]
    logger = deps["logger"]
    run_traceroute = deps["run_traceroute"]
    safe_emit = deps["safe_emit"]
    startup_state = deps["startup_state"]
    tool_versions = deps["tool_versions"]
    auto_scan_config = deps["auto_scan_config"]
    runtime_store = deps.get("runtime_store")
    vulners_script = deps["vulners_script"]

    import platform

    begin_startup_state(startup_state, quick=quick)
    load_auto_scan_config(auto_scan_config)
    append_runtime_log(
        runtime_store=runtime_store,
        category="startup",
        level="INFO",
        message="Startup checks started",
        payload={"quick": bool(quick)},
    )

    logger.info("\n" + "=" * 50)
    logger.info("NmapUI Startup Checks")
    logger.info("=" * 50)

    system_platform = platform.system()
    platform_release = platform.release()
    logger.info(f"Platform detected: {system_platform} ({platform_release})")
    default_interface = get_default_interface_cached()
    logger.info(f"Default Network Interface: {default_interface}")

    errors = startup_state.setdefault("errors", [])

    if quick:
        logger.info("Quick mode: skipping dependency checks")
        startup_state["dependencies_ok"] = True
    else:
        logger.info("\nChecking nmap...")
        nmap_version = check_nmap()
        if nmap_version:
            tool_versions.set_version("nmap", nmap_version)
        else:
            tool_versions.set_version("nmap", "Not installed")
            errors.append("nmap is not installed or not on PATH")

        logger.info("\nChecking vulners script...")
        vulners_ok = bool(check_vulners(vulners_script))
        if not vulners_ok:
            errors.append(f"Vulners NSE script missing at {vulners_script}")
        vulners_dir = vulners_script.parent
        if vulners_dir.exists():
            try:
                version_result = subprocess.run(
                    [
                        "git",
                        "log",
                        "-1",
                        "--oneline",
                        "--date=short",
                        "--pretty=format:%h %ad %s",
                    ],
                    cwd=vulners_dir,
                    capture_output=True,
                    text=True,
                )
                if version_result.returncode == 0:
                    tool_versions.set_version("vulners", version_result.stdout.strip())
                else:
                    tool_versions.set_version("vulners", "Unknown")
            except Exception:
                tool_versions.set_version("vulners", "Unknown")

        logger.info("\nChecking arp-scan...")
        if check_arp_scan():
            try:
                version = (
                    subprocess.check_output(
                        ["arp-scan", "--version"], stderr=subprocess.STDOUT
                    )
                    .decode()
                    .split("\n")[0]
                )
                tool_versions.set_version("arp_scan", version)
            except Exception:
                tool_versions.set_version("arp_scan", "arp-scan (version unknown)")
        else:
            tool_versions.set_version("arp_scan", "Not installed")
        # arp-scan is optional; nmap and the vulners script are required for a
        # full scan, so readiness reflects only those two.
        startup_state["dependencies_ok"] = bool(nmap_version) and vulners_ok
        if not startup_state["dependencies_ok"]:
            logger.error(
                "Startup dependency checks failed; server will start in degraded "
                "mode and /api/health/ready will report not ready: %s",
                "; ".join(errors),
            )

    logger.info("\nLoading previous customer assignment...")
    load_current_assignment()

    logger.info("\nInitializing network key...")
    network_key = run_traceroute("1.1.1.1")
    complete_startup_state(
        startup_state,
        traceroute_initialized=not bool(network_key.get("error")),
    )
    logger.info(f"Network key initialized with {network_key.get('total_hops', 0)} hops")
    append_runtime_log(
        runtime_store=runtime_store,
        category="startup",
        level="INFO" if not network_key.get("error") else "ERROR",
        message="Startup network initialization completed",
        payload={
            "target": network_key.get("target"),
            "total_hops": network_key.get("total_hops", 0),
            "error": network_key.get("error"),
        },
    )

    logger.info("\n" + "=" * 50)
    logger.info("All checks passed. Starting server...")
    logger.info("=" * 50 + "\n")

    tool_versions.set_version("app", get_app_version())
    safe_emit("versions", get_versions())
    safe_emit("auto_scan_status", build_auto_scan_status_payload(auto_scan_config))
    append_runtime_log(
        runtime_store=runtime_store,
        category="startup",
        level="INFO",
        message="Startup checks completed",
        payload={"dependencies_ok": startup_state.get("dependencies_ok", False)},
    )
