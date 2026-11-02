"""Live scan progress, completion and status-strip behaviour on the dashboard."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "index.html"
STATIC_JS = ROOT / "static" / "js"


def _read(name):
    return (STATIC_JS / name).read_text(encoding="utf-8")


def test_every_start_button_locks_while_any_scan_or_report_runs():
    scan_runtime = _read("scan_runtime.js")
    assert "['start-scan-btn', 'generate-report-btn', 'chunked-scan-btn', 'dragnet-scan-btn']" in scan_runtime
    assert "if (kind === 'chunked') return document.getElementById('chunked-scan-btn');" in scan_runtime
    # A Complete or Chunked run is a scan job plus a report job; the report
    # job decides which button is shown as running.
    assert "runningScanJobs.report.details?.chunked ? 'chunked' : 'complete'" in scan_runtime
    assert "job?.job_type !== 'scan' && job?.job_type !== 'report'" in scan_runtime
    # The scan job no longer forces the Quick Scan button to look active.
    assert "setScanUIActive(1, 'quick');" not in scan_runtime
    assert "button.setAttribute('aria-busy', isActive ? 'true' : 'false');" in scan_runtime
    assert ".scan-button-running {" in TEMPLATE.read_text(encoding="utf-8")


def test_finished_scans_replace_the_last_progress_line_with_an_outcome():
    scan_runtime = _read("scan_runtime.js")
    assert "function announceScanOutcome(job)" in scan_runtime
    assert "finished: no live hosts responded." in scan_runtime
    assert "window.setDiscoveryEmptyVariant?.('no-hosts', target);" in scan_runtime


def test_empty_state_has_initial_scanning_and_no_hosts_variants():
    template = TEMPLATE.read_text(encoding="utf-8")
    empty = template[template.index('<div id="discovery-empty-state"'):template.index('<table id="discovery-table"')]
    assert '<div data-empty-variant="initial">' in empty
    assert '<div data-empty-variant="scanning" hidden>' in empty
    assert '<div data-empty-variant="no-hosts" hidden>' in empty
    assert "Scan known targets without host discovery" in empty
    assert "function setDiscoveryEmptyVariant(variant, target)" in _read("discovery_ui.js")


def test_deep_scan_card_and_incomplete_hosts_follow_real_server_events():
    discovery_ui = _read("discovery_ui.js")
    # The server never emits scan_started/phase_stats, so the card is fed from
    # the per-host results that do arrive.
    assert "if (typeof updateDeepScanStats === 'function') updateDeepScanStats();" in discovery_ui
    assert "socket.on('deep_scan_host_complete', data => {" in discovery_ui
    assert "Service scan incomplete. Use Rescan to retry this host." in discovery_ui


def test_status_strip_is_dismissible_and_errors_do_not_time_out():
    template = TEMPLATE.read_text(encoding="utf-8")
    report_status = _read("report_status.js")
    assert 'data-action="hideReportStatus"' in template
    assert "hideReportStatus: () => window.hideReportStatus()," in _read("template_actions.js")
    assert "type === 'error' ? 12000" not in report_status
    assert "if (type === 'success' && !options.persist) {" in report_status
    assert "showReportStatus(window.formatReportCompleteMessage(data), 'success', { persist: true });" in report_status
    # The strip used bg-olive-100, the same lightness as the page background.
    assert "'bg-olive-100' : " not in report_status


@pytest.mark.skipif(not shutil.which("node"), reason="Requires Node.js")
def test_status_strip_shows_nse_script_names_not_install_paths():
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const context = { window: {} };
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const out = vm.runInNewContext(
  "shortenStatusPaths('Executing: nmap -T3 -sV --script /opt/app/release/nmap-vulners/vulners.nse 192.0.2.1')",
  context);
process.stdout.write(JSON.stringify(out));
"""
    output = subprocess.check_output(["node", "-e", script, str(STATIC_JS / "report_status.js")], text=True)
    assert json.loads(output) == "Executing: nmap -T3 -sV --script vulners.nse 192.0.2.1"
