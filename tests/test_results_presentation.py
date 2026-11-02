"""Results table, host detail and Vulners severity presentation.

The severity helpers run under Node so the CVSS band edges are checked with real
JavaScript number parsing rather than by reading source text.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "index.html"
STATIC_JS = ROOT / "static" / "js"


def _run_utils(expression):
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const context = { window: {}, document: { createElement: () => ({}) } };
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
process.stdout.write(JSON.stringify(vm.runInNewContext(process.argv[2], context)));
"""
    output = subprocess.check_output(
        ["node", "-e", script, str(STATIC_JS / "utils.js"), expression], text=True
    )
    return json.loads(output)


@pytest.mark.skipif(not shutil.which("node"), reason="Requires Node.js")
def test_cve_severity_uses_cvss_v3_bands_with_text_labels():
    labels = _run_utils(
        "['9.8','9.0','8.9','7.0','6.9','4.0','3.9','0.1','0','', 'n/a', null]"
        ".map(score => window.cveSeverity(score).label)"
    )
    assert labels == [
        "Critical", "Critical", "High", "High", "Medium", "Medium",
        "Low", "Low", "None", "Unscored", "Unscored", "Unscored",
    ]


@pytest.mark.skipif(not shutil.which("node"), reason="Requires Node.js")
def test_cves_sort_worst_first_and_unscored_last():
    ordered = _run_utils(
        "window.sortCvesBySeverity([{id:'a',score:'6.5'},{id:'b',score:''},"
        "{id:'c',score:'9.8'},{id:'d',score:'7.8'}]).map(c => c.id)"
    )
    assert ordered == ["c", "d", "a", "b"]


def test_results_columns_fit_a_desktop_window_and_never_hide_headers_alone():
    template = TEMPLATE.read_text(encoding="utf-8")
    table = template[template.index('<table id="discovery-table"'):template.index("</table>")]
    # A header that hides at a breakpoint while its body cells stay visible
    # shifts every value under the wrong column on small screens.
    assert "table-cell" not in table
    assert "min-w-[2400px]" not in table
    assert 'class="table-fixed w-full min-w-[70rem] hidden"' in table
    assert "#discovery-table td {" in template
    assert "vertical-align: top;" in template


def test_every_result_row_has_a_labelled_details_button():
    discovery_ui = (STATIC_JS / "discovery_ui.js").read_text(encoding="utf-8")
    assert "detailsBtn.setAttribute('aria-label', `Details for ${result.ip}`);" in discovery_ui
    assert "rescanBtn.setAttribute('aria-label', `Rescan ${result.ip}`);" in discovery_ui
    assert "openHostDetails(result.ip);" in discovery_ui
    # Live Vulners results reach the dialog, not just the table cell.
    assert "mergeHostRecord(data.target, { vulnerabilities: data.cve_array || [] });" in discovery_ui
    # The old entry point was a click handler on a non-focusable <div>.
    assert "onClick: event =>" not in discovery_ui


def test_host_detail_understands_live_and_historical_port_shapes():
    modal = (STATIC_JS / "asset_details_modal.js").read_text(encoding="utf-8")
    assert "function assetServiceRows(asset)" in modal
    assert "asset.ports_detail" in modal
    assert "window.sortCvesBySeverity(asset.vulnerabilities)" in modal
    assert "window.createCveSeverityChip(vuln.score)" in modal
    # "Port N/A (unknown)" was printed for every live finding.
    assert "Port ${vuln.port || 'N/A'}" not in modal


def test_vulnerability_heading_keeps_its_spacing():
    template = TEMPLATE.read_text(encoding="utf-8")
    assert re.search(r'<span>Vulnerabilities \(<span id="asset-cve-count">0</span>\)</span>', template)
