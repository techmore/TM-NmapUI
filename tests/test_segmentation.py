"""Passive VLAN / segmentation analysis (issue #31): one fixture per confidence level."""
import base64
import json
from html import escape
from pathlib import Path

import pytest
from flask import Flask

from nmapui import segmentation
from nmapui.handlers.routes import register_core_routes
from nmapui.segmentation import analyze_segmentation, load_supplied_evidence, segmentation_html
from nmapui.topology_recommendations import append_recommendations


def host(ip, *, mac=None, names=(), hops=(), scripts=(), state="up"):
    parts = [f'<host><status state="{state}"/><address addr="{ip}" addrtype="ipv4"/>']
    if mac:
        parts.append(f'<address addr="{mac}" addrtype="mac" vendor="Example"/>')
    if names:
        parts.append("<hostnames>" + "".join(f'<hostname name="{escape(n)}" type="PTR"/>' for n in names) + "</hostnames>")
    if hops:
        parts.append("<trace>" + "".join(
            f'<hop ttl="{ttl}" ipaddr="{addr}"' + (f' host="{name}"' if name else "") + "/>" for ttl, addr, name in hops
        ) + "</trace>")
    if scripts:
        parts.append("<hostscript>" + "".join(
            f'<script id="{sid}" output="{out}"/>' for sid, out in scripts
        ) + "</hostscript>")
    parts.append("</host>")
    return "".join(parts)


def doc(*hosts):
    return ("<nmaprun>" + "".join(hosts) + "</nmaprun>").encode()


def kinds(analysis, confidence=None):
    return {f["kind"] for f in analysis["findings"] if confidence in (None, f["confidence"])}


# -- no evidence ---------------------------------------------------------------------

def test_no_hosts_yields_no_findings_and_no_section():
    for documents in ([], [doc()], [doc(host("192.168.1.5", state="down"))], [b"not xml"]):
        result = analyze_segmentation(documents)
        assert result["findings"] == [] and result["segments"] == [] and result["recommendations"] == []
        assert segmentation_html(result) == ""
        assert result["summary"]["detected"] == result["summary"]["likely"] == result["summary"]["unverified"] == 0
    assert any("could not be parsed" in n for n in analyze_segmentation([b"not xml"])["limitations"])


def test_public_only_hosts_are_not_grouped_into_private_segments():
    result = analyze_segmentation([doc(host("8.8.8.8"))])
    assert kinds(result) == {"no_private_segments"}
    assert result["findings"][0]["confidence"] == "unverified"


# -- unverified ----------------------------------------------------------------------

def test_single_subnet_is_unverified_and_claims_nothing_about_vlans():
    result = analyze_segmentation([doc(host("192.168.1.10"), host("192.168.1.11"))])
    assert [f["confidence"] for f in result["findings"]] == ["unverified"]
    assert kinds(result) == {"single_segment"}
    text = json.dumps(result).lower()
    assert "does not show whether other vlans" in text
    assert result["summary"]["vlan_ids"] == []


def test_two_subnets_without_routing_or_mac_evidence_stay_unverified():
    result = analyze_segmentation([doc(host("192.168.1.10"), host("10.0.5.20"))])
    assert kinds(result) == {"subnets_unclassified"}
    assert result["findings"][0]["confidence"] == "unverified"
    assert any("deep scan" in r["text"] for r in result["recommendations"])


def test_scanner_local_subnet_is_not_reported_as_unclassified():
    result = analyze_segmentation([doc(host("192.168.1.10", mac="AA:00:00:00:00:01"), host("10.0.5.20"))])
    finding = next(f for f in result["findings"] if f["kind"] == "subnets_unclassified")
    assert "10.0.5.0/24" in finding["title"] and "192.168.1.0/24" not in finding["title"]


# -- likely --------------------------------------------------------------------------

def test_routed_segment_is_likely_and_cites_traceroute():
    xml = doc(
        host("192.168.1.10", mac="AA:00:00:00:00:01", hops=[(1, "192.168.1.10", "")]),
        host("10.0.20.5", hops=[(1, "192.168.1.1", ""), (2, "10.0.20.1", ""), (3, "10.0.20.5", "")]),
    )
    result = analyze_segmentation([xml])
    finding = next(f for f in result["findings"] if f["kind"] == "routed_segment")
    assert finding["confidence"] == "likely" and finding["source"] == "inferred"
    assert "10.0.20.0/24" in finding["title"]
    assert any("192.168.1.1 > 10.0.20.1 > 10.0.20.5" in e for e in finding["evidence"])
    assert "VLAN" in " ".join(r["text"] for r in result["recommendations"])
    assert "detected" not in {f["confidence"] for f in result["findings"]}


def test_multiple_subnets_answering_at_layer2_is_likely_shared_broadcast_domain():
    xml = doc(host("192.168.1.10", mac="AA:00:00:00:00:01"), host("192.168.2.10", mac="AA:00:00:00:00:02"))
    result = analyze_segmentation([xml])
    finding = next(f for f in result["findings"] if f["kind"] == "shared_broadcast_domain")
    assert finding["confidence"] == "likely"
    assert any("AA:00:00:00:00:02" in e for e in finding["evidence"])
    assert "more than one network interface" in finding["summary"]


def test_vlan_name_convention_is_likely_not_detected():
    xml = doc(host("10.0.30.5", hops=[(1, "10.0.30.1", "vlan30.core.example"), (2, "10.0.30.5", "")]))
    result = analyze_segmentation([xml])
    finding = next(f for f in result["findings"] if f["kind"] == "vlan_name_hint")
    assert finding["confidence"] == "likely"
    assert result["summary"]["vlan_ids"] == []  # a name is a hint, not an identifier


def test_end_device_names_must_spell_out_vlan():
    assert "vlan_name_hint" not in kinds(analyze_segmentation([doc(host("10.0.1.5", names=["vl2-laptop", "vl7"]))]))
    assert "vlan_name_hint" in kinds(analyze_segmentation([doc(host("10.0.1.5", names=["vlan7.example"]))]))


# -- detected ------------------------------------------------------------------------

LLDP = "Chassis id: aa:bb\nPort VLAN ID (PVID): 20\nNative VLAN: 1\nVLAN ID: 30"


def test_lldp_cdp_script_output_is_detected_with_citations_and_hygiene_advice():
    xml = doc(host("192.168.1.2", scripts=[("lldp-neighbors", LLDP.replace("\n", "&#10;")), ("cdp-info", "Dynamic Trunking Protocol: desirable")]))
    result = analyze_segmentation([xml])
    assert kinds(result, "detected") == {"vlan_ids_observed", "native_vlan_observed", "trunk_negotiation_observed"}
    ids = next(f for f in result["findings"] if f["kind"] == "vlan_ids_observed")
    assert ids["source"] == "observed"
    assert ids["title"].endswith("20, 30")
    assert any("192.168.1.2 · script lldp-neighbors" in e for e in ids["evidence"])
    assert result["summary"]["vlan_ids"] == [1, 20, 30]
    text = " ".join(r["text"] for r in result["recommendations"])
    assert "Native VLAN 1" in text and "negotiation" in text
    # Detected findings sort first.
    assert result["findings"][0]["confidence"] == "detected"


def test_out_of_range_and_unlabelled_numbers_are_ignored():
    out = "Port VLAN ID: 0&#10;VLAN ID: 5000&#10;Native VLAN: 4095&#10;uptime 20 vlan"
    result = analyze_segmentation([doc(host("192.168.1.2", scripts=[("x", out)]))])
    assert "vlan_ids_observed" not in kinds(result) and "native_vlan_observed" not in kinds(result)


MERAKI = {
    "source": "Meraki dashboard export",
    "vlans": [
        {"id": 10, "name": "Staff", "subnet": "192.168.10.0/24", "applianceIp": "192.168.10.1"},
        {"id": 20, "name": "Guest", "subnet": "192.168.20.0/24"},
    ],
    "ports": [
        {"portId": "24", "type": "trunk", "vlan": 1, "allowedVlans": "all"},
        {"portId": "25", "type": "trunk", "vlan": 10, "allowedVlans": "10,20"},
        {"portId": "3", "type": "access", "vlan": 10},
        {"portId": "4", "type": "access", "vlan": 1},
    ],
}


def test_supplied_meraki_style_config_is_detected_and_correlated_to_scanned_subnets():
    xml = doc(host("192.168.10.7"), host("172.16.9.4"))
    result = analyze_segmentation([xml], MERAKI)
    assert {"config_vlans", "config_correlation", "config_native_vlan_default", "config_trunk_unpruned",
            "config_access_vlan_default", "config_native_in_use", "config_gap"} <= kinds(result)
    by_kind = {f["kind"]: f for f in result["findings"]}
    assert by_kind["config_correlation"]["confidence"] == "detected"
    assert by_kind["config_correlation"]["source"] == "supplied"
    assert "192.168.10.0/24 -> VLAN 10 Staff" in by_kind["config_correlation"]["evidence"]
    assert by_kind["config_gap"]["confidence"] == "unverified"
    assert by_kind["config_native_vlan_default"]["evidence"] == ["24"]
    assert by_kind["config_native_in_use"]["evidence"] == ["25 (native 10)"]
    assert by_kind["config_trunk_unpruned"]["evidence"] == ["24"]  # port 25 is pruned


IOS = """\
vlan 10
 name Staff
vlan 99
 name Parking
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
interface GigabitEthernet1/0/1
 switchport mode dynamic desirable
interface GigabitEthernet1/0/2
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 10,99
 switchport nonegotiate
interface GigabitEthernet1/0/3
 switchport mode access
 switchport access vlan 10
"""


def test_supplied_ios_style_text_is_parsed():
    result = analyze_segmentation([doc(host("192.168.10.7"))], {"config_text": IOS})
    by_kind = {f["kind"]: f for f in result["findings"]}
    assert "VLAN 10 Staff · 192.168.10.0/24" in by_kind["config_vlans"]["evidence"]
    assert by_kind["config_dtp_dynamic"]["evidence"] == ["GigabitEthernet1/0/1"]
    assert by_kind["config_native_vlan_default"]["evidence"] == ["GigabitEthernet1/0/2"]
    assert "config_trunk_unpruned" not in by_kind  # allowed list is explicit
    assert by_kind["config_correlation"]["confidence"] == "detected"


def test_clean_supplied_config_produces_no_hygiene_findings():
    clean = {"vlans": [{"id": 10, "subnet": "192.168.10.0/24"}],
             "ports": [{"portId": "1", "type": "trunk", "vlan": 99, "allowedVlans": "10,20"},
                       {"portId": "2", "type": "access", "vlan": 10}]}
    result = analyze_segmentation([doc(host("192.168.10.7"))], clean)
    assert not [k for k in kinds(result) if k.startswith("config_") and k not in {"config_vlans", "config_correlation"}]


def test_wording_never_claims_certainty_for_inference():
    xml = doc(host("192.168.1.10", mac="AA:00:00:00:00:01"), host("192.168.2.10", mac="AA:00:00:00:00:02"),
              host("10.9.0.5", hops=[(1, "192.168.1.1", ""), (2, "10.9.0.5", "")]))
    result = analyze_segmentation([xml])
    for finding in result["findings"]:
        if finding["confidence"] != "detected":
            assert "confirmed" not in json.dumps(finding).lower()
    assert "switch-level VLAN configuration cannot be derived" in segmentation_html(result)


# -- supplied-evidence loader --------------------------------------------------------

def test_load_supplied_evidence_reads_sidecars_and_ignores_bad_or_huge_files(tmp_path):
    assert load_supplied_evidence(tmp_path) is None
    (tmp_path / segmentation.SUPPLIED_JSON_NAME).write_text(json.dumps(MERAKI))
    (tmp_path / segmentation.SUPPLIED_CONFIG_NAME).write_text(IOS)
    loaded = load_supplied_evidence(tmp_path)
    assert loaded["source"] == "Meraki dashboard export" and "vlan 10" in loaded["config_text"]
    (tmp_path / segmentation.SUPPLIED_JSON_NAME).write_text("{not json")
    assert "vlans" not in load_supplied_evidence(tmp_path)
    (tmp_path / segmentation.SUPPLIED_CONFIG_NAME).write_text("x" * (segmentation.MAX_SUPPLIED_BYTES + 1))
    assert load_supplied_evidence(tmp_path) is None


# -- passive guarantee and rendering -------------------------------------------------

def test_module_has_no_network_or_process_primitives():
    source = Path(segmentation.__file__).read_text()
    for forbidden in ("import socket", "subprocess", "scapy", "import requests", "urllib", "os.system"):
        assert forbidden not in source


def test_html_escapes_scan_derived_text_and_shows_levels():
    hostile = '<img src=x onerror=alert(1)>'
    xml = doc(host("192.168.1.2", names=[f"vlan7.{hostile}"], scripts=[("s", "Port VLAN ID: 5")]))
    html = segmentation_html(analyze_segmentation([xml]))
    assert hostile not in html and "&lt;img" in html
    for word in ("Detected", "Likely", "Unverified", "Limits of this analysis"):
        assert word in html


def test_appendix_includes_segmentation_once_and_updates_the_vlan_status_note():
    xml = doc(host("192.168.1.2", scripts=[("lldp", "Port VLAN ID: 20")]))
    page = append_recommendations("<html><body>Report</body></html>", [xml])
    again = append_recommendations(page, [xml])
    assert again.count('id="segmentation-analysis"') == 1 and again.count('id="topology-recommendations"') == 1
    assert "VLAN evidence is listed under Segmentation" in again
    flat = append_recommendations("<body>Report</body>", [doc(host("192.168.1.2"))])
    assert "Cabling, switch ports and VLAN relationships are unverified." in flat
    assert "VLAN evidence is listed" not in flat


def test_appendix_uses_supplied_evidence():
    page = append_recommendations("<body>R</body>", [doc(host("192.168.10.7"))], supplied_evidence=MERAKI)
    assert "Meraki dashboard export" in page and "native VLAN 1" in page


def test_appendix_is_omitted_when_there_is_nothing_to_report():
    assert append_recommendations("<body>R</body>", [doc()]) == "<body>R</body>"


# -- route ---------------------------------------------------------------------------

def _route_client(monkeypatch, tmp_path, supplied=None):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", raising=False)
    scans_dir = tmp_path / "scans"
    rel = "Acme/2026-03-14/scan_120000_192.168.10.0_24"
    scan_dir = scans_dir / rel
    scan_dir.mkdir(parents=True)
    (scan_dir / "runtime.xml").write_bytes(doc(host("192.168.10.7"), host("192.168.20.9", scripts=[("lldp", "Port VLAN ID: 20")])))
    if supplied:
        (scan_dir / segmentation.SUPPLIED_JSON_NAME).write_text(json.dumps(supplied))

    class Store:
        def get_report_artifact(self, scan_path):
            return {"xml_path": f"{rel}/runtime.xml", "payload": {}} if scan_path == rel else None

    app = Flask(__name__)
    app.config["TESTING"] = True
    register_core_routes(app, {
        "build_liveness_payload": lambda **kw: {"status": "ok"},
        "build_readiness_payload": lambda **kw: ({"status": "ok"}, 200),
        "get_app_version": lambda: "v1", "get_default_interface_cached": lambda: "en0", "get_versions": lambda: {},
        "job_registry": type("J", (), {"snapshot": lambda self: {"has_active_jobs": False, "active_jobs": []}})(),
        "runtime_store": Store(), "scans_dir": scans_dir, "settings_state": {}, "startup_state": {"startup_complete": True},
        "get_auto_scan_thread": lambda: None,
    })
    headers = {"Authorization": "Basic " + base64.b64encode(b"scanner:secret-pass").decode()}
    return app.test_client(), headers, rel


def test_segmentation_route_serves_json_and_html(monkeypatch, tmp_path):
    client, headers, rel = _route_client(monkeypatch, tmp_path, supplied=MERAKI)
    env = {"REMOTE_ADDR": "127.0.0.1"}
    data = client.get(f"/api/runtime/reports/{rel}/segmentation", headers=headers, environ_overrides=env)
    assert data.status_code == 200 and data.headers["Cache-Control"] == "private, no-store"
    payload = data.get_json()
    assert payload["summary"]["detected"] >= 2 and 20 in payload["summary"]["vlan_ids"]
    page = client.get(f"/api/runtime/reports/{rel}/segmentation?format=html", headers=headers, environ_overrides=env)
    assert page.status_code == 200 and page.mimetype == "text/html"
    assert "default-src 'none'" in page.headers["Content-Security-Policy"]
    assert b"Segmentation &amp; VLAN observations" in page.data
    assert client.get("/api/runtime/reports/missing/segmentation", headers=headers, environ_overrides=env).status_code == 404
    assert client.get(f"/api/runtime/reports/{rel}/segmentation").status_code in (401, 403)
