"""Passive, evidence-based VLAN and segmentation analysis (issue #31).

Nothing here sends traffic.  The analysis reads data the scanner already
holds (Nmap XML: addresses, MACs, hostnames, traceroute hops and script
output) plus an optional, read-only configuration export that an operator drops
next to the scan (``l2_evidence.json`` and/or ``switch_config.txt``).  It never
crafts 802.1Q frames, never probes for trunking and never attempts VLAN
hopping.

Every finding carries one of three confidence levels:

``detected``
    A VLAN identifier or trunk setting is present in the data itself, either
    observed in scan script output (LLDP/CDP/802.1Q/DTP text) or stated in a
    supplied switch/firewall configuration.  The finding's ``source`` says
    which; supplied configuration describes intent, not live state.
``likely``
    Several independent observations point to a segment boundary (routed path,
    hostname convention, several subnets sharing one broadcast domain) but no
    VLAN identifier was seen.
``unverified``
    Only subnet grouping, or no evidence at all.  The report says what data
    would settle the question instead of guessing.
"""
from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

VERSION = 1
DETECTED, LIKELY, UNVERIFIED = "detected", "likely", "unverified"
CONFIDENCE_ORDER = {DETECTED: 0, LIKELY: 1, UNVERIFIED: 2}
SOURCE_OBSERVED, SOURCE_SUPPLIED, SOURCE_INFERRED = "observed", "supplied", "inferred"

MAX_EVIDENCE = 6
MAX_SUPPLIED_BYTES = 1024 * 1024
SUPPLIED_JSON_NAME = "l2_evidence.json"
SUPPLIED_CONFIG_NAME = "switch_config.txt"

LIMITATIONS = (
    "Passive analysis of existing scan data only: no VLAN probes, tagged frames or trunk-negotiation requests were sent.",
    "Nmap does not report subnet masks, so hosts are grouped by /24 unless a supplied configuration gives exact subnets.",
    "Absence of evidence is not evidence of absence: a flat-looking result does not prove the network is unsegmented.",
)

_VLAN_VALUE_PATTERNS = (
    ("port_vlan", "Port VLAN ID (LLDP)", re.compile(r"(?:port\s+vlan\s+id|pvid)\s*(?:\(pvid\))?\s*[:=]?\s*(\d{1,4})\b", re.I)),
    ("native_vlan", "Native VLAN (CDP/LLDP)", re.compile(r"native\s+vlan(?:\s+id)?\s*[:=]?\s*(\d{1,4})\b", re.I)),
    ("vlan", "VLAN ID", re.compile(r"(?<!native\s)(?<!port\s)\bvlan[\s_-]*id\s*[:=]?\s*(\d{1,4})\b", re.I)),
    ("vlan", "802.1Q VLAN tag", re.compile(r"802\.1q[^\n]{0,40}?\bvlan\s*[:=]?\s*(\d{1,4})\b", re.I)),
)
_DTP_PATTERN = re.compile(r"\bDTP\b|dynamic\s+trunk|dynamic\s+(?:auto|desirable)", re.I)
_VLAN_NAME_LABEL = re.compile(r"(?<![a-z0-9])(?:vlan|vl)[-_]?(\d{1,4})(?![a-z0-9])", re.I)


def _valid_vlan(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 1 <= number <= 4094 else None


def _cap(items, limit=MAX_EVIDENCE):
    items = list(items)
    if len(items) > limit:
        return items[:limit] + [f"plus {len(items) - limit} more"]
    return items


def _expand_vlan_list(text) -> set[int] | None:
    """Parse '1,5-7' into {1,5,6,7}; None means unrestricted ('all' or empty)."""
    value = str(text if text is not None else "").strip().lower()
    if value in {"", "all", "1-4094", "1-4093"}:
        return None
    if value == "none":
        return set()
    found: set[int] = set()
    for part in re.split(r"[,\s]+", value):
        part = part.removeprefix("add").strip()
        if not part:
            continue
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            continue
        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
        if 1 <= low <= high <= 4094:
            found.update(range(low, high + 1))
    return found if found else None


# -- scan data -------------------------------------------------------------------

def _script_text(script) -> str:
    lines = [script.get("output") or ""]
    for elem in script.iter("elem"):
        if elem.text and elem.text.strip():
            key = elem.get("key")
            lines.append(f"{key}: {elem.text.strip()}" if key else elem.text.strip())
    return "\n".join(lines)


def _usable_private(address):
    return address.version == 4 and address.is_private and not address.is_loopback and not address.is_link_local


def _parse_hosts(xml_documents, limitations):
    hosts = []
    for document in xml_documents or ():
        try:
            root = ET.fromstring(document)
        except ET.ParseError:
            limitations.append("A scan document could not be parsed and was skipped.")
            continue
        for node in root.findall("host"):
            status = node.find("status")
            if status is not None and status.get("state") != "up":
                continue
            ip = mac = None
            vendor = ""
            for address in node.findall("address"):
                kind = address.get("addrtype")
                if kind == "ipv4":
                    ip = address.get("addr")
                elif kind == "mac":
                    mac, vendor = address.get("addr"), address.get("vendor", "")
            try:
                parsed = ipaddress.ip_address(ip) if ip else None
            except ValueError:
                parsed = None
            hops = []
            for hop in node.findall("trace/hop"):
                try:
                    ttl = int(hop.get("ttl") or 0)
                except ValueError:
                    ttl = 0
                hops.append((ttl, hop.get("ipaddr") or "", hop.get("host") or ""))
            hops.sort(key=lambda hop: hop[0])
            hosts.append({
                "ip": ip, "addr": parsed, "mac": mac, "vendor": vendor,
                "names": [n.get("name") for n in node.findall("hostnames/hostname") if n.get("name")],
                "hops": hops,
                "scripts": [(s.get("id", ""), _script_text(s)) for s in node.iter("script")],
            })
    return hosts


def _segments(hosts):
    segments: dict[str, dict] = {}
    for host in hosts:
        if host["addr"] is None or not _usable_private(host["addr"]):
            continue
        network = str(ipaddress.ip_network(f"{host['addr']}/24", strict=False))
        segment = segments.setdefault(network, {"network": network, "hosts": [], "local": [], "routed": []})
        segment["hosts"].append(host["ip"])
        via = [hop for hop in host["hops"] if hop[1] and hop[1] != host["ip"]]
        if host["mac"]:
            segment["local"].append(host)  # MAC replies only arrive from the scanner's own broadcast domain
        elif via:
            segment["routed"].append((host, via))
    return segments


# -- supplied configuration --------------------------------------------------------

def load_supplied_evidence(directory) -> dict | None:
    """Read optional operator-supplied configuration beside a scan, size-capped."""
    directory = Path(directory)
    evidence: dict = {}
    for name in (SUPPLIED_JSON_NAME, SUPPLIED_CONFIG_NAME):
        path = directory / name
        try:
            if not path.is_file() or path.stat().st_size > MAX_SUPPLIED_BYTES:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
            if name == SUPPLIED_JSON_NAME:
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    evidence.update(loaded)
            else:
                evidence["config_text"] = (evidence.get("config_text", "") + "\n" + raw).strip()
                evidence.setdefault("source", SUPPLIED_CONFIG_NAME)
        except (OSError, ValueError):
            continue
    return evidence or None


def _parse_config_text(text):
    vlans: dict[int, dict] = {}
    ports: list[dict] = []
    port = None
    vlan_block = None
    interface_vlan = None
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        indented = line[:1] in (" ", "\t")
        if not indented:
            port = vlan_block = interface_vlan = None
            match = re.match(r"vlan\s+(\d+)$", stripped, re.I)
            if match and _valid_vlan(match.group(1)):
                vlan_block = _valid_vlan(match.group(1))
                vlans.setdefault(vlan_block, {"id": vlan_block})
                continue
            match = re.match(r"interface\s+(\S+)", stripped, re.I)
            if match:
                name = match.group(1)
                svi = re.match(r"vlan(\d+)$", name, re.I)
                if svi and _valid_vlan(svi.group(1)):
                    interface_vlan = _valid_vlan(svi.group(1))
                    vlans.setdefault(interface_vlan, {"id": interface_vlan})
                else:
                    port = {"name": name, "mode": None, "native": None, "allowed": None, "access": None, "nonegotiate": False}
                    ports.append(port)
            continue
        if vlan_block and (match := re.match(r"name\s+(\S.*)", stripped, re.I)):
            vlans[vlan_block]["name"] = match.group(1)
        elif interface_vlan and (match := re.match(r"ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", stripped, re.I)):
            try:
                vlans[interface_vlan]["subnet"] = str(ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False))
            except ValueError:
                pass
        elif port is not None:
            if match := re.match(r"switchport mode\s+(.+)", stripped, re.I):
                port["mode"] = " ".join(match.group(1).lower().split())
            elif match := re.match(r"switchport trunk native vlan\s+(\d+)", stripped, re.I):
                port["native"] = _valid_vlan(match.group(1))
            elif match := re.match(r"switchport trunk allowed vlan\s+(.+)", stripped, re.I):
                port["allowed"] = match.group(1).strip()
            elif match := re.match(r"switchport access vlan\s+(\d+)", stripped, re.I):
                port["access"] = _valid_vlan(match.group(1))
            elif re.match(r"switchport nonegotiate", stripped, re.I):
                port["nonegotiate"] = True
    return list(vlans.values()), [p for p in ports if p["mode"] or p["native"] or p["allowed"] or p["access"]]


def _normalise_supplied(evidence):
    """Return (source, vlans, ports) from Meraki-style JSON fields and/or IOS-style text."""
    if not isinstance(evidence, dict):
        return "", [], []
    source = str(evidence.get("source") or "supplied configuration")[:120]
    vlans: dict[int, dict] = {}
    ports: list[dict] = []
    for item in evidence.get("vlans") or []:
        if not isinstance(item, dict) or (vid := _valid_vlan(item.get("id"))) is None:
            continue
        subnet = None
        try:
            subnet = str(ipaddress.ip_network(str(item.get("subnet")), strict=False)) if item.get("subnet") else None
        except ValueError:
            pass
        vlans[vid] = {"id": vid, "name": str(item.get("name") or "")[:60], "subnet": subnet}
    for item in evidence.get("ports") or []:
        if not isinstance(item, dict):
            continue
        mode = str(item.get("type") or item.get("mode") or "").strip().lower() or None
        vlan = _valid_vlan(item.get("vlan"))
        ports.append({
            "name": str(item.get("name") or item.get("portId") or "port")[:60],
            "mode": mode,
            "native": vlan if mode == "trunk" else _valid_vlan(item.get("native")),
            "allowed": item.get("allowedVlans", item.get("allowed")) if mode == "trunk" else None,
            "access": vlan if mode == "access" else None,
            "nonegotiate": bool(item.get("nonegotiate")),
        })
    text_vlans, text_ports = _parse_config_text(evidence.get("config_text"))
    for entry in text_vlans:
        merged = vlans.setdefault(entry["id"], {"id": entry["id"], "name": "", "subnet": None})
        merged["name"] = merged.get("name") or entry.get("name", "")
        merged["subnet"] = merged.get("subnet") or entry.get("subnet")
    ports.extend(text_ports)
    return source, sorted(vlans.values(), key=lambda v: v["id"]), ports


# -- findings ----------------------------------------------------------------------

class _Findings:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, kind, confidence, source, title, summary, evidence, recommendations):
        self.items.append({
            "id": f"{kind}-{len(self.items) + 1}", "kind": kind, "confidence": confidence, "source": source,
            "title": title, "summary": summary, "evidence": _cap(evidence), "recommendations": recommendations,
        })


def _observed_vlan_findings(hosts, out):
    by_kind: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    dtp: list[str] = []
    for host in hosts:
        label = host["ip"] or "scanned host"
        for script_id, text in host["scripts"]:
            for kind, description, pattern in _VLAN_VALUE_PATTERNS:
                for match in pattern.finditer(text):
                    vid = _valid_vlan(match.group(1))
                    if vid is None:
                        continue
                    line = next((l.strip() for l in text.splitlines() if match.group(0) in l), match.group(0))[:120]
                    cite = f"{label} · script {script_id or 'unknown'} · {description}: {line}"
                    if cite not in by_kind[kind][vid]:
                        by_kind[kind][vid].append(cite)
            if _DTP_PATTERN.search(text):
                dtp.append(f"{label} · script {script_id or 'unknown'} output mentions trunk negotiation")
    native = by_kind.get("native_vlan", {})
    other = {}
    for kind in ("port_vlan", "vlan"):
        for vid, cites in by_kind.get(kind, {}).items():
            other.setdefault(vid, []).extend(cites)
    if other:
        ids = sorted(other)
        recs = [f"Confirm VLAN {', '.join(map(str, ids))} maps to the intended segment and is documented with its subnet and owner."]
        if 1 in other:
            recs.append("VLAN 1 was reported; avoid carrying user or device traffic on the default VLAN.")
        out.add("vlan_ids_observed", DETECTED, SOURCE_OBSERVED,
                f"VLAN identifier{'s' if len(ids) > 1 else ''} reported by network devices: {', '.join(map(str, ids))}",
                "VLAN IDs appear in discovery-protocol or 802.1Q text returned during the scan.",
                [c for vid in ids for c in other[vid]], recs)
    if native:
        ids = sorted(native)
        recs = ["Use a dedicated, otherwise-unused native VLAN on trunks and tag all production VLANs; confirm the native VLAN matches on both ends of each link."]
        if 1 in native:
            recs.insert(0, "Native VLAN 1 was reported; move trunk native VLANs off the default VLAN.")
        out.add("native_vlan_observed", DETECTED, SOURCE_OBSERVED,
                f"Native VLAN reported: {', '.join(map(str, ids))}",
                "A trunk or uplink advertised its native VLAN.",
                [c for vid in ids for c in native[vid]], recs)
    if dtp:
        out.add("trunk_negotiation_observed", DETECTED, SOURCE_OBSERVED,
                "Trunk negotiation (DTP) referenced in scan output",
                "A device appears to participate in dynamic trunk negotiation.", dtp,
                ["Set access ports to a fixed access mode and trunks to a fixed trunk mode with negotiation disabled (for example switchport nonegotiate)."])
    return set(other) | set(native)


def _name_hint_findings(hosts, out):
    hints: dict[int, list[str]] = defaultdict(list)
    for host in hosts:
        # Router-interface names may abbreviate to "vl20"; end-device names must spell out "vlan".
        pairs = [(name, f"{host['ip'] or 'host'} hostname", ("vlan",)) for name in host["names"]]
        pairs += [(hop[2], f"traceroute hop {hop[0]} ({hop[1]})", ("vlan", "vl")) for hop in host["hops"] if hop[2]]
        for name, where, prefixes in pairs:
            for label in str(name).lower().split("."):
                match = _VLAN_NAME_LABEL.search(label) if label.startswith(prefixes) else None
                if match and (vid := _valid_vlan(match.group(1))):
                    cite = f"{where}: {name}"
                    if cite not in hints[vid]:
                        hints[vid].append(cite)
    if hints:
        ids = sorted(hints)
        out.add("vlan_name_hint", LIKELY, SOURCE_INFERRED,
                f"Device names suggest VLAN {', '.join(map(str, ids))}",
                "Reverse-DNS or router-interface names follow a VLAN naming convention. Names are labels, not proof of tagging.",
                [c for vid in ids for c in hints[vid]],
                ["Verify the named VLANs on the switch or router before relying on them; request an LLDP/CDP neighbour table or configuration export to confirm."])
    return set(hints)


def _segment_findings(segments, out):
    covered: set[str] = set()
    locals_ = [s for s in segments.values() if s["local"]]
    if len(locals_) > 1:
        names = [s["network"] for s in locals_]
        covered.update(names)
        evidence = [f"{h['ip']} (MAC {h['mac']}) answered on the scanner's broadcast domain in {s['network']}" for s in locals_ for h in s["local"][:2]]
        out.add("shared_broadcast_domain", LIKELY, SOURCE_INFERRED,
                f"Several IP subnets answered at layer 2: {', '.join(names)}",
                "MAC addresses are only returned for hosts on the scanner's own broadcast domain, so these subnets share a link "
                "with the scanner (unless the scanner host has more than one network interface).",
                evidence,
                ["If these subnets are meant to be isolated, they are not separated at layer 2: verify the port VLAN assignments on the switch and move each subnet to its own VLAN with routed, filtered access between them."])
    for segment in segments.values():
        routed = segment["routed"]
        if not routed or segment["local"]:
            continue
        covered.add(segment["network"])
        routers = []
        for _, via in routed:
            routers.extend(hop[1] for hop in via if hop[1] not in routers)
        gateways = sorted({via[-1][1] for _, via in routed})
        evidence = [f"{h['ip']}: traceroute {' > '.join(hop[1] for hop in via)} > {h['ip']}" for h, via in routed[:3]]
        evidence.append(f"Last router before the segment: {', '.join(gateways)}")
        out.add("routed_segment", LIKELY, SOURCE_INFERRED,
                f"{segment['network']} is reached through a router",
                f"{len(routed)} host(s) here are separated from the scanner by {len(routers)} router hop(s) and returned no MAC address, "
                "so this looks like a separate layer-3 segment (a VLAN or a routed subnet).",
                evidence,
                [f"The scanner reached {segment['network']} across a router: confirm inter-segment firewall/ACL rules match intent, especially if it is meant to be a guest, IoT or server network.",
                 "Obtain the router/L3-switch VLAN interface list to confirm whether this segment is VLAN-backed."])
    # The scanner's own broadcast domain (MAC-bearing hosts) is a known vantage point, not an unclassified subnet.
    rest = sorted(n for n in segments if n not in covered and not segments[n]["local"])
    if len(segments) >= 2 and rest:
        out.add("subnets_unclassified", UNVERIFIED, SOURCE_INFERRED,
                f"Multiple subnets seen without routing evidence: {', '.join(rest)}",
                "Subnet grouping alone does not show whether these are separate VLANs, routed links or one flat network.",
                [f"{n}: {len(segments[n]['hosts'])} responding host(s)" for n in rest],
                ["Run a deep scan (-A includes traceroute) from the scanner, or supply an LLDP/CDP table or switch/router configuration export, to classify these subnets."])
    elif len(segments) == 1 and not covered:
        (segment,) = segments.values()
        out.add("single_segment", UNVERIFIED, SOURCE_INFERRED,
                f"One subnet observed: {segment['network']}",
                "Only a single subnet was seen. This does not show whether other VLANs or segments exist beyond the scanned range.",
                [f"{len(segment['hosts'])} responding host(s)"],
                ["If segmentation matters for this site, scan other known subnets and supply the switch configuration so VLAN boundaries can be checked rather than assumed."])


def _supplied_findings(segments, evidence, out):
    source, vlans, ports = _normalise_supplied(evidence)
    if not vlans and not ports:
        return set()
    ids = {v["id"] for v in vlans}
    if vlans:
        described = [f"VLAN {v['id']}" + (f" {v['name']}" if v.get("name") else "") + (f" · {v['subnet']}" if v.get("subnet") else "") for v in vlans]
        out.add("config_vlans", DETECTED, SOURCE_SUPPLIED, f"{len(vlans)} VLAN(s) defined in {source}",
                "Defined in supplied configuration; this describes configured intent, not live traffic.",
                described, ["Reconcile the configured VLAN list with the scanned subnets and retire VLANs nothing uses."])
        networks = [(ipaddress.ip_network(v["subnet"]), v) for v in vlans if v.get("subnet")]
        mapped, unmatched = [], []
        for network, segment in segments.items():
            seg_net = ipaddress.ip_network(network)
            match = next((v for net, v in networks if seg_net.subnet_of(net) or net.subnet_of(seg_net)), None)
            (mapped if match else unmatched).append((network, match))
        if mapped:
            out.add("config_correlation", DETECTED, SOURCE_SUPPLIED, "Scanned subnets matched to configured VLANs",
                    "A scanned subnet falls inside a subnet stated in the supplied configuration.",
                    [f"{n} -> VLAN {v['id']}" + (f" {v['name']}" if v.get("name") else "") for n, v in mapped],
                    ["Check each matched VLAN's firewall/ACL policy against what the scan could reach."])
        if unmatched and networks:
            out.add("config_gap", UNVERIFIED, SOURCE_INFERRED, "Scanned subnets not described by the supplied configuration",
                    "These subnets answered but no configured VLAN subnet covers them (possibly another device's configuration).",
                    [n for n, _ in unmatched],
                    ["Supply the configuration for the device that routes these subnets, or confirm they are intentionally unmanaged."])
    trunks = [p for p in ports if p["mode"] == "trunk"]
    access_vlans = {p["access"] for p in ports if p["mode"] == "access" and p["access"]}
    native1 = [p["name"] for p in trunks if p["native"] == 1]
    if native1:
        out.add("config_native_vlan_default", DETECTED, SOURCE_SUPPLIED, f"{len(native1)} trunk(s) use native VLAN 1",
                "Trunks are configured with the default native VLAN.", native1,
                ["Move trunk native VLANs to a dedicated, unused VLAN and tag production VLANs, so untagged frames cannot land in a user VLAN."])
    shared = [p["name"] + f" (native {p['native']})" for p in trunks if p["native"] and p["native"] != 1 and p["native"] in access_vlans]
    if shared:
        out.add("config_native_in_use", DETECTED, SOURCE_SUPPLIED, "Trunk native VLAN is also used by access ports",
                "A native VLAN shared with end-device ports weakens VLAN separation.", shared,
                ["Give the native VLAN no access ports; use a separate blackhole VLAN."])
    wide = [p["name"] for p in trunks if _expand_vlan_list(p["allowed"]) is None]
    if wide:
        out.add("config_trunk_unpruned", DETECTED, SOURCE_SUPPLIED, f"{len(wide)} trunk(s) allow all VLANs",
                "No allowed-VLAN list restricts these trunks.", wide,
                ["Prune each trunk to the VLANs that actually need to cross it; list the allowed VLANs explicitly."])
    dynamic = [p["name"] for p in ports if p["mode"] and "dynamic" in p["mode"] and not p["nonegotiate"]]
    if dynamic:
        out.add("config_dtp_dynamic", DETECTED, SOURCE_SUPPLIED, f"{len(dynamic)} port(s) negotiate trunking",
                "Dynamic auto/desirable ports will form a trunk if the neighbour asks.", dynamic,
                ["Set these ports to explicit access (or trunk) mode and disable negotiation (switchport nonegotiate)."])
    vlan1 = [p["name"] for p in ports if p["mode"] == "access" and p["access"] == 1]
    if vlan1:
        out.add("config_access_vlan_default", DETECTED, SOURCE_SUPPLIED, f"{len(vlan1)} access port(s) in VLAN 1",
                "End-device ports remain on the default VLAN.", vlan1,
                ["Assign these ports to purpose-named VLANs and keep VLAN 1 unused."])
    return ids


def _limitations_for(findings, hosts, supplied):
    notes = list(LIMITATIONS)
    if not any(h["hops"] for h in hosts):
        notes.append("No traceroute data was present in this scan; routing-based boundary checks need a deep scan (-A).")
    if not supplied:
        notes.append(f"No switch or router configuration was supplied (optional {SUPPLIED_JSON_NAME} / {SUPPLIED_CONFIG_NAME} beside the scan); VLAN IDs and trunk settings cannot be checked without it or LLDP/CDP data.")
    return notes


def analyze_segmentation(xml_documents, supplied_evidence=None) -> dict:
    """Return ``{'segments', 'findings', 'recommendations', 'summary', 'limitations'}``."""
    extra_limitations: list[str] = []
    hosts = _parse_hosts(xml_documents, extra_limitations)
    segments = _segments(hosts)
    out = _Findings()
    observed_ids = _observed_vlan_findings(hosts, out)
    _name_hint_findings(hosts, out)
    _segment_findings(segments, out)
    supplied_ids = _supplied_findings(segments, supplied_evidence, out)
    findings = sorted(out.items, key=lambda f: CONFIDENCE_ORDER[f["confidence"]])
    if not findings and hosts and not segments:
        out.add("no_private_segments", UNVERIFIED, SOURCE_INFERRED, "No private IPv4 segments observed",
                "Responding hosts were not in private IPv4 ranges, so no subnet grouping was attempted.", [], [])
        findings = out.items
    recommendations, seen = [], set()
    for finding in findings:
        for text in finding["recommendations"]:
            if text not in seen:
                seen.add(text)
                recommendations.append({"confidence": finding["confidence"], "text": text, "basis": finding["id"]})
    summary = {level: sum(f["confidence"] == level for f in findings) for level in CONFIDENCE_ORDER}
    summary["vlan_ids"] = sorted(observed_ids | supplied_ids)
    return {
        "version": VERSION,
        "segments": [
            {"network": s["network"], "hosts": len(s["hosts"]), "local_hosts": len(s["local"]), "routed_hosts": len(s["routed"])}
            for s in sorted(segments.values(), key=lambda s: ipaddress.ip_network(s["network"]))
        ],
        "findings": findings,
        "recommendations": recommendations,
        "summary": summary,
        "limitations": _limitations_for(findings, hosts, supplied_evidence) + extra_limitations,
    }


# -- presentation ------------------------------------------------------------------

_LEVEL_TEXT = {
    DETECTED: "Detected · VLAN ID or trunk setting present in the data",
    LIKELY: "Likely · several observations agree, no VLAN ID seen",
    UNVERIFIED: "Unverified · subnet grouping or no evidence",
}


def segmentation_html(analysis) -> str:
    """Render the analysis as an escaped, print-friendly report section."""
    from html import escape
    if not analysis or (not analysis["findings"] and not analysis["segments"]):
        return ""
    rows = []
    for finding in analysis["findings"]:
        evidence = "".join(f"<li>{escape(str(item))}</li>" for item in finding["evidence"])
        rows.append(
            f'<tr><td><strong class="seg-{escape(finding["confidence"])}">{escape(finding["confidence"].capitalize())}</strong>'
            f'<br/><small>{escape(finding["source"])}</small></td>'
            f'<td><strong>{escape(finding["title"])}</strong><br/>{escape(finding["summary"])}</td>'
            f'<td><ul>{evidence}</ul></td></tr>'
        )
    recs = "".join(
        f'<li><strong>{escape(r["confidence"].capitalize())}:</strong> {escape(r["text"])}</li>' for r in analysis["recommendations"]
    )
    legend = "".join(f"<li>{escape(text)}</li>" for text in _LEVEL_TEXT.values())
    limits = "".join(f"<li>{escape(text)}</li>" for text in analysis["limitations"])
    table = (
        '<table><thead><tr><th>Confidence</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        if rows else '<p>No VLAN or segmentation evidence was present in this scan data.</p>'
    )
    return (
        '<section id="segmentation-analysis" class="topology-recommendations">'
        '<style>#segmentation-analysis ul{margin:0;padding-left:16px}#segmentation-analysis small{color:#5a5d48}'
        '#segmentation-analysis tr{break-inside:avoid}</style>'
        '<h2>Segmentation &amp; VLAN observations</h2>'
        '<p>Passive analysis of data this scan already collected. Observed facts are separated from inference; no VLAN probes were sent, '
        'and switch-level VLAN configuration cannot be derived from host scans alone.</p>'
        f'<ul>{legend}</ul>{table}'
        + (f'<h3>Configuration recommendations</h3><ol>{recs}</ol>' if recs else '')
        + f'<h3>Limits of this analysis</h3><ul>{limits}</ul></section>'
    )


def segmentation_page(analysis, title="Segmentation & VLAN observations") -> str:
    """Standalone, script-free HTML page for the in-app view."""
    from html import escape
    body = segmentation_html(analysis) or "<p>No VLAN or segmentation evidence was present in this scan data.</p>"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title>"
        "<style>body{font:14px/1.45 system-ui,sans-serif;margin:0;background:#f4f3ec;color:#34372b}"
        ".topology-recommendations{max-width:1100px;margin:24px auto;padding:20px;background:#faf9f5;border:1px solid #b5b69d;border-radius:8px}"
        ".topology-recommendations table{width:100%;border-collapse:collapse;font-size:12px}"
        ".topology-recommendations td,.topology-recommendations th{padding:7px;border-bottom:1px solid #d8d5c8;text-align:left;vertical-align:top}"
        "@media(max-width:700px){.topology-recommendations{margin:8px;padding:12px}}</style></head><body>"
        + body + "</body></html>"
    )
