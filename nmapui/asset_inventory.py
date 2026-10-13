"""Printable, write-in inventory reports built from Nmap's saved host data."""

from datetime import datetime
from html import escape

from nmapui.mac_vendor import (
    is_globally_administered_unicast_mac,
    is_locally_administered_mac,
    lookup_mac_vendor,
)


ICON_PATHS = {
    "gateway": '<path d="M4 12h16v7H4zM7 9l5-4 5 4M8 15h.01M12 15h.01M16 15h.01"/><path d="M3 9a9 9 0 0 1 18 0"/>',
    "server": '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h.01M11 7h5M8 12h.01M11 12h5M8 17h.01M11 17h5"/>',
    "desktop": '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    "network": '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="m10.8 7.2-4.5 9.5m6.9-9.5 4.5 9.5M7.5 19h9"/>',
    "unknown": '<path d="M12 3 21 8v8l-9 5-9-5V8z"/><path d="m3.5 8 8.5 5 8.5-5M12 13v8"/>',
    "laptop": '<rect x="5" y="4" width="14" height="12" rx="1.5"/><path d="M2.5 20h19l-1.5-4H4z"/>',
    "linux": '<rect x="4" y="5" width="16" height="14" rx="2"/><path d="m8 10 2 2-2 2m4 0h4"/>',
    "conference": '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m10 9 5 3-5 3z"/>',
    "printer": '<path d="M7 8V3h10v5M6 17H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v7H6zM18 11h.01"/>',
}
def _device_kind(asset):
    explicit_kind = str(asset.get("device_type") or "").lower()
    if explicit_kind in ICON_PATHS:
        return explicit_kind
    name = str(asset.get("hostname") or "").lower()
    vendor = str(asset.get("vendor") or "").lower()
    ports = str(asset.get("ports") or "").lower()
    if any(token in ports for token in ("515", "631", "9100")) or "printer" in name:
        return "printer"
    if "polycom" in vendor or "conference" in name or "phone" in name:
        return "conference"
    if "gateway" in name or "router" in name or "meraki" in vendor:
        return "gateway"
    if any(token in vendor for token in ("ubiquiti", "cisco")) or "access point" in name:
        return "network"
    if "server" in name or "windows server" in str(asset.get("os") or "").lower():
        return "server"
    if "laptop" in name or "notebook" in name:
        return "laptop"
    if "desktop" in name or "workstation" in name:
        return "desktop"
    return "unknown"


def _asset_mac_vendor(asset):
    mac = asset.get("mac")
    if mac and not is_globally_administered_unicast_mac(mac):
        return ""
    return str(asset.get("vendor") or "").strip() or lookup_mac_vendor(mac)


def _service_summary(asset, *, include_mac_vendor=True):
    summary = str(asset.get("scan_summary") or "").strip()
    ports = str(asset.get("ports") or "").strip()
    mac = str(asset.get("mac") or "").strip()
    vendor = _asset_mac_vendor(asset)
    details = []
    if include_mac_vendor and vendor and vendor.casefold() not in summary.casefold():
        details.append(f'MAC OUI vendor: {escape(vendor)}')
    elif include_mac_vendor and not vendor and is_locally_administered_mac(mac):
        if "random" not in summary.casefold() and "private" not in summary.casefold():
            details.append("MAC OUI vendor unavailable: private/randomized address")
    if summary:
        details.append(escape(summary))
    elif ports:
        details.append("Open: " + escape(ports))
    return "<br>".join(details) or "No service details returned"


def _mac_vendor_line(asset, mac):
    if not mac or mac == "—":
        return f"MAC: {mac}"
    vendor = _asset_mac_vendor(asset)
    if vendor:
        return f"MAC: {mac} · OUI vendor: {vendor}"
    if is_locally_administered_mac(mac):
        return f"MAC: {mac} · OUI vendor unavailable (randomized/private address)"
    if not is_globally_administered_unicast_mac(mac):
        return f"MAC: {mac} · OUI vendor unavailable (not a unicast address)"
    return f"MAC: {mac} · OUI vendor unknown"


def render_asset_inventory_html(
    assets,
    *,
    network="",
    title="Network device inventory",
    scanned_at=None,
    orientation="landscape",
    monochrome=False,
    notes="",
):
    """Render a self-contained print layout with vector icons and blank write-in fields."""
    orientation = "portrait" if str(orientation).lower() == "portrait" else "landscape"
    body_classes = " ".join(filter(None, ("monochrome" if monochrome else "", orientation)))
    body_class = f' class="{body_classes}"'
    scanned_at = scanned_at or datetime.now().astimezone().strftime("%B %d, %Y %H:%M %Z")
    network_label = escape(str(network or "Network not recorded"))
    title = escape(str(title or "Network device inventory"))
    assets = list(assets or [])
    expected_count = sum(bool(asset.get("expected")) for asset in assets)
    responding_count = len(assets) - expected_count
    items = []
    for asset in assets:
        is_expected = bool(asset.get("expected"))
        has_proposed_ip = bool(asset.get("proposed_ip"))
        ip = escape(str(asset.get("ip") or asset.get("proposed_ip") or "—"))
        ip_markup = (
            f'<span class="proposed-tag">DRAFT</span><br>{ip}'
            if has_proposed_ip else ip
        )
        hostname = escape(str(asset.get("hostname") or "Hostname not reported"))
        mac = escape(str(asset.get("mac") or "—"))
        kind = _device_kind(asset)
        icon = ICON_PATHS[kind]
        row_class = ' class="expected"' if is_expected else ""
        icon_cell = (
            f'<td class="icon {kind}"><svg viewBox="0 0 24 24" aria-hidden="true">{icon}</svg></td>'
        )
        if orientation == "portrait":
            detail_parts = []
            if is_expected:
                detail_parts.append('<span class="record-status">EXPECTED · NOT OBSERVED</span>')
            detail_parts.append(
                f'<span class="details-copy">{_service_summary(asset, include_mac_vendor=False)}</span>'
            )
            detail_parts.append(
                f'<span class="mac-inline">{escape(_mac_vendor_line(asset, mac))}</span>'
            )
            device_cell = (
                f'<td class="hostname">{hostname}<span class="write"><i></i></span></td>'
            )
            detail_cell = f'<td class="details">{"".join(detail_parts)}</td>'
            items.append(
                f'<tr{row_class}>{icon_cell}<td class="ip">{ip_markup}</td>'
                f'{device_cell}{detail_cell}</tr>'
            )
        else:
            status = '<span class="record-status">EXPECTED · NOT OBSERVED<br></span>' if is_expected else ""
            items.append(
                f'<tr{row_class}>{icon_cell}'
                f'<td class="ip">{ip_markup}</td><td class="hostname">{hostname}</td>'
                f'<td class="details">{status}{_service_summary(asset)}</td>'
                f'<td class="mac">{mac}</td><td class="write"><span></span><span></span></td></tr>'
            )
    column_count = 4 if orientation == "portrait" else 6
    empty = "" if items else (
        f'<tr><td colspan="{column_count}" class="empty">'
        'No responding hosts were recorded in this scan.</td></tr>'
    )
    if orientation == "portrait":
        colgroup = '<col style="width:8%"><col style="width:19%"><col style="width:31%"><col style="width:42%">'
        headings = "<th>TYPE</th><th>IP / DRAFT</th><th>DEVICE NAME · ROOM</th><th>SCAN DETAILS · MAC / OUI VENDOR</th>"
    else:
        colgroup = '<col class="icon"><col class="ip"><col class="hostname"><col class="details"><col class="mac"><col class="write">'
        headings = "<th>TYPE</th><th>IP / DRAFT</th><th>HOSTNAME</th><th>SCAN IDENTIFICATION / MAC OUI VENDOR</th><th>MAC ADDRESS</th><th>YOUR DESCRIPTION / ROOM</th>"
    legend = " ".join(
        f'<span class="{kind}"><svg viewBox="0 0 24 24" aria-hidden="true">{ICON_PATHS[kind]}</svg>{label}</span>'
        for kind, label in (("gateway", "Gateway"), ("server", "Server"), ("desktop", "Desktop"),
                            ("network", "Network gear"), ("printer", "Printer"), ("laptop", "Computer"),
                            ("unknown", "Unidentified"))
    )
    if expected_count:
        legend += '<span class="expected-legend"><b>Expected · not observed · draft IPs require DHCP check</b></span>'
    count_label = f'{responding_count} scan responder' + ("s" if responding_count != 1 else "")
    if expected_count:
        count_label += f' · {expected_count} expected device' + ("s" if expected_count != 1 else "") + " not observed"
    notes_html = f'<aside class="notes">{escape(str(notes))}</aside>' if notes else ""
    monochrome_css = """body.monochrome { color:#111; }
body.monochrome header { border-color:#222; }
body.monochrome h1, body.monochrome .eyebrow, body.monochrome td.ip { color:#111; }
body.monochrome .eyebrow, body.monochrome .sub, body.monochrome footer,
body.monochrome td.details, body.monochrome td.mac, body.monochrome .legend { color:#333; }
body.monochrome .badge { background:#f0f0f0; color:#111; }
body.monochrome th { background:#e6e6e6; color:#111; border-color:#777; }
body.monochrome tbody tr:nth-child(even) { background:#f5f5f5; }
body.monochrome td { border-color:#aaa; }
body.monochrome td.icon svg, body.monochrome .legend svg { color:#111 !important; }
body.monochrome .legend span { color:#111; }
body.monochrome td.write span { border-color:#888; }
body.monochrome .legend b { color:#111; }
body.monochrome .record-status, body.monochrome .proposed-tag { background:#e8e8e8; color:#111; }
body.monochrome .notes { background:#f3f3f3; border-color:#555; color:#111; }
""" if monochrome else ""
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>{title}</title><style>
@page {{ size: Letter {orientation}; margin: 5mm 6mm; }}
* {{ box-sizing:border-box; }}
body {{ color:#182434; font:10pt Arial, sans-serif; margin:0; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
header {{ display:flex; align-items:flex-end; justify-content:space-between; border-bottom:1.5px solid #244c78; padding:0 0 5px; }}
.eyebrow {{ color:#52708f; font-size:8pt; font-weight:bold; letter-spacing:1.4px; text-transform:uppercase; }}
h1 {{ color:#183557; font-size:18pt; letter-spacing:-.3px; margin:3px 0 0; }}
.badge {{ align-items:flex-end; background:#edf4fa; border-radius:4px; color:#244c78; display:flex; flex-direction:column; font-size:7.4pt; font-weight:bold; gap:2px; padding:5px 7px; text-align:right; }}
.badge .orientation {{ font-size:6.4pt; letter-spacing:.5px; }}
.sub {{ color:#536477; font-size:7.8pt; margin:6px 0 8px; }}
table {{ border-collapse:collapse; table-layout:fixed; width:100%; }}
col.icon {{ width:5%; }} col.ip {{ width:12%; }} col.hostname {{ width:19%; }} col.details {{ width:27%; }} col.mac {{ width:17%; }} col.write {{ width:20%; }}
thead {{ display:table-header-group; }} th {{ background:#eaf0f6; border-bottom:1px solid #b8c7d6; color:#35516d; font-size:6.8pt; letter-spacing:.3px; padding:3px 3px; text-align:left; }}
td {{ border-bottom:1px solid #dce3e9; height:24px; padding:1px 3px; vertical-align:middle; }} tbody tr:nth-child(even) {{ background:#f8fafc; }}
td.icon {{ padding:2px; text-align:center; }} td.icon svg {{ height:17px; width:17px; fill:none; stroke:currentColor; stroke-linecap:round; stroke-linejoin:round; stroke-width:1.8; }}
.gateway {{ color:#2d72b8; }} .server {{ color:#7558a6; }} .desktop {{ color:#227e71; }} .network {{ color:#3974a8; }} .unknown {{ color:#758392; }} .laptop {{ color:#34878a; }} .conference {{ color:#bf7a21; }} .printer {{ color:#b6514a; }}
td.ip {{ color:#163a5b; font: bold 8.2pt "DejaVu Sans Mono", monospace; white-space:nowrap; }} td.hostname {{ font-size:7.7pt; font-weight:bold; overflow-wrap:anywhere; }}
td.details {{ color:#47586a; font-size:7pt; line-height:1.18; overflow-wrap:anywhere; }} td.mac {{ color:#273444; font:bold 7.1pt "DejaVu Sans Mono",monospace; overflow-wrap:anywhere; }}
td.write span {{ border-bottom:1px solid #c8d1db; display:block; height:8px; }} .empty {{ color:#667687; font-size:10pt; height:80px; text-align:center; }}
.legend {{ align-items:center; color:#536477; display:flex; flex-wrap:wrap; font-size:6.6pt; gap:8px; margin-top:4px; }} .legend b {{ color:#23415f; }}
.legend span {{ align-items:center; display:inline-flex; gap:3px; }} .legend svg {{ fill:none; height:13px; stroke:currentColor; stroke-linecap:round; stroke-linejoin:round; stroke-width:1.8; width:13px; }}
.proposed-tag, .record-status {{ background:#edf4fa; border-radius:2px; color:#35516d; display:inline-block; font: bold 5.8pt Arial,sans-serif; letter-spacing:.2px; margin-bottom:2px; padding:1px 3px; }}
tr.expected {{ background:#f4f7fa; }}
td.hostname .write {{ display:block; margin-top:3px; }} td.hostname .write i {{ border-bottom:1px solid #c8d1db; display:block; height:10px; }}
.details-copy {{ display:block; }} .mac-inline {{ color:#273444; display:block; font:bold 6.7pt "DejaVu Sans Mono",monospace; margin-top:2px; }}
.notes {{ background:#f3f7fa; border-left:2px solid #8a9bad; color:#47586a; font-size:6.5pt; line-height:1.15; margin-top:3px; padding:3px 5px; }}
body.portrait header {{ align-items:flex-end; }}
body.portrait h1 {{ font-size:17pt; }}
body.portrait .badge {{ max-width:36%; }}
body.portrait .sub {{ font-size:7.5pt; margin:5px 0 6px; }}
body.portrait table {{ font-size:7pt; }}
body.portrait th {{ font-size:6.5pt; padding:3px 3px; }}
body.portrait td {{ height:auto; padding:2px 3px; vertical-align:top; }}
body.portrait td.icon svg {{ height:18px; width:18px; }}
body.portrait td.ip {{ font-size:7.3pt; line-height:1.1; white-space:normal; overflow-wrap:anywhere; }}
body.portrait td.hostname {{ font-size:7.7pt; line-height:1.1; }}
body.portrait td.details {{ font-size:7pt; line-height:1.08; }}
body.portrait td.hostname .write i {{ height:9px; }}
body.portrait .mac-inline {{ font-size:7.2pt; overflow-wrap:anywhere; }}
body.portrait .expected-legend {{ padding-top:1px; }}
{monochrome_css}
footer {{ border-top:1px solid #d7e0e8; color:#667687; display:flex; font-size:6.5pt; justify-content:space-between; margin-top:3px; padding-top:2px; break-inside:avoid; page-break-inside:avoid; }}
</style></head><body{body_class}>
<header><div><div class="eyebrow">Network asset inventory · printable worksheet</div><h1>{title}</h1></div><div class="badge"><span>{network_label}</span><span class="orientation">{orientation.upper()} · LETTER</span></div></header>
<p class="sub">Scan date: {escape(str(scanned_at))} &nbsp;·&nbsp; {count_label}. Hostnames appear when reported; MAC OUI vendors are matched locally from Nmap data. Private/randomized MACs are not attributed.</p>
<table><colgroup>{colgroup}</colgroup>
<thead><tr>{headings}</tr></thead>
<tbody>{''.join(items)}{empty}</tbody></table>
<div class="legend"><b>ICON KEY</b>{legend}</div>
{notes_html}
<footer><span>Blank lines are for device name, owner, location, or purpose.</span><span>Private network information · keep this report secure</span></footer>
</body></html>'''
