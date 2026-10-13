"""Printable, write-in inventory reports built from Nmap's saved host data."""

from datetime import datetime
from html import escape


ICON_PATHS = {
    "gateway": '<path d="M4 12h16v7H4zM7 9l5-4 5 4M8 15h.01M12 15h.01M16 15h.01"/><path d="M3 9a9 9 0 0 1 18 0"/>',
    "server": '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h.01M11 7h5M8 12h.01M11 12h5M8 17h.01M11 17h5"/>',
    "desktop": '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    "network": '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="m10.8 7.2-4.5 9.5m6.9-9.5 4.5 9.5M7.5 19h9"/>',
    "unknown": '<path d="M12 3 21 8v8l-9 5-9-5V8z"/><path d="m3.5 8 8.5 5 8.5-5M12 13v8"/>',
    "laptop": '<rect x="5" y="4" width="14" height="12" rx="1.5"/><path d="M2.5 20h19l-1.5-4H4z"/>',
    "conference": '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m10 9 5 3-5 3z"/>',
    "printer": '<path d="M7 8V3h10v5M6 17H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v7H6zM18 11h.01"/>',
}
ICON_COLORS = {
    "gateway": "#2d72b8", "server": "#7558a6", "desktop": "#227e71",
    "network": "#3974a8", "unknown": "#758392", "laptop": "#34878a",
    "conference": "#bf7a21", "printer": "#b6514a",
}


def _device_kind(asset):
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


def _service_summary(asset):
    ports = str(asset.get("ports") or "").strip()
    vendor = str(asset.get("vendor") or "").strip()
    details = []
    if vendor:
        details.append(escape(vendor))
    if ports:
        details.append("Open: " + escape(ports))
    return "<br>".join(details) or "No service details returned"


def render_asset_inventory_html(assets, *, network="", title="Network device inventory", scanned_at=None):
    """Render a self-contained print layout with vector icons and blank write-in fields."""
    scanned_at = scanned_at or datetime.now().astimezone().strftime("%B %d, %Y %H:%M %Z")
    network_label = escape(str(network or "Network not recorded"))
    title = escape(str(title or "Network device inventory"))
    items = []
    for asset in assets or []:
        ip = escape(str(asset.get("ip") or "—"))
        hostname = escape(str(asset.get("hostname") or "Hostname not reported"))
        mac = escape(str(asset.get("mac") or "—"))
        kind = _device_kind(asset)
        icon = ICON_PATHS[kind]
        items.append(
            f'<tr><td class="icon {kind}"><svg viewBox="0 0 24 24" aria-hidden="true">{icon}</svg></td>'
            f'<td class="ip">{ip}</td><td class="hostname">{hostname}</td>'
            f'<td class="details">{_service_summary(asset)}</td><td class="mac">{mac}</td>'
            '<td class="write"><span></span><span></span></td></tr>'
        )
    empty = "" if items else '<tr><td colspan="6" class="empty">No responding hosts were recorded in this scan.</td></tr>'
    legend = " ".join(
        f'<span><svg viewBox="0 0 24 24" aria-hidden="true">{ICON_PATHS[kind]}</svg>{label}</span>'
        for kind, label in (("gateway", "Gateway"), ("server", "Server"), ("desktop", "Desktop"),
                            ("network", "Network gear"), ("printer", "Printer"), ("laptop", "Computer"),
                            ("unknown", "Unidentified"))
    )
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>{title}</title><style>
@page {{ size: Letter landscape; margin: 12mm 10mm 13mm; }}
* {{ box-sizing:border-box; }}
body {{ color:#182434; font:10pt Arial, sans-serif; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
header {{ display:flex; align-items:flex-end; justify-content:space-between; border-bottom:2px solid #244c78; padding:0 0 8px; }}
.eyebrow {{ color:#52708f; font-size:8pt; font-weight:bold; letter-spacing:1.4px; text-transform:uppercase; }}
h1 {{ color:#183557; font-size:22pt; letter-spacing:-.4px; margin:4px 0 0; }}
.badge {{ background:#edf4fa; border-radius:5px; color:#244c78; font-size:9pt; font-weight:bold; padding:8px 10px; }}
.sub {{ color:#536477; font-size:8.5pt; margin:10px 0 13px; }}
table {{ border-collapse:collapse; table-layout:fixed; width:100%; }}
col.icon {{ width:5%; }} col.ip {{ width:12%; }} col.hostname {{ width:19%; }} col.details {{ width:27%; }} col.mac {{ width:17%; }} col.write {{ width:20%; }}
thead {{ display:table-header-group; }} th {{ background:#eaf0f6; border-bottom:1px solid #b8c7d6; color:#35516d; font-size:7.4pt; letter-spacing:.45px; padding:7px 6px; text-align:left; }}
td {{ border-bottom:1px solid #dce3e9; height:48px; padding:5px 6px; vertical-align:middle; }} tbody tr:nth-child(even) {{ background:#f8fafc; }}
td.icon {{ padding:3px; text-align:center; }} td.icon svg {{ height:23px; width:23px; fill:none; stroke:currentColor; stroke-linecap:round; stroke-linejoin:round; stroke-width:1.8; }}
.gateway {{ color:#2d72b8; }} .server {{ color:#7558a6; }} .desktop {{ color:#227e71; }} .network {{ color:#3974a8; }} .unknown {{ color:#758392; }} .laptop {{ color:#34878a; }} .conference {{ color:#bf7a21; }} .printer {{ color:#b6514a; }}
td.ip {{ color:#163a5b; font: bold 9pt "DejaVu Sans Mono", monospace; white-space:nowrap; }} td.hostname {{ font-size:8.4pt; font-weight:bold; overflow-wrap:anywhere; }}
td.details {{ color:#47586a; font-size:7.8pt; line-height:1.28; overflow-wrap:anywhere; }} td.mac {{ color:#566475; font:7pt "DejaVu Sans Mono",monospace; overflow-wrap:anywhere; }}
td.write span {{ border-bottom:1px solid #c8d1db; display:block; height:15px; }} .empty {{ color:#667687; font-size:10pt; height:80px; text-align:center; }}
.legend {{ align-items:center; color:#536477; display:flex; flex-wrap:wrap; font-size:7.5pt; gap:14px; margin-top:10px; }} .legend b {{ color:#23415f; }}
.legend span {{ align-items:center; display:inline-flex; gap:4px; }} .legend svg {{ fill:none; height:16px; stroke:currentColor; stroke-linecap:round; stroke-linejoin:round; stroke-width:1.8; width:16px; }}
''' + "".join(f'<style>.legend span:nth-of-type({i}) svg {{ color:{color}; }}</style>' for i, color in enumerate(ICON_COLORS.values(), 1)) + f'''
footer {{ border-top:1px solid #d7e0e8; color:#667687; display:flex; font-size:7.5pt; justify-content:space-between; margin-top:10px; padding-top:7px; }}
</style></head><body>
<header><div><div class="eyebrow">Network asset inventory · printable worksheet</div><h1>{title}</h1></div><div class="badge">{network_label}</div></header>
<p class="sub">Scan date: {escape(str(scanned_at))} &nbsp;·&nbsp; {len(items)} responding device(s). Hostnames and vendors are shown only when the scan reported them.</p>
<table><colgroup><col class="icon"><col class="ip"><col class="hostname"><col class="details"><col class="mac"><col class="write"></colgroup>
<thead><tr><th>TYPE</th><th>IP ADDRESS</th><th>HOSTNAME</th><th>SCAN IDENTIFICATION</th><th>MAC ADDRESS</th><th>YOUR DESCRIPTION / ROOM</th></tr></thead>
<tbody>{''.join(items)}{empty}</tbody></table>
<div class="legend"><b>ICON KEY</b>{legend}</div>
<footer><span>Blank lines are for device name, owner, location, or purpose.</span><span>Private network information · keep this report secure</span></footer>
</body></html>'''
