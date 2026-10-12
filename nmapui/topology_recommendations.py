"""Additive, advisory-only addressing appendix for the established Nmap PDF."""
from html import escape
import ipaddress
from collections import defaultdict
import re
import xml.etree.ElementTree as ET

VERSION = 1


def recommendation_html(xml_documents):
    """Describe observations separately from an illustrative /24 address plan.

    No address is declared free, no device role is inferred from its address,
    and no network settings are changed. /24 boundaries are examples rather
    than a claim about a discovered subnet mask or DHCP configuration.
    """
    groups = defaultdict(set)
    incomplete = set()
    for document in xml_documents:
        root = ET.fromstring(document)
        for host in root.findall('host'):
            if host.get('timedout') == 'true':
                incomplete.update(n.get('addr', '') for n in host.findall('address') if n.get('addrtype') == 'ipv4')
            status = host.find('status')
            if status is not None and status.get('state') != 'up':
                continue
            for node in host.findall('address'):
                if node.get('addrtype') != 'ipv4':
                    continue
                address = ipaddress.ip_address(node.get('addr', ''))
                if address.version == 4 and address.is_private and not address.is_loopback and not address.is_link_local:
                    groups[str(ipaddress.ip_network(f'{address}/24', strict=False))].add(address)
    if not groups:
        return ''
    rows = [
        ('Gateway / core', '1–9', 'Keep the existing gateway; do not move it just to fit this example.'),
        ('Servers / services', '10–29', 'Keep existing servers such as .10; record DNS and dependent services.'),
        ('Switches / Wi-Fi', '30–49', 'Reserve management addresses for identified network equipment.'),
        ('Printers / fixed peripherals', '50–69', 'Example: reserve .50 for one verified printer MAC, after checking availability.'),
        ('Fixed workstations', '70–89', 'Only stations that need a stable address; ordinary clients can remain dynamic.'),
        ('Growth / exceptions', '90–99', 'Document exceptions and keep spare capacity.'),
        ('Dynamic clients', '100–254', 'Illustrative DHCP range; confirm the actual scope, exclusions and capacity first.'),
    ]
    sections = []
    for network, addresses in sorted(groups.items()):
        ordered = sorted(addresses)
        prefix = str(ordered[0]).rsplit('.', 1)[0]
        high = sum(int(str(a).rsplit('.', 1)[1]) >= 100 for a in ordered)
        observed = ', '.join(map(str, ordered[:48]))
        if len(ordered) > 48:
            observed += f'; plus {len(ordered) - 48} more observed addresses'
        table = ''.join(f'<tr><td>{escape(role)}</td><td>{prefix}.{escape(span)}</td><td>{escape(note)}</td></tr>' for role, span, note in rows)
        sections.append(f'''
        <h3>{escape(network)} — illustrative address grouping</h3>
        <p><strong>Observed:</strong> {len(ordered)} responding addresses in this /24 grouping; {high} are .100 or higher. This distribution does not establish DHCP use, device roles, subnet mask, or physical connections.</p>
        <div class="topology-pair">
          <div class="topology-box"><strong>BEFORE · observed address inventory</strong><p>[ Existing network ]<br/>└ [ {escape(observed)} ]</p><p>Unclassified devices remain unclassified. Cabling, switch ports and VLAN relationships are unverified.</p></div>
          <div class="topology-box"><strong>AFTER · proposed logical grouping</strong><p>[ Existing gateway / subnet ]<br/>├ [ Servers · retain .10 where applicable ]<br/>├ [ Network equipment · .30–49 ]<br/>├ [ Printers · .50–69 ]<br/>├ [ Fixed stations · .70–89 ]<br/>└ [ Dynamic clients · .100+ ]</p><p>Planning diagram only; these groups are not separate VLANs or a verified physical topology.</p></div>
        </div>
        <table><thead><tr><th>Device group</th><th>Example addresses</th><th>Recommendation</th></tr></thead><tbody>{table}</tbody></table>''')
    coverage_note = ('<p><strong>Incomplete scan coverage:</strong> service scans timed out for ' + escape(', '.join(sorted(incomplete))) + '. Empty port results do not establish that ports are closed or that the device has no vulnerabilities.</p>') if incomplete else ''
    return '''<section id="topology-recommendations" class="card topology-recommendations">
    <style>.topology-recommendations{margin:24px auto;padding:24px;max-width:1100px;color:#34372b;background:#faf9f5;border:1px solid #b5b69d;border-radius:8px}.topology-recommendations h2{font-size:22px}.topology-recommendations h3{margin-top:20px}.topology-recommendations p{margin:8px 0;line-height:1.45}.topology-recommendations table{width:100%;border-collapse:collapse;font-size:12px}.topology-recommendations td,.topology-recommendations th{padding:7px;border-bottom:1px solid #d8d5c8;text-align:left;vertical-align:top}.topology-pair{display:flex;gap:12px;margin:12px 0}.topology-box{flex:1;min-width:0;padding:12px;border:1px solid #aaa98f;border-radius:6px;overflow-wrap:anywhere}.topology-recommendations li{margin:6px 0}@media print{.topology-recommendations{break-before:page;border-radius:0;font-size:10pt;padding:16px;margin:0;max-width:none}.topology-recommendations p,.topology-recommendations li{font-size:10pt;line-height:1.3;margin:6px 0}.topology-recommendations h2{font-size:18pt;margin:8px 0}.topology-recommendations h3{font-size:12pt;margin:12px 0 6px}.topology-recommendations table{font-size:9pt}.topology-recommendations td,.topology-recommendations th{padding:5px}.topology-recommendations>p:last-child{break-inside:avoid}.topology-box{break-inside:avoid}.topology-recommendations h2,.topology-recommendations h3{break-after:avoid}.topology-recommendations tr{break-inside:avoid}}@media(max-width:650px){.topology-pair{display:block}.topology-box{margin-bottom:10px}}</style>
    <h2>Topology &amp; address recommendations</h2>
    ''' + coverage_note + '''
    <p><strong>Option 1 · minimal disruption:</strong> keep the current subnet, gateway and working server addresses. Give only printers, infrastructure and selected fixed stations stable, documented addresses. Prefer DHCP reservations tied to verified device MACs. A printer could use .50 if that address is available and the DHCP configuration permits it.</p>
    <p><strong>Option 2 · future redesign:</strong> assess separate VLANs for staff, guests, printers and building/IoT systems when operational needs justify it. Define routing, access rules and capacity before selecting subnets. No renumbering or configuration change is performed by this report.</p>
    ''' + ''.join(sections) + '''
    <h3>Confirm before assigning an address</h3><ol>
    <li>Read the authoritative DHCP scope, reservations, exclusions, leases and subnet mask. “Not seen in a scan” does not mean unused.</li>
    <li>Identify each device and owner; check inventory and existing DNS records. Keep existing .10 servers and other working fixed addresses unless there is a specific reason to move them.</li>
    <li>For a reservation, ensure the DHCP server supports the chosen address and its allocation policy. For a manually configured static address, exclude it from dynamic allocation and record gateway, mask and DNS settings.</li>
    <li>Move one device at a time during an agreed window. Update print queues and address-based rules as needed; verify connectivity and retain the old configuration for rollback.</li>
    </ol><p><strong>Scope:</strong> conceptual before/after addressing view based on available scan evidence, not a verified physical topology. Confirm all proposals with the network administrator.</p></section>'''


def append_recommendations(html, xml_documents, network_plan=None):
    panel = recommendation_html(xml_documents) + network_plan_html(network_plan)
    if not panel:
        return html
    html = re.sub(r'<section id="(?:topology-recommendations|customer-network-plan)".*?</section>', '', html, flags=re.DOTALL)
    return re.sub(r'</body\s*>', lambda match: panel + match.group(0), html, count=1, flags=re.IGNORECASE)

def network_plan_html(plan):
    """Render user-supplied operational relationships, never guessed cabling."""
    if not isinstance(plan, dict) or not plan.get('devices'):
        return ''
    devices = plan['devices']
    def card(device):
        fields = [escape(str(device.get(key, '') or '')) for key in ('name', 'role', 'status', 'proposed_ip', 'notes')]
        name, role, status, address, notes = fields
        icon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="3" y="3" width="18" height="12" rx="2"/><path d="M8 21h8M12 15v6"/></svg>' if device.get('parent') == 'lan' else '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M6 8V3h12v5M6 17H3V8h18v9h-3M6 14h12v7H6z"/></svg>'
        return f'<article class="plan-device">{icon}<strong>{name}</strong><span>{role}</span><span>{status}</span><b>Proposed: {address}</b><small>{notes}</small></article>'
    branches = []
    for station in devices:
        if station.get('parent') != 'lan':
            continue
        children = [d for d in devices if d.get('parent') == station.get('id')]
        branches.append('<div class="plan-branch">' + card(station) + '<div class="plan-children"><small>Used by this station · connection medium unconfirmed</small>' + ''.join(card(d) for d in children) + '</div></div>')
    table = ''.join('<tr>' + ''.join('<td>' + escape(str(d.get(k, '') or '')) + '</td>' for k in ('name', 'status', 'proposed_ip')) + '</tr>' for d in devices)
    return '''<section id="customer-network-plan" class="topology-recommendations"><style>.plan-root{padding:10px;border:1px solid #95977e;border-radius:6px;background:#e9eadf}.plan-branches{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:14px}.plan-branch{border-left:2px solid #95977e;padding-left:12px}.plan-device{display:grid;grid-template-columns:24px 1fr;gap:4px 8px;border:1px solid #c8c9b9;border-radius:6px;padding:10px;margin:8px 0;background:#faf9f5;break-inside:avoid}.plan-device>svg{grid-row:1 / 6}.plan-children{border-left:1px dashed #95977e;margin-left:12px;padding-left:12px}.plan-device small{line-height:1.4}.plan-device>span,.plan-device>b,.plan-device>small{grid-column:2}.plan-device>b{color:#515b30}@media(max-width:700px){.plan-branches{grid-template-columns:1fr}}@media print{.plan-branches{gap:10px}.plan-device{font-size:9pt}}</style><h2>''' + escape(str(plan.get('title', 'Customer network plan'))) + '''</h2><p><strong>Planned operational map · not verified cabling.</strong> Online/offline notes below are supplied by the customer; Device identity notes distinguish confirmed matches from unverified devices.</p><div class="plan-root">[ Existing LAN · ''' + escape(str(plan.get('subnet', ''))) + ''' ]<br/>Gateway: ''' + escape(str(plan.get('gateway', 'unconfirmed'))) + ''' · switch ports and physical links unverified</div><div class="plan-branches">''' + ''.join(branches) + '''</div><h3>Proposed stable addresses</h3><table><thead><tr><th>Device</th><th>Reported state</th><th>Proposed IP</th></tr></thead><tbody>''' + table + '''</tbody></table><p><strong>Not assigned:</strong> verify the authoritative DHCP scope, exclusions, existing reservations and device MACs before using these addresses. Prefer DHCP reservations. USB-only printers, scales and cameras do not need LAN IP addresses. Retain existing .10 servers and gateway settings.</p></section>'''
