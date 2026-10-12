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
    for document in xml_documents:
        root = ET.fromstring(document)
        for host in root.findall('host'):
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
    return '''<section id="topology-recommendations" class="card topology-recommendations">
    <style>.topology-recommendations{margin:24px auto;padding:24px;max-width:1100px;color:#34372b;background:#faf9f5;border:1px solid #b5b69d;border-radius:8px}.topology-recommendations h2{font-size:22px}.topology-recommendations h3{margin-top:20px}.topology-recommendations p{margin:8px 0;line-height:1.45}.topology-recommendations table{width:100%;border-collapse:collapse;font-size:12px}.topology-recommendations td,.topology-recommendations th{padding:7px;border-bottom:1px solid #d8d5c8;text-align:left;vertical-align:top}.topology-pair{display:flex;gap:12px;margin:12px 0}.topology-box{flex:1;min-width:0;padding:12px;border:1px solid #aaa98f;border-radius:6px;overflow-wrap:anywhere}.topology-recommendations li{margin:6px 0}@media print{.topology-recommendations{break-before:page;border-radius:0;font-size:10pt}.topology-box{break-inside:avoid}.topology-recommendations h2,.topology-recommendations h3{break-after:avoid}.topology-recommendations tr{break-inside:avoid}}@media(max-width:650px){.topology-pair{display:block}.topology-box{margin-bottom:10px}}</style>
    <h2>Topology &amp; address recommendations</h2>
    <p><strong>Option 1 · minimal disruption:</strong> keep the current subnet, gateway and working server addresses. Give only printers, infrastructure and selected fixed stations stable, documented addresses. Prefer DHCP reservations tied to verified device MACs. A printer could use .50 if that address is available and the DHCP configuration permits it.</p>
    <p><strong>Option 2 · future redesign:</strong> assess separate VLANs for staff, guests, printers and building/IoT systems when operational needs justify it. Define routing, access rules and capacity before selecting subnets. No renumbering or configuration change is performed by this report.</p>
    ''' + ''.join(sections) + '''
    <h3>Confirm before assigning an address</h3><ol>
    <li>Read the authoritative DHCP scope, reservations, exclusions, leases and subnet mask. “Not seen in a scan” does not mean unused.</li>
    <li>Identify each device and owner; check inventory and existing DNS records. Keep existing .10 servers and other working fixed addresses unless there is a specific reason to move them.</li>
    <li>For a reservation, ensure the DHCP server supports the chosen address and its allocation policy. For a manually configured static address, exclude it from dynamic allocation and record gateway, mask and DNS settings.</li>
    <li>Move one device at a time during an agreed window. Update print queues and address-based rules as needed; verify connectivity and retain the old configuration for rollback.</li>
    </ol><p><strong>Scope:</strong> conceptual before/after addressing view based on available scan evidence, not a verified physical topology. Confirm all proposals with the network administrator.</p></section>'''


def append_recommendations(html, xml_documents):
    panel = recommendation_html(xml_documents)
    if not panel:
        return html
    html = re.sub(r'<section id="topology-recommendations".*?</section>', '', html, flags=re.DOTALL)
    return re.sub(r'</body\s*>', lambda match: panel + match.group(0), html, count=1, flags=re.IGNORECASE)
