(() => {
  let timer;
  function textNode(tag, value) { const e = document.createElement(tag); e.textContent = value || ''; return e; }
  async function renderPlan() {
    const panel = document.getElementById('network-plan-panel');
    if (!panel) return;
    try {
      const response = await fetch('/api/settings'); if (!response.ok) return;
      const settings = await response.json();
      const target = (document.getElementById('scan-target')?.value || '').trim();
      const customer = document.getElementById('customer-quick-add')?.value || window.currentMatchedCustomerId || '';
      const profile = (settings.target_profiles || []).find(p => p.target === target && p.customer_id === customer && p.network_plan);
      panel.replaceChildren(); panel.classList.toggle('hidden', !profile); if (!profile) return;
      const plan = profile.network_plan;
      panel.append(textNode('h2', plan.title || profile.name), textNode('p', 'Planned operational map · customer-reported device states; cabling and PC identities unverified.'));
      const root = textNode('div', 'LAN ' + plan.subnet + ' · Gateway ' + plan.gateway + ' · switch links unverified'); root.style.cssText = 'padding:8px;border:1px solid #a6ab90;border-radius:6px;margin:8px 0'; panel.append(root);
      const grid = document.createElement('div'); grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px';
      function card(device) {
        const box = document.createElement('article'); box.style.cssText = 'border:1px solid #c4c8b5;border-radius:6px;padding:8px;margin:6px 0;background:#fafaf5';
        box.append(textNode('strong', (device.parent === 'lan' ? '▣ ' : '▤ ') + device.name), textNode('div', device.role), textNode('div', device.status), textNode('b', 'Proposed: ' + device.proposed_ip), textNode('p', device.notes)); return box;
      }
      (plan.devices || []).filter(d => d.parent === 'lan').forEach(station => {
        const branch = document.createElement('div'); branch.style.cssText = 'border-left:2px solid #939b78;padding-left:10px'; branch.append(card(station));
        const children = document.createElement('div'); children.style.cssText = 'margin-left:12px;border-left:1px dashed #939b78;padding-left:10px'; children.append(textNode('small', 'Used by this station · connection type unconfirmed'));
        plan.devices.filter(d => d.parent === station.id).forEach(d => children.append(card(d))); branch.append(children); grid.append(branch);
      }); panel.append(grid, textNode('p', 'Proposed addresses only. Check DHCP scope, reservations and device MACs before assignment. USB-only devices do not need LAN IPs. Preserve existing servers and gateway.'));
    } catch (_) { /* Keep scan controls independent of optional planning data. */ }
  }
  document.addEventListener('change', e => { if (['scan-target','customer-quick-add'].includes(e.target.id)) renderPlan(); });
  document.addEventListener('DOMContentLoaded', () => { renderPlan(); timer = setInterval(renderPlan, 15000); });
})();
