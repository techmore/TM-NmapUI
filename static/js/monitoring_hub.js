// ---- Monitoring Hub (repurposed Dragnet card, issue #11) ----

const MONITOR_CHANGE_KEY = 'nmapui_monitor_change_summary';

function updateMonitoringHubChangeSummary(diffSummary) {
    const el = document.getElementById('monitor-change-summary');
    if (!el) return;
    if (!diffSummary || typeof diffSummary !== 'object') return;

    if (!diffSummary.has_changes) {
        el.textContent = 'No changes';
        el.className = 'font-medium text-olive-500';
        localStorage.removeItem(MONITOR_CHANGE_KEY);
        return;
    }

    const parts = [];
    if (diffSummary.added_hosts?.length) parts.push(`+${diffSummary.added_hosts.length} host`);
    if (diffSummary.removed_hosts?.length) parts.push(`-${diffSummary.removed_hosts.length} host`);
    if (diffSummary.new_ports?.length) parts.push(`+${diffSummary.new_ports.length} port`);
    if (diffSummary.removed_ports?.length) parts.push(`-${diffSummary.removed_ports.length} port`);
    if (diffSummary.new_vulnerabilities?.length) parts.push(`+${diffSummary.new_vulnerabilities.length} CVE`);
    if (diffSummary.removed_vulnerabilities?.length) parts.push(`-${diffSummary.removed_vulnerabilities.length} CVE`);

    if (!parts.length) {
        el.textContent = 'Changed';
    } else {
        el.textContent = parts.join(', ');
        // Persist so the summary survives reloads until the next clean scan.
        try { localStorage.setItem(MONITOR_CHANGE_KEY, el.textContent); } catch (_) {}
    }
    el.className = 'font-bold text-amber-600';
}

function restoreMonitoringHubChangeSummary() {
    const el = document.getElementById('monitor-change-summary');
    if (!el || el.textContent !== '--') return;
    try {
        const saved = localStorage.getItem(MONITOR_CHANGE_KEY);
        if (saved) {
            el.textContent = saved;
            el.className = 'font-bold text-amber-600';
        }
    } catch (_) {}
}

function updateMonitoringHubAutoMonitor(config = {}) {
    const stateEl = document.getElementById('monitor-auto-scan-state');
    const detailEl = document.getElementById('monitor-auto-scan-detail');
    const indicator = document.getElementById('auto-monitor-indicator');
    if (!stateEl) return;

    const enabled = !!config.enabled;
    stateEl.textContent = enabled ? `On (${config.recurrence || 'daily'})` : 'Off';
    stateEl.className = enabled ? 'font-bold text-amber-600' : 'font-medium text-olive-400';
    indicator?.classList.toggle('hidden', !enabled);

    if (detailEl) {
        if (enabled) {
            detailEl.textContent = `${config.startTime || '01:00'} - target ${config.target || 'current network'}`;
            detailEl.classList.remove('hidden');
        } else {
            detailEl.textContent = '';
            detailEl.classList.add('hidden');
        }
    }
}

function initializeMonitoringHub(socket) {
    restoreMonitoringHubChangeSummary();

    socket.on('sync_state', (state = {}) => {
        if (state.autoScan) updateMonitoringHubAutoMonitor(state.autoScan);
    });
    socket.on('initial_data', (data = {}) => {
        if (data.autoScan) updateMonitoringHubAutoMonitor(data.autoScan);
    });
    socket.on('auto_scan_config', (config = {}) => updateMonitoringHubAutoMonitor(config));

    socket.on('report_ready', () => {
        // A fresh report means a fresh diff summary may arrive shortly after.
        const el = document.getElementById('monitor-change-summary');
        if (el) { el.textContent = 'checking...'; }
    });
    socket.on('report_diff_summary', (payload = {}) => updateMonitoringHubChangeSummary(payload.diff_summary || payload));

    // Replay/live scan feedback surfaces in the report status strip.
    socket.on('scan_feedback', (data) => {
        const message = typeof data === 'string' ? data : (data?.message || '');
        if (message && typeof window.showReportStatus === 'function') {
            window.showReportStatus(message, 'info');
        }
    });

    document.getElementById('open-reports-tab-btn')?.addEventListener('click', () => {
        document.getElementById('tab-reports-btn')?.click();
    });
}
