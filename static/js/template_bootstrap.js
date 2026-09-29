// Wire tab switching immediately (pure DOM) so tab clicks work while the
// socket is still connecting. Data loads handle their own readiness.
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        if (typeof initializeReportsTab === 'function') initializeReportsTab();
    });
} else if (typeof initializeReportsTab === 'function') {
    initializeReportsTab();
}

// Fetch the loopback socket token, then connect with it (#210).
window.socket = null;
let __socketReadyResolve;
const __socketReady = new Promise((resolve) => { __socketReadyResolve = resolve; });
(async function initSocket() {
    let token = '';
    try {
        const res = await fetch('/api/socket-token');
        if (res.ok) token = (await res.json()).token || '';
    } catch (err) {
        console.warn('Could not fetch socket token.');
    }
    const socket = io.connect(`http://${document.domain}:${location.port}`, {
        auth: { token },
        query: { token }
    });
    window.socket = socket;
    socket.on('connect', () => console.log('Socket.IO connected'));
    socket.on('connect_error', (err) => console.error('Socket.IO error:', err.message));
    __socketReadyResolve(socket);
})();

async function bootstrapTemplateApp() {
    const socket = await __socketReady;
    if (document.readyState === 'loading') {
        await new Promise((resolve) => document.addEventListener('DOMContentLoaded', resolve, { once: true }));
    }
    // Ensure the underlying engine.io connection is live so early
    // emits (tab loads, get_reports) are not dropped.
    if (!socket.connected) {
        await new Promise((resolve) => socket.on('connect', resolve));
    }
    if (typeof initializeScanRuntime === 'function') {
        initializeScanRuntime(socket);
    }
    // Request the legacy sync snapshot now that all listeners are wired (#230 bridge).
    socket.emit('get_initial_data');
    // A transport-level reconnect creates a new server session; module
    // closures still hold the dead socket, so events would vanish. Reload
    // to rebuild everything against the live session (#237 follow-up).
    socket.io.on('reconnect', () => { location.reload(); });
    if (typeof initializeScanButtonWiring === 'function') {
        initializeScanButtonWiring(socket);
    }
    if (typeof initializeDiscoveryUI === 'function') {
        initializeDiscoveryUI(socket);
    }
    if (typeof TableSorter === 'function') {
        window.tableSorter = new TableSorter('discovery-table');
    }
    if (typeof initializeSiteChrome === 'function') {
        initializeSiteChrome();
    }
    if (typeof initializeUpdateModal === 'function') {
        initializeUpdateModal(socket, {
            showReportStatus: window.showReportStatus
        });
    }
    if (typeof initializeAutoUpdateBanner === 'function') {
        initializeAutoUpdateBanner(socket);
    }
    if (typeof initializeLayoutRuntime === 'function') {
        initializeLayoutRuntime();
    }
    if (typeof initializeReportsTab === 'function') {
        initializeReportsTab();
    }
    if (typeof initializeSettingsTab === 'function') {
        initializeSettingsTab(socket);
    }
    if (typeof initializeAutoScanUI === 'function') {
        initializeAutoScanUI(socket, {
            getClientJobs: window.getClientJobs,
            getLastScanTarget: window.getLastScanTarget
        });
    }
    if (typeof initializeReportGenerationUI === 'function') {
        initializeReportGenerationUI(socket, {
            getClientJobs: window.getClientJobs
        });
    }
    if (typeof initializeCustomerUI === 'function') {
        initializeCustomerUI(socket);
    }
    if (typeof initializeMonitoringHub === 'function') {
        initializeMonitoringHub(socket);
    }
    if (typeof initializeAuditLog === 'function') {
        initializeAuditLog();
    }
}

document.getElementById('reload-last-scan-btn').addEventListener('click', function() {
    // Try localStorage first (faster, more current); fall back to server XML
    if (!loadHostsFromStorage()) {
        if (window.currentMatchedCustomerId && window.currentMatchedCustomerId !== 'unknown') {
            socket.emit('resume_from_last_scan', {
                customer_id: window.currentMatchedCustomerId,
                max_days: 30
            });
        }
    }
});
bootstrapTemplateApp();
