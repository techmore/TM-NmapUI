// Wire tab switching immediately (pure DOM) so tab clicks work even while the
// socket is still connecting. Data loads inside each tab handle their own readiness.
document.addEventListener('DOMContentLoaded', () => {
    if (typeof initializeAppTabs === 'function') {
        initializeAppTabs();
    }
    if (typeof initializeReportsTab === 'function') {
        initializeReportsTab();
    }
});

// Fetch the loopback socket token, then connect with it. The server rejects
// handshakes without the token (see allowRequest in server.js).
window.socket = null;
(async function initSocket() {
    let token = '';
    try {
        const res = await fetch('/api/socket-token');
        if (res.ok) {
            token = (await res.json()).token || '';
        }
    } catch (err) {
        console.warn('Could not fetch socket token; retrying unauthenticated.');
    }
    const socket = io.connect(window.location.origin, {
        auth: { token },
        query: { token }
    });
    window.socket = socket;
    socket.on('connect', () => console.log('Socket.IO connected'));
    socket.on('connect_error', (err) => console.error('Socket.IO auth/connect error:', err.message));
    window.dispatchEvent(new CustomEvent('socket-ready', { detail: socket }));
})();

// All module initialization needs the live socket, so wait for it (or DOM ready)
// before wiring modules. Both conditions are awaited below.
let socketReadyPromise = null;
function whenSocketReady() {
    if (!socketReadyPromise) {
        socketReadyPromise = new Promise((resolve) => {
            if (window.socket) return resolve(window.socket);
            window.addEventListener('socket-ready', (e) => resolve(e.detail), { once: true });
        });
    }
    return socketReadyPromise;
}
function whenDomReady() {
    if (document.readyState !== 'loading') return Promise.resolve();
    return new Promise((resolve) => document.addEventListener('DOMContentLoaded', resolve, { once: true }));
}

async function bootstrapApp() {
    const [socket] = await Promise.all([whenSocketReady(), whenDomReady()]);
    // Ensure the engine.io connection is live so early emits are not dropped.
    if (!socket.connected) {
        await new Promise((resolve) => socket.on('connect', resolve));
    }
    if (typeof initializeScanRuntime === 'function') {
        initializeScanRuntime(socket);
    }
    // Request the legacy sync snapshot now that all listeners are wired (#230 bridge).
    socket.emit('get_initial_data');
    // Transport-level reconnect = new server session; closures hold the dead socket.
    // Reload to rebuild everything against the live session (#237 follow-up).
    if (socket.io) {
        socket.io.on('reconnect', () => { location.reload(); });
    }
    if (typeof initializeScanButtonWiring === 'function') {
        initializeScanButtonWiring(socket);
    }
    if (typeof initializeDiscoveryUI === 'function') {
        initializeDiscoveryUI(socket);
    }
    if (typeof initializeMonitoringHub === 'function') {
        initializeMonitoringHub(socket);
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
    if (typeof initializeAuditLog === 'function') {
        initializeAuditLog();
    }

    const reloadLastScanBtn = document.getElementById('reload-last-scan-btn');
    if (reloadLastScanBtn) {
        reloadLastScanBtn.addEventListener('click', function() {
            if (typeof loadHostsFromStorage === 'function' && !loadHostsFromStorage()) {
                if (window.currentMatchedCustomerId && window.currentMatchedCustomerId !== 'unknown') {
                    socket.emit('resume_from_last_scan', {
                        customer_id: window.currentMatchedCustomerId,
                        max_days: 30
                    });
                }
            }
        });
    }
}

bootstrapApp();
