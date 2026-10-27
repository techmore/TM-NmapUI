const APP_TABS = ['dashboard', 'history', 'reports', 'customers', 'logs', 'settings'];

// Per-tab activation callbacks. A feature module that owns a tab's data
// (reports_tab.js owns History and Reports) registers here instead of
// redefining switchAppTab, so this file keeps the one tab switcher and its
// shared behaviour (cross-tab sync, hash, tab:changed) always runs.
const appTabActivationHandlers = new Map();
const APP_TAB_SYNC_KEY = 'nmapui.activeTab';
const APP_TAB_SYNC_CHANNEL = 'nmapui-ui-state';

function registerAppTabActivation(tab, handler) {
    if (!APP_TABS.includes(tab) || typeof handler !== 'function') return;
    appTabActivationHandlers.set(tab, handler);
}

function readAppTabFromHash() {
    const tab = (window.location.hash || '').slice(1);
    return APP_TABS.includes(tab) ? tab : null;
}

function readStoredAppTab() {
    try {
        const tab = localStorage.getItem(APP_TAB_SYNC_KEY);
        return APP_TABS.includes(tab || '') ? tab : null;
    } catch (error) {
        return null;
    }
}

// Pure DOM: wire the tab strip and cross-tab sync as soon as the DOM is
// ready, before Socket.IO connects, so tabs and their HTTP-loaded panels work
// without a socket. Safe to call more than once.
let appTabsInitialized = false;
function initializeAppTabs() {
    if (appTabsInitialized) return;
    appTabsInitialized = true;

    ensureTabPanelsAreSiblings();

    APP_TABS.forEach(tab => {
        const btn = document.getElementById(`tab-${tab}-btn`);
        if (btn) {
            btn.addEventListener('click', () => {
                switchAppTab(tab, { broadcast: true, persist: true });
            });
        }
    });
    // Only real tab names switch tabs, so in-page anchors such as the skip
    // link (#scan-target) keep working.
    window.addEventListener('hashchange', () => {
        const tab = readAppTabFromHash();
        if (tab && tab !== window.activeNmapUITab) switchAppTab(tab, { broadcast: true, persist: true });
    });

    const applyRemoteTab = (tab) => {
        if (!APP_TABS.includes(tab) || tab === window.activeNmapUITab) return;
        switchAppTab(tab, { broadcast: false, persist: false });
    };
    window.addEventListener('storage', (event) => {
        if (event.key === APP_TAB_SYNC_KEY && typeof event.newValue === 'string') {
            applyRemoteTab(event.newValue);
        }
    });
    if (typeof BroadcastChannel !== 'undefined') {
        new BroadcastChannel(APP_TAB_SYNC_CHANNEL).addEventListener('message', (event) => {
            applyRemoteTab(event.data?.tab);
        });
    }

    switchAppTab(readAppTabFromHash() || readStoredAppTab() || 'dashboard', { broadcast: false, persist: false });
}

function initializeSiteChrome() {
    const dateTimeEl = document.getElementById('current-date-time');

    const updateDateTime = () => {
        const now = new Date();
        if (dateTimeEl) dateTimeEl.textContent = now.toLocaleDateString() + ' ' + now.toLocaleTimeString();
    };
    updateDateTime();
    setInterval(updateDateTime, 1000);

    initializeAppTabs();

    document.getElementById('refresh-history-tab-btn')?.addEventListener('click', () => {
        window.socket?.emit('get_history');
    });
    document.getElementById('refresh-reports-btn')?.addEventListener('click', () => {
        window.socket?.emit('get_reports');
    });
    document.getElementById('refresh-customers-tab-btn')?.addEventListener('click', () => {
        if (typeof window.loadCustomersTab === 'function') {
            window.loadCustomersTab(true);
        } else {
            setTabStatus('customers-tab-status', 'Customer management is not connected in this build.');
        }
    });
    document.getElementById('refresh-settings-btn')?.addEventListener('click', () => {
        if (typeof window.loadSettingsTab === 'function') {
            window.loadSettingsTab(true);
        } else {
            setTabStatus('settings-tab-status', 'Settings are displayed from the current page configuration.');
        }
    });
}

function ensureTabPanelsAreSiblings() {
    const dashboardPanel = document.getElementById('dashboard-tab-panel');
    if (!dashboardPanel || !dashboardPanel.parentElement) return;

    const parent = dashboardPanel.parentElement;
    ['history', 'reports', 'customers', 'logs', 'settings'].forEach(tab => {
        const panel = document.getElementById(`${tab}-tab-panel`);
        if (panel && panel.parentElement === dashboardPanel) {
            parent.insertBefore(panel, dashboardPanel.nextSibling);
        }
    });
}

function setTabButtonState(button, active) {
    if (!button) return;
    button.classList.toggle('action-button-primary', active);
    button.classList.toggle('text-olive-700', !active);
    button.classList.toggle('hover:bg-olive-100', !active);
    button.setAttribute('aria-selected', active ? 'true' : 'false');
    button.setAttribute('tabindex', active ? '0' : '-1');
}

function setTabStatus(elementId, message, isError = false) {
    const status = document.getElementById(elementId);
    if (!status) return;
    if (!message) {
        status.textContent = '';
        status.classList.add('hidden');
        return;
    }
    status.textContent = message;
    status.classList.remove('hidden');
    status.classList.toggle('bg-red-50', isError);
    status.classList.toggle('text-red-700', isError);
    status.classList.toggle('bg-olive-50', !isError);
    status.classList.toggle('text-olive-800', !isError);
}

// Default activation for tabs no module has registered a handler for.
function activateAppTabDefault(tab) {
    if (tab === 'history') {
        window.socket?.emit('get_history');
    } else if (tab === 'reports') {
        window.socket?.emit('get_reports');
    } else if (tab === 'customers') {
        if (typeof window.loadCustomersTab === 'function') {
            window.loadCustomersTab();
        } else {
            setTabStatus('customers-tab-status', 'Customer management is not connected in this build.');
        }
    } else if (tab === 'settings') {
        if (typeof window.loadSettingsTab === 'function') {
            window.loadSettingsTab();
        } else {
            setTabStatus('settings-tab-status', '');
        }
    }
}

// The only switchAppTab. Do not redefine it in another module: register a
// per-tab callback with registerAppTabActivation() or listen for the
// `tab:changed` window event instead.
// broadcast: tell other NmapUI windows; persist: remember the tab for them.
function switchAppTab(tab, options = {}) {
    const { broadcast = false, persist = false } = options;
    if (!APP_TABS.includes(tab)) tab = 'dashboard';
    const previousTab = window.activeNmapUITab || null;
    window.activeNmapUITab = tab;
    if (persist) {
        try {
            localStorage.setItem(APP_TAB_SYNC_KEY, tab);
        } catch (error) {
            // Storage can be unavailable; the BroadcastChannel still syncs.
        }
    }
    if (window.location.hash !== `#${tab}`) {
        window.history.replaceState(null, '', `#${tab}`);
    }

    APP_TABS.forEach(t => {
        const panel = document.getElementById(`${t}-tab-panel`);
        if (panel) panel.classList.toggle('hidden', t !== tab);
        setTabButtonState(document.getElementById(`tab-${t}-btn`), t === tab);
    });

    const resultsPanel = document.getElementById('dashboard-results-panel');
    if (resultsPanel) resultsPanel.classList.toggle('hidden', tab !== 'dashboard');

    const handler = appTabActivationHandlers.get(tab);
    if (handler) {
        handler({ tab, previousTab });
    } else {
        activateAppTabDefault(tab);
    }

    window.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab, previousTab } }));

    if (broadcast) {
        window.dispatchEvent(new CustomEvent('nmapui-tab-changed', { detail: { tab } }));
        if (typeof BroadcastChannel !== 'undefined') {
            const channel = new BroadcastChannel(APP_TAB_SYNC_CHANNEL);
            channel.postMessage({ type: 'tab', tab });
            channel.close();
        }
    }
}

window.switchAppTab = switchAppTab;
window.registerAppTabActivation = registerAppTabActivation;
window.initializeAppTabs = initializeAppTabs;

function initializeAuditLog() {
    const logEntries = document.getElementById('log-entries');
    const logCountBadge = document.getElementById('log-count-badge');
    const logEntryCount = document.getElementById('log-entry-count');
    const tabEntries = document.getElementById('logs-tab-entries');
    const tabEmpty = document.getElementById('logs-tab-empty');
    const tabCount = document.getElementById('logs-tab-count');
    const searchInput = document.getElementById('logs-search-input');
    const levelFilter = document.getElementById('logs-level-filter');
    const capturedEntries = [];
    let count = 0;

    const renderLogsTab = () => {
        if (!tabEntries || !tabEmpty) return;
        const search = (searchInput?.value || '').trim().toLowerCase();
        const level = levelFilter?.value || 'all';
        const visible = capturedEntries.filter(entry => {
            const levelMatches = level === 'all' || entry.level === level;
            const textMatches = !search || `${entry.timestamp} ${entry.level} ${entry.message}`.toLowerCase().includes(search);
            return levelMatches && textMatches;
        });
        tabEntries.replaceChildren();
        visible.forEach(entry => {
            const div = document.createElement('div');
            div.className = `text-${entry.level === 'error' ? 'red' : 'zinc'}-400`;
            div.textContent = `[${entry.timestamp.split('T')[1].split('.')[0]}] [${entry.level.toUpperCase()}] ${entry.message}`;
            tabEntries.appendChild(div);
        });
        tabEntries.classList.toggle('hidden', visible.length === 0);
        tabEmpty.classList.toggle('hidden', visible.length > 0);
        if (tabCount) tabCount.textContent = `${visible.length} visible entr${visible.length === 1 ? 'y' : 'ies'}`;
    };

    window.socket.on('log_entry', (entry) => {
        capturedEntries.push(entry);
        count++;
        if (logCountBadge) {
            logCountBadge.textContent = count;
            logCountBadge.classList.remove('hidden');
        }
        if (logEntryCount) logEntryCount.textContent = `${count} entries`;

        const div = document.createElement('div');
        div.className = `text-${entry.level === 'error' ? 'red' : 'zinc'}-400`;
        div.textContent = `[${entry.timestamp.split('T')[1].split('.')[0]}] [${entry.level.toUpperCase()}] ${entry.message}`;
        if (logEntries) {
            logEntries.appendChild(div);
            logEntries.scrollTop = logEntries.scrollHeight;
        }
        renderLogsTab();
    });

    searchInput?.addEventListener('input', renderLogsTab);
    levelFilter?.addEventListener('change', renderLogsTab);
    document.getElementById('logs-clear-btn')?.addEventListener('click', () => {
        capturedEntries.length = 0;
        count = 0;
        if (logEntries) logEntries.replaceChildren();
        if (logCountBadge) logCountBadge.classList.add('hidden');
        if (logEntryCount) logEntryCount.textContent = '0 entries';
        renderLogsTab();
    });
    document.getElementById('logs-export-btn')?.addEventListener('click', () => {
        const text = capturedEntries.map(entry => `[${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.message}`).join('\n');
        navigator.clipboard?.writeText(text);
        if (tabCount) tabCount.textContent = `Copied ${capturedEntries.length} entr${capturedEntries.length === 1 ? 'y' : 'ies'} to clipboard`;
    });
}

function toggleLogPanel() {
    const panel = document.getElementById('log-panel');
    panel.classList.toggle('hidden');
}

function initializeLayoutRuntime() {
    // Placeholder for layout initialization
    console.log('Layout runtime initialized');
}
