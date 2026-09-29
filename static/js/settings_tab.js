let settingsTabInitialized = false;

function setSettingsStatus(message, isError = false) {
    const status = document.getElementById('settings-tab-status');
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

function getSettingsStorageKey() {
    return 'gemini-nmap-settings';
}

function loadLocalSettingsWithoutSecrets() {
    let saved;
    try {
        saved = JSON.parse(localStorage.getItem(getSettingsStorageKey()) || 'null');
    } catch (error) {
        return null;
    }
    if (!saved || typeof saved !== 'object' || Array.isArray(saved)) return null;

    // Older versions kept the remote-sync key in localStorage. Remove it before
    // applying the settings so a password field cannot silently restore it.
    if (Object.prototype.hasOwnProperty.call(saved, 'remoteSyncApiKey')) {
        const safeSettings = { ...saved };
        delete safeSettings.remoteSyncApiKey;
        try {
            localStorage.removeItem(getSettingsStorageKey());
            localStorage.setItem(getSettingsStorageKey(), JSON.stringify(safeSettings));
        } catch (error) {
            // At minimum, remove the legacy copy of the secret if rewriting the
            // non-secret preferences fails (for example, due to storage quota).
            try { localStorage.removeItem(getSettingsStorageKey()); } catch (_) {}
        }
        saved = safeSettings;
    }
    return saved;
}

function saveLocalSettingsWithoutSecrets(settings) {
    const safeSettings = { ...settings };
    delete safeSettings.remoteSyncApiKey;
    localStorage.setItem(getSettingsStorageKey(), JSON.stringify(safeSettings));
}

function escapeSettingsHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function collectSettingsForm() {
    return {
        scanOnlyMode: document.getElementById('settings-scan-only-mode')?.checked || false,
        excludedTargets: document.getElementById('settings-excluded-targets')?.value || '',
        maxScanMinutes: document.getElementById('settings-max-scan-minutes')?.value || '',
        saveReportsDesktop: document.getElementById('settings-save-reports-desktop')?.checked || false,
        autoMonitorEnabledByDefault: document.getElementById('settings-auto-monitor-enabled-by-default')?.checked || false,
        autoMonitorRecurrence: document.getElementById('settings-auto-monitor-recurrence')?.value || 'weekly',
        autoMonitorDay: document.getElementById('settings-auto-monitor-day')?.value || 'sunday',
        autoMonitorTime: document.getElementById('settings-auto-monitor-time')?.value || '01:00',
        autoMonitorTimezone: document.getElementById('settings-auto-monitor-timezone')?.value?.trim() || '',
        googleDriveEnabled: document.getElementById('settings-google-drive-enabled')?.checked || false,
        googleDriveFolder: document.getElementById('settings-google-drive-folder')?.value || '',
        remoteSyncEnabled: document.getElementById('settings-remote-sync-enabled')?.checked || false,
        remoteSyncEndpoint: document.getElementById('settings-remote-sync-endpoint')?.value || '',
        remoteSyncApiKey: document.getElementById('settings-remote-sync-api-key')?.value || ''
    };
}

function applySettingsForm(settings) {
    if (!settings) return;
    if (document.getElementById('settings-scan-only-mode')) document.getElementById('settings-scan-only-mode').checked = !!settings.scanOnlyMode;
    if (document.getElementById('settings-excluded-targets')) document.getElementById('settings-excluded-targets').value = settings.excludedTargets || '';
    if (document.getElementById('settings-max-scan-minutes')) document.getElementById('settings-max-scan-minutes').value = settings.maxScanMinutes || '';
    if (document.getElementById('settings-save-reports-desktop')) document.getElementById('settings-save-reports-desktop').checked = !!settings.saveReportsDesktop;
    if (document.getElementById('settings-auto-monitor-enabled-by-default')) document.getElementById('settings-auto-monitor-enabled-by-default').checked = !!settings.autoMonitorEnabledByDefault;
    if (document.getElementById('settings-auto-monitor-recurrence')) document.getElementById('settings-auto-monitor-recurrence').value = settings.autoMonitorRecurrence || 'weekly';
    if (document.getElementById('settings-auto-monitor-day')) document.getElementById('settings-auto-monitor-day').value = settings.autoMonitorDay || 'sunday';
    if (document.getElementById('settings-auto-monitor-time')) document.getElementById('settings-auto-monitor-time').value = settings.autoMonitorTime || '01:00';
    if (document.getElementById('settings-auto-monitor-timezone')) document.getElementById('settings-auto-monitor-timezone').value = settings.autoMonitorTimezone || '';
    if (document.getElementById('settings-google-drive-enabled')) document.getElementById('settings-google-drive-enabled').checked = !!settings.googleDriveEnabled;
    if (document.getElementById('settings-google-drive-folder')) document.getElementById('settings-google-drive-folder').value = settings.googleDriveFolder || '';
    if (document.getElementById('settings-remote-sync-enabled')) document.getElementById('settings-remote-sync-enabled').checked = !!settings.remoteSyncEnabled;
    if (document.getElementById('settings-remote-sync-endpoint')) document.getElementById('settings-remote-sync-endpoint').value = settings.remoteSyncEndpoint || '';
    if (document.getElementById('settings-remote-sync-api-key')) document.getElementById('settings-remote-sync-api-key').value = settings.remoteSyncApiKey || '';
}

function setGoogleDriveStatus(message, isError = false) {
    const status = document.getElementById('settings-google-drive-status');
    if (!status) return;
    status.textContent = message || 'Ready';
    status.classList.toggle('text-red-700', isError);
    status.classList.toggle('text-olive-600', !isError);
}

function renderGoogleDriveSummary({ config = {}, status = {} } = {}) {
    const enabledState = document.getElementById('settings-google-drive-enabled-state');
    const connectedState = document.getElementById('settings-google-drive-connected-state');
    const folderState = document.getElementById('settings-google-drive-folder-state');
    const folderId = config.folderId || config.folder || '';

    if (enabledState) {
        enabledState.textContent = config.enabled ? 'Enabled' : 'Disabled';
        enabledState.className = config.enabled ? 'font-semibold text-emerald-700' : 'font-semibold text-olive-600';
    }
    if (connectedState) {
        connectedState.textContent = status.connected ? 'Connected' : (status.configured ? 'Not connected' : 'Credentials missing');
        connectedState.className = status.connected ? 'font-semibold text-emerald-700' : 'font-semibold text-amber-700';
    }
    if (folderState) folderState.textContent = folderId || 'Auto-create Nmap Reports';
}

function applyGoogleDriveConfig(config = {}, status = {}) {
    const enabled = document.getElementById('settings-google-drive-enabled');
    const folder = document.getElementById('settings-google-drive-folder');
    if (enabled) enabled.checked = !!config.enabled;
    if (folder) folder.value = config.folderId || config.folder || '';
    renderGoogleDriveSummary({ config, status });
}

function renderSettingsRuntimeSummary() {
    const summary = document.getElementById('settings-runtime-summary');
    if (!summary) return;
    const reportCount = document.querySelectorAll('#reports-tab-list > *').length;
    const historyCount = document.querySelectorAll('#history-tab-list > *').length;
    summary.innerHTML = `
        <div class="rounded-xl border border-olive-200 bg-white px-4 py-3 text-sm text-olive-700">
            <span class="block text-xs font-bold uppercase tracking-widest text-olive-500">Loaded Reports</span>
            <span class="mt-1 block text-2xl font-bold text-olive-950">${reportCount}</span>
        </div>
        <div class="rounded-xl border border-olive-200 bg-white px-4 py-3 text-sm text-olive-700">
            <span class="block text-xs font-bold uppercase tracking-widest text-olive-500">Loaded History</span>
            <span class="mt-1 block text-2xl font-bold text-olive-950">${historyCount}</span>
        </div>
    `;
}

function applyServerSettingsDocument(doc = {}) {
    const scanRules = doc.scan_rules || {};
    const reports = doc.reports || {};
    const sync = doc.sync || {};
    applySettingsForm({
        scanOnlyMode: !!scanRules.scan_only_mode,
        excludedTargets: (scanRules.excluded_targets || []).join('\n'),
        maxScanMinutes: scanRules.max_scan_minutes != null ? String(scanRules.max_scan_minutes) : '',
        saveReportsDesktop: !!reports.save_to_desktop,
        googleDriveEnabled: !!(sync.google_drive || {}).enabled,
        googleDriveFolder: (sync.google_drive || {}).folder_id || '',
        remoteSyncEnabled: !!(sync.remote_sync || {}).enabled,
        remoteSyncEndpoint: (sync.remote_sync || {}).endpoint || '',
    });
    const remoteSyncKey = document.getElementById('settings-remote-sync-api-key');
    if (remoteSyncKey) remoteSyncKey.value = '';
    const remoteSyncKeyStatus = document.getElementById('settings-remote-sync-key-status');
    if (remoteSyncKeyStatus) {
        remoteSyncKeyStatus.textContent = (sync.remote_sync || {}).api_key_configured
            ? 'A key is stored encrypted on this scanner. Leave this field blank to keep it, or enter a replacement.'
            : 'No key is stored on this scanner.';
    }
    // Auto-monitor defaults come from the server document, not localStorage.
    const defaults = (doc.auto_monitor || {}).defaults || {};
    if (document.getElementById('settings-auto-monitor-enabled-by-default')) {
        document.getElementById('settings-auto-monitor-enabled-by-default').checked = !!defaults.enabled_by_default;
    }
    if (document.getElementById('settings-auto-monitor-recurrence')) {
        document.getElementById('settings-auto-monitor-recurrence').value = defaults.recurrence || 'weekly';
    }
    if (document.getElementById('settings-auto-monitor-day')) {
        document.getElementById('settings-auto-monitor-day').value = defaults.day_of_week || 'sunday';
    }
    if (document.getElementById('settings-auto-monitor-time')) {
        document.getElementById('settings-auto-monitor-time').value = defaults.time || '01:00';
    }
    if (document.getElementById('settings-auto-monitor-timezone')) {
        document.getElementById('settings-auto-monitor-timezone').value = defaults.timezone || '';
    }
    renderGoogleDriveSummary({ config: sync.google_drive || {}, status: {} });
}

async function refreshGoogleDriveSummaryFromStatus() {
    try {
        const response = await fetch('/api/settings/google-drive/status');
        if (!response.ok) return;
        const status = await response.json();
        let config = {};
        try {
            const doc = await fetchServerSettings();
            if (doc) config = (doc.sync || {}).google_drive || {};
        } catch (error) {
            config = {};
        }
        renderGoogleDriveSummary({ config, status });
    } catch (error) {
        // Node dev runtime: socket 'google_drive_status' handler covers this.
        window.socket?.emit('get_google_drive_status');
    }
}

async function fetchServerSettings() {
    try {
        const response = await fetch('/api/settings');
        if (!response.ok) return null;
        return await response.json();
    } catch (error) {
        return null;
    }
}

async function loadSettingsTab() {
    const saved = loadLocalSettingsWithoutSecrets();
    if (saved) applySettingsForm(saved);
    window.socket?.emit('get_google_drive_status');
    renderSettingsRuntimeSummary();
    setSettingsStatus('Loading settings...');
    const doc = await fetchServerSettings();
    if (doc) {
        applyServerSettingsDocument(doc);
        setSettingsStatus('Settings loaded from the local runtime.');
    } else {
        setSettingsStatus(saved ? 'Settings loaded from this browser.' : 'Settings tab ready.');
    }
    await refreshGoogleDriveSummaryFromStatus();
}

function buildAutoMonitorDefaultsPayload(settings, existingDoc = {}) {
    // The settings form owns auto_monitor.defaults; keep any existing rules.
    const existing = (existingDoc.auto_monitor || {});
    const defaults = existing.defaults || {};
    return {
        defaults: {
            enabled_by_default: !!settings.autoMonitorEnabledByDefault,
            recurrence: settings.autoMonitorRecurrence || defaults.recurrence || 'weekly',
            day_of_week: settings.autoMonitorDay || defaults.day_of_week || 'sunday',
            time: settings.autoMonitorTime || defaults.time || '01:00',
            timezone: settings.autoMonitorTimezone || '',
        },
        rules: Array.isArray(existing.rules) ? existing.rules : [],
    };
}

function buildServerSettingsPayload(settings, existingDoc = {}) {
    // POST /api/settings replaces the whole document server-side
    // (settings_state.clear() + update), so carry forward sections the
    // settings form does not own: target_profiles and auto_monitor.
    const existingSync = existingDoc.sync || {};
    return {
        scan_rules: {
            scan_only_mode: !!settings.scanOnlyMode,
            excluded_targets: String(settings.excludedTargets || '')
                .split(/[\n,]+/)
                .map((entry) => entry.trim())
                .filter(Boolean),
            max_scan_minutes: Number.parseInt(settings.maxScanMinutes, 10) || 120,
        },
        reports: {
            save_to_desktop: !!settings.saveReportsDesktop,
        },
        sync: {
            google_drive: {
                enabled: !!settings.googleDriveEnabled,
                folder_id: settings.googleDriveFolder || '',
            },
            remote_sync: {
                enabled: !!settings.remoteSyncEnabled,
                endpoint: settings.remoteSyncEndpoint || '',
                api_key: settings.remoteSyncApiKey || '',
                api_key_configured: !!(existingSync.remote_sync || {}).api_key_configured,
            },
        },
        target_profiles: [
            ...(Array.isArray(existingDoc.target_profiles) ? existingDoc.target_profiles : []),
            ...pendingTargetProfiles,
        ],
        auto_monitor: buildAutoMonitorDefaultsPayload(settings, existingDoc),
    };
}

async function saveSettingsTab() {
    let settings;
    try {
        settings = collectSettingsForm();
        saveLocalSettingsWithoutSecrets(settings);
    } catch (error) {
        setSettingsStatus('Failed to save local settings.', true);
        return;
    }
    window.socket?.emit('save_google_drive_settings', {
        enabled: settings.googleDriveEnabled,
        folderId: settings.googleDriveFolder
    });
    try {
        // POST /api/settings clears and replaces the whole server document.
        // If we cannot read the current doc first, a replacement save could
        // wipe target_profiles / auto_monitor rules - abort instead of risk it.
        const currentDoc = await fetchServerSettings();
        if (!currentDoc) {
            throw new Error('could not read current settings from the runtime; save aborted to avoid data loss');
        }
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(buildServerSettingsPayload(settings, currentDoc)),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload.success !== true) {
            throw new Error(payload.error || `Save failed (${response.status})`);
        }
        pendingTargetProfiles = [];
        applyServerSettingsDocument(payload.settings || {});
        renderSettingsRuntimeSummary();
        setSettingsStatus('Settings saved to the local runtime and this browser.');
    } catch (error) {
        renderSettingsRuntimeSummary();
        setSettingsStatus(`Saved locally in this browser only (${error.message}).`);
    }
}

function captureCurrentTarget() {
    const target = document.getElementById('scan-target')?.value || '';
    const targetInput = document.getElementById('settings-profile-target');
    if (targetInput) targetInput.value = target;
    setSettingsStatus(target ? 'Current dashboard target copied into the profile form.' : 'No dashboard target is available to copy.');
}

// Target profiles added this session; persisted with the next settings save.
let pendingTargetProfiles = [];

function addTargetProfile() {
    const name = document.getElementById('settings-profile-name')?.value || 'Target Profile';
    const target = document.getElementById('settings-profile-target')?.value || '';
    const notes = document.getElementById('settings-profile-notes')?.value || '';
    const list = document.getElementById('settings-profile-list');
    if (!list || !target) {
        setSettingsStatus('Add a target before saving a profile.', true);
        return;
    }
    const profile = {
        id: (crypto?.randomUUID ? crypto.randomUUID().replace(/-/g, '').slice(0, 12) : `p${Date.now()}`),
        name,
        target,
        customer_id: document.getElementById('settings-profile-customer')?.value || '',
        customer_name: '',
        notes,
        scan_rules: {
            scan_only_mode: !!document.getElementById('settings-profile-scan-only-mode')?.checked,
            excluded_targets: String(document.getElementById('settings-profile-excluded-targets')?.value || '')
                .split(/[\n,]+/)
                .map((entry) => entry.trim())
                .filter(Boolean),
            max_scan_minutes: Number.parseInt(
                document.getElementById('settings-profile-max-scan-minutes')?.value || '', 10,
            ) || 120,
        },
    };
    pendingTargetProfiles.push(profile);
    const card = document.createElement('div');
    card.className = 'rounded-xl border border-olive-200 bg-white px-4 py-3 text-sm text-olive-800';
    card.innerHTML = `<div class="font-bold text-olive-950">${escapeSettingsHTML(name)}</div><div class="mt-1 font-mono text-xs">${escapeSettingsHTML(target)}</div>${notes ? `<div class="mt-1 text-xs text-olive-600">${escapeSettingsHTML(notes)}</div>` : ''}`;
    list.prepend(card);
    setSettingsStatus(`Profile saved locally - click Save Settings to persist it to the runtime.`);
}

function initializeSettingsTab(socket) {
    if (settingsTabInitialized) return;
    settingsTabInitialized = true;

    // Load initial settings
    socket.on('initial_data', (data) => {
        if (data.googleDrive) applyGoogleDriveConfig(data.googleDrive);
        socket.emit('get_google_drive_status');
    });

    socket.on('google_drive_status', (data = {}) => {
        if (data.config) applyGoogleDriveConfig(data.config, data);
        setGoogleDriveStatus(data.status || data.error || 'Google Drive status updated.', !data.success && !!data.error);
    });

    socket.on('google_drive_auth_url', (data = {}) => {
        if (!data.success || !data.auth_url) {
            setGoogleDriveStatus(data.error || 'Unable to start Google Drive authorization.', true);
            return;
        }
        setGoogleDriveStatus('Google authorization opened. Complete sign-in in the browser window.');
        window.open(data.auth_url, '_blank', 'noopener,noreferrer');
    });

    socket.on('google_drive_upload_complete', (data = {}) => {
        setGoogleDriveStatus(data.status || 'Report uploaded to Google Drive.');
        socket.emit('get_google_drive_status');
    });

    document.getElementById('save-settings-btn')?.addEventListener('click', saveSettingsTab);
    document.getElementById('refresh-settings-btn')?.addEventListener('click', loadSettingsTab);
    document.getElementById('capture-current-target-btn')?.addEventListener('click', captureCurrentTarget);
    document.getElementById('add-target-profile-btn')?.addEventListener('click', addTargetProfile);
    document.getElementById('settings-google-drive-test-btn')?.addEventListener('click', async () => {
        setGoogleDriveStatus('Checking Google Drive status...');
        try {
            const response = await fetch('/api/settings/google-drive/status');
            const status = await response.json();
            renderGoogleDriveSummary({ config: {}, status: status });
            setGoogleDriveStatus(status.connected ? 'Google Drive is connected.' : 'Google Drive is not connected.');
        } catch (error) {
            socket.emit('get_google_drive_status');
        }
    });
    document.getElementById('settings-google-drive-connect-btn')?.addEventListener('click', async () => {
        setGoogleDriveStatus('Starting Google Drive authorization...');
        try {
            const response = await fetch('/api/settings/google-drive/auth-url');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const result = await response.json();
            if (!result.success || !result.auth_url) throw new Error(result.error || 'No authorization URL returned');
            setGoogleDriveStatus('Complete sign-in in the browser window that opened.');
            window.open(result.auth_url, '_blank', 'noopener,noreferrer');
        } catch (error) {
            // Node dev runtime implements this via socket events instead.
            setGoogleDriveStatus('Starting Google Drive authorization via local runtime...');
            socket.emit('connect_google_drive');
        }
    });
    document.getElementById('settings-google-drive-disconnect-btn')?.addEventListener('click', async () => {
        setGoogleDriveStatus('Disconnecting Google Drive...');
        try {
            const response = await fetch('/api/settings/google-drive/disconnect', { method: 'POST' });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const result = await response.json();
            if (!result.success) throw new Error(result.error || 'Disconnect failed');
            setGoogleDriveStatus(result.status || 'Google Drive disconnected.');
            // The disconnect route only revokes the token; also flip
            // sync.google_drive.enabled off so report uploads stop failing.
            const currentDoc = await fetchServerSettings();
            if (currentDoc) {
                const payload = buildServerSettingsPayload(collectSettingsForm(), {
                    ...currentDoc,
                    sync: {
                        ...(currentDoc.sync || {}),
                        google_drive: {
                            ...((currentDoc.sync || {}).google_drive || {}),
                            enabled: false,
                        },
                    },
                });
                await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
            }
        } catch (error) {
            // Node dev runtime fallback.
            socket.emit('disconnect_google_drive');
        }
    });
    document.getElementById('settings-google-drive-import-btn')?.addEventListener('click', () => {
        document.getElementById('settings-google-drive-credentials-file')?.click();
    });
    document.getElementById('settings-google-drive-credentials-file')?.addEventListener('change', event => {
        const file = event.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = async () => {
            setGoogleDriveStatus('Importing Google Drive credentials...');
            try {
                const response = await fetch('/api/settings/google-drive/credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ credentials: String(reader.result || '') }),
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const result = await response.json();
                if (!result.success) throw new Error(result.error || 'Import rejected');
                setGoogleDriveStatus(result.status || 'Credentials imported.');
            } catch (error) {
                // Node dev runtime fallback.
                socket.emit('save_google_drive_credentials', { credentialsJson: String(reader.result || '') });
            }
        };
        reader.onerror = () => setGoogleDriveStatus('Failed to read credentials file.', true);
        reader.readAsText(file);
    });
    document.getElementById('settings-remote-sync-test-btn')?.addEventListener('click', () => {
        document.getElementById('settings-remote-sync-status').textContent = 'Remote sync integration is not connected in this build.';
    });
    const setMaintenanceStatus = (message, isError = false) => {
        const status = document.getElementById('settings-maintenance-status');
        if (!status) return;
        status.textContent = message;
        status.classList.toggle('text-red-700', isError);
        status.classList.toggle('text-olive-600', !isError);
    };
    document.getElementById('settings-runtime-backfill-btn')?.addEventListener('click', async () => {
        setMaintenanceStatus('Running runtime backfill...');
        try {
            const response = await fetch('/api/runtime/maintenance/backfill', { method: 'POST' });
            const payload = await response.json();
            if (!response.ok || payload.success !== true) throw new Error(payload.error || `Backfill failed (${response.status})`);
            setMaintenanceStatus(`Backfill complete: ${payload.backfilled} artifact(s) indexed.`);
            renderSettingsRuntimeSummary();
        } catch (error) {
            setMaintenanceStatus(`Backfill failed: ${error.message}`, true);
        }
    });
    document.getElementById('settings-runtime-retention-btn')?.addEventListener('click', async () => {
        setMaintenanceStatus('Pruning logs and compacting the database...');
        try {
            const response = await fetch('/api/runtime/maintenance/retention', { method: 'POST' });
            const payload = await response.json();
            if (!response.ok || payload.success !== true) throw new Error(payload.error || `Retention failed (${response.status})`);
            setMaintenanceStatus('Retention policies applied and database compacted.');
        } catch (error) {
            setMaintenanceStatus(`Retention failed: ${error.message}`, true);
        }
    });
    document.getElementById('settings-runtime-export-btn')?.addEventListener('click', () => {
        setMaintenanceStatus('Preparing runtime database export...');
        window.location.href = '/api/runtime/export';
        setMaintenanceStatus('Runtime database download started.');
    });
}

window.loadSettingsTab = loadSettingsTab;
window.initializeSettingsTab = initializeSettingsTab;
