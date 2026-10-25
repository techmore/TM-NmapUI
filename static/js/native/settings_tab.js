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
window.setGoogleDriveStatus = setGoogleDriveStatus;

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

function loadSettingsTab() {
    try {
        const saved = JSON.parse(localStorage.getItem(getSettingsStorageKey()) || 'null');
        applySettingsForm(saved);
        window.socket?.emit('get_google_drive_status');
        renderSettingsRuntimeSummary();
        setSettingsStatus(saved ? 'Settings loaded from this browser.' : 'Settings tab ready. Save stores these controls locally for this browser.');
    } catch (error) {
        setSettingsStatus('Failed to load local settings.', true);
    }
}

function saveSettingsTab() {
    try {
        const settings = collectSettingsForm();
        localStorage.setItem(getSettingsStorageKey(), JSON.stringify(settings));
        window.socket?.emit('save_google_drive_settings', {
            enabled: settings.googleDriveEnabled,
            folderId: settings.googleDriveFolder
        });
        if (window.webkit?.messageHandlers?.nmapuiRequest?.postMessage) {
            window.webkit.messageHandlers.nmapuiRequest.postMessage({
                event: 'save_app_settings',
                payload: settings
            });
        } else {
            window.socket?.emit?.('save_app_settings', settings);
        }
        renderSettingsRuntimeSummary();
        setSettingsStatus('Settings saved for this browser and native app.');
    } catch (error) {
        setSettingsStatus('Failed to save local settings.', true);
    }
}

function captureCurrentTarget() {
    const target = document.getElementById('scan-target')?.value || '';
    const targetInput = document.getElementById('settings-profile-target');
    if (targetInput) targetInput.value = target;
    setSettingsStatus(target ? 'Current dashboard target copied into the profile form.' : 'No dashboard target is available to copy.');
}

function addTargetProfile() {
    const name = document.getElementById('settings-profile-name')?.value || 'Target Profile';
    const target = document.getElementById('settings-profile-target')?.value || '';
    const notes = document.getElementById('settings-profile-notes')?.value || '';
    const list = document.getElementById('settings-profile-list');
    if (!list || !target) {
        setSettingsStatus('Add a target before saving a profile.', true);
        return;
    }
    const card = document.createElement('div');
    card.className = 'rounded-xl border border-olive-200 bg-white px-4 py-3 text-sm text-olive-800';
    card.innerHTML = `<div class="font-bold text-olive-950">${escapeSettingsHTML(name)}</div><div class="mt-1 font-mono text-xs">${escapeSettingsHTML(target)}</div>${notes ? `<div class="mt-1 text-xs text-olive-600">${escapeSettingsHTML(notes)}</div>` : ''}`;
    list.prepend(card);
    setSettingsStatus('Target profile added to this session.');
}

function applyPrivilegeHelperStatus(data = {}) {
    const state = document.getElementById('settings-privilege-helper-state');
    const status = document.getElementById('settings-privilege-helper-status');
    const installBtn = document.getElementById('settings-privilege-helper-install-btn');
    const ready = !!data.ready;
    if (state) {
        state.textContent = ready ? 'Ready' : 'Not installed';
        state.className = ready ? 'font-semibold text-emerald-700' : 'font-semibold text-amber-700';
    }
    if (status) {
        status.textContent = data.status || (ready
            ? 'Privileged scanner helper is ready for interactive and scheduled scans.'
            : 'Install once with admin approval. After that, full scans and schedules need no password.');
        status.classList.toggle('text-red-700', !!data.error);
        status.classList.toggle('text-olive-600', !data.error);
    }
    if (installBtn) {
        installBtn.textContent = ready ? 'Reinstall Helper' : 'Install Helper';
    }
}
window.applyPrivilegeHelperStatus = applyPrivilegeHelperStatus;

function requestPrivilegeHelperStatus() {
    if (window.webkit?.messageHandlers?.nmapuiRequest?.postMessage) {
        window.webkit.messageHandlers.nmapuiRequest.postMessage({ event: 'get_privilege_helper_status', payload: {} });
        return;
    }
    window.socket?.emit?.('get_privilege_helper_status');
}

function installPrivilegeHelper() {
    const status = document.getElementById('settings-privilege-helper-status');
    if (status) status.textContent = 'Requesting administrator approval to install the scanner helper…';
    if (window.webkit?.messageHandlers?.nmapuiRequest?.postMessage) {
        window.webkit.messageHandlers.nmapuiRequest.postMessage({ event: 'install_privilege_helper', payload: {} });
        return;
    }
    window.socket?.emit?.('install_privilege_helper');
}

function initializeSettingsTab(socket) {
    if (settingsTabInitialized) return;
    settingsTabInitialized = true;

    // Load initial settings
    socket.on('initial_data', (data) => {
        if (data.googleDrive) applyGoogleDriveConfig(data.googleDrive);
        socket.emit('get_google_drive_status');
        requestPrivilegeHelperStatus();
    });

    socket.on('privilege_helper_status', applyPrivilegeHelperStatus);
    if (typeof window.__nmapuiHandleNativeRuntimeEvent === 'function') {
        const previous = window.__nmapuiHandleNativeRuntimeEvent;
        window.__nmapuiHandleNativeRuntimeEvent = (eventName, payloadJSON) => {
            try {
                const payload = typeof payloadJSON === 'string' ? JSON.parse(payloadJSON || '{}') : (payloadJSON || {});
                const actual = payload && typeof payload === 'object' && 'payload' in payload ? payload.payload : payload;
                if (eventName === 'privilege_helper_status') {
                    applyPrivilegeHelperStatus(actual || {});
                }
            } catch (_) { /* ignore */ }
            previous(eventName, payloadJSON);
        };
    } else {
        window.__nmapuiHandleNativeRuntimeEvent = (eventName, payloadJSON) => {
            try {
                const payload = typeof payloadJSON === 'string' ? JSON.parse(payloadJSON || '{}') : (payloadJSON || {});
                const actual = payload && typeof payload === 'object' && 'payload' in payload ? payload.payload : payload;
                if (eventName === 'privilege_helper_status') applyPrivilegeHelperStatus(actual || {});
            } catch (_) { /* ignore */ }
        };
    }

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
    document.getElementById('settings-privilege-helper-install-btn')?.addEventListener('click', installPrivilegeHelper);
    requestPrivilegeHelperStatus();
    document.getElementById('settings-google-drive-test-btn')?.addEventListener('click', () => {
        setGoogleDriveStatus('Checking Google Drive status...');
        socket.emit('get_google_drive_status');
    });
    document.getElementById('settings-google-drive-connect-btn')?.addEventListener('click', () => {
        setGoogleDriveStatus('Starting Google Drive authorization...');
        if (window.webkit?.messageHandlers?.nmapuiRequest?.postMessage) {
            window.webkit.messageHandlers.nmapuiRequest.postMessage({ event: 'connect_google_drive', payload: {} });
        } else {
            socket.emit('connect_google_drive');
        }
    });
    document.getElementById('settings-google-drive-disconnect-btn')?.addEventListener('click', () => {
        setGoogleDriveStatus('Disconnecting Google Drive...');
        if (window.webkit?.messageHandlers?.nmapuiRequest?.postMessage) {
            window.webkit.messageHandlers.nmapuiRequest.postMessage({ event: 'disconnect_google_drive', payload: {} });
        } else {
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
        reader.onload = () => {
            setGoogleDriveStatus('Importing Google Drive credentials...');
            socket.emit('save_google_drive_credentials', { credentialsJson: String(reader.result || '') });
        };
        reader.onerror = () => setGoogleDriveStatus('Failed to read credentials file.', true);
        reader.readAsText(file);
    });
    document.getElementById('settings-remote-sync-test-btn')?.addEventListener('click', () => {
        document.getElementById('settings-remote-sync-status').textContent = 'Remote sync integration is not connected in this build.';
    });
    ['settings-runtime-backfill-btn', 'settings-runtime-retention-btn', 'settings-runtime-export-btn'].forEach(id => {
        document.getElementById(id)?.addEventListener('click', () => {
            document.getElementById('settings-maintenance-status').textContent = 'Runtime maintenance endpoints are not connected in this build.';
        });
    });
}

window.loadSettingsTab = loadSettingsTab;
window.initializeSettingsTab = initializeSettingsTab;
