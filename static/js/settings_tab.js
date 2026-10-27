let settingsTabInitialized = false;
let settingsTabLoaded = false;
let settingsState = null;
let googleDriveAuthStatus = null;

function setSettingsStatus(message, isError = false) {
    const status = document.getElementById('settings-tab-status');
    if (!status) {
        return;
    }

    if (!message) {
        status.textContent = '';
        status.classList.add('hidden');
        status.classList.remove('bg-red-50', 'text-red-700', 'bg-olive-50', 'text-olive-800');
        return;
    }

    status.textContent = message;
    status.classList.remove('hidden');
    status.classList.remove('bg-red-50', 'text-red-700', 'bg-olive-50', 'text-olive-800');
    status.classList.add(isError ? 'bg-red-50' : 'bg-olive-50');
    status.classList.add(isError ? 'text-red-700' : 'text-olive-800');
}

function getSettingsFormState() {
    return {
        schema_version: 1,
        target_profiles: settingsState?.target_profiles || [],
        scan_rules: {
            scan_only_mode: document.getElementById('settings-scan-only-mode')?.checked || false,
            excluded_targets: (document.getElementById('settings-excluded-targets')?.value || '')
                .split('\n')
                .map((value) => value.trim())
                .filter(Boolean),
            max_scan_minutes: Number.parseInt(
                document.getElementById('settings-max-scan-minutes')?.value || '120',
                10,
            ) || 120,
        },
        reports: {
            save_to_desktop: document.getElementById('settings-save-reports-desktop')?.checked || false,
        },
        sync: {
            google_drive: {
                enabled: document.getElementById('settings-google-drive-enabled')?.checked || false,
                folder_id: document.getElementById('settings-google-drive-folder')?.value || '',
                status: document.getElementById('settings-google-drive-status')?.textContent || 'Not configured',
            },
            remote_sync: {
                enabled: document.getElementById('settings-remote-sync-enabled')?.checked || false,
                endpoint: document.getElementById('settings-remote-sync-endpoint')?.value || '',
                api_key: document.getElementById('settings-remote-sync-api-key')?.value || '',
                status: document.getElementById('settings-remote-sync-status')?.textContent || 'Not configured',
            },
        },
        auto_monitor: {
            defaults: {
                enabled_by_default: document.getElementById('settings-auto-monitor-enabled-by-default')?.checked || false,
                recurrence: document.getElementById('settings-auto-monitor-recurrence')?.value || 'weekly',
                day_of_week: document.getElementById('settings-auto-monitor-day')?.value || 'sunday',
                time: document.getElementById('settings-auto-monitor-time')?.value || '01:00',
                scan_mode: 'complete_pdf',
            },
            rules: settingsState?.auto_monitor?.rules || [],
        },
    };
}

function populateProfileCustomerOptions() {
    const profileCustomer = document.getElementById('settings-profile-customer');
    const currentCustomer = document.getElementById('current-customer');
    if (!profileCustomer || !currentCustomer) {
        return;
    }

    const existingValue = profileCustomer.value;
    profileCustomer.replaceChildren();

    const defaultOption = document.createElement('option');
    defaultOption.value = '';
    defaultOption.textContent = 'Use current customer selection';
    profileCustomer.appendChild(defaultOption);

    Array.from(currentCustomer.options || []).forEach((option) => {
        if (!option.value) {
            return;
        }
        profileCustomer.appendChild(option.cloneNode(true));
    });

    profileCustomer.value = existingValue;
}

function renderRuntimeSummary(summary) {
    const container = document.getElementById('settings-runtime-summary');
    if (!container) {
        return;
    }

    const maintenanceBackfill = summary.maintenance_backfill || {};
    const maintenanceRetention = summary.maintenance_retention || {};
    const persistedCounts = summary.persisted_counts || {};
    const lastBackfillValue = maintenanceBackfill.last_run_at
        ? `${new Date(maintenanceBackfill.last_run_at).toLocaleString()} (${maintenanceBackfill.last_backfilled || 0})`
        : 'Never';
    const lastRetentionValue = maintenanceRetention.last_run_at
        ? `${new Date(maintenanceRetention.last_run_at).toLocaleString()} (${maintenanceRetention.deleted_runtime_logs || 0} logs, ${maintenanceRetention.deleted_customer_scan_history || 0} history)`
        : 'Never';

    const cards = [
        ['Profiles', String(summary.target_profiles_count || 0)],
        ['Exclusions', String(summary.excluded_targets_count || 0)],
        ['Scan-only mode', summary.scan_only_mode ? 'Enabled' : 'Disabled'],
        ['Max scan duration', `${summary.max_scan_minutes || 120} min`],
        ['Desktop reports', summary.reports_save_to_desktop ? 'Enabled' : 'Disabled'],
        ['Google Drive', summary.google_drive_enabled ? 'Enabled' : 'Disabled'],
        ['Remote sync', summary.remote_sync_enabled ? 'Enabled' : 'Disabled'],
        ['Reports in DB', String(persistedCounts.report_artifacts || 0)],
        ['History rows', String(persistedCounts.customer_scan_history || 0)],
        ['Runtime logs', String(persistedCounts.runtime_logs || 0)],
        ['Last backfill', lastBackfillValue],
        ['Last retention', lastRetentionValue],
    ];

    container.replaceChildren();
    cards.forEach(([label, value]) => {
        const card = document.createElement('div');
        card.className = 'rounded-xl border border-olive-200 bg-white px-4 py-3';
        card.innerHTML = `<div class="text-xs font-bold uppercase tracking-widest text-olive-500">${label}</div><div class="mt-1 text-lg font-semibold text-olive-900">${value}</div>`;
        container.appendChild(card);
    });

    const toolVersions = summary.tool_versions || {};
    const settingsNmapVersion = document.getElementById('settings-nmap-version');
    const settingsVulnersVersion = document.getElementById('settings-vulners-version');
    const settingsArpScanVersion = document.getElementById('settings-arpscan-version');
    if (settingsNmapVersion) settingsNmapVersion.textContent = `Nmap: ${toolVersions.nmap || 'Not found'}`;
    if (settingsVulnersVersion) settingsVulnersVersion.textContent = `Vulners: ${toolVersions.vulners || 'Not found'}`;
    if (settingsArpScanVersion) settingsArpScanVersion.textContent = `ARP-Scan: ${toolVersions.arp_scan || 'Not found'}`;
}

function setSyncStatus(elementId, message, isError = false) {
    const element = document.getElementById(elementId);
    if (!element) {
        return;
    }

    element.textContent = message;
    element.classList.remove('text-olive-600', 'text-red-700', 'text-emerald-700');
    if (isError) {
        element.classList.add('text-red-700');
        return;
    }
    if (/ready|accepted|configured/i.test(message)) {
        element.classList.add('text-emerald-700');
        return;
    }
    element.classList.add('text-olive-600');
}

function updateGoogleDriveAuthButtons() {
    const connectButton = document.getElementById('settings-google-drive-connect-btn');
    const disconnectButton = document.getElementById('settings-google-drive-disconnect-btn');
    const importButton = document.getElementById('settings-google-drive-import-btn');
    if (!connectButton || !disconnectButton || !importButton) {
        return;
    }

    const connected = !!googleDriveAuthStatus?.connected;
    connectButton.disabled = connected;
    disconnectButton.disabled = !connected;
    connectButton.classList.toggle('opacity-50', connected);
    disconnectButton.classList.toggle('opacity-50', !connected);
    importButton.disabled = false;
    importButton.classList.remove('opacity-50');
}

function setMaintenanceStatus(message, isError = false) {
    const element = document.getElementById('settings-maintenance-status');
    if (!element) {
        return;
    }

    element.textContent = message;
    element.classList.remove('text-olive-600', 'text-red-700', 'text-emerald-700');
    if (isError) {
        element.classList.add('text-red-700');
        return;
    }
    if (/backfilled|completed|ready/i.test(message)) {
        element.classList.add('text-emerald-700');
        return;
    }
    element.classList.add('text-olive-600');
}

function applyProfileToDashboard(profile) {
    const targetInput = document.getElementById('scan-target');
    if (targetInput) {
        targetInput.value = profile.target || '';
        targetInput.dispatchEvent(new Event('input', { bubbles: true }));
    }

    const customerSelect = document.getElementById('current-customer');
    if (customerSelect && profile.customer_id) {
        customerSelect.value = profile.customer_id;
        customerSelect.dispatchEvent(new Event('change', { bubbles: true }));
    }

    if (typeof window.setLastScanTarget === 'function' && profile.target) {
        window.setLastScanTarget(profile.target);
    }

    setSettingsStatus(`Applied profile "${profile.name}" to the Dashboard.`);
    if (typeof window.switchAppTab === 'function') {
        window.switchAppTab('dashboard');
    }
}

function renderTargetProfiles(profiles) {
    const list = document.getElementById('settings-profile-list');
    if (!list) {
        return;
    }

    list.replaceChildren();

    if (!profiles.length) {
        const empty = document.createElement('div');
        empty.className = 'rounded-xl border border-dashed border-olive-300 bg-white/70 px-4 py-4 text-sm text-olive-700';
        empty.textContent = 'No target profiles saved yet.';
        list.appendChild(empty);
        return;
    }

    profiles.forEach((profile) => {
        const card = document.createElement('div');
        card.className = 'rounded-xl border border-olive-200 bg-white p-4';
        card.innerHTML = `
            <div class="flex items-start justify-between gap-3">
                <div>
                    <div class="text-sm font-semibold text-olive-900">${profile.name}</div>
                    <div class="mt-1 font-mono text-sm text-olive-700">${profile.target}</div>
                    <div class="mt-2 text-xs text-olive-600">${profile.customer_name || 'No customer pinned'}</div>
                    <div class="mt-2 text-xs text-olive-600">Profile rules: ${profile.scan_rules?.scan_only_mode ? 'scan-only' : 'default mode'}${(profile.scan_rules?.excluded_targets || []).length ? ` | ${profile.scan_rules.excluded_targets.length} exclusion(s)` : ''}${profile.scan_rules?.max_scan_minutes ? ` | max ${profile.scan_rules.max_scan_minutes} min` : ''}</div>
                    ${profile.notes ? `<div class="mt-2 text-xs text-olive-600">${profile.notes}</div>` : ''}
                </div>
            </div>
        `;

        const actions = document.createElement('div');
        actions.className = 'mt-3 flex flex-wrap gap-2';

        const useButton = document.createElement('button');
        useButton.type = 'button';
        useButton.className = 'action-button action-button-primary action-button-compact';
        useButton.textContent = 'Use Profile';
        useButton.addEventListener('click', () => applyProfileToDashboard(profile));
        actions.appendChild(useButton);

        const deleteButton = document.createElement('button');
        deleteButton.type = 'button';
        deleteButton.className = 'action-button action-button-secondary action-button-compact';
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => {
            settingsState.target_profiles = (settingsState.target_profiles || []).filter(
                (candidate) => candidate.id !== profile.id
            );
            renderTargetProfiles(settingsState.target_profiles);
        });
        actions.appendChild(deleteButton);

        card.appendChild(actions);
        list.appendChild(card);
    });
}

function fillSettingsForm(state) {
    settingsState = state;
    document.getElementById('settings-scan-only-mode').checked = !!state.scan_rules?.scan_only_mode;
    document.getElementById('settings-excluded-targets').value = (state.scan_rules?.excluded_targets || []).join('\n');
    const maxScanInput = document.getElementById('settings-max-scan-minutes');
    if (maxScanInput) {
        maxScanInput.value = state.scan_rules?.max_scan_minutes || 120;
    }
    document.getElementById('settings-save-reports-desktop').checked = !!state.reports?.save_to_desktop;
    document.getElementById('settings-profile-scan-only-mode').checked = false;
    document.getElementById('settings-profile-excluded-targets').value = '';
    const profileMaxScanInput = document.getElementById('settings-profile-max-scan-minutes');
    if (profileMaxScanInput) {
        profileMaxScanInput.value = '';
    }
    document.getElementById('settings-google-drive-enabled').checked = !!state.sync?.google_drive?.enabled;
    document.getElementById('settings-google-drive-folder').value = state.sync?.google_drive?.folder_id || '';
    document.getElementById('settings-google-drive-status').textContent = state.sync?.google_drive?.status || 'Not configured';
    document.getElementById('settings-remote-sync-enabled').checked = !!state.sync?.remote_sync?.enabled;
    document.getElementById('settings-remote-sync-endpoint').value = state.sync?.remote_sync?.endpoint || '';
    document.getElementById('settings-remote-sync-api-key').value = state.sync?.remote_sync?.api_key || '';
    document.getElementById('settings-remote-sync-status').textContent = state.sync?.remote_sync?.status || 'Not configured';
    document.getElementById('settings-auto-monitor-enabled-by-default').checked = !!state.auto_monitor?.defaults?.enabled_by_default;
    document.getElementById('settings-auto-monitor-recurrence').value = state.auto_monitor?.defaults?.recurrence || 'weekly';
    document.getElementById('settings-auto-monitor-day').value = state.auto_monitor?.defaults?.day_of_week || 'sunday';
    document.getElementById('settings-auto-monitor-time').value = state.auto_monitor?.defaults?.time || '01:00';
    populateProfileCustomerOptions();
    renderTargetProfiles(state.target_profiles || []);
}

function syncMaintenanceStatusFromSummary(summary) {
    const maintenanceBackfill = summary?.maintenance_backfill || {};
    const maintenanceRetention = summary?.maintenance_retention || {};
    if (maintenanceRetention.last_run_at) {
        setMaintenanceStatus(
            `Last retention: ${new Date(maintenanceRetention.last_run_at).toLocaleString()} (${maintenanceRetention.deleted_runtime_logs || 0} log(s), ${maintenanceRetention.deleted_customer_scan_history || 0} history row(s)).`
        );
        return;
    }
    if (maintenanceBackfill.last_run_at) {
        setMaintenanceStatus(
            `Last backfill: ${new Date(maintenanceBackfill.last_run_at).toLocaleString()} (${maintenanceBackfill.last_backfilled || 0} artifact(s)).`
        );
        return;
    }
    setMaintenanceStatus('Ready');
}

async function loadRuntimeSettingsSummary() {
    const response = await fetch('/api/runtime/settings-summary');
    if (!response.ok) {
        throw new Error(`Failed to load runtime settings summary (${response.status})`);
    }
    const summary = await response.json();
    renderRuntimeSummary(summary);
    syncMaintenanceStatusFromSummary(summary);
}

async function loadGoogleDriveAuthStatus() {
    const response = await fetch('/api/settings/google-drive/status');
    if (!response.ok) {
        throw new Error(`Failed to load Google Drive status (${response.status})`);
    }
    googleDriveAuthStatus = await response.json();
    setSyncStatus('settings-google-drive-status', googleDriveAuthStatus.status || 'Not connected', false);
    updateGoogleDriveAuthButtons();
}

async function loadSettingsTab(force = false) {
    if (settingsTabLoaded && !force) {
        return;
    }

    setSettingsStatus('Loading settings...');
    try {
        const response = await fetch('/api/settings');
        if (!response.ok) {
            throw new Error(`Failed to load settings (${response.status})`);
        }

        const state = await response.json();
        fillSettingsForm(state);
        await loadRuntimeSettingsSummary();
        await loadGoogleDriveAuthStatus();
        settingsTabLoaded = true;
        setSettingsStatus('');
    } catch (error) {
        console.error('Error loading settings:', error);
        setSettingsStatus(error.message || 'Failed to load settings.', true);
    }
}

async function connectGoogleDrive() {
    setSyncStatus('settings-google-drive-status', 'Starting Google Drive authorization...');
    try {
        if (!googleDriveAuthStatus?.configured) {
            throw new Error('Google Drive credentials are missing. Use Import Credentials to upload your credentials.json, then connect again.');
        }
        const response = await fetch('/api/settings/google-drive/auth-url');
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.auth_url) {
            throw new Error(payload.error || `Failed to start Google Drive auth (${response.status})`);
        }
        window.open(payload.auth_url, '_blank', 'noopener,noreferrer');
        setSyncStatus('settings-google-drive-status', 'Google Drive authorization opened in a new tab.');
        waitForGoogleDriveConnection();
    } catch (error) {
        console.error('Error starting Google Drive auth:', error);
        setSyncStatus('settings-google-drive-status', error.message || 'Failed to start Google Drive auth.', true);
    }
}

async function waitForGoogleDriveConnection(timeoutMs = 90000, intervalMs = 4000) {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
        await loadGoogleDriveAuthStatus();
        if (googleDriveAuthStatus?.connected) {
            await loadSettingsTab(true);
            return;
        }
    }
}

async function disconnectGoogleDriveAccount() {
    setSyncStatus('settings-google-drive-status', 'Disconnecting Google Drive...');
    try {
        const response = await fetch('/api/settings/google-drive/disconnect', { method: 'POST' });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload.success !== true) {
            throw new Error(payload.error || `Failed to disconnect Google Drive (${response.status})`);
        }
        await loadGoogleDriveAuthStatus();
    } catch (error) {
        console.error('Error disconnecting Google Drive:', error);
        setSyncStatus('settings-google-drive-status', error.message || 'Failed to disconnect Google Drive.', true);
    }
}

async function uploadGoogleDriveCredentials(file) {
    if (!file) {
        return;
    }
    setSyncStatus('settings-google-drive-status', 'Uploading Google Drive credentials...');
    try {
        const text = await file.text();
        const credentials = JSON.parse(text);
        const response = await fetch('/api/settings/google-drive/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credentials }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload.success !== true) {
            throw new Error(payload.error || `Failed to save credentials (${response.status})`);
        }
        setSyncStatus('settings-google-drive-status', payload.status || 'Credentials saved', false);
        await loadGoogleDriveAuthStatus();
    } catch (error) {
        console.error('Error uploading Google Drive credentials:', error);
        setSyncStatus('settings-google-drive-status', error.message || 'Failed to upload credentials.', true);
    }
}

function importGoogleDriveCredentials() {
    document.getElementById('settings-google-drive-credentials-file')?.click();
}

async function handleGoogleDriveCredentialsSelection(event) {
    const input = event.target;
    const file = input?.files?.[0];
    if (!file) {
        return;
    }
    try {
        await uploadGoogleDriveCredentials(file);
    } finally {
        input.value = '';
    }
}

async function saveSettingsTab() {
    const nextState = getSettingsFormState();

    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(nextState),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.success) {
            throw new Error(payload.error || `Failed to save settings (${response.status})`);
        }

        settingsState = payload.settings;
        fillSettingsForm(settingsState);
        await loadRuntimeSettingsSummary();
        setSettingsStatus('Settings saved.');
    } catch (error) {
        console.error('Error saving settings:', error);
        setSettingsStatus(error.message || 'Failed to save settings.', true);
    }
}

async function testGoogleDriveSettings() {
    const folderId = document.getElementById('settings-google-drive-folder')?.value || '';
    setSyncStatus('settings-google-drive-status', 'Testing Google Drive configuration...');

    try {
        const response = await fetch('/api/settings/validate/google-drive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_id: folderId }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.status) {
            throw new Error(payload.error || `Drive validation failed (${response.status})`);
        }

        setSyncStatus('settings-google-drive-status', payload.status, false);
    } catch (error) {
        console.error('Error validating Google Drive settings:', error);
        setSyncStatus('settings-google-drive-status', error.message || 'Drive validation failed.', true);
    }
}

async function testRemoteSyncSettings() {
    const endpoint = document.getElementById('settings-remote-sync-endpoint')?.value || '';
    const apiKey = document.getElementById('settings-remote-sync-api-key')?.value || '';
    setSyncStatus('settings-remote-sync-status', 'Testing remote sync configuration...');

    try {
        const response = await fetch('/api/settings/validate/remote-sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ endpoint, api_key: apiKey }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.status) {
            throw new Error(payload.error || `Remote sync validation failed (${response.status})`);
        }

        setSyncStatus('settings-remote-sync-status', payload.status, false);
    } catch (error) {
        console.error('Error validating remote sync settings:', error);
        setSyncStatus('settings-remote-sync-status', error.message || 'Remote sync validation failed.', true);
    }
}

async function runRuntimeBackfill() {
    setMaintenanceStatus('Running runtime backfill...');

    try {
        const response = await fetch('/api/runtime/maintenance/backfill', {
            method: 'POST',
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload.success !== true) {
            throw new Error(payload.error || `Runtime backfill failed (${response.status})`);
        }

        setMaintenanceStatus(`Backfilled ${payload.backfilled} scan artifact(s).`, false);
        await loadRuntimeSettingsSummary();
        if (typeof window.loadReportsTab === 'function') {
            window.loadReportsTab(true);
        }
        if (typeof window.loadHistoryTab === 'function') {
            window.loadHistoryTab(true);
        }
    } catch (error) {
        console.error('Error running runtime backfill:', error);
        setMaintenanceStatus(error.message || 'Runtime backfill failed.', true);
    }
}

async function exportRuntimeDatabase() {
    setMaintenanceStatus('Preparing runtime database export...');

    try {
        const response = await fetch('/api/runtime/export');
        if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            throw new Error(payload.error || `Runtime database export failed (${response.status})`);
        }

        const blob = await response.blob();
        const exportUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        const contentDisposition = response.headers.get('content-disposition') || '';
        const match = contentDisposition.match(/filename="?([^"]+)"?/i);
        link.href = exportUrl;
        link.download = match?.[1] || 'nmapui-runtime.sqlite3';
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(exportUrl);
        setMaintenanceStatus(`Exported runtime database as ${link.download}.`, false);
    } catch (error) {
        console.error('Error exporting runtime database:', error);
        setMaintenanceStatus(error.message || 'Runtime database export failed.', true);
    }
}

async function runRuntimeRetention() {
    setMaintenanceStatus('Pruning runtime logs/history and compacting the database...');

    try {
        const response = await fetch('/api/runtime/maintenance/retention', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                runtime_logs_keep_latest: 5000,
                customer_history_keep_latest: 2000,
                compact: true,
            }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload.success !== true) {
            throw new Error(payload.error || `Runtime retention failed (${response.status})`);
        }

        setMaintenanceStatus(
            `Pruned ${payload.deleted_runtime_logs || 0} log(s), ${payload.deleted_customer_scan_history || 0} history row(s), compacted DB to ${payload.after_bytes || 0} bytes.`,
            false
        );
        await loadRuntimeSettingsSummary();
        if (typeof window.loadLogsTab === 'function') {
            window.loadLogsTab();
        }
    } catch (error) {
        console.error('Error running runtime retention:', error);
        setMaintenanceStatus(error.message || 'Runtime retention failed.', true);
    }
}

function addTargetProfile() {
    const nameInput = document.getElementById('settings-profile-name');
    const targetInput = document.getElementById('settings-profile-target');
    const customerSelect = document.getElementById('settings-profile-customer');
    const notesInput = document.getElementById('settings-profile-notes');
    const profileScanOnlyInput = document.getElementById('settings-profile-scan-only-mode');
    const profileExcludedTargetsInput = document.getElementById('settings-profile-excluded-targets');
    const profileMaxScanInput = document.getElementById('settings-profile-max-scan-minutes');
    const currentCustomer = document.getElementById('current-customer');

    const name = (nameInput?.value || '').trim();
    const target = (targetInput?.value || '').trim();
    if (!name || !target) {
        setSettingsStatus('Profile name and target are required.', true);
        return;
    }

    const selectedValue = customerSelect?.value || '';
    const selectedOption = selectedValue
        ? customerSelect.selectedOptions[0]
        : currentCustomer?.selectedOptions?.[0];

    settingsState = settingsState || {
        target_profiles: [],
        scan_rules: { scan_only_mode: false, excluded_targets: [], max_scan_minutes: 120 },
        sync: { google_drive: {}, remote_sync: {} },
        auto_monitor: {
            defaults: {
                enabled_by_default: false,
                recurrence: 'weekly',
                day_of_week: 'sunday',
                time: '01:00',
                scan_mode: 'complete_pdf',
            },
            rules: [],
        },
    };

    settingsState.target_profiles = settingsState.target_profiles || [];
    settingsState.target_profiles.push({
        id: `${Date.now()}`,
        name,
        target,
        customer_id: selectedValue || '',
        customer_name: selectedOption ? selectedOption.textContent.split(' (')[0] : '',
        notes: (notesInput?.value || '').trim(),
        scan_rules: {
            scan_only_mode: !!profileScanOnlyInput?.checked,
            excluded_targets: (profileExcludedTargetsInput?.value || '')
                .split('\n')
                .map((value) => value.trim())
                .filter(Boolean),
            max_scan_minutes: Number.parseInt(profileMaxScanInput?.value || '', 10) || null,
        },
    });

    renderTargetProfiles(settingsState.target_profiles);
    nameInput.value = '';
    targetInput.value = '';
    if (notesInput) {
        notesInput.value = '';
    }
    if (profileScanOnlyInput) {
        profileScanOnlyInput.checked = false;
    }
    if (profileExcludedTargetsInput) {
        profileExcludedTargetsInput.value = '';
    }
    if (customerSelect) {
        customerSelect.value = '';
    }
    setSettingsStatus('Target profile added locally. Save Settings to persist it.');
}

function captureCurrentTarget() {
    const dashboardTarget = document.getElementById('scan-target')?.value || '';
    document.getElementById('settings-profile-target').value = dashboardTarget;
}

function initializeSettingsTab() {
    if (settingsTabInitialized) {
        return;
    }
    settingsTabInitialized = true;

    document.getElementById('save-settings-btn')?.addEventListener('click', saveSettingsTab);
    document.getElementById('refresh-settings-btn')?.addEventListener('click', () => {
        settingsTabLoaded = false;
        loadSettingsTab(true);
    });
    document.getElementById('add-target-profile-btn')?.addEventListener('click', addTargetProfile);
    document.getElementById('capture-current-target-btn')?.addEventListener('click', captureCurrentTarget);
    document.getElementById('settings-google-drive-test-btn')?.addEventListener('click', testGoogleDriveSettings);
    document.getElementById('settings-google-drive-connect-btn')?.addEventListener('click', connectGoogleDrive);
    document.getElementById('settings-google-drive-disconnect-btn')?.addEventListener('click', disconnectGoogleDriveAccount);
    document.getElementById('settings-google-drive-import-btn')?.addEventListener('click', importGoogleDriveCredentials);
    document.getElementById('settings-google-drive-credentials-file')?.addEventListener('change', handleGoogleDriveCredentialsSelection);
    document.getElementById('settings-remote-sync-test-btn')?.addEventListener('click', testRemoteSyncSettings);
    document.getElementById('settings-runtime-backfill-btn')?.addEventListener('click', runRuntimeBackfill);
    document.getElementById('settings-runtime-retention-btn')?.addEventListener('click', runRuntimeRetention);
    document.getElementById('settings-runtime-export-btn')?.addEventListener('click', exportRuntimeDatabase);
    populateProfileCustomerOptions();
}

window.loadSettingsTab = loadSettingsTab;
window.initializeSettingsTab = initializeSettingsTab;
window.exportRuntimeDatabase = exportRuntimeDatabase;
