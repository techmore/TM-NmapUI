let autoScanHttpBusy = false;

function applyAutoScanConfigState(config = {}) {
    if (!config || typeof config !== 'object') return;
    // Flask payloads use start_time/end_time; the Node dev runtime uses startTime.
    window.currentAutoScanConfig = config || {};
    const autoScanToggle = document.getElementById('auto-scan-toggle');
    const startTimeInput = document.getElementById('auto-start-time');
    const endTimeInput = document.getElementById('auto-end-time');
    if (autoScanToggle) autoScanToggle.checked = !!config.enabled;
    if (startTimeInput) startTimeInput.value = config.startTime || config.start_time || '01:00';
    if (endTimeInput) endTimeInput.value = config.endTime || config.end_time || '06:00';
}

// The packaged Flask runtime exposes /api/auto_scan/*; prefer it and fall back
// to socket events for the Node dev runtime. Returns true when handled via HTTP.
async function sendAutoScanUpdate(payload) {
    if (autoScanHttpBusy) {
        // Never report an in-flight update as handled - the caller must still
        // emit over socket so rapid toggle changes cannot be silently dropped.
        return false;
    }
    autoScanHttpBusy = true;
    try {
        const response = await fetch('/api/auto_scan/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!response.ok) return false;
        // The update acknowledgement is only {success: true}; pull the
        // effective config (incl. next_run/warning fields) separately.
        await refreshAutoScanStatus();
        return true;
    } catch (error) {
        return false;
    } finally {
        autoScanHttpBusy = false;
    }
}

async function refreshAutoScanStatus() {
    try {
        const response = await fetch('/api/auto_scan/status');
        if (!response.ok) return;
        applyAutoScanConfigState(await response.json());
    } catch (error) {
        // Socket handlers remain the fallback on the Node dev runtime.
    }
}

function initializeAutoScanUI(socket) {
    const autoScanToggle = document.getElementById('auto-scan-toggle');
    const autoScanModal = document.getElementById('auto-scan-modal');
    if (!autoScanToggle || !autoScanModal) return;

    window.currentAutoScanConfig = window.currentAutoScanConfig || {};

    autoScanToggle.addEventListener('change', () => {
        if (autoScanToggle.checked) {
            autoScanModal.classList.remove('hidden');
        } else {
            sendAutoScanUpdate({ enabled: false }).then((handled) => {
                if (!handled) socket.emit('disable_auto_scan');
            });
        }
    });

    socket.on('sync_state', (state = {}) => applyAutoScanConfigState(state.autoScan));
    socket.on('initial_data', (data = {}) => applyAutoScanConfigState(data.autoScan));
    socket.on('auto_scan_config', applyAutoScanConfigState);
    socket.on('auto_scan_status', applyAutoScanConfigState);
    refreshAutoScanStatus();
}

async function saveAutoScanTimes() {
    const startTime = document.getElementById('auto-start-time')?.value || '01:00';
    const endTime = document.getElementById('auto-end-time')?.value || '06:00';

    // Flask schedule is a daily start/end window scanning the current network
    // target; recurrence/target selectors only exist on the Node dev runtime.
    const handled = await sendAutoScanUpdate({ enabled: true, start_time: startTime, end_time: endTime });
    if (!handled) {
        window.socket.emit('enable_auto_scan', { startTime, target: document.getElementById('scan-target')?.value });
    }
    document.getElementById('auto-scan-modal').classList.add('hidden');
}

function saveAndRunScan() {
    saveAutoScanTimes();
    const target = document.getElementById('scan-target').value;
    window.socket.emit('start_complete_scan', { target, scanKind: 'complete' });
}

function hideAutoScanTimeModal() {
    document.getElementById('auto-scan-modal').classList.add('hidden');
    document.getElementById('auto-scan-toggle').checked = !!window.currentAutoScanConfig?.enabled;
}
