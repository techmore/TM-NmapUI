function initializeAutoScanUI(socket) {
    const autoScanToggle = document.getElementById('auto-scan-toggle');
    const autoScanModal = document.getElementById('auto-scan-modal');
    const recurrenceInput = document.getElementById('auto-recurrence');
    const startTimeInput = document.getElementById('auto-start-time');
    if (!autoScanToggle || !autoScanModal) return;

    window.currentAutoScanConfig = window.currentAutoScanConfig || {};
    let countdownTimer = null;

    function applyAutoScanConfig(config = {}) {
        // auto_scan_config envelope may wrap values in {enabled, schedule, config}
        const nested = config.config && typeof config.config === 'object' ? config.config : config;
        const enabled = !!(nested.enabled ?? config.enabled);
        const recurrence = nested.recurrence || config.schedule || 'daily';
        const startTime = nested.startTime || '01:00';
        const target = nested.target || '';
        const nextRunAt = nested.nextRunAt || config.nextRunAt || '';
        const nextRunLabel = nested.nextRunLabel || config.nextRunLabel || '';

        window.currentAutoScanConfig = {
            enabled,
            recurrence,
            startTime,
            target,
            nextRunAt,
            nextRunLabel
        };

        autoScanToggle.checked = enabled;
        if (recurrenceInput) recurrenceInput.value = recurrence;
        if (startTimeInput) startTimeInput.value = startTime;
        updateAutoScanWarningBanner(window.currentAutoScanConfig);
    }

    function updateAutoScanWarningBanner(config = {}) {
        const banner = document.getElementById('auto-scan-warning-banner');
        const nextRunEl = document.getElementById('auto-scan-warning-next-run');
        const countdownEl = document.getElementById('auto-scan-warning-countdown');
        if (!banner) return;

        if (countdownTimer) {
            clearInterval(countdownTimer);
            countdownTimer = null;
        }

        if (!config.enabled || !config.nextRunAt) {
            banner.classList.add('hidden');
            return;
        }

        banner.classList.remove('hidden');
        if (nextRunEl) {
            nextRunEl.textContent = config.nextRunLabel
                ? `(${config.nextRunLabel})`
                : `(next: ${config.nextRunAt})`;
        }

        const targetMs = Date.parse(config.nextRunAt);
        if (!Number.isFinite(targetMs) || !countdownEl) {
            if (countdownEl) countdownEl.textContent = '--:--:--';
            return;
        }

        const tick = () => {
            const remaining = Math.max(0, targetMs - Date.now());
            const totalSeconds = Math.floor(remaining / 1000);
            const hours = Math.floor(totalSeconds / 3600);
            const minutes = Math.floor((totalSeconds % 3600) / 60);
            const seconds = totalSeconds % 60;
            const pad = (n) => String(n).padStart(2, '0');
            countdownEl.textContent = `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
            if (remaining <= 0) {
                countdownEl.textContent = '00:00:00';
            }
        };
        tick();
        countdownTimer = setInterval(tick, 1000);
    }

    autoScanToggle.addEventListener('change', () => {
        if (autoScanToggle.checked) {
            autoScanModal.classList.remove('hidden');
        } else {
            socket.emit('disable_auto_scan');
        }
    });

    socket.on('sync_state', (state = {}) => applyAutoScanConfig(state.autoScan || {}));
    socket.on('initial_data', (data = {}) => applyAutoScanConfig(data.autoScan || {}));
    socket.on('auto_scan_config', applyAutoScanConfig);

    // Native bridge may emit config outside socket.on in some paths.
    window.__nmapuiApplyAutoScanConfig = applyAutoScanConfig;
}

function saveAutoScanTimes() {
    const recurrence = document.getElementById('auto-recurrence').value;
    const startTime = document.getElementById('auto-start-time').value;
    const target = document.getElementById('scan-target').value;

    window.socket.emit('enable_auto_scan', { recurrence, startTime, target });
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
