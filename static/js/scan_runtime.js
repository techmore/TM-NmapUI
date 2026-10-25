const clientJobs = {
    scan: { status: 'idle' },
    report: { status: 'idle' }
};
let scanRuntimeInitialized = false;

function getClientJobs() {
    return clientJobs;
}

function updateJobButtons() {
    const scanRunning = clientJobs.scan.status === 'running';
    const reportRunning = clientJobs.report.status === 'running';
    const stopButton = document.getElementById('stop-scan-btn');

    const startScanBtn = document.getElementById('start-scan-btn');
    const generateReportBtn = document.getElementById('generate-report-btn');

    if (startScanBtn) {
        startScanBtn.disabled = scanRunning;
        startScanBtn.classList.toggle('opacity-60', scanRunning);
        startScanBtn.classList.toggle('cursor-not-allowed', scanRunning);
    }

    if (generateReportBtn) {
        generateReportBtn.disabled = reportRunning;
        generateReportBtn.classList.toggle('opacity-60', reportRunning);
        generateReportBtn.classList.toggle('cursor-not-allowed', reportRunning);
    }

    if (stopButton) {
        const canStop = scanRunning || reportRunning;
        stopButton.disabled = !canStop;
        stopButton.classList.toggle('opacity-50', !canStop);
        stopButton.classList.toggle('cursor-not-allowed', !canStop);
    }
}

function syncScanJobVisualState(job) {
    const startScanBtn = document.getElementById('start-scan-btn');
    if (!startScanBtn) {
        return;
    }

    const isRunning = job?.status === 'running' || job?.status === 'cancelling';
    if (
        isRunning
        && typeof window.resetReportVisualState === 'function'
        && getClientJobs().report.status !== 'running'
        && getClientJobs().report.status !== 'cancelling'
    ) {
        window.resetReportVisualState();
    }
    startScanBtn.classList.toggle('card-pulsing', isRunning);
}

function syncScanVisualStateFromFeedback(message) {
    if (typeof message !== 'string' || !message) {
        return;
    }

    if (
        message.includes('quick scan')
        || message.includes('deep scan')
        || message.includes('ARP scan')
        || message.includes('Starting scan')
    ) {
        if (typeof window.resetReportVisualState === 'function') {
            window.resetReportVisualState();
        }
        syncScanJobVisualState({ status: 'running' });
    }
}

function normalizeFeedbackMessage(msg) {
    if (typeof msg === 'string') return msg;
    if (msg && typeof msg.message === 'string') return msg.message;
    return '';
}

function setCardPulsing(id, pulsing) {
    const element = document.getElementById(id);
    if (!element) return;
    element.classList.toggle('card-pulsing', pulsing);
}

function setHostStatusIndicator(ip, active) {
    const tb = document.querySelector('#discovery-table tbody');
    for (let row of tb.rows) {
        const ipCell = window.getDiscoveryTableCell ? window.getDiscoveryTableCell(row, 'ip') : row.cells[1];
        const statusCell = window.getDiscoveryTableCell ? window.getDiscoveryTableCell(row, 'status') : row.cells[0];
        if (ipCell?.textContent === ip && statusCell) {
            statusCell.innerHTML = active
                ? '<span class="relative flex size-3"><span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-olive-400 opacity-75"></span><span class="relative inline-flex size-3 rounded-full bg-olive-500"></span></span>'
                : '';
            break;
        }
    }
}

function clearAllHostStatusIndicators() {
    const tb = document.querySelector('#discovery-table tbody');
    Array.from(tb.rows).forEach(row => {
        const statusCell = window.getDiscoveryTableCell ? window.getDiscoveryTableCell(row, 'status') : row.cells[0];
        if (statusCell) {
            statusCell.innerHTML = '';
        }
    });
}

function initializeScanRuntime(socket) {
    if (scanRuntimeInitialized) {
        return;
    }
    scanRuntimeInitialized = true;
    const showReportStatus = window.showReportStatus || (() => {});
    const updateReportProgress = window.updateReportProgress || (() => {});
    const dimExistingRows = window.dimExistingRows || (() => {});
    const saveHostsToStorage = window.saveHostsToStorage || (() => {});

    socket.on('connect', () => console.log('Socket.IO connected'));

    socket.on('quick_scan_start', () => {
        console.log('Quick scan started - pulsing card');
        setCardPulsing('quick-scan-card', true);
        dimExistingRows();
    });

    socket.on('quick_scan_complete', () => {
        console.log('Quick scan complete - stopping pulse');
        setCardPulsing('quick-scan-card', false);
        syncScanJobVisualState({ status: 'completed' });
    });

    socket.on('arp_scan_start', () => {
        console.log('ARP scan started');
    });

    socket.on('arp_scan_complete', () => {
        console.log('ARP scan complete');
    });

    socket.on('deep_scan_start', () => {
        console.log('Deep scan started - pulsing card');
        setCardPulsing('quick-scan-card', false);
        setCardPulsing('deep-scan-card', true);
    });

    socket.on('deep_scan_host_start', (data) => {
        console.log('Deep scan started for host:', data.ip);
        setHostStatusIndicator(data.ip, true);
    });

    socket.on('deep_scan_host_complete', (data) => {
        console.log('Deep scan complete for host:', data.ip);
        setHostStatusIndicator(data.ip, false);
    });

    socket.on('deep_scan_complete', () => {
        console.log('All deep scans complete - stopping pulse');
        setCardPulsing('deep-scan-card', false);
        syncScanJobVisualState({ status: 'completed' });
        clearAllHostStatusIndicators();
        saveHostsToStorage();
        const reloadButton = document.getElementById('reload-last-scan-btn');
        if (reloadButton) {
            reloadButton.classList.remove('hidden');
        }
    });

    socket.on('scan_feedback', msg => {
        const message = normalizeFeedbackMessage(msg);
        if (!message) return;
        if (message.includes('Loaded') && message.includes('assets from scan')) {
            console.log('Suppressed recovery feedback in container');
            return;
        }
        syncScanVisualStateFromFeedback(message);
        const container = document.getElementById('feedback-container');
        container.parentElement.classList.remove('hidden');
        const paragraph = document.createElement('p');
        paragraph.textContent = message;
        container.appendChild(paragraph);
    });

    socket.on('job_status', function(data) {
        if (!data || !data.job_type) return;
        clientJobs[data.job_type] = data;
        updateJobButtons();

        if (data.job_type === 'scan') {
            syncScanJobVisualState(data);
        }

        if (data.job_type === 'report' && data.status === 'running' && data.details) {
            const message = data.details.message || 'Generating report...';
            updateReportProgress(message);
            showReportStatus(message, 'info');
        }

        if (data.job_type === 'scan' && data.status === 'running' && data.details?.message) {
            showReportStatus(data.details.message, 'info');
        }
    });

    socket.on('job_cancelled', function(data) {
        if (!data || !data.message) return;
        if (data.job_type === 'scan') {
            syncScanJobVisualState({ status: 'completed' });
        }
        showReportStatus(data.message, 'info');
    });

    socket.on('auth_error', function(data) {
        const message = data?.error || 'Unauthorized';
        console.error('Socket auth error:', message);
        showReportStatus(message, 'error');
    });

    socket.on('scan_error', function(message) {
        const text = typeof message === 'string' ? message : (message?.error || 'Scan failed');
        console.error('Scan error:', text);
        syncScanJobVisualState({ status: 'completed' });
        showReportStatus(text, 'error');
    });

    document.getElementById('start-scan-btn').addEventListener('click', () => {
        if (clientJobs.scan.status === 'running') {
            return;
        }
        const target = document.getElementById('scan-target').value;
        socket.emit('start_scan', target);
    });

    document.getElementById('stop-scan-btn').addEventListener('click', function() {
        if (clientJobs.report.status === 'running') {
            socket.emit('cancel_job', { job_type: 'report' });
            return;
        }

        if (clientJobs.scan.status === 'running') {
            socket.emit('cancel_job', { job_type: 'scan' });
        }
    });
}

window.getClientJobs = getClientJobs;
window.initializeScanRuntime = initializeScanRuntime;
window.syncScanJobVisualState = syncScanJobVisualState;
