function createReportProgressCard(message) {
    const reportCard = document.createElement('div');
    reportCard.id = 'report-progress-card';
    reportCard.className = 'mt-4 bg-olive-50 p-4 rounded-xl border border-olive-300 card-pulsing';
    const row = document.createElement('div');
    row.className = 'flex items-center gap-3';

    const indicator = document.createElement('span');
    indicator.className = 'relative flex size-3';

    const ping = document.createElement('span');
    ping.className = 'absolute inline-flex h-full w-full animate-ping rounded-full bg-olive-500 opacity-75';
    indicator.appendChild(ping);

    const dot = document.createElement('span');
    dot.className = 'relative inline-flex size-3 rounded-full bg-olive-600';
    indicator.appendChild(dot);

    const text = document.createElement('p');
    text.id = 'report-progress-text';
    text.className = 'text-sm font-medium text-olive-900';
    text.textContent = message;

    row.appendChild(indicator);
    row.appendChild(text);
    reportCard.appendChild(row);
    const statusDiv = document.getElementById('report-status');
    statusDiv.parentNode.insertBefore(reportCard, statusDiv.nextSibling);
}

function updateReportProgress(message) {
    const progressText = document.getElementById('report-progress-text');
    if (!progressText) {
        createReportProgressCard(message);
        return;
    }

    progressText.textContent = message;
}

function removeReportProgressCard() {
    const card = document.getElementById('report-progress-card');
    if (card) {
        card.remove();
    }
}

function clearReportStatusActions() {
    const actions = document.getElementById('report-status-actions');
    if (!actions) {
        return;
    }
    actions.replaceChildren();
    actions.classList.add('hidden');
}

function showReportActions(path) {
    const actions = document.getElementById('report-status-actions');
    if (!actions || !path) {
        return;
    }

    actions.replaceChildren();

    const buildLink = (href, label, newTab = false) => {
        const link = document.createElement('a');
        link.href = href;
        link.textContent = label;
        link.className = 'action-button action-button-primary action-button-compact';
        if (newTab) {
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
        }
        actions.appendChild(link);
    };

    buildLink(`/api/runtime/reports/${path}/html`, 'View Report', true);
    buildLink(`/api/runtime/reports/${path}/pdf`, 'Download PDF');
    buildLink(`/api/runtime/reports/${path}/xml`, 'Download XML');
    actions.classList.remove('hidden');
}

let reportStatusHideTimer = null;

const REPORT_STATUS_TONES = {
    info: ['bg-white', 'border-olive-300', 'border-l-olive-600', 'text-olive-900'],
    success: ['bg-emerald-50', 'border-emerald-300', 'border-l-emerald-700', 'text-emerald-900'],
    error: ['bg-red-50', 'border-red-300', 'border-l-red-700', 'text-red-900'],
};

// Progress lines name the bundled NSE script by its absolute install path;
// the strip shows the file name (the audit log keeps the full command).
function shortenStatusPaths(message) {
    return String(message ?? '').replace(/(?:\/[^\s/]+)+\/([^\s/]+\.nse)\b/g, '$1');
}

function hideReportStatus() {
    if (reportStatusHideTimer) {
        clearTimeout(reportStatusHideTimer);
        reportStatusHideTimer = null;
    }
    document.getElementById('report-status')?.classList.add('hidden');
}

function showReportStatus(message, type, options = {}) {
    const statusDiv = document.getElementById('report-status');
    const statusText = document.getElementById('report-status-text');
    const tone = REPORT_STATUS_TONES[type] ? type : 'info';

    statusDiv.classList.remove('hidden', 'bg-olive-100', 'bg-olive-200', 'bg-red-100', 'text-olive-800', 'text-red-800',
        ...new Set(Object.values(REPORT_STATUS_TONES).flat()));
    statusDiv.classList.add(...REPORT_STATUS_TONES[tone]);
    // Errors interrupt assistive technology; progress and success are polite.
    statusDiv.setAttribute('role', type === 'error' ? 'alert' : 'status');
    statusDiv.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
    statusDiv.dataset.statusType = type || 'info';

    statusText.textContent = shortenStatusPaths(message);

    if (type !== 'success') {
        clearReportStatusActions();
    }

    if (reportStatusHideTimer) {
        clearTimeout(reportStatusHideTimer);
        reportStatusHideTimer = null;
    }
    // Errors stay until dismissed or replaced (WCAG 2.2.1); a plain success
    // note may clear itself, but never once report links are attached.
    if (type === 'success' && !options.persist) {
        reportStatusHideTimer = setTimeout(() => {
            const actions = document.getElementById('report-status-actions');
            if (actions && !actions.classList.contains('hidden') && actions.children.length) return;
            statusDiv.classList.add('hidden');
            reportStatusHideTimer = null;
        }, 8000);
    }
}

function showReportCompleteStatus(data) {
    removeReportProgressCard();
    showReportStatus(window.formatReportCompleteMessage(data), 'success', { persist: true });
    showReportActions(data?.path);
}

window.createReportProgressCard = createReportProgressCard;
window.updateReportProgress = updateReportProgress;
window.removeReportProgressCard = removeReportProgressCard;
window.clearReportStatusActions = clearReportStatusActions;
window.showReportActions = showReportActions;
window.showReportStatus = showReportStatus;
window.hideReportStatus = hideReportStatus;
window.showReportCompleteStatus = showReportCompleteStatus;
