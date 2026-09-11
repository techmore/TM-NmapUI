function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && (parts[1] >= 16 && parts[1] <= 31)) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
}

let activeScanPhase = null;
let activePhaseStartedAt = null;
let activePhaseTimer = null;
let activeScanKind = null;

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function formatDurationSeconds(totalSeconds) {
    const seconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
    const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
    const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
    const s = String(seconds % 60).padStart(2, '0');
    return `${h}:${m}:${s}`;
}

function formatReportTimestamp(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'Unknown date';
    return date.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit'
    });
}

function startPhaseTimer(phase, startedAt) {
    activeScanPhase = phase;
    activePhaseStartedAt = startedAt ? new Date(startedAt).getTime() : Date.now();
    if (activePhaseTimer) clearInterval(activePhaseTimer);

    const targetId = phase === 1 ? 'quick-time' : 'deep-time';
    const tick = () => setText(targetId, formatDurationSeconds((Date.now() - activePhaseStartedAt) / 1000));
    tick();
    activePhaseTimer = setInterval(tick, 1000);
}

function stopPhaseTimer(phase, duration) {
    if (activePhaseTimer && activeScanPhase === phase) {
        clearInterval(activePhaseTimer);
        activePhaseTimer = null;
        activeScanPhase = null;
        activePhaseStartedAt = null;
    }
    setText(phase === 1 ? 'quick-time' : 'deep-time', formatDurationSeconds(duration));
}

function getHighCVEList(data) {
    if (Array.isArray(data.highCVEs)) return data.highCVEs.filter(Boolean);
    if (typeof data.highCVEs !== 'string' || !data.highCVEs.trim()) return [];
    return data.highCVEs.split(',').map(item => item.trim()).filter(Boolean);
}

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function renderCVELink(cveText) {
    const safeText = escapeHTML(cveText);
    const cveId = String(cveText).match(/CVE-\d{4}-\d+/)?.[0];
    if (!cveId) return safeText;
    return `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" target="_blank" rel="noopener noreferrer" class="block text-red-700 underline decoration-red-300 underline-offset-2 hover:text-red-900">${safeText}</a>`;
}

function renderScreenshotCell(data) {
    const screenshots = Array.isArray(data.screenshots) ? data.screenshots : [];
    const shot = screenshots[screenshots.length - 1] || (data.screenshotUrl ? {
        dashboardUrl: data.screenshotUrl,
        url: data.screenshotTarget || data.screenshotUrl
    } : null);
    if (!shot?.dashboardUrl) return '<span>--</span>';
    const title = shot.url || 'Open gowitness screenshot';
    const dashUrl = escapeHTML(shot.dashboardUrl);
    return `
        <a href="${dashUrl}" target="_blank" rel="noopener noreferrer" title="${escapeHTML(title)}" data-screenshot-url="${dashUrl}" data-screenshot-title="${escapeHTML(title)}">
            <img src="${dashUrl}" alt="${escapeHTML(title)}">
        </a>`;
}

function openScreenshotPreview(imageUrl, title) {
    let overlay = document.getElementById('screenshot-preview-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'screenshot-preview-overlay';
        overlay.className = 'fixed inset-0 z-[80] hidden items-center justify-center bg-black/75 p-4';
        overlay.innerHTML = `
            <div class="max-h-full w-full max-w-6xl overflow-hidden rounded-lg bg-white shadow-2xl">
                <div class="flex items-center justify-between gap-3 border-b border-olive-100 px-4 py-3">
                    <p class="screenshot-preview-title min-w-0 truncate text-sm font-semibold text-olive-900"></p>
                    <div class="flex items-center gap-2">
                        <a class="screenshot-preview-open rounded-md border border-olive-200 px-3 py-1.5 text-xs font-semibold text-olive-700 hover:bg-olive-50" target="_blank" rel="noopener noreferrer">Open image</a>
                        <button class="screenshot-preview-close rounded-md border border-olive-200 px-3 py-1.5 text-xs font-semibold text-olive-700 hover:bg-olive-50" type="button">Close</button>
                    </div>
                </div>
                <div class="max-h-[82vh] overflow-auto bg-zinc-950 p-3">
                    <img class="mx-auto max-h-[78vh] max-w-full object-contain" alt="">
                </div>
            </div>`;
        document.body.appendChild(overlay);
        overlay.addEventListener('click', event => {
            if (event.target === overlay || event.target.closest('.screenshot-preview-close')) {
                overlay.classList.add('hidden');
                overlay.classList.remove('flex');
            }
        });
    }
    overlay.querySelector('img').src = imageUrl;
    overlay.querySelector('img').alt = title || 'gowitness screenshot';
    overlay.querySelector('.screenshot-preview-title').textContent = title || imageUrl;
    overlay.querySelector('.screenshot-preview-open').href = imageUrl;
    overlay.classList.remove('hidden');
    overlay.classList.add('flex');
}

function reportActionLink({ href, title, icon, download = false, disabled = false }) {
    if (disabled || !href) {
        return `<span title="${escapeHTML(title)}" class="inline-flex size-8 items-center justify-center rounded-lg border border-zinc-200 bg-zinc-50 text-zinc-400"><i data-lucide="${icon}" class="size-4"></i></span>`;
    }
    return `<a href="${escapeHTML(href)}" ${download ? 'download' : 'target="_blank" rel="noopener noreferrer"'} title="${escapeHTML(title)}" aria-label="${escapeHTML(title)}" class="inline-flex size-8 items-center justify-center rounded-lg border border-olive-200 bg-white text-olive-700 transition-colors hover:border-olive-300 hover:bg-olive-50 hover:text-olive-950"><i data-lucide="${icon}" class="size-4"></i></a>`;
}

function refreshLucideIcons() {
    if (window.lucide?.createIcons) window.lucide.createIcons();
}

function getScanCustomerProfilePrefix() {
    if (typeof window.getSelectedCustomerProfilePrefix === 'function') {
        return window.getSelectedCustomerProfilePrefix();
    }
    return window.currentCustomerProfile?.prefix || '';
}

function getCVECountsFromRows() {
    return Array.from(document.querySelectorAll('#discovery-table tbody tr')).reduce((totals, row) => {
        totals.high += Number(row.dataset.highCveCount || 0);
        totals.low += Number(row.dataset.lowCveCount || 0);
        return totals;
    }, { high: 0, low: 0 });
}

function updateCVESummaries() {
    const totals = getCVECountsFromRows();
    const total = totals.high + totals.low;
    const summaryCVEs = document.getElementById('summary-cves');
    const deepCVEs = document.getElementById('deep-cves');
    const dragnetCVEs = document.getElementById('dragnet-cves');

    if (summaryCVEs) summaryCVEs.textContent = total ? `${total} (${totals.high} >=7.0, ${totals.low} LOW)` : '--';
    if (deepCVEs) deepCVEs.textContent = totals.high ? `${totals.high} >=7.0` : '--';
    if (dragnetCVEs) dragnetCVEs.textContent = totals.high ? `${totals.high} >=7.0` : '--';
}

// ---- Monitoring Hub (repurposed Dragnet card, issue #11) ----

const MONITOR_CHANGE_KEY = 'nmapui_monitor_change_summary';

function updateMonitoringHubChangeSummary(diffSummary) {
    const el = document.getElementById('monitor-change-summary');
    if (!el) return;
    if (!diffSummary || typeof diffSummary !== 'object') return;

    if (!diffSummary.has_changes) {
        el.textContent = 'No changes';
        el.className = 'font-medium text-olive-500';
        localStorage.removeItem(MONITOR_CHANGE_KEY);
        return;
    }

    const parts = [];
    if (diffSummary.added_hosts?.length) parts.push(`+${diffSummary.added_hosts.length} host`);
    if (diffSummary.removed_hosts?.length) parts.push(`-${diffSummary.removed_hosts.length} host`);
    if (diffSummary.new_ports?.length) parts.push(`+${diffSummary.new_ports.length} port`);
    if (diffSummary.removed_ports?.length) parts.push(`-${diffSummary.removed_ports.length} port`);
    if (diffSummary.new_vulnerabilities?.length) parts.push(`+${diffSummary.new_vulnerabilities.length} CVE`);
    if (diffSummary.removed_vulnerabilities?.length) parts.push(`-${diffSummary.removed_vulnerabilities.length} CVE`);

    if (!parts.length) {
        el.textContent = 'Changed';
    } else {
        el.textContent = parts.join(', ');
        // Persist so the summary survives reloads until the next clean scan.
        try { localStorage.setItem(MONITOR_CHANGE_KEY, el.textContent); } catch (_) {}
    }
    el.className = 'font-bold text-amber-600';
}

function restoreMonitoringHubChangeSummary() {
    const el = document.getElementById('monitor-change-summary');
    if (!el || el.textContent !== '--') return;
    try {
        const saved = localStorage.getItem(MONITOR_CHANGE_KEY);
        if (saved) {
            el.textContent = saved;
            el.className = 'font-bold text-amber-600';
        }
    } catch (_) {}
}

function updateMonitoringHubAutoMonitor(config = {}) {
    const stateEl = document.getElementById('monitor-auto-scan-state');
    const detailEl = document.getElementById('monitor-auto-scan-detail');
    const indicator = document.getElementById('auto-monitor-indicator');
    if (!stateEl) return;

    const enabled = !!config.enabled;
    stateEl.textContent = enabled ? `On (${config.recurrence || 'daily'})` : 'Off';
    stateEl.className = enabled ? 'font-bold text-amber-600' : 'font-medium text-olive-400';
    indicator?.classList.toggle('hidden', !enabled);

    if (detailEl) {
        if (enabled) {
            detailEl.textContent = `${config.startTime || '01:00'} - target ${config.target || 'current network'}`;
            detailEl.classList.remove('hidden');
        } else {
            detailEl.textContent = '';
            detailEl.classList.add('hidden');
        }
    }
}

function initializeMonitoringHub(socket) {
    restoreMonitoringHubChangeSummary();

    socket.on('sync_state', (state = {}) => {
        if (state.autoScan) updateMonitoringHubAutoMonitor(state.autoScan);
    });
    socket.on('initial_data', (data = {}) => {
        if (data.autoScan) updateMonitoringHubAutoMonitor(data.autoScan);
    });
    socket.on('auto_scan_config', (config = {}) => updateMonitoringHubAutoMonitor(config));

    socket.on('report_ready', () => {
        // A fresh report means a fresh diff summary may arrive shortly after.
        const el = document.getElementById('monitor-change-summary');
        if (el) { el.textContent = 'checking...'; }
    });
    socket.on('report_diff_summary', (payload = {}) => updateMonitoringHubChangeSummary(payload.diff_summary || payload));

    // Replay/live scan feedback surfaces in the report status strip.
    socket.on('scan_feedback', (data) => {
        const message = typeof data === 'string' ? data : (data?.message || '');
        if (message && typeof window.showReportStatus === 'function') {
            window.showReportStatus(message, 'info');
        }
    });

    document.getElementById('open-reports-tab-btn')?.addEventListener('click', () => {
        if (typeof switchAppTab === 'function') switchAppTab('reports');
    });
}


function getDiscoveryTableStats() {
    const rows = Array.from(document.querySelectorAll('#discovery-table tbody tr'));
    return rows.reduce((stats, row) => {
        stats.hostCount++;
        const ports = row.querySelector('.ports-cell')?.textContent || '';
        if (ports && ports !== '--') {
            stats.openPortCount += ports.split(',').map(port => port.trim()).filter(Boolean).length;
        }
        stats.criticalCVECount += Number(row.dataset.highCveCount || 0);
        stats.lowCVECount += Number(row.dataset.lowCveCount || 0);
        return stats;
    }, { hostCount: 0, openPortCount: 0, criticalCVECount: 0, lowCVECount: 0 });
}

function updateQuickScanStats(stats = getDiscoveryTableStats()) {
    setText('quick-hosts', stats.hostCount || '--');
}

function updateDeepScanStats(stats = getDiscoveryTableStats()) {
    setText('deep-hosts', stats.hostCount || '--');
    setText('deep-ports', stats.openPortCount || '--');
    setText('deep-cves', stats.criticalCVECount ? `${stats.criticalCVECount} >=7.0` : '--');
}

function highlightActiveScanHost(data) {
    if (!data || !data.ip) return;

    const label = data.hostname ? `${data.ip} (${data.hostname})` : data.ip;
    setText('scan-console-status', `Scanning ${label}`);

    document.querySelectorAll('#discovery-table tbody tr.is-active-scan-host').forEach(row => {
        row.classList.remove('is-active-scan-host', 'bg-amber-50', 'ring-1', 'ring-amber-300');
    });

    updateHostRow({ ip: data.ip, hostname: data.hostname });
    const row = document.getElementById(`row-${data.ip.replace(/\./g, '-')}`);
    if (row) row.classList.add('is-active-scan-host', 'bg-amber-50', 'ring-1', 'ring-amber-300');
}

let appVersion = null;

function initializeScanRuntime(socket) {
    socket.on('job_status', (job = {}) => {
        if (job.job_type !== 'scan') return;
        if (job.status === 'running' || job.status === 'cancelling') {
            setScanUIActive(1, 'quick');
            if (activeScanPhase !== 1) startPhaseTimer(1, job.started_at);
        } else if (activeScanKind === 'quick') {
            const elapsed = activePhaseStartedAt ? (Date.now() - activePhaseStartedAt) / 1000 : 0;
            stopPhaseTimer(1, elapsed);
            resetScanUI();
        }
    });

    socket.on('sync_state', (state) => {
        if (state.version) {
            appVersion = state.version;
            const versionEl = document.getElementById('app-version');
            if (versionEl) versionEl.textContent = state.version;
        }
        if (state.customerProfile && typeof renderCustomerFingerprint === 'function') {
            renderCustomerFingerprint(state.customerProfile);
        }

        if (state.hosts && state.hosts.length > 0) {
            const tableBody = document.querySelector('#discovery-table tbody');
            tableBody.innerHTML = '';
            state.hosts.forEach(host => {
                updateHostRow(host);
            });
            updateQuickScanStats({ hostCount: state.hosts.length });
            updateDeepScanStats(getDiscoveryTableStats());
        }

        if (state.isScanning) {
            document.getElementById('scan-target').value = state.target;
            setScanUIActive(state.phase, state.scanKind);
            startPhaseTimer(state.phase, state.startTime);
        } else if (state.target) {
            // Prefill with the last known scan target when idle (#230 protocol bridge).
            document.getElementById('scan-target').value = state.target;
        }

        if (state.lastResult) {
            document.getElementById('last-scan-time-val').textContent = state.lastResult.duration + 's';
            document.getElementById('last-scan-duration').classList.remove('hidden');
        }

        if (state.hops && state.hops.length > 0) {
            const routePath = document.getElementById('route-path');
            routePath.innerHTML = '';
            state.hops.forEach(hop => {
                renderHop(hop);
            });
        }
    });

    socket.on('scan_started', (data) => {
        setScanUIActive(data.phase, data.scanKind);
        startPhaseTimer(data.phase, data.startTime);
        if (data.phase === 1) {
            const tb = document.querySelector('#discovery-table tbody');
            if (tb) tb.innerHTML = '';
            setText('quick-time', '00:00:00');
            setText('quick-hosts', '--');
            setText('deep-time', '--:--:--');
            setText('deep-hosts', '--');
            setText('deep-ports', '--');
            setText('deep-cves', '--');
            setText('summary-hosts', '--');
            setText('summary-ports', '--');
            setText('summary-cves', '--');
        }
        if (data.phase >= 2) {
            setText('deep-time', '00:00:00');
            updateDeepScanStats(getDiscoveryTableStats());
        }
    });

    socket.on('phase_complete', (data) => {
        stopPhaseTimer(data.phase, data.duration);
        if (data.phase === 1) {
            updateQuickScanStats(data);
        }
        if (data.phase >= 2) {
            updateDeepScanStats(data);
        }
    });

    socket.on('phase_stats', (data) => {
        if (data.phase >= 2) {
            updateDeepScanStats(data);
        }
    });

    socket.on('phase_host_started', (data) => {
        highlightActiveScanHost(data);
    });

    socket.on('scan_stopped', () => {
        resetScanUI();
    });

    socket.on('initial_data', (data) => {
        document.getElementById('local-ip-value').textContent = data.localIP;
        document.getElementById('subnet-mask-value').textContent = data.mask;
        document.getElementById('cidr-value').textContent = data.cidr;
        document.getElementById('public-ip-value').textContent = data.publicIP;
        if (data.customerProfile && typeof renderCustomerFingerprint === 'function') {
            renderCustomerFingerprint(data.customerProfile);
        }
        
        const targetInput = document.getElementById('scan-target');
        if (!targetInput.value) {
            targetInput.value = data.cidr;
        }
    });

    socket.emit('get_initial_data');
    socket.emit('get_history');
    socket.emit('get_reports');

    socket.on('traceroute_hop', (data) => {
        renderHop(data);
    });

    socket.on('scan_complete', (data) => {
        resetScanUI();
        stopPhaseTimer(data.phase, data.duration);
        document.getElementById('last-scan-time-val').textContent = data.duration + 's';
        document.getElementById('last-scan-duration').classList.remove('hidden');
        socket.emit('get_history');
        socket.emit('get_reports');
    });

    socket.on('report_ready', (data) => {
        const reportStatus = document.getElementById('report-status');
        if (reportStatus) {
            const actions = [
                reportActionLink({ href: data.url, title: 'Open HTML report', icon: 'file-code-2' }),
                reportActionLink({ href: data.pdfUrl, title: 'Open PDF report', icon: 'file-text', disabled: !data.pdfUrl }),
                reportActionLink({ href: data.pdfUrl, title: 'Download PDF', icon: 'download', download: true, disabled: !data.pdfUrl }),
                reportActionLink({ href: data.drivePdfUrl || data.driveHtmlUrl, title: 'Open PDF in Google Drive', icon: 'cloud', disabled: !(data.drivePdfUrl || data.driveHtmlUrl) })
            ].join('');
            reportStatus.classList.remove('hidden');
            document.getElementById('report-status-text').innerHTML = `
                <div class="flex flex-wrap items-center gap-3">
                    <span class="min-w-0 flex-1 text-sm text-emerald-900 font-medium">Report Ready: <strong>${escapeHTML(data.name)}</strong>${data.customerProfile ? `<span class="block truncate text-xs text-emerald-700">${escapeHTML(data.customerProfile.folderName)}</span>` : ''}</span>
                    <div class="flex items-center gap-1.5">${actions}</div>
                </div>
            `;
            refreshLucideIcons();
        }
        socket.emit('get_reports');
    });

    socket.on('history_data', (data) => {
        const historyList = document.getElementById('history-tab-list');
        const historyStatus = document.getElementById('history-tab-status');
        if (historyList) {
            if (!data || data.length === 0) {
                historyList.innerHTML = '';
                if (historyStatus) {
                    historyStatus.textContent = 'No scan history found yet.';
                    historyStatus.classList.remove('hidden');
                }
                return;
            }
            if (historyStatus) {
                historyStatus.textContent = '';
                historyStatus.classList.add('hidden');
            }
            historyList.innerHTML = data.map(item => {
                const failed = item.status === 'failed';
                return `
                <div class="bg-white border ${failed ? 'border-red-200' : 'border-olive-200'} rounded-2xl p-5 shadow-sm hover:shadow-md transition-shadow">
                    <div class="flex justify-between items-start mb-4">
                        <span class="text-[10px] font-bold ${failed ? 'text-red-500' : 'text-olive-400'} uppercase tracking-widest">${new Date(item.timestamp).toLocaleString()}</span>
                        <span class="px-2 py-1 ${failed ? 'bg-red-100 text-red-700' : 'bg-olive-100 text-olive-700'} text-[10px] font-bold rounded-lg">${failed ? 'FAILED' : `${item.duration}s`}</span>
                    </div>
                    <div class="mb-4">
                        <h4 class="text-olive-900 font-bold text-lg">${escapeHTMLValue(item.customerProfile?.baseName || item.target)}</h4>
                        <p class="text-xs text-olive-500">${escapeHTMLValue(item.hostCount)} Hosts Discovered${item.customerProfile?.folderName ? ` | ${escapeHTMLValue(item.customerProfile.folderName)}` : ''}</p>
                        ${failed && item.error ? `<p class="mt-2 line-clamp-2 rounded-lg bg-red-50 p-2 font-mono text-[10px] text-red-700">${escapeHTML(item.error)}</p>` : ''}
                    </div>
                    <div class="grid gap-2 sm:grid-cols-2">
                        ${item.reportUrl ? `<a href="${item.reportUrl}" target="_blank" class="block text-center py-2 bg-olive-50 text-olive-700 text-xs font-bold rounded-xl hover:bg-olive-100 transition-colors">OPEN HTML</a>` : ''}
                        ${item.pdfUrl ? `<a href="${item.pdfUrl}" target="_blank" class="block text-center py-2 bg-red-50 text-red-700 text-xs font-bold rounded-xl hover:bg-red-100 transition-colors">OPEN PDF</a>` : ''}
                    </div>
                </div>
            `;
            }).join('');
        }
    });

    socket.on('reports_data', (data) => {
        const reportsList = document.getElementById('reports-tab-list');
        const reportsStatus = document.getElementById('reports-tab-status');
        const reportsBadge = document.getElementById('reports-badge');
        if (reportsBadge) {
            reportsBadge.textContent = data && data.length > 99 ? '99+' : String((data || []).length);
            reportsBadge.classList.toggle('hidden', !data || data.length === 0);
        }
        if (reportsList) {
            if (!data || data.length === 0) {
                reportsList.innerHTML = '';
                if (reportsStatus) {
                    reportsStatus.textContent = 'No completed reports found yet.';
                    reportsStatus.classList.remove('hidden');
                }
                return;
            }
            if (reportsStatus) {
                reportsStatus.textContent = '';
                reportsStatus.classList.add('hidden');
            }
            reportsList.innerHTML = data.map(report => {
                const failed = report.status === 'failed';
                const reportTimestamp = formatReportTimestamp(report.date);
                const durationText = report.duration ? formatDurationSeconds(report.duration) : '';
                const actions = [
                    reportActionLink({ href: report.url, title: 'Open HTML report', icon: 'file-code-2' }),
                    reportActionLink({ href: report.pdfUrl, title: 'Open PDF report', icon: 'file-text', disabled: !report.pdfUrl }),
                    reportActionLink({ href: report.xmlUrl, title: 'Open XML report', icon: 'braces', disabled: !report.xmlUrl }),
                    reportActionLink({ href: report.pdfUrl, title: 'Download PDF', icon: 'download', download: true, disabled: !report.pdfUrl }),
                    reportActionLink({ href: report.drivePdfUrl || report.driveHtmlUrl, title: 'Open PDF in Google Drive', icon: 'cloud', disabled: !(report.drivePdfUrl || report.driveHtmlUrl) })
                ].join('');
                return `
                    <div class="bg-white border ${failed ? 'border-red-200' : 'border-olive-200'} rounded-lg p-3 shadow-sm transition-shadow hover:shadow-md">
                        <div class="flex items-start justify-between gap-3">
                            <div class="min-w-0">
                                <h4 class="truncate text-sm font-bold text-olive-900" title="${escapeHTML(report.name)}">${escapeHTML(report.name)}</h4>
                                <p class="mt-0.5 truncate font-mono text-[10px] text-olive-500" title="${escapeHTML(report.folder || '')}">${escapeHTML(report.folder || 'reports')}</p>
                            </div>
                            <span class="shrink-0 text-[10px] font-bold uppercase ${failed ? 'text-red-500' : 'text-olive-400'}">${failed ? 'Failed' : 'Report'}</span>
                        </div>
                        <div class="mt-2 grid gap-1 text-[10px] leading-snug text-olive-600">
                            <span>${escapeHTML(reportTimestamp)}</span>
                            ${durationText ? `<span>Scan time ${escapeHTML(durationText)}</span>` : ''}
                        </div>
                        ${failed && report.error ? `<p class="mt-2 line-clamp-2 rounded-lg bg-red-50 p-2 font-mono text-[10px] text-red-700">${escapeHTML(report.error)}</p>` : ''}
                        <div class="mt-3 flex items-center justify-between gap-2">
                            <span class="text-[10px] font-medium ${failed ? 'text-red-600' : 'text-olive-500'}">${failed ? `Failed${report.duration ? ` after ${report.duration}s` : ''}` : (report.drivePdfUrl || report.driveHtmlUrl ? 'Drive synced' : 'Local only')}</span>
                            <div class="flex items-center gap-1.5">${actions}</div>
                        </div>
                    </div>
                `;
            }).join('');
            refreshLucideIcons();
        }
    });

    socket.on('reports_refresh', () => socket.emit('get_reports'));
}

function renderHop(data) {
    const routePath = document.getElementById('route-path');
    if (!routePath) return;
    if (routePath.querySelector('span.italic')) {
        routePath.innerHTML = '';
    }
    if (document.getElementById(`hop-${data.hop}`)) return;
    const isPrivate = isPrivateIP(data.ip);
    const colorClass = isPrivate ? 'bg-amber-100 text-amber-700 border-amber-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200';
    if (data.hop > 1) {
        const arrow = document.createElement('span');
        arrow.className = 'text-olive-300 mx-1';
        arrow.textContent = '→';
        routePath.appendChild(arrow);
    }
    const hopSpan = document.createElement('span');
    hopSpan.id = `hop-${data.hop}`;
    hopSpan.className = `px-2 py-1 rounded-lg text-[10px] font-mono font-bold border ${colorClass} shadow-sm`;
    hopSpan.textContent = `${data.hop}: ${data.ip}`;
    routePath.appendChild(hopSpan);
    const allHops = Array.from(routePath.querySelectorAll('[id^="hop-"]'));
    document.getElementById('total-hops').textContent = allHops.length;
    let privateCount = 0; let publicCount = 0; let lastIp = '--';
    allHops.forEach(el => {
        const ip = el.textContent.split(': ')[1];
        if (isPrivateIP(ip)) privateCount++; else publicCount++;
        lastIp = ip;
    });
    document.getElementById('private-hops').textContent = privateCount;
    document.getElementById('public-hops').textContent = publicCount;
    document.getElementById('exit-ip').textContent = lastIp;
}

function getScanButtonByKind(kind) {
    if (kind === 'complete') return document.getElementById('generate-report-btn');
    if (kind === 'dragnet') return document.getElementById('dragnet-scan-btn');
    return document.getElementById('start-scan-btn');
}

function setScanUIActive(phase, scanKind = activeScanKind || 'quick') {
    activeScanKind = scanKind;
    const scanButtons = [
        document.getElementById('start-scan-btn'),
        document.getElementById('generate-report-btn'),
        document.getElementById('dragnet-scan-btn')
    ].filter(Boolean);
    const activeButton = getScanButtonByKind(scanKind);

    scanButtons.forEach(button => {
        button.disabled = true;
        button.classList.toggle('opacity-50', button !== activeButton);
        button.classList.toggle('opacity-90', button === activeButton);
        button.classList.toggle('ring-4', button === activeButton);
        button.classList.toggle('ring-white/50', button === activeButton);
        button.querySelector('.scan-button-pulse')?.classList.toggle('hidden', button !== activeButton);
    });

    if (phase === 1) {
        document.getElementById('quick-scan-indicator')?.classList.remove('hidden');
        document.getElementById('deep-scan-indicator')?.classList.add('hidden');
    }
    if (phase >= 2) {
        document.getElementById('quick-scan-indicator')?.classList.add('hidden');
        document.getElementById('deep-scan-indicator')?.classList.remove('hidden');
    }
}

function resetScanUI() {
    activeScanKind = null;
    [
        document.getElementById('start-scan-btn'),
        document.getElementById('generate-report-btn'),
        document.getElementById('dragnet-scan-btn')
    ].filter(Boolean).forEach(button => {
        button.disabled = false;
        button.classList.remove('opacity-50', 'opacity-90', 'ring-4', 'ring-white/50');
        button.querySelector('.scan-button-pulse')?.classList.add('hidden');
    });
    if (document.getElementById('quick-scan-indicator')) document.getElementById('quick-scan-indicator').classList.add('hidden');
    if (document.getElementById('deep-scan-indicator')) document.getElementById('deep-scan-indicator').classList.add('hidden');
    document.querySelectorAll('#discovery-table tbody tr.is-active-scan-host').forEach(row => {
        row.classList.remove('is-active-scan-host', 'bg-amber-50', 'ring-1', 'ring-amber-300');
    });
    setText('scan-console-status', 'Waiting for scan activity');
}

function updateHostRow(data) {
    const tableBody = document.querySelector('#discovery-table tbody');
    if (!tableBody) return;
    let row = document.getElementById(`row-${data.ip.replace(/\./g, '-')}`);
    if (!row) {
        row = document.createElement('tr');
        row.id = `row-${data.ip.replace(/\./g, '-')}`;
        row.className = 'hover:bg-olive-50 transition-colors border-b border-olive-100';
        row.innerHTML = `
            <td class="px-0 py-0.5 text-center"><span class="size-2 rounded-full bg-emerald-500 inline-block shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span></td>
            <td class="px-1 py-0.5 font-mono text-[11px] text-olive-900 ip-cell">${escapeHTMLValue(data.ip)}</td>
            <td class="px-1 py-0.5 font-mono text-[10px] text-olive-600 mac-cell">${escapeHTMLValue(data.mac || '--')}</td>
            <td class="px-0 py-0.5 text-[10px] text-olive-700 truncate vendor-cell" title="${escapeHTMLValue(data.vendor || '--')}">${escapeHTMLValue(data.vendor || '--')}</td>
            <td class="px-0 py-0.5 text-[10px] font-medium text-olive-900 truncate hostname-cell" title="${escapeHTMLValue(data.hostname || '--')}">${escapeHTMLValue(data.hostname || '--')}</td>
            <td class="px-0 py-0.5 text-[10px] cve-cell">--</td>
            <td class="px-0 py-0.5 text-[10px] text-olive-700 os-cell">${escapeHTMLValue(data.os || '--')}</td>
            <td class="px-0 py-0.5 text-[10px] text-olive-700 latency-cell">${escapeHTMLValue(data.latency || '--')}</td>
            <td class="px-0 py-0.5 text-[10px] text-olive-700 ports-cell">${escapeHTMLValue(data.ports || '--')}</td>
            <td class="px-0 py-0.5 text-[10px] text-olive-700 version-cell">${escapeHTMLValue(data.version || '--')}</td>
            <td class="px-0 py-0.5 screenshot-cell">${renderScreenshotCell(data)}</td>
            <td class="px-0 py-0.5 text-right"><button class="text-[10px] font-bold text-olive-600 bg-olive-100 hover:bg-olive-200 px-0 py-0.5 rounded-full transition-all">DETAILS</button></td>
        `;
        tableBody.appendChild(row);
    }

    if (data.mac) row.querySelector('.mac-cell').textContent = data.mac;
    if (data.vendor) {
        const vendorCell = row.querySelector('.vendor-cell');
        vendorCell.textContent = data.vendor;
        vendorCell.title = data.vendor;
    }
    if (data.hostname) {
        const hostnameCell = row.querySelector('.hostname-cell');
        hostnameCell.textContent = data.hostname;
        hostnameCell.title = data.hostname;
    }
    if (data.os) row.querySelector('.os-cell').textContent = data.os;
    if (data.latency) row.querySelector('.latency-cell').textContent = data.latency;
    if (data.ports) row.querySelector('.ports-cell').textContent = data.ports;
    if (data.version) row.querySelector('.version-cell').textContent = data.version;
    if (data.screenshots || data.screenshotUrl) row.querySelector('.screenshot-cell').innerHTML = renderScreenshotCell(data);
    
    const highCVEs = getHighCVEList(data);
    const lowCVECount = Number(data.lowCVECount || 0);
    row.dataset.highCveCount = String(highCVEs.length);
    row.dataset.lowCveCount = String(lowCVECount);

    const cveCell = row.querySelector('.cve-cell');
    let html = '';
    if (highCVEs.length > 0) {
        const highCVEText = highCVEs.map(escapeHTML).join('\n');
        html += `<div class="font-mono text-[10px] leading-snug" title="${highCVEText}">${highCVEs.map(renderCVELink).join('')}</div>`;
    }
    if (lowCVECount > 0) {
        html += `<div class="mt-1 inline-flex px-1.5 py-0.5 bg-amber-50 text-amber-700 rounded-md font-medium" title="Found ${lowCVECount} LOW priority CVEs in the report">${lowCVECount} LOW</div>`;
    }
    cveCell.innerHTML = html || '--';
    updateCVESummaries();
}

function initializeScanButtonWiring(socket) {
    const startScanBtn = document.getElementById('start-scan-btn');
    const completeScanBtn = document.getElementById('generate-report-btn');
    const dragnetScanBtn = document.getElementById('dragnet-scan-btn');
    const stopScanBtn = document.getElementById('stop-scan-btn');
    const vpnHelperToggle = document.getElementById('vpn-helper-toggle');
    const vpnForceOsWrapper = document.getElementById('vpn-force-os-wrapper');
    const vpnForceOsToggle = document.getElementById('vpn-force-os-toggle');

    const syncVpnControls = () => {
        const enabled = !!vpnHelperToggle?.checked;
        vpnForceOsWrapper?.classList.toggle('hidden', !enabled);
        vpnForceOsWrapper?.classList.toggle('flex', enabled);
        if (!enabled && vpnForceOsToggle) vpnForceOsToggle.checked = false;
    };
    vpnHelperToggle?.addEventListener('change', syncVpnControls);
    syncVpnControls();

    if (startScanBtn) {
        startScanBtn.addEventListener('click', () => {
            const target = document.getElementById('scan-target').value;
            socket.emit('start_quick_scan', { target, customerProfilePrefix: getScanCustomerProfilePrefix() });
        });
    }
    if (completeScanBtn) {
        completeScanBtn.addEventListener('click', () => {
            const target = document.getElementById('scan-target').value;
            const vpnHelper = !!vpnHelperToggle?.checked;
            const forceOsDetection = vpnHelper && !!vpnForceOsToggle?.checked;
            socket.emit('start_complete_scan', { target, vpnHelper, forceOsDetection, customerProfilePrefix: getScanCustomerProfilePrefix() });
        });
    }
    if (dragnetScanBtn) {
        dragnetScanBtn.addEventListener('click', () => {
            const target = document.getElementById('scan-target').value;
            socket.emit('start_dragnet_scan', { target });
        });
    }
    if (stopScanBtn) {
        stopScanBtn.addEventListener('click', () => {
            socket.emit('stop_scan');
        });
    }
    document.getElementById('discovery-table')?.addEventListener('click', event => {
        const link = event.target.closest('[data-screenshot-url]');
        if (!link || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
        event.preventDefault();
        openScreenshotPreview(link.dataset.screenshotUrl, link.dataset.screenshotTitle);
    });

    socket.on('discovery_update', (data) => {
        updateHostRow(data);
        const stats = getDiscoveryTableStats();
        if (activeScanPhase === 1) updateQuickScanStats(stats);
        if (activeScanPhase >= 2 || data.ports || data.highCVEs || data.lowCVECount) updateDeepScanStats(stats);
        setText('summary-hosts', stats.hostCount || '--');
        setText('summary-ports', stats.openPortCount || '--');
    });
}
