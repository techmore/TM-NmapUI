(function () {
    let logCount = 0;
    const logEntries = [];
    const MAX_LOG_ENTRIES = 1000;
    const LEVEL_STYLES = {
        log: 'text-olive-300',
        info: 'text-olive-300',
        warn: 'text-amber-400',
        error: 'text-red-400',
        scan: 'text-emerald-400',
        raw: 'text-olive-500',
        report: 'text-sky-300',
        job: 'text-violet-300',
        update: 'text-amber-300',
    };
    let logsTabInitialized = false;
    let persistedLogsLoaded = false;
    let persistedRefreshTimer = null;

    function timestamp() {
        return new Date().toISOString().replace('T', ' ').slice(0, 23);
    }

    function getLevelLabel(level) {
        if (level === 'scan') return 'SCN';
        if (level === 'raw') return 'RAW';
        if (level === 'job') return 'JOB';
        if (level === 'report') return 'RPT';
        if (level === 'update') return 'UPD';
        return level.slice(0, 3).toUpperCase();
    }

    function createLogRow(entry) {
        const div = document.createElement('div');
        div.className = `flex gap-2 leading-5 ${LEVEL_STYLES[entry.level] || 'text-olive-300'}`;

        const timeSpan = document.createElement('span');
        timeSpan.className = 'text-olive-600 flex-shrink-0 select-none';
        timeSpan.textContent = entry.timestamp;

        const levelSpan = document.createElement('span');
        levelSpan.className = `uppercase font-bold flex-shrink-0 w-6 select-none ${LEVEL_STYLES[entry.level] || ''}`;
        levelSpan.textContent = getLevelLabel(entry.level);

        const msgSpan = document.createElement('span');
        msgSpan.className = 'break-all whitespace-pre-wrap';
        msgSpan.textContent = entry.message;

        div.appendChild(timeSpan);
        div.appendChild(levelSpan);
        div.appendChild(msgSpan);
        return div;
    }

    function appendStructuredLog(entry) {
        if (!entry || !entry.message) {
            return;
        }
        logEntries.push({
            timestamp: entry.created_at || entry.timestamp || timestamp(),
            level: String(entry.level || 'info').toLowerCase(),
            message: String(entry.message),
            source: entry.source || 'persisted',
        });
        if (logEntries.length > MAX_LOG_ENTRIES) {
            logEntries.splice(0, logEntries.length - MAX_LOG_ENTRIES);
        }
        logCount = logEntries.length;
    }

    function replacePersistedLogs(entries) {
        const localEntries = logEntries.filter((entry) => entry.source !== 'persisted');
        logEntries.length = 0;
        localEntries.forEach((entry) => logEntries.push(entry));
        entries.forEach((entry) => appendStructuredLog({ ...entry, source: 'persisted' }));
        logCount = logEntries.length;
    }

    function updateCounts(visibleCount = logCount) {
        const countEl = document.getElementById('log-entry-count');
        if (countEl) {
            countEl.textContent = `${logCount} entr${logCount === 1 ? 'y' : 'ies'}`;
        }

        const tabCount = document.getElementById('logs-tab-count');
        if (tabCount) {
            tabCount.textContent = `${visibleCount} visible entr${visibleCount === 1 ? 'y' : 'ies'} of ${logCount}`;
        }

        const badge = document.getElementById('log-count-badge');
        if (badge) {
            badge.textContent = logCount > 999 ? '999+' : logCount;
            badge.classList.toggle('hidden', logCount === 0);
        }
    }

    function renderLogsTab() {
        const container = document.getElementById('logs-tab-entries');
        const empty = document.getElementById('logs-tab-empty');
        if (!container || !empty) {
            return;
        }

        const search = document.getElementById('logs-search-input')?.value?.trim().toLowerCase() || '';
        const levelFilter = document.getElementById('logs-level-filter')?.value || 'all';

        const visibleEntries = logEntries.filter((entry) => {
            const levelMatches =
                levelFilter === 'all' ||
                entry.level === levelFilter ||
                (levelFilter === 'error' && entry.level === 'error') ||
                (levelFilter === 'warn' && entry.level === 'warn');

            if (!levelMatches) {
                return false;
            }

            if (!search) {
                return true;
            }

            return (
                entry.timestamp.toLowerCase().includes(search) ||
                entry.level.toLowerCase().includes(search) ||
                entry.message.toLowerCase().includes(search)
            );
        });

        container.replaceChildren();
        visibleEntries.forEach((entry) => {
            container.appendChild(createLogRow(entry));
        });

        container.classList.toggle('hidden', visibleEntries.length === 0);
        empty.classList.toggle('hidden', visibleEntries.length > 0);
        if (visibleEntries.length === 0) {
            empty.textContent = logEntries.length
                ? 'No log entries match the current filters.'
                : 'No log entries captured yet.';
        }
        updateCounts(visibleEntries.length);
    }

    function exportVisibleLogs() {
        const search = document.getElementById('logs-search-input')?.value?.trim().toLowerCase() || '';
        const levelFilter = document.getElementById('logs-level-filter')?.value || 'all';
        const visibleEntries = logEntries.filter((entry) => {
            const levelMatches = levelFilter === 'all' || entry.level === levelFilter;
            const searchMatches =
                !search ||
                entry.timestamp.toLowerCase().includes(search) ||
                entry.level.toLowerCase().includes(search) ||
                entry.message.toLowerCase().includes(search);
            return levelMatches && searchMatches;
        });

        const text = visibleEntries
            .map((entry) => `${entry.timestamp} ${getLevelLabel(entry.level)} ${entry.message}`)
            .join('\n');

        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `nmapui-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    function initializeLogsTab() {
        if (logsTabInitialized) {
            return;
        }
        logsTabInitialized = true;

        document.getElementById('logs-search-input')?.addEventListener('input', renderLogsTab);
        document.getElementById('logs-level-filter')?.addEventListener('change', renderLogsTab);
        document.getElementById('logs-export-btn')?.addEventListener('click', exportVisibleLogs);
        document.getElementById('logs-clear-btn')?.addEventListener('click', () => window.clearLog());
        loadPersistedLogs();
        renderLogsTab();
    }

    function loadPersistedLogs() {
        if (persistedLogsLoaded) {
            return;
        }
        persistedLogsLoaded = true;
        refreshPersistedLogs();
    }

    function refreshPersistedLogs() {
        fetch('/api/runtime/logs?limit=200')
            .then((response) => response.json())
            .then((data) => {
                const entries = Array.isArray(data?.entries) ? data.entries : [];
                replacePersistedLogs(entries.slice().reverse());
                renderLogsTab();
            })
            .catch(() => {
            });
    }

    function schedulePersistedLogRefresh() {
        if (persistedRefreshTimer !== null) {
            return;
        }
        persistedRefreshTimer = setTimeout(function () {
            persistedRefreshTimer = null;
            refreshPersistedLogs();
        }, 300);
    }

    function appendLog(level, message) {
        const entry = { timestamp: timestamp(), level, message: String(message), source: 'local' };
        logEntries.push(entry);
        if (logEntries.length > MAX_LOG_ENTRIES) {
            logEntries.splice(0, logEntries.length - MAX_LOG_ENTRIES);
        }
        logCount = logEntries.length;

        const container = document.getElementById('log-entries');
        if (!container) {
            renderLogsTab();
            return;
        }

        container.appendChild(createLogRow(entry));
        while (container.childElementCount > MAX_LOG_ENTRIES) {
            container.firstElementChild?.remove();
        }

        if (container.scrollHeight - container.scrollTop < container.clientHeight + 80) {
            container.scrollTop = container.scrollHeight;
        }

        renderLogsTab();
    }

    function serializeArgs(args) {
        return Array.from(args)
            .map((arg) => {
                if (typeof arg === 'string') {
                    return arg;
                }
                try {
                    return JSON.stringify(arg);
                } catch {
                    return String(arg);
                }
            })
            .join(' ');
    }

    function bindConsoleInterceptors() {
        const originalLog = console.log.bind(console);
        const originalInfo = console.info.bind(console);
        const originalWarn = console.warn.bind(console);
        const originalError = console.error.bind(console);

        console.log = function (...args) {
            originalLog(...args);
            appendLog('log', serializeArgs(args));
        };
        console.info = function (...args) {
            originalInfo(...args);
            appendLog('info', serializeArgs(args));
        };
        console.warn = function (...args) {
            originalWarn(...args);
            appendLog('warn', serializeArgs(args));
        };
        console.error = function (...args) {
            originalError(...args);
            appendLog('error', serializeArgs(args));
        };
    }

    function bindWindowErrorLogger() {
        window.addEventListener('error', function (event) {
            appendLog(
                'error',
                (event.message || String(event)) +
                    (event.filename ? ` @ ${event.filename}:${event.lineno}` : '')
            );
        });
    }

    function bindSocketLogEvents() {
        if (typeof socket === 'undefined') {
            return false;
        }

        socket.on('scan_feedback', function (data) {
            schedulePersistedLogRefresh();
        });
        socket.on('scan_raw_output', function (data) {
            const lines = (data.output || '').split('\n');
            lines.forEach(function (line) {
                if (line.trim()) {
                    appendLog('raw', `[${data.target || ''}] ${line}`);
                }
            });
        });
        socket.on('job_status', function (data) {
            schedulePersistedLogRefresh();
        });
        socket.on('report_complete', function (data) {
            schedulePersistedLogRefresh();
        });
        socket.on('report_error', function (data) {
            schedulePersistedLogRefresh();
        });
        socket.on('update_status', function (data) {
            schedulePersistedLogRefresh();
        });
        socket.on('update_error', function (data) {
            schedulePersistedLogRefresh();
        });
        return true;
    }

    function initializeAuditLog() {
        initializeLogsTab();
        bindConsoleInterceptors();
        bindWindowErrorLogger();

        if (!bindSocketLogEvents()) {
            setTimeout(function () {
                bindSocketLogEvents();
            }, 2000);
        }
    }

    window.toggleLogPanel = function () {
        const panel = document.getElementById('log-panel');
        if (!panel) return;
        const isHidden = panel.classList.contains('hidden');
        panel.classList.toggle('hidden');
        if (isHidden) {
            const container = document.getElementById('log-entries');
            if (container) {
                container.scrollTop = container.scrollHeight;
            }
            const badge = document.getElementById('log-count-badge');
            if (badge) {
                badge.classList.add('hidden');
            }
        }
    };

    window.clearLog = function () {
        const container = document.getElementById('log-entries');
        if (container) {
            container.replaceChildren();
        }
        logEntries.length = 0;
        logCount = 0;
        renderLogsTab();
    };

    window.copyLog = function (event) {
        const container = document.getElementById('log-entries');
        if (!container) return;

        const text = Array.from(container.querySelectorAll('div'))
            .map((div) => div.textContent)
            .join('\n');

        navigator.clipboard.writeText(text).then(function () {
            const button = event?.target;
            if (!button) {
                return;
            }
            const original = button.textContent;
            button.textContent = 'Copied!';
            setTimeout(function () {
                button.textContent = original;
            }, 1500);
        }).catch(function () {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        });
    };

    window._appendLog = appendLog;
    window.initializeAuditLog = initializeAuditLog;
    window.renderLogsTab = renderLogsTab;
    window.exportVisibleLogs = exportVisibleLogs;
})();
