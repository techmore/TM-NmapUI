function updateDateTime() {
    const now = new Date();
    const options = {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    document.getElementById('current-date-time').textContent = now.toLocaleDateString('en-US', options);
}

function startPreciseClock() {
    updateDateTime();

    const now = new Date();
    const secondsUntilNextMinute = 60 - now.getSeconds();
    const msUntilNextMinute = secondsUntilNextMinute * 1000 - now.getMilliseconds();

    setTimeout(() => {
        updateDateTime();
        setInterval(updateDateTime, 60000);
    }, msUntilNextMinute);
}

function renderHistoryState(message, isError = false) {
    const historyList = document.getElementById('history-list');
    historyList.replaceChildren();
    const paragraph = document.createElement('p');
    paragraph.className = isError ? 'text-red-600' : 'text-olive-600';
    paragraph.textContent = message;
    historyList.appendChild(paragraph);
}

function createHistoryDiffSummary(diffSummary) {
    if (!diffSummary || !diffSummary.has_changes) {
        return null;
    }

    const diffCard = document.createElement('div');
    diffCard.className =
        'mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900';

    const diffTitle = document.createElement('p');
    diffTitle.className = 'font-semibold text-amber-900';
    diffTitle.textContent = 'Changes since previous scan';
    diffCard.appendChild(diffTitle);

    const diffMeta = document.createElement('p');
    diffMeta.className = 'mt-1 text-xs text-amber-700';
    diffMeta.textContent = `Baseline: ${new Date(diffSummary.baseline_timestamp).toLocaleString()}`;
    diffCard.appendChild(diffMeta);

    const diffFacts = [];
    if (diffSummary.added_hosts?.length) {
        diffFacts.push(`${diffSummary.added_hosts.length} new host(s)`);
    }
    if (diffSummary.removed_hosts?.length) {
        diffFacts.push(`${diffSummary.removed_hosts.length} removed host(s)`);
    }
    if (diffSummary.changed_hosts?.length) {
        diffFacts.push(`${diffSummary.changed_hosts.length} changed host(s)`);
    }
    if (diffSummary.new_ports?.length) {
        diffFacts.push(`${diffSummary.new_ports.length} new port(s)`);
    }
    if (diffSummary.removed_ports?.length) {
        diffFacts.push(`${diffSummary.removed_ports.length} removed port(s)`);
    }
    if (diffSummary.new_vulnerabilities?.length) {
        diffFacts.push(
            `${diffSummary.new_vulnerabilities.length} new vulnerabilit${diffSummary.new_vulnerabilities.length === 1 ? 'y' : 'ies'}`
        );
    }
    if (diffSummary.removed_vulnerabilities?.length) {
        diffFacts.push(
            `${diffSummary.removed_vulnerabilities.length} resolved vulnerabilit${diffSummary.removed_vulnerabilities.length === 1 ? 'y' : 'ies'}`
        );
    }

    const diffList = document.createElement('p');
    diffList.className = 'mt-2 text-sm text-amber-800';
    diffList.textContent = diffFacts.join(' • ');
    diffCard.appendChild(diffList);

    return diffCard;
}

function renderHistoryList(scans) {
    const historyList = document.getElementById('history-list');
    historyList.replaceChildren();

    scans.forEach(scan => {
        const card = document.createElement('div');
        card.className = 'bg-olive-50 p-4 rounded-lg border border-olive-300';

        const header = document.createElement('div');
        header.className = 'flex justify-between items-start mb-2';
        const details = document.createElement('div');
        details.className = 'flex-1 min-w-0';

        const title = document.createElement('h3');
        title.className = 'font-display text-lg text-olive-900';
        title.textContent = scan.customer_name || 'Unknown';
        details.appendChild(title);

        const dateText = document.createElement('p');
        dateText.className = 'text-sm text-olive-600';
        dateText.textContent = new Date(scan.timestamp).toLocaleString();
        details.appendChild(dateText);

        const targetText = document.createElement('p');
        targetText.className = 'text-sm text-olive-700 mt-1';
        targetText.appendChild(document.createTextNode('Target: '));
        const targetSpan = document.createElement('span');
        targetSpan.className = 'font-mono';
        targetSpan.textContent = scan.target;
        targetText.appendChild(targetSpan);
        details.appendChild(targetText);

        const diffCard = createHistoryDiffSummary(scan.diff_summary);
        if (diffCard) {
            details.appendChild(diffCard);
        }
        header.appendChild(details);

        const actions = document.createElement('div');
        actions.className = 'flex gap-2';

        const buildLink = (href, label, className, newTab = false) => {
            const link = document.createElement('a');
            link.href = href;
            if (newTab) {
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
            }
            link.className = className;
            link.textContent = label;
            actions.appendChild(link);
        };

        if (scan.has_html) {
            buildLink(`/api/runtime/reports/${scan.path}/html`, 'View HTML', 'px-3 py-1 bg-olive-600 text-white rounded text-sm hover:bg-olive-700', true);
        }
        if (scan.has_pdf) {
            buildLink(`/api/runtime/reports/${scan.path}/pdf`, 'Download PDF', 'px-3 py-1 bg-olive-700 text-white rounded text-sm hover:bg-olive-800');
        }
        if (scan.has_xml) {
            buildLink(`/api/runtime/reports/${scan.path}/xml`, 'Download XML', 'px-3 py-1 bg-olive-500 text-white rounded text-sm hover:bg-olive-600');
        }

        const deleteButton = document.createElement('button');
        deleteButton.className = 'px-3 py-1 bg-red-600 text-white rounded text-sm hover:bg-red-700';
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => deleteScan(scan.path));
        actions.appendChild(deleteButton);

        header.appendChild(actions);
        card.appendChild(header);
        historyList.appendChild(card);
    });
}

async function deleteScan(path) {
    if (!confirm('Are you sure you want to delete this scan?')) {
        return;
    }

    try {
        const response = await fetch(`/api/runtime/history/${path}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadScanHistory();
        } else {
            alert('Error deleting scan');
        }
    } catch (error) {
        console.error('Error deleting scan:', error);
        alert('Error deleting scan');
    }
}

function initializeLayoutRuntime() {
    startPreciseClock();

    const historyButton = document.getElementById('view-history-btn');
    if (!historyButton || historyButton.dataset.historyWired === 'true') {
        return;
    }
    historyButton.dataset.historyWired = 'true';
    historyButton.addEventListener('click', function() {
        if (typeof window.showHistoryModal === 'function') {
            window.showHistoryModal();
        }
    });
}

window.renderHistoryState = renderHistoryState;
window.createHistoryDiffSummary = createHistoryDiffSummary;
window.renderHistoryList = renderHistoryList;
window.deleteScan = deleteScan;
window.initializeLayoutRuntime = initializeLayoutRuntime;
