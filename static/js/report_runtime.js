(function () {
    const tableIds = [
        'table-overview',
        'table-services',
        'web-services',
        'table-product-versions',
        'table-ssh-auth',
    ];

    function makeButton(label, action) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'rounded bg-olive-700 px-3 py-1 text-white hover:bg-olive-800';
        button.dataset.reportAction = action;
        button.textContent = label;
        return button;
    }

    function csvValue(value) {
        const text = String(value ?? '');
        const spreadsheetSafeText = /^[\s\uFEFF]*[=+\-@]/u.test(text) ? `'${text}` : text;
        return `"${spreadsheetSafeText.replace(/"/g, '""')}"`;
    }

    function downloadCsv(table) {
        const rows = [
            ...Array.from(table.querySelectorAll('thead tr, tbody tr'))
                .filter(row => !row.hidden)
                .map(row => Array.from(row.cells, cell => csvValue(cell.textContent)).join(',')),
        ];
        const blob = new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${table.id}.csv`;
        link.hidden = true;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function installTableControls(table) {
        if (!table.tHead || !table.tBodies.length) return;

        const controls = document.createElement('div');
        controls.className = 'report-table-controls mb-3 flex flex-wrap items-center gap-2 text-sm no-print';

        const label = document.createElement('label');
        label.className = 'flex items-center gap-2 text-olive-800';
        label.textContent = 'Filter this table';

        const filter = document.createElement('input');
        filter.type = 'search';
        filter.className = 'rounded border border-olive-300 bg-white px-2 py-1';
        filter.setAttribute('aria-label', `Filter ${table.id}`);
        label.appendChild(filter);
        controls.appendChild(label);
        controls.appendChild(makeButton('Download CSV', 'export-csv'));
        table.parentNode.insertBefore(controls, table);

        filter.addEventListener('input', () => {
            const query = filter.value.trim().toLocaleLowerCase();
            Array.from(table.tBodies[0].rows).forEach(row => {
                row.hidden = query !== '' && !row.textContent.toLocaleLowerCase().includes(query);
            });
        });

        Array.from(table.tHead.rows[0].cells).forEach((cell, index) => {
            const labelText = cell.textContent.trim();
            const sortButton = document.createElement('button');
            sortButton.type = 'button';
            sortButton.className = 'report-sort-button';
            sortButton.textContent = labelText;
            sortButton.setAttribute('aria-label', `Sort by ${labelText}`);
            sortButton.setAttribute('aria-sort', 'none');
            cell.replaceChildren(sortButton);
            sortButton.addEventListener('click', () => {
                const descending = sortButton.dataset.direction !== 'ascending';
                table.querySelectorAll('.report-sort-button').forEach(button => {
                    button.dataset.direction = '';
                    button.setAttribute('aria-sort', 'none');
                });
                sortButton.dataset.direction = descending ? 'descending' : 'ascending';
                sortButton.setAttribute('aria-sort', descending ? 'descending' : 'ascending');
                const rows = Array.from(table.tBodies[0].rows);
                rows.sort((left, right) => {
                    const leftText = left.cells[index]?.textContent.trim() || '';
                    const rightText = right.cells[index]?.textContent.trim() || '';
                    const order = leftText.localeCompare(rightText, undefined, {
                        numeric: true,
                        sensitivity: 'base',
                    });
                    return descending ? -order : order;
                });
                rows.forEach(row => table.tBodies[0].appendChild(row));
            });
        });
    }

    function escapeRegExp(value) {
        return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function clearHighlights(root) {
        root.querySelectorAll('mark.report-keyword').forEach(mark => {
            mark.replaceWith(document.createTextNode(mark.textContent || ''));
        });
        root.normalize();
    }

    function highlightKeywords() {
        const table = document.getElementById('table-services');
        const input = document.getElementById('keyword-input');
        if (!table || !input) return;
        clearHighlights(table);

        const terms = input.value.split(',').map(value => value.trim()).filter(Boolean);
        if (!terms.length) return;
        const pattern = new RegExp(terms.sort((a, b) => b.length - a.length).map(escapeRegExp).join('|'), 'ig');
        const walker = document.createTreeWalker(table, NodeFilter.SHOW_TEXT);
        const textNodes = [];
        while (walker.nextNode()) {
            const node = walker.currentNode;
            if (node.parentElement && !node.parentElement.closest('button, mark')) textNodes.push(node);
        }

        textNodes.forEach(node => {
            const text = node.nodeValue || '';
            pattern.lastIndex = 0;
            if (!pattern.test(text)) return;
            pattern.lastIndex = 0;
            const fragment = document.createDocumentFragment();
            let lastIndex = 0;
            for (const match of text.matchAll(pattern)) {
                fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
                const mark = document.createElement('mark');
                mark.className = 'highlight-keyword report-keyword';
                mark.textContent = match[0];
                fragment.appendChild(mark);
                lastIndex = match.index + match[0].length;
            }
            fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
            node.replaceWith(fragment);
        });
    }

    function toggleHostDetails(header) {
        const content = document.getElementById(header.dataset.collapseTarget || '');
        if (!content) return;
        const expanded = header.getAttribute('aria-expanded') === 'true';
        content.hidden = expanded;
        header.setAttribute('aria-expanded', String(!expanded));
    }

    document.addEventListener('click', event => {
        const header = event.target instanceof Element
            ? event.target.closest('[data-collapse-target]')
            : null;
        if (header) {
            toggleHostDetails(header);
            return;
        }

        const actionButton = event.target instanceof Element
            ? event.target.closest('[data-report-action]')
            : null;
        if (!actionButton) return;
        if (actionButton.dataset.reportAction === 'highlight') highlightKeywords();
        if (actionButton.dataset.reportAction === 'reset') window.location.reload();
        if (actionButton.dataset.reportAction === 'export-csv') {
            const table = actionButton.closest('div')?.nextElementSibling;
            if (table instanceof HTMLTableElement) downloadCsv(table);
        }
    });

    document.addEventListener('keydown', event => {
        if (!['Enter', ' '].includes(event.key)) return;
        const header = event.target instanceof Element
            ? event.target.closest('[data-collapse-target]')
            : null;
        if (!header) return;
        event.preventDefault();
        toggleHostDetails(header);
    });

    tableIds.forEach(id => {
        const table = document.getElementById(id);
        if (table) installTableControls(table);
    });
})();
