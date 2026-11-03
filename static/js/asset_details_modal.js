// Normalise the three port shapes the dashboard sees: live deep-scan objects
// ({port, protocol, service}), live "22/ssh" strings and historical
// "22 (ssh)" strings parsed from saved XML.
function assetServiceRows(asset) {
    if (Array.isArray(asset.ports_detail) && asset.ports_detail.length) {
        return asset.ports_detail.map(port => {
            const [name = 'unknown', ...rest] = String(port.service || '').trim().split(/\s+/);
            return { port: String(port.port), protocol: port.protocol || 'tcp', name, version: rest.join(' ') };
        });
    }
    const raw = asset.open_ports || (typeof asset.ports === 'string' ? asset.ports : '');
    return String(raw || '').split(',').map(item => item.trim()).filter(Boolean).map(item => {
        const match = item.match(/^(\d+)(?:\/(\w+))?(?:\s*\(([^)]*)\)|\/(\S+))?/);
        if (!match) return null;
        return { port: match[1], protocol: 'tcp', name: match[3] || match[4] || match[2] || 'unknown', version: '' };
    }).filter(Boolean);
}

function renderAssetServices(asset) {
    const servicesContainer = document.getElementById('asset-detail-services');
    servicesContainer.replaceChildren();

    const rows = assetServiceRows(asset);
    if (rows.length) {
        rows.forEach(row => {
            const serviceDiv = document.createElement('div');
            serviceDiv.className = 'flex items-start gap-3 p-3 bg-white rounded border border-olive-200';

            const infoDiv = document.createElement('div');
            infoDiv.className = 'flex-shrink-0 w-28';
            const portSpan = document.createElement('span');
            portSpan.className = 'font-mono text-sm font-bold text-olive-900';
            portSpan.textContent = `${row.port}/${row.protocol}`;
            infoDiv.appendChild(portSpan);
            const serviceSpan = document.createElement('div');
            serviceSpan.className = 'text-xs text-olive-700';
            serviceSpan.textContent = row.name;
            infoDiv.appendChild(serviceSpan);
            serviceDiv.appendChild(infoDiv);

            const versionText = document.createElement('div');
            versionText.className = row.version ? 'min-w-0 flex-1 break-words text-sm text-olive-800' : 'flex-1 text-xs italic text-olive-600';
            versionText.textContent = row.version || 'No version detected';
            serviceDiv.appendChild(versionText);
            servicesContainer.appendChild(serviceDiv);
        });
        return;
    }

    const empty = document.createElement('p');
    empty.className = 'text-sm text-olive-600 italic';
    empty.textContent = 'No open ports detected';
    servicesContainer.appendChild(empty);
}

function renderAssetVulnerabilities(asset) {
    const cveContainer = document.getElementById('asset-detail-cves');
    cveContainer.replaceChildren();

    const vulnerabilities = window.sortCvesBySeverity(asset.vulnerabilities);
    if (vulnerabilities.length > 0) {
        vulnerabilities.forEach(vuln => {
            const cveDiv = document.createElement('div');
            cveDiv.className = 'flex items-start justify-between gap-3 p-3 bg-white rounded border border-olive-200';

            const left = document.createElement('div');
            left.className = 'min-w-0';
            const title = document.createElement('a');
            title.className = 'font-mono text-sm font-bold text-olive-900 underline decoration-olive-300 underline-offset-2 hover:text-olive-700';
            title.textContent = vuln.id || 'Unknown CVE';
            if (setSafeExternalLink(title, vuln.url)) {
                title.setAttribute('aria-label', `${vuln.id || 'Vulnerability'} (opens in a new tab)`);
                left.appendChild(title);
            } else {
                const plain = document.createElement('span');
                plain.className = 'font-mono text-sm font-bold text-olive-900';
                plain.textContent = vuln.id || 'Unknown CVE';
                left.appendChild(plain);
            }
            if (vuln.port) {
                const meta = document.createElement('div');
                meta.className = 'text-xs text-olive-700 mt-1';
                meta.textContent = vuln.service ? `Port ${vuln.port} (${vuln.service})` : `Port ${vuln.port}`;
                left.appendChild(meta);
            }
            cveDiv.appendChild(left);
            cveDiv.appendChild(window.createCveSeverityChip(vuln.score));
            cveContainer.appendChild(cveDiv);
        });
        return;
    }

    const empty = document.createElement('p');
    empty.className = 'text-sm text-olive-600 italic';
    empty.textContent = 'No vulnerabilities detected';
    cveContainer.appendChild(empty);
}

function showAssetDetailsModal(asset) {
    const modal = document.getElementById('asset-details-modal');

    document.getElementById('asset-detail-ip').textContent = asset.ip || 'Unknown';
    document.getElementById('asset-detail-hostname').textContent = asset.hostname ? `(${asset.hostname})` : '';
    document.getElementById('asset-detail-mac').textContent = asset.mac || 'N/A';
    document.getElementById('asset-detail-vendor').textContent = asset.vendor || 'Unknown';
    document.getElementById('asset-detail-status').textContent = asset.status || 'up';

    const vendorLink = document.getElementById('asset-vendor-link');
    if (asset.vendor && asset.vendor !== 'Unknown') {
        const vendorSearchUrl = `https://www.google.com/search?q=${encodeURIComponent(asset.vendor + ' company website')}`;
        vendorLink.href = vendorSearchUrl;
        vendorLink.classList.remove('hidden');
    } else {
        vendorLink.classList.add('hidden');
    }

    renderAssetServices(asset);

    const cveSection = document.getElementById('asset-cve-section');
    const cveCount = document.getElementById('asset-cve-count');

    if (asset.vulnerabilities && asset.vulnerabilities.length > 0) {
        cveCount.textContent = asset.vulnerabilities.length;
        cveSection.classList.remove('hidden');
    } else {
        cveSection.classList.add('hidden');
    }
    renderAssetVulnerabilities(asset);

    modal.classList.remove('hidden');
}

function closeAssetDetailsModal() {
    document.getElementById('asset-details-modal').classList.add('hidden');
}

window.renderAssetServices = renderAssetServices;
window.renderAssetVulnerabilities = renderAssetVulnerabilities;
window.showAssetDetailsModal = showAssetDetailsModal;
window.closeAssetDetailsModal = closeAssetDetailsModal;
