function historicalScanAgeDays(value, now = new Date()) {
    if (typeof value !== 'string' || !value.trim()) return null;
    const scan = new Date(value);
    if (!Number.isFinite(scan.getTime()) || !Number.isFinite(now.getTime())) return null;
    const day = date => Date.UTC(date.getFullYear(), date.getMonth(), date.getDate());
    const age = (day(now) - day(scan)) / 86400000;
    return age >= 0 ? age : null;
}

function showHistoricalDataBanner(data) {
    const banner = document.getElementById('historical-data-banner');
    const title = document.getElementById('historical-title');
    const details = document.getElementById('historical-details');
    const hosts = document.getElementById('historical-hosts');
    const vulns = document.getElementById('historical-vulns');
    const exploits = document.getElementById('historical-exploits');

    const ageDays = historicalScanAgeDays(data.scan_date);
    let ageText = '';
    let bannerColor = 'bg-olive-100 border-olive-600';

    if (ageDays === null) {
        ageText = 'at an unconfirmed date';
        title.textContent = 'Saved Scan';
        bannerColor = 'bg-amber-50 border-amber-500';
    } else if (ageDays === 0) {
        ageText = 'today';
        title.textContent = 'Scan from Today';
        bannerColor = 'bg-olive-100 border-olive-600';
    } else if (ageDays === 1) {
        ageText = 'yesterday';
        title.textContent = 'Scan from Yesterday';
        bannerColor = 'bg-amber-50 border-amber-500';
    } else {
        ageText = `${ageDays} days ago`;
        title.textContent = `Scan from ${ageDays} Days Ago`;
        bannerColor = 'bg-amber-100 border-amber-600';
    }

    const scanDate = new Date(data.scan_date);
    const dateStr = Number.isFinite(scanDate.getTime()) && typeof data.scan_date === 'string' ? scanDate.toLocaleString() : 'Unknown';

    details.textContent = `Scanned ${ageText} on ${dateStr} • Target: ${data.target || 'Unknown'}`;
    hosts.textContent = `📊 ${data.total || 0} hosts`;
    vulns.textContent = `🔒 ${data.total_vulnerabilities || 0} CVEs`;
    exploits.textContent = `⚠️  ${data.total_exploits || 0} exploits`;

    const bannerInner = banner.querySelector('div');
    bannerInner.className = `${bannerColor} border-l-4 p-4 rounded-lg shadow-sm`;

    banner.classList.remove('hidden');
}

function hideHistoricalDataBanner() {
    const banner = document.getElementById('historical-data-banner');
    banner.classList.add('hidden');
}

function showScanSummaryBanner(data) {
    const banner = document.getElementById('scan-summary-banner');

    document.getElementById('summary-duration').textContent = data.duration_formatted || '--';
    document.getElementById('summary-hosts').textContent = data.hosts_up || 0;
    document.getElementById('summary-ports').textContent = data.total_ports || 0;
    document.getElementById('summary-cves').textContent = data.total_cves || 0;

    banner.classList.remove('hidden');

    setTimeout(() => {
        hideScanSummaryBanner();
    }, 30000);
}

function hideScanSummaryBanner() {
    const banner = document.getElementById('scan-summary-banner');
    banner.classList.add('hidden');
}

window.showHistoricalDataBanner = showHistoricalDataBanner;
window.hideHistoricalDataBanner = hideHistoricalDataBanner;
window.showScanSummaryBanner = showScanSummaryBanner;
window.hideScanSummaryBanner = hideScanSummaryBanner;
