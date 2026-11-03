/**
 * Shared frontend utilities.
 * Loaded first (after vendor scripts) so every other module can use them.
 */

/**
 * Escape a value for safe interpolation into innerHTML template strings.
 * Canonical XSS helper — use this instead of per-file copies.
 */
function escapeHTMLValue(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

/** Resolve a link only when its scheme can safely navigate or load content. */
function safeHttpHref(value) {
    if (typeof value !== 'string' || !value.trim()) return null;

    try {
        const url = new URL(value, window.location.origin);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
        return url.href;
    } catch {
        return null;
    }
}

/**
 * CVSS v3 qualitative severity for a Vulners score. The text label carries
 * the meaning, so the chip colour is never the only cue (WCAG 1.4.1).
 */
function cveSeverity(score) {
    const value = Number.parseFloat(score);
    if (!Number.isFinite(value)) {
        return { label: 'Unscored', rank: 0, className: 'bg-zinc-100 text-zinc-800 ring-zinc-300' };
    }
    if (value >= 9) return { label: 'Critical', rank: 4, className: 'bg-red-700 text-white ring-red-800' };
    if (value >= 7) return { label: 'High', rank: 3, className: 'bg-red-100 text-red-800 ring-red-300' };
    if (value >= 4) return { label: 'Medium', rank: 2, className: 'bg-amber-100 text-amber-900 ring-amber-300' };
    if (value > 0) return { label: 'Low', rank: 1, className: 'bg-olive-100 text-olive-800 ring-olive-300' };
    return { label: 'None', rank: 0, className: 'bg-zinc-100 text-zinc-800 ring-zinc-300' };
}

/** Highest score first; unscored entries sink to the end. */
function sortCvesBySeverity(cves) {
    const score = cve => {
        const value = Number.parseFloat(cve?.score);
        return Number.isFinite(value) ? value : -1;
    };
    return (Array.isArray(cves) ? [...cves] : []).sort((a, b) => score(b) - score(a));
}

/** A "9.8 Critical" chip for a CVE score. */
function createCveSeverityChip(score) {
    const severity = cveSeverity(score);
    const chip = document.createElement('span');
    chip.className = `inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${severity.className}`;
    const value = Number.parseFloat(score);
    chip.textContent = Number.isFinite(value) ? `${value.toFixed(1)} ${severity.label}` : severity.label;
    return chip;
}

window.escapeHTMLValue = escapeHTMLValue;
window.safeHttpHref = safeHttpHref;
window.cveSeverity = cveSeverity;
window.sortCvesBySeverity = sortCvesBySeverity;
window.createCveSeverityChip = createCveSeverityChip;
