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

window.escapeHTMLValue = escapeHTMLValue;
window.safeHttpHref = safeHttpHref;
