"""Execute the Archive modal's asynchronous history reads without a live scanner."""

from pathlib import Path
import os
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(not shutil.which("node"), reason="Requires Node.js for browser state regression")
def test_history_refresh_preserves_evidence_and_ignores_superseded_reads():
    script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
    constructor(tag) {
        this.tagName = tag;
        this.children = [];
        this.dataset = {};
        this.listeners = {};
        this.value = '';
        this.classList = { add() {}, remove() {} };
    }
    set textContent(value) { this._text = String(value); this.replaceChildren(); }
    get textContent() { return (this._text || '') + this.children.map(child => child.textContent).join(''); }
    appendChild(child) { child.parentElement = this; this.children.push(child); return child; }
    append(...children) { children.forEach(child => this.appendChild(child)); }
    prepend(child) { child.parentElement = this; this.children.unshift(child); }
    replaceChildren(...children) {
        this.children.forEach(child => child.parentElement = null);
        this.children = []; this.append(...children);
    }
    remove() {
        if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(child => child !== this);
        this.parentElement = null;
    }
    addEventListener(event, listener) { this.listeners[event] = listener; }
    setAttribute(name, value) { this[name] = value; }
}
const ids = {};
for (const id of ['history-list','history-modal','history-customer-filter','history-date-filter','history-changed-filter']) {
    ids[id] = new Element('div'); ids[id].id = id;
}
function descendant(element, id) {
    if (element.id === id) return element;
    for (const child of element.children) { const found = descendant(child, id); if (found) return found; }
    return null;
}
const pending = [];
const context = {
    window: { deleteScan() {} },
    console: { error() {} },
    document: {
        getElementById(id) { return ids[id] || descendant(ids['history-list'], id); },
        createElement(tag) { return new Element(tag); },
        createTextNode(text) { const node = new Element('#text'); node.textContent = text; return node; },
    },
    fetch(url) {
        assert.equal(url, '/api/runtime/history');
        const next = pending.shift();
        assert.ok(next, 'Unexpected history request');
        return next;
    },
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const row = (name) => ({ customer_name:name, path:`${name}/scan`, target:'192.0.2.1', timestamp:'2026-10-25T12:00:00Z' });
const response = (history, status=200) => ({ok:status===200, status, async json() { return {history}; }});
const list = ids['history-list'];
function deferred() { let resolve; const promise = new Promise(done => resolve = done); return {promise, resolve}; }

(async () => {
    pending.push(Promise.resolve(response([row('Saved customer')])));
    await context.loadScanHistory();
    const saved = list.children[0];
    assert.match(saved.textContent, /Saved customer/);

    // An expired session is not an empty successful history response.
    pending.push(Promise.resolve({ok:false,status:401,async json(){return {error:'Unauthorized'};}}));
    await context.loadScanHistory();
    assert.equal(list.children[1], saved, 'A failed refresh must retain the existing evidence node');
    assert.equal(list.children[0].role, 'alert');
    assert.match(list.children[0].textContent, /out of date/);

    pending.push(Promise.resolve(response([row('Retry recovered')])));
    const retry = list.children[0].children[1];
    await retry.listeners.click();
    assert.match(list.textContent, /Retry recovered/);
    assert.equal(list.children.length, 1, 'Successful retry clears the failure notice');

    // Reject malformed successful JSON before mutating the displayed list.
    const recovered = list.children[0];
    pending.push(Promise.resolve(response({not:'an array'})));
    await context.loadScanHistory();
    assert.equal(list.children[1], recovered);

    const older = deferred(), newer = deferred();
    pending.push(older.promise, newer.promise);
    const firstRead = context.loadScanHistory(), secondRead = context.loadScanHistory();
    newer.resolve(response([row('Newest filter result')]));
    await secondRead;
    older.resolve(response([row('Outdated result')]));
    await firstRead;
    assert.match(list.textContent, /Newest filter result/);
    assert.doesNotMatch(list.textContent, /Outdated result/);

    // A late failed read must not replace a newer successful selection.
    const failed = deferred();
    pending.push(failed.promise, Promise.resolve(response([row('Current history')])));
    const oldFailure = context.loadScanHistory();
    await context.loadScanHistory();
    failed.resolve({ok:false,status:503});
    await oldFailure;
    assert.match(list.textContent, /Current history/);
    assert.equal(list.children.length, 1);

    // Closing the modal invalidates in-flight work without changing its saved view.
    const closed = deferred(); pending.push(closed.promise);
    const hiddenRead = context.loadScanHistory();
    context.hideHistoryModal();
    closed.resolve(response([row('Arrived after close')]));
    await hiddenRead;
    assert.doesNotMatch(list.textContent, /Arrived after close/);
    console.log('Archive history state regressions passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run(
        ["node", "-e", script, str(ROOT / "static/js/history_modal.js")],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Archive history state regressions passed" in result.stdout


@pytest.mark.skipif(os.environ.get("NMAPUI_RUN_BROWSER_REGRESSION") != "1", reason="Opt-in Chromium regression")
def test_archive_failed_refresh_keeps_saved_cards_and_retry_recovers_in_chromium():
    from playwright.sync_api import sync_playwright

    history = {"history": [{"customer_name": "Saved archive customer", "path": "fixture/scan", "target": "192.0.2.1", "timestamp": "2026-10-25T12:00:00Z"}]}
    responses = [(200, history), (503, {"error": "Unavailable"}), (200, {"history": []})]
    document = """<!doctype html><html><body>
        <div id="history-modal"><select id="history-customer-filter"><option value="">All Customers</option></select>
        <input id="history-date-filter" type="date"><input id="history-changed-filter" type="checkbox">
        <div id="history-list"></div></div></body></html>"""

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()

        def local_route(route):
            if route.request.url.endswith("/api/runtime/history"):
                status, body = responses.pop(0)
                route.fulfill(status=status, json=body)
            else:
                route.fulfill(body=document, content_type="text/html")

        page.route("http://archive.test/**", local_route)
        try:
            page.goto("http://archive.test/")
            page.add_script_tag(path=str(ROOT / "static/js/history_modal.js"))
            page.evaluate("loadScanHistory()")
            page.locator("#history-list h3").get_by_text("Saved archive customer", exact=True).wait_for()
            page.evaluate("window.savedArchiveCard = document.querySelector('#history-list > div')")
            page.evaluate("loadScanHistory()")
            assert page.evaluate("document.getElementById('history-list').contains(window.savedArchiveCard)")
            assert "out of date" in page.get_by_role("alert").inner_text()
            page.get_by_role("button", name="Retry saved history").click()
            page.get_by_text("No scans found", exact=True).wait_for()
            assert page.get_by_role("alert").count() == 0
            assert not responses
        finally:
            browser.close()
