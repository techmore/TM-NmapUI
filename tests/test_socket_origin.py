"""Execute both production socket bootstraps across browser origin forms."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(not shutil.which("node"), reason="Requires Node.js for bootstrap regression")
@pytest.mark.parametrize("bootstrap", ["template_bootstrap.js", "app_bootstrap.js"])
def test_bootstrap_preserves_current_origin_scheme_host_and_port(bootstrap):
    script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
(async () => {
    for (const origin of ['http://localhost', 'https://scanner.example',
                          'http://127.0.0.1:54321', 'https://[::1]:54321']) {
        const location = new URL(origin);
        let observed;
        const context = {
            window: {location, addEventListener() {}, dispatchEvent() {}},
            document: {readyState:'loading', domain:location.hostname,
                       addEventListener() {}, getElementById() { return {addEventListener() {}}; }},
            location, console, CustomEvent: class {},
            fetch: async () => ({ok:false}),
            io: {connect(url) { observed = url; return {on() {}, connected:false}; }}
        };
        vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(observed, location.origin);
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run(["node", "-e", script, str(ROOT / "static/js" / bootstrap)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
