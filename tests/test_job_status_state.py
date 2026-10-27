"""Run the shared browser job-status guard with actual JavaScript semantics."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(not shutil.which("node"), reason="Requires Node.js for browser state regression")
def test_source_run_terminality_is_shared_bounded_and_preserves_legacy_pause_behavior():
    script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const context = { window: {} };
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const accept = context.window.acceptJobStatus;
const packet = (id, status, type='scan', extra={}) => ({source_job_id:id, status, job_type:type, ...extra});
for (const status of ['completed', 'cancelled', 'failed', 'interrupted', 'error']) {
    const id = `run-${status}`;
    assert.equal(accept(packet(id, 'running')), true);
    assert.equal(accept(packet(id, 'running', 'scan', {paused:true})), true);
    assert.equal(accept(packet(id, 'running', 'scan', {paused:false})), true);
    const terminal = packet(id, status);
    for (let consumer=0; consumer<3; consumer++) assert.equal(accept(terminal), true);
    assert.equal(accept({job_type:'scan', status:'idle'}), true);
    for (let consumer=0; consumer<3; consumer++) {
        assert.equal(accept(packet(id, 'cancelling')), false);
        assert.equal(accept(packet(id, 'running')), false);
    }
    assert.equal(accept(packet(id, 'running', 'report')), true, 'Job types have separate run identities');
}
assert.equal(accept(packet('next-run', 'running')), true);
assert.equal(accept({job_type:'scan', status:'running'}), true);
assert.equal(accept({job_type:'scan', status:'cancelled'}), true);
assert.equal(accept({job_type:'scan', source_job_id:'', status:'running'}), true);
for (let i=0; i<257; i++) assert.equal(accept(packet(`bounded-${i}`, 'completed')), true);
assert.equal(accept(packet('bounded-0', 'running')), true, 'Oldest receipt is evicted at the documented bound');
assert.equal(accept(packet('bounded-256', 'running')), false);
'''
    subprocess.run(["node", "-e", script, str(ROOT / "static/js/job_status_state.js")], check=True, capture_output=True, text=True)


def test_both_browser_entrypoints_load_the_shared_guard_before_status_consumers():
    marker = '/static/js/job_status_state.js'
    for name in ['templates/index.html', 'index.html']:
        html = (ROOT / name).read_text()
        assert html.count(marker) == 1
        for consumer in ['scan_runtime', 'report_generation_ui', 'audit_log']:
            consumer_script = f'/static/js/{consumer}.js'
            if consumer_script in html:
                assert html.index(marker) < html.index(consumer_script)
