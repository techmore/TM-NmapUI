// Remember completed source runs for every job_status consumer in this page.
// Source-less legacy packets do not erase completion receipts. The finite
// history bounds memory over long-lived scanner sessions.
(function () {
    const terminalRuns = new Map();
    const terminalLimit = 256;
    const terminalStatuses = new Set(['completed', 'cancelled', 'failed', 'interrupted', 'error']);

    window.acceptJobStatus = function (job) {
        if (typeof job?.source_job_id !== 'string' || !job.source_job_id
            || typeof job.job_type !== 'string' || !job.job_type) return true;
        const key = JSON.stringify([job.job_type, job.source_job_id]);
        if (terminalStatuses.has(job.status)) {
            // Idempotent: all subscribers must accept the same terminal packet.
            terminalRuns.set(key, true);
            if (terminalRuns.size > terminalLimit) terminalRuns.delete(terminalRuns.keys().next().value);
            return true;
        }
        return !terminalRuns.has(key);
    };
})();
