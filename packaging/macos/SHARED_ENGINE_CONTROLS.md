# Canonical scan controls (transport slice)

`SharedEngineSocketClient` uses the same loopback endpoint and memory-only
UTF-8 Basic credentials as the read-only `SharedEngineClient`. It fetches the
CSRF token over authenticated HTTP, then authenticates Socket.IO with both the
Basic header and token. Tokens are not credentials. Neither enters a URL.
Listeners are installed before connecting. The initial transport is standard
Engine.IO 4 polling using the official Socket.IO Swift 16.1.1 protocol code.
The narrowly patched, pinned SDK and full license/provenance are in
`Vendor/SocketIO`; Starscream is locked in `Package.resolved`. Both dependency
licenses ship in the signed application resource bundle.

All URL sessions use copied ephemeral configurations with no credential,
cookie or cache stores and no ambient proxy configuration. Delegates refuse
redirects and authentication challenges. Credentials are never persisted by
this client, and SDK debug logging is disabled.

The MainActor API exposes startScan/cancel/pause/resume and a typed state
snapshot. `job_status` is authoritative; raw source UUIDs are required for every
control. Displayed completed outcomes are retained separately from current
scanner capacity, since a reconnected observer can receive terminal status
followed by source-less idle when the old owner is cleared. Retired source IDs
cannot replace a newer run. Unknown statuses stay unknown and disable controls.
Pause distinguishes server-requested pause from process/checkpoint pause.

Disconnected mutations throw immediately and are never queued. An uncertain
start is never replayed. Reconnect is explicit, fetches a fresh token and sends
only get_job_status. Both scan and report snapshots must arrive before controls
are enabled. An uncertain start remains blocked until a new source identity is
observed or the caller explicitly acknowledges the uncertainty after syncing.
No local engine fallback or alternate REST scan workflow exists here.

Tests use the frozen canonical source `911f83d837c6ea992f2592b4633c59e4a5c1ee29`
with a real, single-worker Gunicorn and an owned nmap executable that performs
no networking. Both local trust and Socket.IO auth-disable switches are forced
false before importing the canonical app. Tests exercise strict Unicode Basic
auth, token-only rejection, start, real process pause/resume, reconnect, source
identity races, cancel of running and stopped groups, and canonical errors.
Separate stdlib fixtures exercise HTTP and polling redirect/challenge refusal.
No scheduler, native helper, Keychain, installed service or LAN scan is used.

This slice does not change AppDelegate or route native UI actions. A follow-up
must construct the HTTP and Socket.IO clients together on attach, clear the UI
password, expose one coherent canonical scan flow, and keep legacy archives and
schedules explicitly separate until migration is implemented. It must not
claim full write-path parity or launch the old native engine on control errors.
