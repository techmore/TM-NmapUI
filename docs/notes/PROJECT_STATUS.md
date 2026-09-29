# Project status — 2026-09-29

## Product direction

The deployment targets are macOS and Ubuntu scanner hosts, with a
cross-platform browser UI. The September 10 remediation plan records one shared
Flask backend; a future native SwiftUI frontend should use that API rather than
duplicate the scan engine. The current Mac product is a Swift menu-bar launcher
around Flask. macOS has a LaunchDaemon installer. Ubuntu now has a root-mode
installer and `systemd` unit candidate. Both installer defaults trust loopback
callers (`NMAPUI_TRUST_LOCAL_UI=true`), so local processes can reach the
control surface without credentials. The user explicitly accepted this
boundary on 2026-09-25 for a dedicated loopback-bound scanner host; deployments
with a reverse proxy or untrusted local users must set it to `false`. On
2026-09-27 the candidate
passed install, privileged loopback scan, upgrade, rollback and reboot in a
disposable Ubuntu 24.04 LTS ARM64 VM. A fresh validation also confirmed failed
upgrades and failed rollbacks restore the prior working release. This is useful
installed-service evidence, but not a production-support declaration or a
substitute for a physical scanner host.
The older `swift-native`
branch contains substantial native UI and its own scan, report, privilege-helper
and scheduling implementation. Reconcile those designs before integrating it;
native/web parity is not yet verified.

September 25–26 in-repo hardening now includes a root-owned staged runtime for the
Mac LaunchDaemon and an Ubuntu 24.04 LTS installer candidate with a systemd
unit. Both use a single threaded Gunicorn worker and preserve mutable state
outside the code release. This is **not** a production-readiness declaration:
Ubuntu's disposable-VM checks do not cover physical network interfaces or
unattended soak behavior, and no installed LaunchDaemon validation has been
done on macOS.
Most recent local checks on Python 3.11: **616 passed / 27 skipped**; the
CI-equivalent browser group passed **22 tests**, including report CSP, settings
secret storage, scan/report cancellation, external-resource blocking and a
representative report-to-PDF render. A four-page synthetic letter PDF was
visually reviewed; the target metadata now reports the final Nmap argument,
zero-width progress segments no longer clip labels, the Web Services table
wraps within page bounds, and a small host card stays together. This does not
replace the still-open generated production-scan PDF check. Authenticated
staged Gunicorn/Chromium sign-in + Socket.IO after reload passed again on
September 29 (**1 passed**). The packaged Mac smoke passed on September 29
(**1 passed**, including Unicode credentials and WAL-safe DB migration); the full staged
Gunicorn/WebSocket smoke passed **4 passed / 2 skipped locally** on September
28. Generated Mac/Ubuntu artifact tests passed, and `pip-audit` found no
known vulnerabilities in the pinned
requirements. Pinned UI assets rebuild reproducibly from a clean npm install;
their separate npm audit also found no known vulnerabilities. The current
PDF-rendering policy disables JavaScript and blocks non-local resources in
Playwright; wkhtmltopdf disables JavaScript and local-file access; WeasyPrint is
restricted to report-local files. The root-mode Playwright test also passed in
the installed Ubuntu service. The unsupported `textutil -convert pdf` fallback
is removed, so exhausting the supported renderers now fails explicitly. On
2026-09-27, both Mac installer dry runs were
repeated and still fail closed because Nmap is absent from the protected
service PATH; the Homebrew Nmap is user-owned. `sudo -n` requires a password,
so a protected scanner toolchain cannot be provisioned unattended. No NmapUI
LaunchDaemon is installed.

The current auth hardening derives session signatures from the active
username/password, so credential rotation revokes existing long-lived browser
sessions. Empty credentials and the built-in password cannot authorize remote
requests; acknowledging the default password is accepted only with trusted
loopback binding. HTTPS reverse-proxy deployments can set
`NMAPUI_COOKIE_SECURE=true`; both service validators accept only boolean
values, the Mac launcher preserves the setting, and new loopback-HTTP service
environments default it to `false`. Focused auth and installer regressions
passed on September 28 (144 tests).

The September 29 auth review reproduced a same-site cross-origin form POST:
a valid session cookie let a page on another localhost port execute Drive
disconnect. Authenticated state-changing HTTP routes now validate browser
Origin/Referer against the app origin or explicit `NMAPUI_ALLOWED_ORIGINS`;
headerless API clients retain credential-based access. Login and logout POSTs
also enforce the origin policy. Chromium confirms the foreign form carries the
session cookie but receives 403 without executing its handler, while the same
origin control succeeds. The same review found valid non-ASCII credentials
raised `TypeError` in the string comparison; credentials now compare as UTF-8
bytes, and login/session and Basic API regressions verify Unicode credentials.
The packaged smoke also passes with Unicode credentials. Focused
auth/session tests pass (90), browser
regressions pass (20), and staged Gunicorn browser login/reload/WebSocket access
passes with the guard enabled. This is specific HTTP mutation protection; the
physical-host and release gates remain open. The reviewable candidate scope is
recorded in `docs/notes/PRODUCTION_CANDIDATE_REVIEW.md`.

On 2026-09-27, the main UI CSP stopped allowing inline script execution and now
sets `base-uri`, `object-src`, `form-action`, and `frame-ancestors`. The Tailwind
config is compiled to a committed stylesheet, while pinned Socket.IO and Lucide
browser libraries are served locally; application bootstrap scripts and former
inline event handlers also use same-origin/delegated loading. The asset build is
reproducible in CI and requires no Node runtime in packaged/service deployments.
The first compiled-CSS browser run caught a hidden-modal cascade conflict, now
fixed with a direct hidden-state rule and regression assertion. Chromium verifies
the policy, audit-log controls, and hostile Socket.IO-rendered data. The HTML-sink
pass found and fixed unescaped duration values in history and failed-report cards;
other traced dynamic frontend sinks escape values or use `textContent`. The npm
asset dependency audit found no known vulnerabilities. That browser pass also
exposed and fixed a duplicate `initializeLayoutRuntime` definition that had
shadowed the Archive button wiring; the history-modal script is now loaded and
its open/close flow is covered. This is focused CSP and frontend-sink hardening,
not completion of the broader secrets review or the manual production PDF-layout
check.

On 2026-09-27, the generated HTML report audit found that CDN scripts, inline
handlers and Tailwind Play CDN were incompatible with the app's restrictive CSP.
New reports now embed the compiled stylesheet and a single first-party runtime
authorized by an exact SHA-256 CSP hash; both current and legacy HTML routes use
an isolated report policy. Chromium verifies escaped hostile XML, report styling,
filtering, CSV download with spreadsheet-formula neutralization, highlighting
and host collapse. A separate visual pass confirmed the rendered HTML
appearance. The report audit also fixed severity totals that were counting
host-level text instead of structured port-level CVSS records; both report
stylesheets now use the same numeric thresholds and disclose that empty Vulners
results do not prove a host is vulnerability-free. The manual generated-scan/PDF
layout check remains open, as do physical-host scan and unattended-operation
gates.

The service runtime stager now allowlists the active `vulners.nse` script and
license rather than copying the whole third-party source directory, including
the unused Enterprise script and example images. Complete Scan can query
Vulners.com with detected software/CPE and version details. Managed service
credentials now default this off; an operator must explicitly set
`NMAPUI_ENABLE_VULNERS=true` after approving the inventory egress. Local
development retains the previous enabled default.

A broader runtime egress check found that installed-service startup disabled
only the startup traceroute; browser connections still requested topology and
local-IP data, triggering a probe to `1.1.1.1` and a public-IP lookup at
`api.ipify.org`. The dashboard also checked GitHub's latest-release API on
browser connect. Managed macOS and Ubuntu service credentials now disable
network fingerprinting, update checks and Vulners enrichment by default; each
is a separate documented opt-in. Runtime, workflow, installer and service-env
tests verify those controls and preserve explicit operator choices. Local
development retains the previous enabled defaults. The update lookup remains
cached for six hours after success and one minute after failure when enabled.
Inter and Instrument Serif are bundled with their OFL licenses, and the UI and
generated-report policies no longer permit Google Fonts egress. Browser
coverage verifies local fonts and stubs test HTTP lookups. The same pass fixed
remote-sync API-key persistence: older keys in
`localStorage` are scrubbed on settings load, new saves persist only non-secret
preferences locally, the password field clears after save, and the scanner
continues storing the key encrypted. Its focused browser test also caught and
fixed `/api/settings` dropping the encrypted-key presence indicator during
normalization. The browser suite now passes 19 tests. A production-gate review
found that the Stop button emitted legacy `stop_scan` while the backend only
handled `cancel_job`; the scan button now uses the authenticated cancel API,
and the server accepts `stop_scan` as a backward-compatible alias. There was
also no report-cancel affordance even though backend cancellation was
supported. A dedicated Stop Report control now uses the same authenticated
cancel API. Browser regressions verify both cancellation states and idle
control recovery without launching Nmap. Process-level tests also found that
deep-scan cancellation was swallowed before reaching the top-level job
finalizer and that a subprocess exiting at the moment of cancellation could
return as successful. Deep-scan errors now propagate to top-level job
completion, and the command runner checks cancellation after process
completion. The top-level finalizer closes cancellation requests that race normal
completion. Process regressions cover scan/report cleanup and late cancellation.

The Ubuntu installer/systemd candidate and primary Playwright PDF path were
validated in fresh disposable Ubuntu 24.04 LTS ARM64 VMs using the production
workflow-equivalent commands. The installer dry run, systemd unit verification,
staged artifact/server checks (27 passed, 2 skipped), and root privileged
loopback SYN scan passed. The
installed service passed the root-mode PDF security regression,
authenticated browser login and Socket.IO with `NMAPUI_TRUST_LOCAL_UI=false`,
stop/start, SIGKILL restart with
interrupted-job recovery, upgrade, rollback, uninstall with credential/database
and release preservation, then reinstall and reboot with systemd enabled/active
and readiness restored. The latest fresh VM also ran the current CI lifecycle
script and confirmed a deliberately broken upgrade and rollback both restore
the prior files, links, enabled/active state and readiness. It listens only on
`127.0.0.1:9000`. This is strong lifecycle evidence, but all scan validation is
loopback-only: physical interface discovery, real authorized subnet scans, and
unattended soak remain open. The user approved submission of this reviewed
candidate on September 29; hosted CI for these changes remains pending. The latest hosted
run on PR #240 passed unit/contract, browser and packaged Mac jobs on pushed
commit `e939022`; it does not include this candidate's changes. Following that
run's runtime warnings, Linux jobs are now pinned to Ubuntu 24.04 and the
workflow uses Node-24-compatible checkout/setup-python action majors. Those
workflow updates also await hosted execution. PR #240 remains draft.
Staged releases now expose a public release identifier in readiness; both
installers require it to match the release they just started, so an unrelated
listener cannot satisfy the startup check. An earlier unmanaged development
listener on this Mac has stopped; port 9000 is currently free.
Readiness now probes the configured bind address, maps wildcard binds through
loopback, and both launchers bracket IPv6 addresses for Gunicorn. A live local
HTTP check also confirms readiness and staged release identity on the bound
address.
Mac scan assets are now pinned inside each staged release; the sudo helper does
not trust an environment override for its asset root. The Mac installer backs
up its installed launcher, helper, sudoers rule and plist and restores them,
the previous release link, and the prior loaded-service state if deployment
fails. Unit-level rollback simulations pass; an installed-host rollback is
still required.
The optional Mac sudo helper now rejects caller-controlled data roots and
user-writable scanner commands. It runs Nmap output in a private root spool,
then drops to the service user's identity before publishing files. Scan job
timeouts/cancellation signal the whole process group, and completion also
cleans up any descendant that outlives the command, with real child-process
regressions. The Mac and Ubuntu installers use protected service PATHs;
the Mac provenance check also recursively inspects non-system Mach-O libraries.
Both installers now verify a protected Nmap NSE/data tree and set a fixed
`NMAPDIR`; the Mac helper independently checks that tree before each privileged
Nmap invocation. The current Mac dry runs fail by design until this host has a
protected scanner toolchain. Ubuntu has the disposable-VM evidence above;
macOS still needs an installed LaunchDaemon scan before its privileged path can
be signed off.
The installers now reject reused credentials whose data, log, or Playwright
browser paths disagree with their managed locations, as well as duplicate
settings and ports the service cannot bind. Ubuntu's wrapper reasserts its
protected PATH after systemd reads the environment file. These checks prevent
an apparently ready service from later writing into a read-only or untrusted
location; an existing custom data location requires an explicit migration.
The shared service-environment validator rejects unrecognized process-injection
keys such as `LD_PRELOAD` and `PYTHONPATH`. Ubuntu's launcher now also pins the
NSE/style assets to its staged release even if an old environment file contains
an asset override.
Ubuntu upgrades now preserve each release's root-owned launcher and systemd
unit alongside its code. Manual rollback restores the matching launcher/unit
transactionally; failed upgrades and failed rollbacks restore the prior files,
release links and service state in unit-level simulations. The installer
rejects an unmanaged existing service or release path before replacement.
Install, upgrade and successful rollback also passed in the disposable Ubuntu
VM. Fresh installed-service failure injections also confirmed that both an
unready upgrade and an unready rollback restore the prior launcher, unit,
release links, enabled/active state and readiness.
Local UI trust now parses `Origin` and `Referer` hosts instead of accepting a
substring containing `localhost` or `127.0.0.1`; cross-site Fetch Metadata is
also rejected. Request-level regressions cover hostile lookalike domains and
IPv6 loopback, while the default Socket.IO/CORS origins include IPv6 loopback.
This closes a code-level browser-origin bypass, not a full external security
assessment.
Ubuntu uninstall now refuses unmanaged service files and checks the managed
release before stopping or removing its unit and launcher; the installed VM
confirmed credentials, runtime DB, and release archives survive uninstall.
Mac release switching had an actual BSD `mv` bug: without `-h`, replacing a
symlink to a directory moved the new link inside the old release. A regression
reproduced the failure and now passes with symlink-safe replacement; the
automatic rollback test uses the real switch function. The Mac installer also
stops a loaded daemon before replacing live service artifacts, rejects
unmanaged installed files/releases, and refuses in-place daemon-user changes
before altering data ownership. Uninstall performs the same managed-release
preflight. These are code and simulation results; real LaunchDaemon upgrade,
rollback and uninstall verification is still required.
The Mac installer now archives the matching wrapper, scanner helper, sudoers
rule and plist with each staged release and tracks the previous release link.
`--rollback` restores those files and links transactionally; unit-level
successful and failed rollback simulations pass. Uninstall removes both links
but keeps release archives and mutable data. The installed-host rollback gate
remains open.
Auto-Monitor now rejects a scheduled slot before the rule's creation
time. A new rule enabled after its daily or weekly time no longer runs an
unintended immediate catch-up scan; regression tests include an IANA-zone
spring-forward gap and a cadence anchor older than creation. Missed slots
after creation still catch up once. Legacy rules with an anchor but no
creation timestamp use that persisted anchor as the activation fallback. The
calendar transitions also need validation in an installed unattended service.
Startup recovery now drains stale jobs in bounded 200-row batches with a stable
database cursor instead of leaving later rows behind when an entire first batch
fails. It attempts each job once, continues past individual write failures, and
caps both success and failure log samples. A real SQLite regression covers
same-timestamp pagination and more than 200 interrupted jobs; simulated write
failures cover later batches. Incomplete recovery is recorded in readiness and
returns HTTP 503 instead of presenting a healthy service with stale running
jobs.
The shutdown reaper now gives tracked scan process groups a bounded SIGTERM
grace period before SIGKILL and refuses jobs/process attachments once shutdown
begins. Tests exercise a stubborn scan child, application SIGTERM and the
staged Gunicorn master's shutdown of its worker. They do not establish how an
installed Mac service handles an uncatchable SIGKILL or power loss. Ubuntu
reboot recovery and installed-service SIGKILL/interrupted-job recovery passed
in disposable VMs; Mac reboot/sleep and installed-service crash recovery remain
outstanding.
Runtime SQLite report listings and recent-job listings used table scans and
temporary order-by sorts in `EXPLAIN QUERY PLAN`. Idempotent read indexes now
cover the global and per-customer report order and job update order, including
existing version-1 databases. The schema version remains 1 so the preserved
rollback release can still open the database; a regression checks both data
preservation and the indexed query plans. Installed-host load and disk-growth
measurements are still required.
The service also has process-wide scan/report admission control, capped at two
active jobs by default and configurable with `NMAPUI_MAX_CONCURRENT_JOBS`;
over-capacity requests are rejected instead of spawning unlimited heavy work.
Daily runtime-database maintenance retains bounded log/history/finished-job
rows and their job events; limits now have validated positive-integer overrides
in the protected service environment while retaining the existing defaults.
Normal report-list queries omit the large per-scan asset snapshot. Daily
maintenance does not run `VACUUM` inline with scheduled work; compaction remains
an explicit authenticated operation. Saved reports and scan folders are
intentionally not deleted. An SQLite regression verifies daily pruning status
is persisted while saved report rows and on-disk files remain intact; the
retention/backup policy and installed-host disk-growth behavior remain open
lifecycle decisions.
Chunked Nmap XML merging collects scan targets during the merge pass and parses
each input XML file once. It now writes the merged tree to a synced temporary
file and atomically publishes it, avoiding a second full serialized XML copy
and preserving any previous report after a serialization failure. On this
macOS ARM64 host, a synthetic high-volume fixture (65,536 host records, 64
input files, 15.42 MiB output) merged in 0.98 seconds with a 205.3 MiB process
high-water RSS; the same fixture before streaming serialization measured 272.5
MiB. The fixture is a local synthetic benchmark, not a production scan, so
large real-scan throughput and installed-host memory behavior still need
measurement.
The menu-bar app build's opt-in runtime database migration previously copied
only the SQLite main file, which could omit committed transactions still in its
WAL. It now uses SQLite's backup API for the source snapshot and installed
database, validates both, refuses same-file/hard-link destinations, and skips
a redundant copy when the source is already the runtime data location. A
migration snapshot is first built in a private file beside the destination;
only a validated, synced snapshot atomically replaces the existing database.
The helper refuses destination WAL/SHM sidecars so an open runtime database is
not replaced, and an injected mid-snapshot failure verifies the previous DB is
preserved. Runtime export also removes its temporary database if backup fails.
The packaged Mac smoke test covers committed rows still in the source WAL.
These checks do not replace a separate pre-upgrade backup or installed-host
rollback verification. On this host, the latest root and `--user` Mac installer dry
runs still fail closed because Nmap is absent from the protected service PATH;
root mode also warns that the base Python is not root-owned. The current
revision's earlier UI/security checkpoint passed 17 browser regressions,
including PDF resource security, generated-report CSP/CSV safety and
remote-sync secret handling (567 passed / 24 skipped at that checkpoint).
Staged runtime asset checks and staged Gunicorn/WebSocket checks passed.
Dependency audits and Ubuntu lifecycle/reboot results are recorded above;
physical-host discovery, unattended soak, and hosted CI on this exact candidate
remain open.
Auto-scan configuration writes now use distinct, synced temporary files and
propagate write failures. HTTP and Socket.IO updates no longer acknowledge or
broadcast settings that could not be saved, and overlapping updates serialize
their disk and in-memory state. A queued auto-scan or Auto-Monitor rule is
rechecked immediately before execution, so an operator can disable it while
earlier worker tasks are pending. Tests cover write failure, concurrent updates
and both queued-disable paths; installed-service timing behavior remains to be
validated.
Shared state and secret writes now use unique, synced, owner-only temporary
files. Session signing-key creation fails closed on corrupt or unwritable state
instead of returning an ephemeral key; the supervised worker validates it before
readiness. Concurrent remote-sync/Drive key creation publishes only one key,
and reading ciphertext with a missing key does not silently mint a replacement.
Existing remote-sync and Drive files are tightened to owner-only permissions
when read. The shared state writer also protects JSON/YAML documents from
concurrent temporary-file collisions and preserves the previous document if
syncing a replacement fails.
The readiness endpoint now requires a live scheduler thread. Whole-document
settings saves preserve server-owned Auto-Monitor run and creation markers, and
serialize with scheduler updates so a stale browser form cannot erase a just-
completed run. Unit and staged-worker tests cover these paths; installed-host
crash, power-loss and multi-process behavior still need verification.

## Where work stopped

- `main` / `origin/main`: `2828bd36`, PR #239 merged August 24. Latest CI passed
  unit/contract, browser regression and packaged Mac smoke jobs:
  https://github.com/techmore/TM-NmapUI/actions/runs/32763844258
- Draft PR #240 is open and mergeable. The most recent hosted run at this status
  snapshot passed all three
  checks (unit/contract, browser, packaged Mac smoke):
  https://github.com/techmore/TM-NmapUI/actions/runs/36169719816
  The implementation review started from `b2d52a3b`. It adds `5bb6556e` (validating scanner
  helper), `70bffdce` (root-default appliance mode), and `5ff6227c` (review fixes
  and current documentation).
- Local verification on September 24: `.venv/bin/python -m pytest -q` → **405
  passed, 9 skipped**; explicit browser regressions → **8 passed in 13.21s**;
  packaged Mac smoke → **1 passed in 52.63s**. Both root and `--user` installer
  dry runs passed. A direct app launch returned healthy liveness/readiness,
  authenticated login and issued a Socket.IO token. A real Quick Scan of
  `127.0.0.1` completed, but as the unprivileged development process Nmap
  reported zero hosts and ARP enrichment skipped for lack of privileges. This
  confirms why the installed privileged path still needs a live test.
- `swift-native`: 29 commits unique relative to main; main has 10 absent from it.
  Keep for selective integration and native parity review, not a blind merge.
- `alpha/mac-known-good-2026-09-07-1040` and tag
  `alpha-mac-known-good-2026.09.07-1040`: preserve as the intentional rollback.
- `claude/quirky-torvalds`: keep pending review. `git cherry origin/main` reports
  20 patch-unique commits; it is not proven redundant.
- No other local or remote feature branch is both merged and disposable. Keep
  the active unattended branch, alpha rollback, and unique native/Claude work.

## Cleanup completed
- Removed local and remote `fix/zombie-jobs-disable-scan-buttons` after verifying
  its tip is an ancestor of main (merged PR #238).
- Fetched/pruned the already-deleted remote runtime-contract branch.
- Pruned only the dead `/private/tmp/nmapui-swift` worktree registration; the
  `swift-native` branch remains intact.
- Reopened #230 after discovering five expected-failure markers hidden behind
  the successful CI status. Its initial closure in this review was premature.
  The first explicit local browser run produced 2 passed, 5 xfailed. Fixes are
  now in PR #240: use real network Socket.IO clients, initialize the test port
  before the origin allowlist, isolate runtime data, supply actual comparison
  assets, and test the current UI. Fixed Quick Scan job-state updates and report
  reconnect classification. The latest local browser result is **8 passed in
  13.21s**, with no skips or expected failures. PR #240 also adds live/replayed
  state coverage for #161; leave both issues open until the PR merges.
- PR #240 remains a draft. Ubuntu disposable-VM install, loopback scan,
  authenticated browser/WebSocket, crash recovery, upgrade/rollback, reboot and
  uninstall checks pass. Mac installed-daemon testing, physical Ubuntu interface
  discovery and unattended soak verification are outstanding.
- Closed #160 as a duplicate of the more detailed, high-priority #106 after
  consolidating its header/summary parity and related #154/#155 tasks. Keep #230
  open until its fixes merge; keep #223, #226 and #237 for native Mac work.

## Backlog organization

### Daemon review follow-up

The installer now reads credentials as literal values instead of sourcing shell
code, so the default `Application Support` path and passwords with shell
characters work. Generated shell/plist paths are escaped, credentials are
required, and runtime ownership supports the selected service user. Installation
checks bounded readiness rather than liveness. Generated-artifact tests execute
the wrapper without installing a service. A real subprocess test confirms that
the scheduler lock is released after its owner receives SIGKILL.
Earlier follow-up validation: full suite **405 passed, 9 skipped**; browser
regressions **8 passed**; packaged Mac smoke **1 passed in 52.63s**. At that
stage both installer dry runs passed plist, sudoers, wrapper and helper checks.
The app also passed live
health, login and socket-token checks in an isolated process; authenticated
remote token access now has a dedicated unit test.

Release blockers: privilege isolation is **implemented but optional**. The
installer now stages root-owned assets and ships a validating helper
(`packaging/macos/nmapui-privileged-scanner`) that sudoers can grant instead of
`nmap` itself, and `--user <name>` runs the backend as a non-root account. Per
the September 12 platform decision, **root remains the default**: this platform
treats root as the goal, so the daemon installs as root with no sudoers
dependency and no extra decision. That keeps the earlier residual risk
deliberately accepted — the web backend is root. Per the September 25 user
decision, loopback access no longer requires sign-in; every process on the
scanner host can reach the control surface. Non-loopback requests still require
credentials, and the service must remain loopback-bound unless remote access
is deliberately configured.

What remains unverified on macOS is everything requiring the installed root
LaunchDaemon: it has not been installed, rebooted, interrupted or soaked, and
neither mode has executed a live privileged scan end to end. The separate
Ubuntu disposable VM passed its installed privileged loopback scan, but that
does not establish physical-interface discovery or real-host support. The
in-process reaper still cannot clean up children after `SIGKILL`. Keep PR #240
in draft pending the remaining platform checks and hosted candidate CI.

1. **Finish and integrate unattended baseline.** Review the local branch and run
   browser/packaged checks against this exact revision before merging. Complete
   reboot/sleep/crash verification and remaining security/privilege validation.
2. **Ubuntu scanner-host deployment.** macOS and Ubuntu are the scanner-host
   targets; browser clients can run cross-platform. The in-repo installer now
   generates a root-mode `systemd` unit and supports stage/upgrade, rollback and
   uninstall with data preservation. A disposable Ubuntu 24.04 ARM64 VM passed
   install, a privileged loopback scan, upgrade/rollback and reboot. Failed
   upgrade and rollback recovery have also been injected against the installed
   service in a disposable VM. Physical scanner-host/interface scans and an
   unattended soak remain open, as does hosted CI on the current candidate, in
   [#241](https://github.com/techmore/TM-NmapUI/issues/241). Per the September 11
   user decision, container networking is unsuitable for the intended
   deployment; container packaging is retired from the active roadmap. Windows
   is not a scanner-host target. Existing container files remain historical
   references to the legacy Node runtime.
3. **Native Mac frontend (#223).** Inventory reusable SwiftUI screens and connect
   them to the shared backend. Keep #226 (lifecycle extraction) and #237 (helper
   authorization) open: their implementation appears on the unmerged Swift line,
   not established in the canonical product.
4. **Reports.** #160 has been closed as a duplicate of detailed, canonical #106
   after its unique requirements were consolidated. Existing PDF fixes do not
   prove full visual parity.
5. **Operational follow-through.** Close #161 with PR #240 after merge; retain
   #163 (data lifecycle) and #164 (security). Unit tests cover daylight-saving
   scheduling, but it still needs installed-service validation. Runtime DB
   retention, secret-file permissions, installer rollback, and duplicate-
   install preflight are implemented and have focused tests; the lifecycle
   policy for saved scan/report folders, broader secrets/third-party script and
   HTML-sink review, real
   installed Mac rollback, and host-level disk-growth behavior remain open.
   Remote Mac management through DigitalOcean is recorded in the preserved
   release notes, but is not verified implemented.
6. **Later features.** #4 remote sync, #10 pause/resume, #14 GoWitness and #31 VLAN
   should be evaluated against the shared backend before being declared done;
   an implementation in a legacy/native branch is insufficient.

## Documentation to reconcile

Use README and the September 10 audit's phase status as current context. The
audit's original findings and some introductory notes describe earlier code;
do not treat every finding as still unresolved. Its status says “Draft” despite
later locked decisions and implementation updates. The January
`CLAUDE_WORK_PLAN.md` remains historical. Root AGENTS has current navigation
above its generated map; BUILDING, SETUP, release checklist and repository
layout now describe the supported Flask/Swift path.
Do not remove legacy assets wholesale: verify Flask/static/report dependencies
first. Keep the rollback archive intact; migrating it to release storage can be
done separately without rewriting Git history.
