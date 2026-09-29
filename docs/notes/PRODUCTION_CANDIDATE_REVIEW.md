# Production candidate review — 2026-09-29

The current candidate is on `fix/unattended-operation`, based on committed
revision `e939022ccc88e741c334d4a60e6fa76e861b9491`. This reviewed changeset is
approved for submission to the existing [draft PR #240](https://github.com/techmore/TM-NmapUI/pull/240), which
has successful September 25 checks for that base revision; those checks do not
include this candidate. All four hosted jobs subsequently passed on `df93691c`
in [run 36624110222](https://github.com/techmore/TM-NmapUI/actions/runs/36624110222).
No release version has been selected.

## Changes ready for review

- Stage immutable scanner-service releases with protected tool and asset
  paths, persistent state, release-specific readiness, and transactional
  install/upgrade/rollback behavior for macOS and Ubuntu.
- Bound scan/report admission, cancel complete process groups, stop stubborn
  children at shutdown, and reconcile interrupted jobs in bounded batches.
- Preserve scheduler run/creation markers across settings saves and reject
  disabled queued work; cover missed slots and daylight-saving transitions.
- Add compatible runtime DB indexes and bounded retention while preserving
  saved report folders. Migrate WAL commits through validated atomic snapshots.
- Persist secrets privately, revoke sessions on credential rotation, reject
  default remote credentials, and support Secure cookies behind HTTPS proxies.
  Block browser mutations from untrusted origins, including same-site forms
  that carry valid session cookies; accept Unicode login and API credentials.
- Serve pinned scripts, styles, and fonts locally; tighten UI/report CSP,
  escape untrusted scan metadata, and keep remote-sync API keys out of browser
  storage. Managed services default external enrichment/update lookups off.
- Correct report severity counts and PDF layout; isolate PDF resources and
  publish merged XML atomically with lower peak memory for large fixtures.
- Extend CI with reproducible assets and Ubuntu installed-service lifecycle,
  privileged loopback scan, authenticated browser/WebSocket, and failed
  upgrade/rollback checks, alongside the existing Mac packaged smoke.

## Evidence on the current candidate

| Verification | Result |
| --- | --- |
| Full Python 3.11 suite | 619 passed, 27 skipped |
| Auth/session group | 90 passed |
| Chromium browser regressions | 20 passed |
| Browser-backed PDF checks | 2 passed |
| Staged Gunicorn login, reload and Socket.IO | 1 passed on September 29 |
| Packaged Mac app with Unicode Basic credentials and WAL migration | 1 passed on September 29 |
| Diff whitespace check | Passed |
| Common token/private-key format scan over changed files | No matches; limited to those formats |

Earlier September 28 evidence includes the full staged server smoke (4 passed,
2 skipped). The latest auth changes were validated in the staged server and
packaged app after that run. Disposable Ubuntu 24.04 ARM64
VM evidence covers installed lifecycle and privileged loopback scanning, as
described in [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Publication and hosted validation

The candidate was committed on `fix/unattended-operation` and pushed to its
existing draft PR with user approval on September 29. Its title and description
cover the service, auth and reporting changes listed above. Keep the PR draft
while completing scanner-host acceptance. All four hosted checks passed on
`17fa8ad1` in [run 36625140587](https://github.com/techmore/TM-NmapUI/actions/runs/36625140587).

The first submitted candidate, `feef24b5`, exposed hosted-runner gaps in
[CI run 36618599556](https://github.com/techmore/TM-NmapUI/actions/runs/36618599556):
Linux installer contracts needed GNU no-follow `mv` semantics and an explicit
test interpreter, a template contract still inspected the pre-extraction Git
index, browser report tests lacked `xsltproc`, and the hosted image's writable
`/usr/share` correctly failed root scanner provenance validation. Follow-up
changes correct the contracts/dependencies and protect that runner directory;
the production safety check remains unchanged. Hosted validation of the
follow-up revision is required.

The second hosted run on `3f8e033a` passed unit/contract tests, asset
reproducibility and the dependency audit. It exposed an additional writable
runner parent (`/opt`) during actual service installation and a font test that
checked readiness before explicitly requesting the face. CI now protects both
runner directories, and the font regression requires successfully loaded real
faces. The first run's macOS packaged job passed. These follow-up checks still
require a green hosted run on the final candidate.

Subsequent hosted evidence passed macOS packaging and the complete browser,
unit and audit jobs. Installed Ubuntu login returned HTTP 403 on its own form;
the application now uses `Referrer-Policy: same-origin` so local form provenance
is preserved without disclosing referrers to foreign origins. Foreign/opaque
origins remain rejected. Installed logs also exposed repeated-signal logging
reentrancy and Gunicorn's optional control socket under protected `/root`;
shutdown now guards repeat signals and avoids buffered logging, and service
wrappers disable that unused socket. After these changes the full local suite
passed 616/27, browser/PDF passed 22, and full staged server smoke passed 4/2.

Hosted installed-service validation then passed the strict-auth browser session,
reload and WebSocket checks. Upgrade preflight correctly rejected the runner's
writable `/usr/local/bin`; CI now provisions protected `/usr/local` parents too.
The Ubuntu installer also verifies destination parents before first-install
mutation, with regressions for writable and symlink-resolved directory ancestry.

All four jobs then passed on `df93691c`, including the entire installed Ubuntu
lifecycle. A prior Mac run had timed out waiting for health; the smoke harness
now avoids undrained subprocess pipes and captures launch diagnostics to a file.
All four hosted jobs also passed on the harness/documentation follow-up
`17fa8ad1`, confirming the final submitted runtime and test harness together.

## Gates still requiring external evidence or decisions

- Require fresh green checks after any subsequent code or release-version
  change; the submitted runtime and harness passed all four jobs on `17fa8ad1`.
- Provision the protected Mac scanner toolchain and validate the installed
  LaunchDaemon; this Mac currently has user-owned Homebrew Nmap and requires a
  sudo password.
- Validate a supported physical Ubuntu scanner host, authorized SYN/OS/ARP
  discovery through its real interface, resulting reports, and unattended soak.
- Complete the installed-host scheduler, recovery, retention/disk-growth,
  backup/restore and report-layout checks in the
  [release checklist](../guides/RELEASE_CHECKLIST.md).
- Approve the release version and saved scan/report retention and backup policy.

The passing local tests support publishing the candidate for CI. Production
launch remains gated by the installed-host evidence and release decisions.
