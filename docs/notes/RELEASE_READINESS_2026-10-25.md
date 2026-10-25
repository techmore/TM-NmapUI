# Release readiness — October 25, 2026

This is the evidence ledger for the requested next release across the web,
macOS native experience and elementary OS. The release is **not yet qualified**.
Do not infer release approval from a draft PR, passing unit tests, or older
September installer evidence.

The later [release preflight](RELEASE_PREFLIGHT_2026-10-25.md) records the current
nine-branch/five-PR merge assessment, nine open issues, duplicate Actions trigger
repair and reproduced browser-test startup race. Sources and run links below
remain evidence for their named checkpoints; the old `911f83d8` integration pin
must be replaced with the final qualified candidate before release.

## Candidate and integration sources

- Shared engine/web/macOS candidate: [PR #254](https://github.com/techmore/TM-NmapUI/pull/254),
  branch `codex/repository-audit-2026-10-25`. The frozen executable candidate is
  `0e7d22ed8f60ea325dd6cbc77192ea9ff64340b9` (`v2026.10.25`); later
  documentation commits do not change that engine pin.
- Native elementary OS app: [PR #1](https://github.com/techmore/TM-NmapUI-elementary/pull/1)
  in separate repository `techmore/TM-NmapUI-elementary`;
  current reviewed head `4b3f1c5` on `codex/native-status-oauth-2026-10-25`.
- Daedalus scanner bundle: separate repository `techmore/tm-daedalus`; atomic
  bundle publication is reviewed in [PR #23](https://github.com/techmore/tm-daedalus/pull/23).
  A separately reproduced accepted-receipt replay race is fixed in stacked
  [PR #24](https://github.com/techmore/tm-daedalus/pull/24), with all final hosted
  checks passed. Stacked [PR #25](https://github.com/techmore/tm-daedalus/pull/25)
  passed all nine hosted checks with engine `911f83d8` at `5eaa20d4`;
  the coordinated replacement with `0e7d22ed` is being qualified.
- Daedalus sign-ups with TM-NmapUI onboarding are tracked by
  [Daedalus #22](https://github.com/techmore/tm-daedalus/issues/22), linked to its
  existing deployment and customer acceptance gates.
- Preserve the known-good alpha branch/tag. `swift-native` remains separate
  with unique work and must be evaluated for native UI parity before integration.

## Required evidence

| Requirement | Current evidence and remaining work |
| --- | --- |
| Shared engine correctness | Frozen engine `0e7d22ed` passed all four hosted jobs in [run 40244555753](https://github.com/techmore/TM-NmapUI/actions/runs/40244555753): 889 unit/contract tests (45 gated/platform skips), 39 browser/PDF tests, five packaged Mac checks, 31 staged Ubuntu checks (two skips) and installed systemd lifecycle. Python/both npm audits and clean asset reproduction passed. Local preflight checks passed 890 tests (44 skipped). |
| Web behavior and accessibility | The 39-test Chromium/PDF group includes Archive recovery and a deliberately blocked Socket.IO transport: HTTP Settings Save and Google popup feedback remain usable before connection, then late connection cannot duplicate handlers or erase action feedback. An unchanged rerun was not used to hide the earlier two-test hosted failure. |
| Runtime status privacy | Status now follows configured authentication and returns no-store. Before the fix, unauthenticated callers could read customer/target/session details. Actual packaged runtime checks prove strict unauthenticated 401, Unicode Basic 200/no-store and public health readiness; unit cases also cover browser sessions, trusted-loopback boundaries and insecure configuration. Explicitly blank binds cannot acknowledge default credentials. |
| Job status ordering | All three web consumers and the native reducer reject late active packets for terminal source UUIDs. The 39-test browser group includes completed/cancelled scan/report sequences, idle and late same-run packets, plus actual HTTPS Socket.IO startup. The synthetic-job test now acknowledges initial real registry snapshots before injection; the reproduced bootstrap race is resolved without relaxing assertions. |
| Drive transfer reliability | Bounded 8 MiB resumable chunks; tests cover confirmed offsets, ambiguous completion, 401 refresh, rate limits, malformed responses, redirects, source mutation and partial failure. |
| Drive consent and deployment policy | One-time PKCE state, origin protection, no-store responses, encrypted private tokens and serialized disconnect are implemented/tested. Real production OAuth client configuration, consent, synthetic uploads and revocation still require live account evidence. See `docs/guides/GOOGLE_DRIVE.md`. |
| Daedalus command contract | Targeted tests cover namespace isolation, reconnect owner selection, replay deduplication and persisted scan/report state. The portal currently offers start/cancel/update; do not advertise remote pause/resume until implemented there. |
| Daedalus packaged source | PR #25 at `5eaa20d4` embeds clean engine `911f83d8`, ZIP SHA-256 `2448dc411efe6e96e02ce25a52c39886422b122bdf7a22626b361d09ad468ebc`. All nine hosted checks passed in runs 40242011350 and 40242011514, including five managed Linux scenarios. Recovery preserved 14 original payloads and ended with no pending/review events or preservation failures. Historical approved hosted report templates remain unchanged. The replacement `0e7d22ed` kit is being rebuilt and qualified. |
| Native macOS menu/status | Canonical fixes cover daemon attachment, mixed metadata, paused states, bounded polling, strict-auth requests and truthful job endings. Process tests cover respawning descendants and unrelated stale-marker PIDs. Build replacement is read-only preflight: active/unverified bundles are refused, and shared scanner locks are preserved. |
| Native SwiftUI packaging | [PR #255](https://github.com/techmore/TM-NmapUI/pull/255) at `dcd13230` passed all four hosted jobs in [run 40240040149](https://github.com/techmore/TM-NmapUI/actions/runs/40240040149): 362 Python tests (11 skipped), eight unmasked browsers, 91 Swift tests, 36 optimized-bundle/process/temporary-install checks and the retained Flask-wrapper smoke. The candidate is `v2026.10.25`, numeric build `2026.10.34560`, with exact source and all four ad-hoc-signed helper identities verified. This is not installed privileged-helper or public distribution qualification. |
| Native Drive and retained web fallback | [PR #256](https://github.com/techmore/TM-NmapUI/pull/256) adds expiry/rotation/revocation handling, account isolation, single-use PKCE, bounded resumable chunks, source identity checks and truthful early-completion/callback handling. Drive head `817f26b2` passed all four hosted jobs; later combined head `b5ce036b` also fixes fallback HTTP startup, status privacy, credential policy and Origin guards. Its local checks passed 457 Python tests (12 skipped), ten unmasked browsers and exact-source packaged strict-auth smoke; all four hosted jobs passed in [40241893951](https://github.com/techmore/TM-NmapUI/actions/runs/40241893951). Native fallback authentication remains Basic-only; it does not implement canonical browser sessions. |
| Native shared scanner library | [PR #257](https://github.com/techmore/TM-NmapUI/pull/257) at `375be6cd` passed all four hosted checks in [40243950317](https://github.com/techmore/TM-NmapUI/actions/runs/40243950317): 110 Swift plus 17 Drive tests and 36 packaging checks. Real canonical engine `911f83d8` exercises auth/routes/SQLite/artifacts; fixture-only literal binding removed a blocking reverse-DNS dependency without increasing readiness deadlines. Light/dark/error/long-name renders and byte-identical canonical/offline report captures passed. Offline HTML restricts scripts/subresources but external-viewer navigation is not an HTTP sandbox. Credentials are not forwarded. Repinning to `0e7d22ed` remains pending. |
| Shared scan/schedule execution parity | Still open. [PR #258](https://github.com/techmore/TM-NmapUI/pull/258) at `ce5e6bcd` passed all four hosted checks in [40244263029](https://github.com/techmore/TM-NmapUI/actions/runs/40244263029), including strict authenticated Socket.IO controls against engine `911f83d8`, terminal UUID reduction and explicit reconciliation after uncertain commands. App-wide source routing, menu/keyboard/WK controls and legacy startup isolation are being qualified separately. Customer IDs, archives, report workflows and scheduler ownership still need migration/parity evidence. |
| Native elementary app and dropdown | Current `4b3f1c5` pins installation and CI to `911f83d8` and passed [all Linux checks](https://github.com/techmore/TM-NmapUI-elementary/actions/runs/40241772449): 32 helper/installer tests, GTK/WebKit/Wingpanel build, installed staging, four indicator renders, light/dark offline and online windows, and Ctrl+3 Reports with visual/OCR checks. The artifact receipt confirms the exact engine and no active jobs. This online fixture uses trusted loopback. Physical desktop install/reboot/privilege/consent remains open; OS 9 tanit-unstable container evidence does not establish OS 8 or physical-host support. |
| Real report generation | A one-port Nmap TCP-connect scan of a temporary loopback HTTP fixture generated XML, HTML and a three-page letter PDF. Visual review caught/fixed split interactive print controls, service-column wrapping and incorrect generator attribution. The fixture is not evidence of privileged or physical-interface discovery. |
| Dependency and asset standards | Compatible pins updated, legacy body-parser advisory patched, Python and both npm audits clean at audit time. Browser assets reproduce from clean npm install. Re-audit the final release tree. |
| Performance | Synthetic 32 MiB transfer allocation fell from 71,321,550 to 17,014,203 bytes; 128 MiB from 285,231,142 to 17,016,487 bytes. These are traced Python allocations without network I/O, not throughput or complete RSS measurements. |
| Installed Linux service | Hosted installed-service/privileged-loopback job passed on exact engine `0e7d22ed`. Physical Ubuntu interface discovery, authorized-subnet scanning and unattended soak remain open per #241. |
| Installed macOS service | Current candidate still needs installed-host privilege, upgrade/rollback, shutdown, reboot/sleep and soak evidence from an appropriate test host. Do not disturb the existing SSH-forwarded listener on local port 9000. |
| Release metadata and distribution | Candidate `v2026.10.25` is selected and numeric Mac metadata is validated. Final-version shared-engine package checks passed. No Developer ID Application identity is available on this host; public signing/notarization, installed native helper lifecycle and rollback qualification remain open. No release tag or publication yet. |

## Verification checkpoints

All four jobs passed for frozen engine `0e7d22ed` in
[run 40244555753](https://github.com/techmore/TM-NmapUI/actions/runs/40244555753):
889 unit/contract tests (45 skipped), 39 browser/PDF tests, five Mac packaged
checks, 31 staged Ubuntu checks (two skipped), privileged loopback and installed
systemd lifecycle checks. The same run passed Python and both npm dependency
audits and clean browser-asset reproduction. Local preflight checks passed
890 tests (44 skipped); platform/gated counts differ from Linux CI.

The `911f83d8` downstream checkpoint remains historical evidence until each
integration finishes its exact-source replacement. Root qualification cannot
stand in for a downstream runtime, package or UI test.

The earlier hosted Mac startup timeout on `632e40d` was traced to a 60-second
public traceroute. Packaged startup now defaults that optional network discovery
off, preserves explicit opt-in, and tests bounded readiness with startup,
scanner dependencies and scheduler evidence. The local package readiness probe
completed in 0.78 seconds; the fresh hosted package job passed. The timeout was
not increased to hide the failure.

Local loopback report generation and manual web review remain deliberately
separate from physical-host scan, installed native helper and real-account
Google OAuth acceptance. Native Drive recovery currently lasts within a helper
invocation; it is not a durable cross-process upload checkpoint. Do not infer
Google policy approval from transport tests.

Release completion requires current evidence for every applicable row above and
the chosen scope in `docs/guides/RELEASE_CHECKLIST.md`. Open or indirect evidence
remains open; merge state alone is not deployment or acceptance.
