# Release readiness — October 25, 2026

This is the evidence ledger for the requested next release across the web,
macOS native experience and elementary OS. The release is **not yet qualified**.
Do not infer release approval from a draft PR, passing unit tests, or older
September installer evidence.

## Candidate and integration sources

- Shared engine/web/macOS candidate: [PR #254](https://github.com/techmore/TM-NmapUI/pull/254),
  branch `codex/repository-audit-2026-10-25`. The frozen executable candidate is
  `46a18a27bbc9df5fec061f6df226159b18f788e5` (`v2026.10.25`); later
  documentation commits do not change that engine pin.
- Native elementary OS app: [PR #1](https://github.com/techmore/TM-NmapUI-elementary/pull/1)
  in separate repository `techmore/TM-NmapUI-elementary`;
  current reviewed head `70ba34b` on `codex/native-status-oauth-2026-10-25`.
- Daedalus scanner bundle: separate repository `techmore/tm-daedalus`; atomic
  bundle publication is reviewed in [PR #23](https://github.com/techmore/tm-daedalus/pull/23).
  A separately reproduced accepted-receipt replay race is fixed in stacked
  [PR #24](https://github.com/techmore/tm-daedalus/pull/24), with all final hosted
  checks passed. Stacked [PR #25](https://github.com/techmore/tm-daedalus/pull/25)
  packages the exact frozen engine; all five final managed Linux scenarios passed.
- Daedalus sign-ups with TM-NmapUI onboarding are tracked by
  [Daedalus #22](https://github.com/techmore/tm-daedalus/issues/22), linked to its
  existing deployment and customer acceptance gates.
- Preserve the known-good alpha branch/tag. `swift-native` remains separate
  with unique work and must be evaluated for native UI parity before integration.

## Required evidence

| Requirement | Current evidence and remaining work |
| --- | --- |
| Shared engine correctness | Exact engine `46a18a27` passed all four hosted jobs in run 40237064491: 866 unit/contract tests (38 gated skips), 32 browser/PDF tests, five packaged Mac checks, staged Ubuntu and installed systemd lifecycle. Dependency audits and asset reproduction passed in the same run. |
| Web behavior and accessibility | Exact-engine Chromium/PDF group passed 32 tests, including Archive refresh recovery. Live isolated Gunicorn review verified settings save, navigation and empty reports without scanning a LAN. |
| Drive transfer reliability | Bounded 8 MiB resumable chunks; tests cover confirmed offsets, ambiguous completion, 401 refresh, rate limits, malformed responses, redirects, source mutation and partial failure. |
| Drive consent and deployment policy | One-time PKCE state, origin protection, no-store responses, encrypted private tokens and serialized disconnect are implemented/tested. Real production OAuth client configuration, consent, synthetic uploads and revocation still require live account evidence. See `docs/guides/GOOGLE_DRIVE.md`. |
| Daedalus command contract | Targeted tests cover namespace isolation, reconnect owner selection, replay deduplication and persisted scan/report state. The portal currently offers start/cancel/update; do not advertise remote pause/resume until implemented there. |
| Daedalus packaged source | PR #25 embeds clean engine `46a18a27`, ZIP SHA-256 `1ce5cdd8ca0d9ee0da0b87aab0bbb8133f0b4584df5964c6c595bc1b5ad30a0d`, 138 files and no dirty source paths. Hosted core and all five managed Linux scenarios passed in runs 40237616019 and 40237616213. Local validation passed 1,648 tests and 523 subtests plus Ruff. Recovery preserved 14 original payloads and ended with no pending/review events or preservation failures. Historical hosted report templates remain byte-for-byte pinned to their approved baseline. |
| Native macOS menu/status | Pushed fixes cover daemon attachment, mixed-type metadata, paused states, stale polling, strict-auth status and truthful completion indicators. Real-process Swift tests prove TERM-respawn descendants are stopped while an unrelated stale-marker PID survives. Numeric bundle metadata and actual packaged smoke pass. |
| Full SwiftUI parity | [PR #255](https://github.com/techmore/TM-NmapUI/pull/255), based on `swift-native`, fixes helper stamps, hermetic scheduling/Drive tests, deterministic real-loopback discovery and native packaging. At `1391dae9`, local checks passed 91 Swift tests, 355 Python tests (10 gated skips), eight real browser regressions without xfail masks, fallback packaged smoke and optimized native bundle validation. Resources, exact source revision and all four ad-hoc-signed helper identities are verified. Mandatory native hosted CI was added, but a workflow context error is being repaired before hosted qualification. Stacked [PR #256](https://github.com/techmore/TM-NmapUI/pull/256) adds native Drive expiry/refresh, single-use PKCE, loopback handling and bounded resumable uploads; its 10 new Drive tests and 91 existing Swift tests passed locally. Integration with the updated base and hosted checks remain required. The app still uses separate native scan/report/storage/scheduler implementations, so this does not establish shared-Flask parity or installed-helper qualification. |
| Native elementary app and dropdown | `70ba34b` passed all 32 helper/installer tests, required GTK/WebKit/Wingpanel compilation, installed artifact staging and offline/indicator renders, plus real light/dark online dashboards against immutable engine `46a18a27`, and native Ctrl+3 to WebKit Reports in [Linux CI](https://github.com/techmore/TM-NmapUI-elementary/actions/runs/40237352420). Visual/OCR checks passed. Installer rollback and conflict handling are covered by isolated lifecycle tests; real desktop install/reboot/privilege/consent acceptance remains open. OS 9 tanit-unstable container evidence does not prove OS 8 or physical-host support. |
| Real report generation | A one-port Nmap TCP-connect scan of a temporary loopback HTTP fixture generated XML, HTML and a three-page letter PDF. Visual review caught/fixed split interactive print controls, service-column wrapping and incorrect generator attribution. The fixture is not evidence of privileged or physical-interface discovery. |
| Dependency and asset standards | Compatible pins updated, legacy body-parser advisory patched, Python and both npm audits clean at audit time. Browser assets reproduce from clean npm install. Re-audit the final release tree. |
| Performance | Synthetic 32 MiB transfer allocation fell from 71,321,550 to 17,014,203 bytes; 128 MiB from 285,231,142 to 17,016,487 bytes. These are traced Python allocations without network I/O, not throughput or complete RSS measurements. |
| Installed Linux service | Hosted installed-service/privileged-loopback job passed on exact engine `46a18a27`. Physical Ubuntu interface discovery, authorized-subnet scanning and unattended soak remain open per #241. |
| Installed macOS service | Current candidate still needs installed-host privilege, upgrade/rollback, shutdown, reboot/sleep and soak evidence from an appropriate test host. Do not disturb the existing SSH-forwarded listener on local port 9000. |
| Release metadata and distribution | Candidate `v2026.10.25` is selected and numeric Mac metadata is validated. Final-version shared-engine package checks passed. No Developer ID Application identity is available on this host; public signing/notarization, installed native helper lifecycle and rollback qualification remain open. No release tag or publication yet. |

## Verification checkpoints

All four jobs passed for frozen engine `46a18a27` in
[run 40237064491](https://github.com/techmore/TM-NmapUI/actions/runs/40237064491):
866 unit/contract tests (38 skipped), 32 browser/PDF tests, five Mac packaged
checks, 31 staged Ubuntu checks (two skipped), privileged loopback and installed
systemd lifecycle checks. The same run passed Python and both npm dependency
audits and clean browser-asset reproduction.

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
