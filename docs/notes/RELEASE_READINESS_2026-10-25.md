# Release readiness — October 25, 2026

This is the evidence ledger for the requested next release across the web,
macOS native experience and elementary OS. The release is **not yet qualified**.
Do not infer release approval from a draft PR, passing unit tests, or older
September installer evidence.

## Candidate and integration sources

- Shared engine/web/macOS candidate: [PR #254](https://github.com/techmore/TM-NmapUI/pull/254),
  branch `codex/repository-audit-2026-10-25`.
- Native elementary OS app: [PR #1](https://github.com/techmore/TM-NmapUI-elementary/pull/1)
  in separate repository `techmore/TM-NmapUI-elementary`;
  reviewed changes start at `52327da` on `codex/native-status-oauth-2026-10-25`.
- Daedalus scanner bundle: separate repository `techmore/tm-daedalus`; atomic
  bundle publication is reviewed in [PR #23](https://github.com/techmore/tm-daedalus/pull/23).
  A separately reproduced accepted-receipt replay race is fixed in stacked
  [PR #24](https://github.com/techmore/tm-daedalus/pull/24); its final hosted
  interrupted-recovery checks are still running.
- Daedalus sign-ups with TM-NmapUI onboarding are tracked by
  [Daedalus #22](https://github.com/techmore/tm-daedalus/issues/22), linked to its
  existing deployment and customer acceptance gates.
- Preserve the known-good alpha branch/tag. `swift-native` remains separate
  with unique work and must be evaluated for native UI parity before integration.

## Required evidence

| Requirement | Current evidence and remaining work |
| --- | --- |
| Shared engine correctness | Drive, bridge namespace/replay and source-state changes are pushed. Hosted unit/contract checks passed on `5b4ee9c`; later candidate commits need their own checks. |
| Web behavior and accessibility | Chromium/PDF group passed 31 tests. Live isolated Gunicorn review verified settings save, navigation and empty reports without scanning a LAN. Archive refresh resilience changes are under review. |
| Drive transfer reliability | Bounded 8 MiB resumable chunks; tests cover confirmed offsets, ambiguous completion, 401 refresh, rate limits, malformed responses, redirects, source mutation and partial failure. |
| Drive consent and deployment policy | One-time PKCE state, origin protection, no-store responses, encrypted private tokens and serialized disconnect are implemented/tested. Real production OAuth client configuration, consent, synthetic uploads and revocation still require live account evidence. See `docs/guides/GOOGLE_DRIVE.md`. |
| Daedalus command contract | Targeted tests cover namespace isolation, reconnect owner selection, replay deduplication and persisted scan/report state. The portal currently offers start/cancel/update; do not advertise remote pause/resume until implemented there. |
| Daedalus packaged source | Its existing embedded engine remains `ead49881`. Refresh only from the final clean, committed NmapUI release tree; validate the rebuilt kit and lifecycle before rollout. |
| Native macOS menu/status | Pushed fixes cover daemon attachment, mixed-type metadata, paused states, stale polling, strict-auth status and truthful completion indicators. Real-process Swift tests prove TERM-respawn descendants are stopped while an unrelated stale-marker PID survives. Numeric bundle metadata and actual packaged smoke pass. |
| Full SwiftUI parity | [PR #255](https://github.com/techmore/TM-NmapUI/pull/255), based on `swift-native`, fixes helper stamps, hermetic scheduling/Drive tests, deterministic real-loopback discovery and native packaging. At `73a55de5`, 91 Swift tests, 27 validation tests and the optimized native bundle smoke pass; resources, exact source revision and all four ad-hoc-signed helper identities are verified. The app still uses separate native scan/report/storage/scheduler implementations, so this does not establish shared-Flask parity or installed-helper qualification. |
| Native elementary app and dropdown | `e1fc4b0` passed required GTK/WebKit/Wingpanel compilation, navigation/helper tests and offline/indicator renders, plus real light/dark online dashboards against exact engine `632e40d`, and native Ctrl+3 to WebKit Reports in [Linux CI](https://github.com/techmore/TM-NmapUI-elementary/actions/runs/40236118981). Visual/OCR checks passed. Immutable engine staging and safe installer rollback are under review; real desktop install/privilege/consent acceptance remains open. |
| Real report generation | A one-port Nmap TCP-connect scan of a temporary loopback HTTP fixture generated XML, HTML and a three-page letter PDF. Visual review caught/fixed split interactive print controls, service-column wrapping and incorrect generator attribution. The fixture is not evidence of privileged or physical-interface discovery. |
| Dependency and asset standards | Compatible pins updated, legacy body-parser advisory patched, Python and both npm audits clean at audit time. Browser assets reproduce from clean npm install. Re-audit the final release tree. |
| Performance | Synthetic 32 MiB transfer allocation fell from 71,321,550 to 17,014,203 bytes; 128 MiB from 285,231,142 to 17,016,487 bytes. These are traced Python allocations without network I/O, not throughput or complete RSS measurements. |
| Installed Linux service | Hosted installed-service/privileged-loopback job passed on `5b4ee9c`. Physical Ubuntu interface discovery, authorized-subnet scanning and unattended soak remain open per #241. |
| Installed macOS service | Current candidate still needs installed-host privilege, upgrade/rollback, shutdown, reboot/sleep and soak evidence from an appropriate test host. Do not disturb the existing SSH-forwarded listener on local port 9000. |
| Release metadata and distribution | Candidate `v2026.10.25` is selected and numeric Mac metadata is validated. Final-version artifact checks, signing/distribution requirements and rollback qualification remain open. No release tag or publication yet. |

## Verification checkpoints

Integrated local checks on the `632e40d` implementation passed 860 tests (37
skipped) and 32 browser/PDF regressions, including the Archive recovery browser
test now explicitly included in hosted CI. Actual Mac packaged smoke passed
after numeric bundle-version assertions were added. The candidate `v2026.10.25`
also passed 860 tests and actual Mac packaged smoke locally. Three additional
Drive malformed/early-completion regressions passed in the focused 133-test
Drive/auth group; final integrated/current-head checks remain required.

Hosted Mac packaged smoke on `632e40d` failed once with a startup health timeout;
the captured runtime spent 60 seconds on a public traceroute. The packaged
startup/network isolation is being corrected and requires a fresh hosted pass.
This failure is not dismissed because the local package smoke succeeded.

All four hosted jobs passed on `7dab739376bcb910da43929e4e12000e21dbe667` in
[run 40234377360](https://github.com/techmore/TM-NmapUI/actions/runs/40234377360):
832 unit/contract tests (36 skipped), 31 browser/PDF tests, Mac packaged smoke
(1 passed), staged Ubuntu checks (31 passed, 2 skipped), privileged loopback
smoke and installed systemd lifecycle. Later native and history edits still
require a fresh integrated run and current-head hosted CI.

The pushed `5b4ee9c` has passing unit/contract and browser checks in
[push CI](https://github.com/techmore/TM-NmapUI/actions/runs/40233713325) and
[PR CI](https://github.com/techmore/TM-NmapUI/actions/runs/40233717942).
Its packaged Mac job passed in the push run and its installed Ubuntu service
job passed in the PR run. At this checkpoint duplicate runs were still finishing;
record terminal current-head runs before release. CI now groups push/PR work by
source repository and branch so superseded candidate checks can be cancelled.

The first isolated full-suite attempt found two test assumptions: a hardcoded
`data/scans` directory despite `NMAPUI_DATA_DIR`, and an outdated runtime-store
stub missing `job_type`. Both were corrected without relaxing production path
containment or typed persisted-job filtering. A new integrated full-suite run
must verify all subsequent native and web edits together.

Release completion requires current evidence for every applicable row above and
the chosen scope in `docs/guides/RELEASE_CHECKLIST.md`. Open or indirect evidence
remains open; merge state alone is not deployment or acceptance.
