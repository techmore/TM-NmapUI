# Release preflight — October 25, 2026

Candidate version: `v2026.10.25`. Latest published release:
[`v2026.4.26.4.00`](https://github.com/techmore/TM-NmapUI/releases/tag/v2026.4.26.4.00).
No new tag, public release, installed service or account authorization is
created by this preflight. Preserve the known-good alpha tag and existing
runtime data. This assessment follows the owner's request to inspect branches,
issues and the Actions queue before the next release.

## Branch and merge assessment

Snapshot of the nine remote branches, with `main` at `bec25d94`:

| Branch / PR | Reviewed source | Disposition |
| --- | --- | --- |
| `main` | `bec25d94` | Canonical Flask/backend and Mac launcher release base. |
| `claude/scan-pause-resume` | `37fc3212` | Already an ancestor of main; zero unique commits. No merge needed. |
| `claude/vlan-detection` | `699a9721` | Already an ancestor of main; zero unique commits. No merge needed. |
| `codex/repository-audit-2026-10-25`, [#254](https://github.com/techmore/TM-NmapUI/pull/254) | `a8f58fc2` | Primary next-release candidate. Latest hosted run passed unit, Ubuntu and Mac packaging; three browser cases failed. This preflight repairs the reproduced test startup race; fresh hosted checks are required. Keep the broader release acceptance gates open. |
| `swift-native` | `01e6d892` | 29 commits absent from main, with 80 main commits absent from it. Preserve separately; merging this directly would combine independent scanner/scheduler implementations without established parity. |
| `codex/swift-native-helper-stamp-2026-10-25`, [#255](https://github.com/techmore/TM-NmapUI/pull/255) | `dcd13230` | First merge candidate into `swift-native`: all four hosted jobs passed in [40240040149](https://github.com/techmore/TM-NmapUI/actions/runs/40240040149). Packaging/test evidence does not establish installed-helper or distribution acceptance. |
| `codex/native-drive-hardening-2026-10-25`, [#256](https://github.com/techmore/TM-NmapUI/pull/256) | `b5ce036b` | Next native merge candidate, stacked on #255; all four hosted jobs passed in [40241893951](https://github.com/techmore/TM-NmapUI/actions/runs/40241893951). Real-account Drive qualification remains open. |
| `codex/native-shared-engine-library-2026-10-25`, [#257](https://github.com/techmore/TM-NmapUI/pull/257) | `375be6cd` | Hold for hosted fixture qualification. Earlier heads failed readiness deadlines. Current [40243950317](https://github.com/techmore/TM-NmapUI/actions/runs/40243950317) was still running at inspection. Read-only shared-library integration does not establish scan/schedule execution parity. |
| `codex/native-shared-controls-2026-10-25`, [#258](https://github.com/techmore/TM-NmapUI/pull/258) | `c9b9e993` | Hold behind #257 and its own native checks in [40243514042](https://github.com/techmore/TM-NmapUI/actions/runs/40243514042). Adapter/reducer work is not yet routed through native UI controls. |

All five PRs were drafts at inspection. The native merge order is #255, #256,
#257, #258, retaining dependent commits and rerunning checks after base changes.
Passing tests identify review candidates; no draft has been marked ready or
merged by this assessment. Branches and rollback refs remain intact.

## Nine open issues

| Issue | Release disposition |
| --- | --- |
| [#241 Ubuntu scanner host](https://github.com/techmore/TM-NmapUI/issues/241) | Installer/systemd and disposable-VM lifecycle evidence exist; physical-interface discovery and unattended soak still block a production-support claim. The issue's original “no installer” description is historical. |
| [#237 helper authorization](https://github.com/techmore/TM-NmapUI/issues/237) | Native implementation and stamp repairs exist; installed authorization, stable distribution identity and update/lifecycle acceptance remain open. |
| [#226 lifecycle extraction](https://github.com/techmore/TM-NmapUI/issues/226) | Implementation is present on the native branch. Verify its acceptance commands and chosen final native behavior before closure; it is not yet integrated into main. |
| [#223 SwiftUI migration](https://github.com/techmore/TM-NmapUI/issues/223) | Keep open for shared-engine UI/execution and data/scheduler ownership parity. It does not block a clearly scoped Flask/launcher candidate. |
| [#164 security hardening](https://github.com/techmore/TM-NmapUI/issues/164) | Auth/origin/secret-storage fixes have coverage. Retain the broader initiative; do not equate dependency audits with full security acceptance. |
| [#163 runtime data lifecycle](https://github.com/techmore/TM-NmapUI/issues/163) | Runtime paths, SQLite recovery and retention controls exist; saved-artifact retention and installed-host disk-growth/soak evidence remain open. |
| [#106 HTML/PDF parity](https://github.com/techmore/TM-NmapUI/issues/106) | Synthetic and loopback samples have automated coverage; representative authorized production-scan reports still need final layout acceptance. |
| [#14 screenshots](https://github.com/techmore/TM-NmapUI/issues/14) | Optional enrichment follow-up; keep outside required core scan completion. Do not claim its complete storage/UI acceptance. |
| [#4 remote sync](https://github.com/techmore/TM-NmapUI/issues/4) | Optional export/sync initiative; retain destination, retry and operational acceptance work. Native Drive transport tests do not close this generic sync scope. |

No issues were closed or rewritten from implementation presence alone.

## Actions queue and repairs

The candidate workflow triggered full checks on both `codex/**` pushes and PR
updates. Shared concurrency eventually cancelled duplicate push runs, but they
could allocate runners, install dependencies and delay their PR counterpart
before cancellation completed. At inspection only the two current native PR
runs above remained active; there was no obsolete live run to cancel safely.
Their native test step was doing fixture qualification, rather than waiting
for an available runner. Existing native jobs already have a 20-minute bound.

This preflight changes the canonical workflow to:

- Run feature changes through PRs, including drafts. Push checks remain on
  `main`, `dev` and `swift-native`; manual dispatch supports pre-PR checks.
- Keep source-branch concurrency so newer revisions supersede obsolete work.
- Use read-only repository permissions and explicit 15-minute unit/browser,
  20-minute Mac packaging and 30-minute installed Ubuntu job limits.

These workflow changes take effect where this commit is integrated. The native
stack has its own divergent workflow and needs the same trigger policy carried
forward separately; this preflight does not claim to have changed those heads.

The failing browser regression injected jobs outside the real registry while
bootstrap's `get_job_status` response was still in flight. The real idle snapshot
could reset the injected state before the first assertion. Reproduced locally
before the repair (one failure, three passes). The test now waits for the real
initial handler to finish and for an acknowledged snapshot over Socket.IO,
with bounded waits and all stale-event assertions retained. No production
status semantics or test assertions were relaxed.

Local Python 3.11 validation of this preflight passed 890 unit/contract tests
(44 explicitly gated/platform skips) and the full 39-test CI browser/PDF group.
The four previously racy terminal-event cases also passed as a focused group.
Workflow YAML, trigger/permission/job-bound assertions and `git diff --check`
passed. Hosted qualification of this new commit is required before integration.

## Release sequence

1. Integrate this preflight into #254 and require all four checks on its new
   source. Select the final immutable engine commit after qualification;
   `911f83d8` is an earlier downstream API checkpoint, not the final release.
2. Refresh and requalify the elementary and Daedalus engine pins against that
   exact source; prior pinned integrations cannot prove later changes.
3. Complete the applicable installed-host, report, Google account and
   signing/notarization gates in the [release ledger](RELEASE_READINESS_2026-10-25.md)
   and [checklist](../guides/RELEASE_CHECKLIST.md), recording any explicitly
   narrowed candidate scope. Keep SwiftUI preview scope distinct until parity.
4. Build final artifacts from the qualified clean tree, verify numeric Mac
   versions/source metadata and checksums, then prepare release notes/assets
   against that exact source. Public tagging/publication remains pending.
