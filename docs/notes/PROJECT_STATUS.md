# Project status — 2026-09-11

## Product direction

The intended destination is a native macOS experience and a cross-platform web
experience. The September 10 remediation plan records one shared Flask backend;
a future native SwiftUI frontend should use that API rather than duplicate the
scan engine. The current Mac product is a Swift menu-bar launcher around Flask.
The older `swift-native` branch contains substantial native UI and its own scan,
report, privilege-helper and scheduling implementation. Reconcile those designs
before integrating it; native/web parity is not yet verified.

## Where work stopped

- `main` / `origin/main`: `2828bd36`, PR #239 merged August 24. Latest CI passed
  unit/contract, browser regression and packaged Mac smoke jobs:
  https://github.com/techmore/TM-NmapUI/actions/runs/32763844258
- Current `fix/unattended-operation`: `19dd4457`, 11 commits ahead of main,
  none behind, no remote branch or PR. Includes two preservation/documentation
  commits and nine unattended-operation/documentation commits. Implemented work
  includes actual scheduled execution, degraded startup, daemon installation,
  prompt-free privilege paths, authentication, interrupted-job recovery,
  missed-schedule catch-up, and Flask installation documentation.
- Verification today: `.venv/bin/python -m pytest -q` → **373 passed, 8 skipped**.
  This does not establish real reboot, prolonged unattended operation, native UI
  parity or Windows support. Browser and packaged tests are gated in this run.
- `swift-native`: 29 commits unique relative to main; main has 10 absent from it.
  Keep for selective integration and native parity review, not a blind merge.
- `alpha/mac-known-good-2026-09-07-1040` and tag
  `alpha-mac-known-good-2026.09.07-1040`: preserve as the intentional rollback.
- `claude/quirky-torvalds`: keep pending review. `git cherry origin/main` reports
  20 patch-unique commits; it is not proven redundant.

## Cleanup completed

- Removed local and remote `fix/zombie-jobs-disable-scan-buttons` after verifying
  its tip is an ancestor of main (merged PR #238).
- Fetched/pruned the already-deleted remote runtime-contract branch.
- Pruned only the dead `/private/tmp/nmapui-swift` worktree registration; the
  `swift-native` branch remains intact.
- Closed #230: both its browser-CI and runtime-contract acceptance criteria are
  supported by the successful main CI run above.
- No open pull requests were present at review time.

## Backlog organization

1. **Finish and integrate unattended baseline.** Review the local branch and run
   browser/packaged checks against this exact revision before merging. Complete
   reboot/sleep/crash verification and remaining security/privilege validation.
2. **Cross-platform web distribution.** Directly install the shared Flask backend
   on the scanner host and use browser clients. Per the September 11 user
   decision, container networking is unsuitable for the intended deployment;
   container packaging is retired from the active roadmap. Verify native Linux
   installation/service supervision and explicitly define whether Windows means
   browser access only or a local scanner host. Existing container files remain
   historical references to the legacy Node runtime.
3. **Native Mac frontend (#223).** Inventory reusable SwiftUI screens and connect
   them to the shared backend. Keep #226 (lifecycle extraction) and #237 (helper
   authorization) open: their implementation appears on the unmerged Swift line,
   not established in the canonical product.
4. **Reports.** #106 and #160 overlap. Recommend retaining detailed #106 as the
   canonical initiative and closing #160 as duplicate after preserving any unique
   requirements. Existing PDF fixes do not prove full visual parity.
5. **Operational follow-through.** Retain #161 (multi-tab state), #163 (data
   lifecycle), #164 (security). Remaining audit work includes DST, retention,
   secrets/CSP review, safe upgrades, and duplicate-install handling. Remote Mac
   management through DigitalOcean is recorded in the preserved release notes,
   but is not verified implemented.
6. **Later features.** #4 remote sync, #10 pause/resume, #14 GoWitness and #31 VLAN
   should be evaluated against the shared backend before being declared done;
   an implementation in a legacy/native branch is insufficient.

## Documentation to reconcile

Use README and the September 10 audit's phase status as current context. The
audit's original findings and some introductory notes describe earlier code;
do not treat every finding as still unresolved. Its status says “Draft” despite
later locked decisions and implementation updates. The January
`CLAUDE_WORK_PLAN.md`, root AGENTS code map and BUILDING.md are stale.
Do not remove legacy assets wholesale: verify Flask/static/report dependencies
first. Keep the rollback archive intact; migrating it to release storage can be
done separately without rewriting Git history.
