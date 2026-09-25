# Project status — 2026-09-25

## Product direction

The deployment targets are macOS and Ubuntu scanner hosts, with a
cross-platform browser UI. The September 10 remediation plan records one shared
Flask backend; a future native SwiftUI frontend should use that API rather than
duplicate the scan engine. The current Mac product is a Swift menu-bar launcher
around Flask. macOS has a LaunchDaemon installer. Ubuntu can run the app
manually, but does not yet have a supported installer, `systemd` unit,
production privilege model or host-level validation. The older `swift-native`
branch contains substantial native UI and its own scan, report, privilege-helper
and scheduling implementation. Reconcile those designs before integrating it;
native/web parity is not yet verified.

## Where work stopped

- `main` / `origin/main`: `2828bd36`, PR #239 merged August 24. Latest CI passed
  unit/contract, browser regression and packaged Mac smoke jobs:
  https://github.com/techmore/TM-NmapUI/actions/runs/32763844258
- Draft PR #240 is at remote commit `ec842d56`, which passes all three hosted
  checks (unit/contract, browser, packaged Mac smoke):
  https://github.com/techmore/TM-NmapUI/actions/runs/36057099197
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
- PR #240 remains a draft while real privileged scan, reboot/sleep, crash and
  unattended soak verification are outstanding.
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
Follow-up validation: full suite **405 passed, 9 skipped**; browser regressions
**8 passed**; packaged Mac smoke **1 passed in 52.63s**. Both installer dry runs
passed plist, sudoers, wrapper and helper checks. The app also passed live
health, login and socket-token checks in an isolated process; authenticated
remote token access now has a dedicated unit test.

Release blockers: privilege isolation is **implemented but optional**. The
installer now stages root-owned assets and ships a validating helper
(`packaging/macos/nmapui-privileged-scanner`) that sudoers can grant instead of
`nmap` itself, and `--user <name>` runs the backend as a non-root account. Per
the September 12 platform decision, **root remains the default**: this platform
treats root as the goal, so the daemon installs as root with no sudoers
dependency and no extra decision. That keeps the earlier residual risk
deliberately accepted — the web backend is root, mitigated by loopback-only
  binding by default, enforced sign-in and the removed local-trust bypass.

What remains unverified is everything that needs root: **no production
LaunchDaemon has been installed, rebooted, killed or soaked**, and neither mode
has executed a live privileged scan end to end. The unprivileged UI scan of
loopback completed but found no hosts; production discovery needs the privileged
service. The in-process reaper still cannot clean up children after `SIGKILL`.
Keep PR #240 in draft pending those checks.

1. **Finish and integrate unattended baseline.** Review the local branch and run
   browser/packaged checks against this exact revision before merging. Complete
   reboot/sleep/crash verification and remaining security/privilege validation.
2. **Ubuntu scanner-host deployment.** macOS and Ubuntu are the scanner-host
   targets; browser clients can run cross-platform. The app runs manually on
   Ubuntu, but a supported installer, `systemd` supervision, privileged scanning
   model, upgrade/uninstall path and host validation remain open in
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
   #163 (data lifecycle) and #164 (security). Remaining audit work includes DST,
   retention, secrets/CSP review, safe upgrades, and duplicate-install handling. Remote Mac
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
`CLAUDE_WORK_PLAN.md` remains historical. Root AGENTS has current navigation
above its generated map; BUILDING, SETUP, release checklist and repository
layout now describe the supported Flask/Swift path.
Do not remove legacy assets wholesale: verify Flask/static/report dependencies
first. Keep the rollback archive intact; migrating it to release storage can be
done separately without rewriting Git history.
