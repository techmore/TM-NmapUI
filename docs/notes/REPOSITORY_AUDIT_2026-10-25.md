# Repository audit — October 25, 2026

## Repository and upstream

Audited the clean local checkout at `ead49881`, fetched/pruned origin, and
fast-forwarded `main` to `bec25d941ef0e79913d42d94ac758b7fc5dd2325`.
GitHub reports `techmore/TM-NmapUI` is not a fork and has no parent/source
repository. Origin is the canonical upstream; no additional upstream remote
is configured. Enumerated both public forks and compared their default branches:
`aszgym871-create/TM-NmapUI` is 70 commits behind, with no unique commits;
`macxwhale/TM-NmapUI` is four commits ahead with Docker/GoWitness packaging
changes. Those changes are excluded because this project's deployment plan
explicitly retires container packaging in favor of direct scanner-host networking.
The 22 incoming commits include merged pause/resume (#252),
passive VLAN analysis (#253), accessibility fixes (#250), npm security patches
(#248, #251), asset inventory exports and the elementary repository split (#249).

[CI for that upstream revision](https://github.com/techmore/TM-NmapUI/actions/runs/39768960864)
passed. This is evidence for the upstream revision, not hosted validation of
the additional local dependency/CI changes in this audit.

## Branches

No branches or rollback tags were deleted. Remote-tracking references to
already-deleted remote branches were pruned by fetch.

| Branch | Finding and disposition |
| --- | --- |
| `main` | Current with `origin/main` at `bec25d94` before audit edits. |
| `alpha/mac-known-good-2026-09-07-1040` | Local branch and known-good tag preserved; its remote branch was already deleted. |
| `fix/unattended-operation` | Tip `0fc510e2` is an ancestor of main; #240 merged October 12. Local branch retained; remote was already deleted. |
| `origin/claude/scan-pause-resume` | Tip `37fc3212` is merged into main. Retained. |
| `origin/claude/vlan-detection` | Tip `699a9721` is merged into main. Retained. |
| `claude/quirky-torvalds` | 20 patch-unique commits according to `git cherry main`; retain for selective review. Includes superseded runtime work plus Drive/API/interface changes requiring separate comparison. |
| `swift-native` | Main has 80 commits absent from it; it has 29 absent from main. Native lifecycle/helper/UI work remains separate; retain for parity review rather than merging duplicate scanner/runtime implementations. |

## Issues and release gates

GitHub returned nine open issues and zero open PRs. Issue state was read only;
this audit does not close issues or publish comments.

| Issues | Current disposition |
| --- | --- |
| #241 Ubuntu scanner host | Installer and disposable-VM coverage exist. Physical-interface discovery and unattended soak remain release gates. |
| #223, #226, #237 native macOS | Native UI, lifecycle extraction and helper authorization require selective integration and installed-host validation. |
| #163 runtime lifecycle | DB/path/retention implementations exist; saved artifact retention and host disk-growth behavior remain open. |
| #164 security | Auth, origin checks, encrypted settings and pinned dependency audits exist; broader installed-host/security review remains open. |
| #106 report parity | Existing HTML/PDF regressions help; production scan samples and layout review remain open. |
| #14 web screenshots | Requires a separate enrichment workflow and storage/UI design. |
| #4 remote sync | Requires completion of the optional export destination, retry and status model. |

The status document still described #240 as draft and main as `2828bd36`.
Added a current audit entry and explicitly labeled the September checkpoint as
historical so those old statements are not interpreted as present state.

## Applied dependency changes

| Dependency | Before | After |
| --- | --- | --- |
| Legacy Node `body-parser` | 1.20.8 | 1.20.9 |
| Flask-SocketIO | 5.6.1 | 5.7.0 |
| Flask-Cors | 6.0.2 | 6.0.5 |
| cryptography | 50.0.1 | 50.0.2 |
| Playwright | 1.58.0 | 1.64.1 |
| lucide | 1.47.0 | 1.61.0 |
| socket.io-client | 4.8.3 | 4.8.4 |
| Tailwind CSS | 3.4.17 | 3.4.19 |

The legacy lockfile had one high-severity advisory,
[GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828),
for denial of service when parsing compressed requests. Patched the lockfile
without changing the legacy runtime architecture. Added CI audits for both
JavaScript lockfiles alongside the existing Python audit. Rebuilt committed
CSS and vendor JavaScript from the updated exact pins.

Tailwind 4.3.3 is available, but its major-version migration is deferred because
the current build uses Tailwind 3 configuration/CLI and embedded report styles.
The Python outdated listing also includes transitive and development packages
installed in the shared local environment; it is not a requirements lockfile.
A clean Python 3.11 install resolves the current compatible transitive versions.

## Bundled Vulners source

Compared the active bundled `nmap-vulners/vulners.nse` with
[`vulnersCom/nmap-vulners`](https://github.com/vulnersCom/nmap-vulners)
at repository HEAD `47c73ec5addcaad04904f233c6f85dfe76c58ed5`.
The new script is a substantial behavioral change: it classifies itself as
`intrusive`, downloads a fingerprint catalog from GitHub at scan time, probes
HTTP paths, and changes the finding output. The bundled version classifies
itself as `safe` and performs software/CPE lookups. Retained the bundled source:
replacement needs explicit probe/egress policy, Nmap compatibility, report XML
contract tests and installed-service verification. This is a tracked upstream
integration gap, not a routine package patch.

## Validation

- Clean Python 3.11 environment, final requirements: **763 passed, 33 skipped**
  (`pytest -q`, 38.30 seconds). Skips include explicitly gated browser,
  packaged, privileged and installed-service checks.
- Current Playwright 1.64.1 / Chromium 156 browser and PDF regression group:
  **28 passed** (20.87 seconds). Covers live/replayed job state, pause/resume,
  accessibility, cancellation, origin/CSP defenses and PDF resource controls.
- Earlier Python 3.14 run before the Playwright bump: **763 passed, 33 skipped**.
- macOS packaged-app smoke: **1 passed** (47.52 seconds), including bundle
  build, authenticated runtime access, Unicode credentials and DB migration.
- Final `pip-audit -r requirements.txt` and both `npm audit --package-lock-only`
  checks: **zero known vulnerabilities**. Clean environment `pip check` passes.
- Clean `npm ci --prefix scripts/ui-assets` and asset rebuild pass. SHA-256
  checksums of the CSS, Lucide and Socket.IO assets are identical across the
  initial updated build and the clean-install rebuild.
- `git diff --check` passes.

The initial restricted-sandbox unit attempt failed on denied socket binding and
runtime log access; rerunning with socket access and isolated data resolved all
four failures. The initial browser attempt lacked the pinned Chromium binary;
the final run installed and used the browser corresponding to current Playwright.
These were test-environment failures, not application changes.

No physical-host privileged scans, service installs, reboot or unattended soak
were performed in this audit. Hosted CI must still validate the audit commit.
