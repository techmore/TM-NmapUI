# Disposable macOS installed-service qualification

This harness may provision **only a new GitHub-hosted macOS arm64 VM** in the
explicit `codex/macos-installed-qualification-2026-10-25` workflow. It has no
local override. Do not run its provisioning, builds, installer, or privileged
commands on a developer's Mac. `--plan` and the unit tests are unprivileged and
do not execute those operations.

The first hosted attempt (`40245175016`) refused `/usr/local/bin` before any
provisioning write. The diagnostic-only phase completed with the provisioning step skipped. The
current hardcoded phase is **lifecycle**, enabled after review of that evidence
and the bounded two-directory preparation below. A read-only diagnostic
records exact ancestor owner/mode/flags/ACLs and immediate child metadata/hashes
in the workflow workspace. It performs no sudo, build, install, chown, chmod,
or service action. Inventory run `40245362133` completed with provisioning skipped. It found only
`/usr/local/bin` and `/usr/local/share` unprotected: runner UID 501/admin GID 80,
0775, ordinary directories with no ACL/xattr/flags. The implemented preparation
accepts exactly that observed shape, with no Intel Homebrew locations present,
and changes only those two directory inodes to root:wheel 0755 through bound
`O_NOFOLLOW` descriptors. Before/after receipts must prove all immediate child
bytes, owners, modes and symlinks unchanged, and `/opt/homebrew` unchanged.
All production validators still run unchanged after that preparation. The
concrete implementation and stubbed tests were reviewed before enabling the
next disposable lifecycle attempt. No installed gate is claimed until its
actual receipts pass.

The workflow is restricted to the named repository and branch; it never runs
for PR events. Pushing that reviewed branch explicitly starts qualification.
A later manual dispatch also requires the disposable-install confirmation.
The initial runtime pin is `0e7d22ed8f60ea325dd6cbc77192ea9ff64340b9`; the harness
checkout and runtime checkout are distinct. Receipt identities record both
immutable commits. No runtime source or installer is patched to accept tests.

Before the first write, the harness refuses any existing NmapUI system label,
managed release/state/log/assets, plist, wrapper, helper, sudoers entry,
qualification prefix, or planned tool symlink. Uninspectable launchd status
fails closed. Other existing ancestors must already be root-owned and non-writable
by other users. The only preparation exception is the two generic directory
inodes described above; the harness does not take over a Homebrew prefix or
alter any existing child toolchain file. A port is allocated on loopback and checked again before
configuration and by the production installer.

Pinned upstream sources and SHA256 provenance are in
`macos_qualification_sources.json`. Python's official Sigstore digest and
OpenSSL/Nmap published digests were compared with downloaded archive bytes.
libpcap and arp-scan publish upstream archives without SHA256 sidecars; their
manifest checksums were computed from those official HTTPS release downloads.
No PGP or Sigstore signature verification is claimed. Every VM download must
match the committed digest before extraction. All upstream licenses, including
Nmap's NPSL and bundled library notices, are retained with the receipts.

CPython, static OpenSSL, libpcap, arp-scan and Nmap are built inside the new
protected `/Library/NmapUIQualification` prefix. Nmap retains TLS, SSH, Lua/NSE,
raw capture and its complete script/data tree. Only ancillary Zenmap/Ndiff are
omitted. The unchanged production validators check tool paths, ancestors,
transitive absolute dylibs, `/usr/bin/python3` (the separate helper interpreter),
and the full Nmap data tree. A supplementary audit protects the complete base
Python/stdlib/venv and recursively resolves Python extension/wheel libraries,
including valid `@loader_path` and resolved rpaths. It rejects writable or
unresolvable dependency paths and does not weaken the tool validators.

The real installer runs in the system launchd domain as root with strict HTTP
and Socket.IO auth, private generated credentials, an owned alternate port,
and optional network fingerprint/update/Vulners egress disabled. It installs
real Chromium for the existing authenticated browser/session/WebSocket test.
No Google authorization, LAN discovery, GUI app launch or signing step occurs.

The standalone SYN proof scans exactly one owned `127.0.0.1` listener port and
retains Nmap XML showing it open. The separate actual API proof starts the
canonical quick workflow against only `127.0.0.1`, suppressing ARP using the
existing scan-only setting. That workflow also performs the canonical service
scan of loopback ports: its original XML chunks must reassemble with matching
length/SHA256, one loopback host, successful completion and SYN technique.
These are distinct receipts; neither substitutes a fake scanner or handler.

Lifecycle assertions cover protected artifacts/release identity and root UID,
strict HTTP/token-only socket rejection and positive browser/session access,
real API job identity/completion/XML, launchd respawn after SIGKILL with SQLite
interruption recovery, upgrade, rollback, failed upgrade and failed rollback
restoration, then uninstall with unchanged credentials/data/releases. Cleanup
requires this job's protected ownership markers and the production installed
artifact validators; it does not stop an unowned service. The VM disposal also
removes provisioned tools, which the service uninstaller deliberately retains.

Artifacts contain structured sanitized receipts, tool/dependency inventories,
loopback scan XML and licenses. Credentials and raw private service state/logs
are not uploaded. A successful job is disposable-VM evidence only. Reboot,
physical interface discovery, unattended soak, developer signing,
notarization and real OAuth remain untested.

Local validation:

```sh
python -m pytest -q tests/test_macos_installed_qualification.py tests/test_stage_runtime.py tests/test_daemon_installer.py
python scripts/ci/macos_installed_qualification.py --plan
```

These commands never invoke provisioning or a real installer.
