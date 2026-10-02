# Splicore Phase 9 Distribution & Service Foundation Report

- Documentation status: Historical
- Audience: Maintainers, distribution reviewers and future integration authors
- Last reviewed: 2026-10-02
- Owner: Project maintainers
- Responsibility: Phase 9 implementation acceptance and qualification boundaries.
- Lifecycle: Acceptance snapshot; subsequent phases use their own reports.

## Baseline

Phase 8 Freeze: `bd141f98e28d9499a88fe610ba3fc49aca48bf14`.
Branch: `codex/phase-9-distribution-service-foundation`. HEAD and main remain at
that commit. Entry working tree was clean; the Phase 9 implementation is now
unstaged. No protocol functionality or upstream runtime files changed.
Historical Phase 0–8 reports and SQL migrations 0001–0004 are unchanged.

Evidence root: `D:\splicore-validation\phase9-20261002`.
Native isolated-service evidence: `/root/splicore-p9-20261002/service-gate-review`;
bounded copies are under the Windows evidence root's `service-gate-review`.
Earlier successful campaigns and diagnostic failures remain available separately.
Final package identity and SHA256 are recorded in `final-a2/update.json`,
`final-repeat2/update.json` and `final-b2/update.json`; package inspection is in
`inspection-final-a2.json`. These files remain outside the repository.

## Product Layout

| Purpose | Installed path |
| --- | --- |
| Binary | `/usr/local/bin/splicore` |
| Config | `/etc/splicore/splicore.yaml` |
| Receipt / ownership | `/etc/splicore/install.json`, `.owned` |
| State | `/var/lib/splicore/` |
| Database | `/var/lib/splicore/state.db` |
| Vault key | `/var/lib/splicore/master.key` |
| Runtime / API UDS | `/run/splicore/`, `/run/splicore/splicore.sock` |
| Logs | journald |
| Engines | `/var/lib/splicore/engines/xray-artifact/` |
| Upgrade backups | `/var/lib/splicore-upgrades/` |

The existing `state.db` name is retained rather than introducing a second DB.
No permanent product data depends on `/root`, temporary paths or the caller's
working directory. External qualification fixtures are disposable test data.

## Service User

User: `splicore`. Group: `splicore`. Dedicated system identity, non-login shell,
no automatically created home. Root performs installation; the daemon runs as
the dedicated non-root UID. Capabilities: `CAP_NET_BIND_SERVICE` only, inherited
by the owned Xray child. No CAP_NET_ADMIN or installer firewall changes.
The installed gate checks the actual daemon UID and effective capability mask.

## systemd

Unit: [splicore.service](../../distribution/splicore.service), installed as
`/etc/systemd/system/splicore.service`. One Type=notify unit owns every listener;
there are no per-protocol, Xray or mita units.

Start: initialize protected state, recover committed runtimes, send READY.
Stop: SIGTERM invokes existing graceful shutdown; a 30-second deadline permits
final cgroup cleanup. Restart: restored SQLite generation and traffic PASS.
Reload: unsupported; bootstrap changes require restart.
Status, doctor and API health PASS. Crash recovery uses Restart=on-failure and
bounded start limits; transient runtime files are removed between generations.

Hardening: NoNewPrivileges, PrivateTmp, ProtectSystem=strict, ProtectHome,
ProtectKernelTunables/Modules/Logs, ProtectControlGroups, restricted address
families, UMask=0077, LimitNOFILE=65536 and minimal capability sets.
KillMode=mixed permits owner shutdown followed by cgroup cleanup.
Each option's reason is documented in [operations](../OPERATIONS.md).
Low-port TCP/UDP traffic PASS with the unprivileged-port threshold at 1024.

## Bootstrap

Config schema: 1. [Bootstrap](../../distribution/splicore.yaml) carries state,
runtime/API and optional external engine paths, plus process logging settings.
SQLite remains the account/inbound/credential authority.

First start: PASS from absent state/DB/key. Existing migrations initialize schema4;
no real proxy accounts or example listeners are created. A master key is generated
only when both DB and key are absent. Existing DB without its original key rejects.
Permissions are checked before use; sensitive files and directories stay private.

## Packaging

Format: versioned local tar.gz. Development package A is `0.0.0-dev`, B is
`0.0.0-dev.1`; neither is a release. Artifacts:

- amd64: Linux package and actual installed-service runtime PASS.
- arm64: Linux package build PASS; runtime NOT QUALIFIED.
- Windows: amd64 executable build/tests PASS; production service NOT QUALIFIED.
- Source: complete checkout source archive with per-file SOURCE_PROVENANCE.json.

Packages include the binary, unit, bootstrap, local installer, manifest,
SHA256SUMS, LICENSE/NOTICE, linked dependency licenses and minimal operation docs.
Inspection confirms sorted regular members, safe names/modes, complete inventories
and every hash. Each Linux package contains 81 regular members, including 66
license members. Archive SHA256 lives in external update.json; per-file SHA256
and manifest SHA256 are verified without a self-referential archive digest.

Manifest schema1 records product/version, Git commit, source digest/dirty flag,
fixed build time, Go toolchain, GOOS/GOARCH/tags, config1/DB4/protocol ABI1/API v1,
sing-box v1.14.1 baseline and pinned optional Xray references.

## Build

Reproducibility: PASS, two builds of identical final source produce identical
Linux amd64/arm64 packages, Windows binary, source archive and update metadata.
Go1.26.6, CGO=0, trimpath, buildvcs=false, tags `with_quic,with_utls`, fixed epoch
1790899200. Toolchain, source, platform, version and epoch are explicit inputs.
Version injection uses linker variables; no source generation occurs.

Source dirtied by build: **NO** (`source_changed_by_build:false`). The worktree
already contains authorized uncommitted implementation changes, so artifact
`source_dirty:true` is accurate. This does not claim a clean Git worktree.
See [build entry](../../scripts/splicore-package.py) and inspection evidence.

## Xray Distribution

Strategy: OPTION B, separate pinned optional engine artifact; no bundled engine
and no automatic operator-path substitution. Version: official v26.3.27,
commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`.
Linux amd64 SHA256:
`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.
Windows reference SHA256:
`15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1`.
Local engine installation validates the fixed artifact hash and version.
Linux arm64 Xray remains unqualified and rejects engine installation.
Auto latest download: **NO**. Phase 6 artifact unchanged.

## Mieru

Embedded: **YES**, official v3.38.0 in the existing Native Engine.
External mita: **NO**. No download, extra daemon or separate service.
Distribution smoke confirms both managed TCP and UDP profiles.

## Install

Clean install: **PASS**. First start: **PASS**. Empty DB/listener inventory,
correct schema, dedicated user, canonical paths and healthy UDS API confirmed.
Local archive plus explicit SHA256 is required; no network download occurs.
Preflight checks platform, systemd, ownership, archive bounds and manifest.

Atomic binary install: private root-owned staging, verified provenance, fsync
and same-directory rename. Links, special entries, duplicate/traversal names,
unexpected members and hash/size/mode mismatches reject. Manifest/checksum files
are checked as regular and bounded before reading. Privileged staging rejects
group/other write access. Existing unowned files fail closed.

## Upgrade

Normal A to B: **PASS**, logical database contents, key and bootstrap preserved;
installed traffic remains healthy. DB backup: **PASS**, stopped service plus
exclusive installation lock and coherent SQLite VACUUM INTO snapshot, rather
than a live WAL file copy.

Migration: existing schema4 startup **PASS**. Failure rollback: **PASS**, a private
external source copy advertises schema5 and runs DDL followed by an intentional
SQL failure. Original migrations are untouched. Exact logical table hashes,
integrity/FKs, binary/unit/config/key/receipt and old schema4 health are restored.
The installer reports the candidate failure after successful rollback.

Forward-only rollback restores the matching pre-upgrade snapshot; it never
pretends an older binary can downgrade a committed new DB. Updates acknowledged
after the snapshot are not retained on rollback; keep API changes quiet during
maintenance. Backups remain private. Power loss or a killed installer requires
manual recovery from those backups; subsequent inconsistent receipts fail closed.

## Uninstall

Program only: **PASS**. State retained: **PASS**, including matching key/config,
credentials, engine artifacts and service identity. Reinstall: **PASS** with the
same state and restored installed traffic.

Purge: **PASS** with explicit `--purge`, in the disposable environment only.
Path safety: **PASS**, fixed owned trees are validated before removal; symlinks
and same-filesystem bind mounts reject without disrupting healthy service.
Foreign ownership, special files and mount boundaries also reject. Dedicated UID
and root installation lock remain reserved; journald retention remains host-owned.

## Doctor

Result: **PASS**. Installed CLI checks binary/receipt identity, bootstrap/state/DB/
key/runtime/socket/unit permissions, systemd activity, pinned Xray, schema,
health, pending operations, protocol/engine/exporter registries. Output is safe
fixed details and counts; no credentials. SQLite integrity/FKs are separately
verified by the service gate. No full live-response OpenAPI fixture gate is claimed;
the installed Version projection and static contract checks pass.

## Support Bundle

Generated: **PASS**. Automatic upload: **NO**. Secret redaction: **PASS**, blocking.
Fixed projections include validated version, system/schema/registry counts,
doctor, configured booleans, listener classes/statuses, bounded journal summary
and sanitized crash records. Raw config/DB/key/export/Xray JSON/journal MESSAGE/
panic text, real hosts and domain identifiers are excluded.

Every decompressed archive member is scanned against synthetic Snell PSK,
HY2/TUIC/Mieru passwords, VLESS UUID, REALITY private key and API token.
Unit tests inject malicious diagnostics/crash fields; installed tests include
actual generated credentials and prove synthetic secrets entered the unit journal
before scanning the bundle. No secret appears. Output is new/private/no-overwrite.

## Crash Recovery

Splicore parent: SIGKILL of the actual installed MainPID followed by systemd
restart **PASS**. Xray child: original owned children exit, old config artifacts
disappear and two new owned Xray children restore **PASS**. pidfds identify the
original processes; cleanup uses existing Pdeathsig plus unit cgroup ownership.
SQLite: integrity/FKs and committed state **PASS**. Listener duplication:
none; all eight cells pass after recovery without port conflicts.
Unrelated Xray: **UNAFFECTED**, running the same engine executable outside the
service cgroup throughout the crash test.

Exit records retain 16 sanitized version/commit/component/engine/protocol/time/
classification entries; concurrent retention is protected by a narrow flock.
Journald handles log retention; support reads are bounded to 128 summarized entries.
No permanent unbounded product file log was introduced.

## Permissions

| Item | Observed mode / ownership |
| --- | --- |
| Config | 0640, root:splicore |
| DB / vault key | 0600, splicore:splicore |
| State / runtime | 0700, splicore:splicore |
| Xray config / generation | 0600 / 0700, splicore:splicore |
| Support bundle / parent | 0600 / 0700, invoking principal |
| Crash records | 0600, splicore:splicore |
| Upgrade transactions | root-owned private tree |

The installed gate records daemon UID, effective CAP_NET_BIND_SERVICE, threshold
1024 and sensitive modes in permissions.json; focused tests cover private outputs.

## Installed-service Protocol Smoke

| Profile | Listener | Result |
| --- | --- | --- |
| Snell v6 | TCP80 | PASS, TCP/UDP payload |
| HY2 static TLS | UDP443 | PASS, TCP/UDP payload |
| TUIC v5 | UDP444 | PASS, TCP/UDP payload |
| VLESS Native | TCP446 | PASS, plain TCP flow none |
| VLESS Xray | TCP447 | PASS, plain TCP flow none |
| FinalMask/Sudoku | TCP448 | PASS, bounded plain TCP |
| Mieru TCP listener | TCP449 | PASS, TCP/UDP payload |
| Mieru UDP listener | UDP450 | PASS, TCP/UDP payload |

Six stages: initial, restart, crash-recovery, upgrade, rollback and reinstall.
Total: **48/48 PASS**, using installed CLI/API, canonical profile exports and
exact local reference clients. Pinned clients: Mihomo1.19.30, sing-box1.14.1,
Xray26.3.27 and Mieru3.38.0. Source/runtime reference probes alone do not count.
This is packaging regression smoke, not expanded protocol qualification.
Vision, masked UDP and masked TLS/REALITY remain outside accepted support.

## NoBrand Contract

Artifact pinning: exact qualified version, URL and platform with immutable build
identity. Checksum: independently trusted SHA256 metadata. Install/update: local
verified archive via the documented installer. Canonical API/import: existing
protected domain APIs and explicit exports, independent of runtime internals.
Latest auto-follow: **NO**. Stable/beta/nightly qualification is defined for future
use; no channel or update server is published. Real NoBrand source/HEAD/status
and tracked hashes are unchanged.

## Platform

Ubuntu amd64: **PASS**, Ubuntu24.04 WSL2 with existing systemd and actual installed
unit in disposable mount/net/PID/UTS/IPC/cgroup namespaces; only loopback networking.
The lab has a new private filesystem layout, read-only source/system binds and
owned transient-unit cleanup. Host service configuration and WSL settings unchanged.
Linux arm64: **BUILD PASS / RUNTIME NOT QUALIFIED**, including Mieru and optional
Xray qualification. Windows: **BUILD / OWNED TESTS PASS**, no production service
or DACL qualification. SELinux/AppArmor: **NOT CERTIFIED**, never disabled.

## CI

Distribution gate: manual [workflow](../../.github/workflows/splicore-distribution.yml)
for a dedicated disposable self-hosted Linux runner with provisioned offline
toolchain/module/reference fixtures. Includes default race/checkptr, blocking
secret tests, repeated builds/checksums, package verification, real systemd
install/upgrade/failure/restart/uninstall smoke. No existing protocol gate removed.
Workflow is implemented; no remote CI run, artifact upload or publication claimed.

Local regression PASS: full owned Go tests with QUIC/uTLS/Xray integration tags,
default race/checkptr, operations/distribution race `-count=10`, affected shared
`common/adapter/transport` race suites, owned vet and Windows owned tests.
After the final manifest/staging guards, targeted default race and Windows package
tests pass. A first Linux temp-permission failure on the Windows mount is retained
as diagnostic evidence; native Linux temporary directories pass.

## Security

Secrets: blocking allowlist/projection archive tests PASS; raw journals stay private.
Supply chain: fixed modules/toolchain, source provenance, all artifact/per-file
SHA256, bundled attribution/licenses; signatures remain deferred. A checksum
provides integrity relative to trusted metadata, not publisher authentication.
Installer: local inputs, bounded verification, root-owned staging and atomic
replacement. Purge: explicit flag, fixed owned trees and mount/symlink rejection.
No firewall modifications, external scans, production rollout or NoBrand changes.
Docker: **DO NOT QUERY / TOUCH**, no Docker commands or dependency.

## Documentation

Canonical: [installation](../INSTALLATION.md), [upgrade](../UPGRADE.md),
[uninstall](../UNINSTALL.md), [operations](../OPERATIONS.md),
[support bundle](../SUPPORT_BUNDLE.md), [distribution](../DISTRIBUTION.md).
[ADR0021](../adr/0021-linux-local-distribution.md) records the proposed reviewed
design; implementation acceptance does not change ADR approval status.
README and documentation navigation describe the Experimental installable service.
Owned documentation links, metadata and OpenAPI schema/reference checks PASS.
Historical Phase 0–8: **UNCHANGED**.

## Git

Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
HEAD/refs/remotes unchanged; staged files0. Source/build data audit PASS;
all generated artifacts, state, fixtures, logs and caches remain external.
Upstream runtime files changed: **0**. Real NoBrand changes: **0**.

## Deferred

Public release, real NoBrand integration/canary, stable/beta/nightly publication,
signatures, Panel/payment, unified quota/rate, persistent usage, Vision, expanded
mask support, arm64/other distribution runtimes, Windows service/DACLs,
SELinux/AppArmor certification and automatic power-loss installer recovery.

## Final Result

**DISTRIBUTION FOUNDATION READY FOR REVIEW**.
Experimental local service foundation; Phase 9 remains unstaged and unfrozen.

## Blockers

None within the accepted local amd64 distribution foundation scope.
Deferred qualifications above remain required before broader production claims.
