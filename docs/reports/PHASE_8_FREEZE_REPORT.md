# Splicore Phase 8 Freeze Report

- Documentation status: Historical
- Audience: Maintainers and checkpoint reviewers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Record the authorized Phase 8 local freeze, evidence and bounded qualification.
- Lifecycle: Preserve this checkpoint; subsequent implementation requires separate scope and evidence.

## Baseline

Phase 7: `ca48d8429abb21fcaf7ee21d68e37d1ec5d6ec4d`.
Entry branch: `codex/phase-8-mieru-native-integration`; HEAD/main both Phase 7.
Index empty, no unknown commits or changes, no origin. The maintainer authorized
explicit staging, exactly one Phase 8 commit, main fast-forward and creation of
`codex/phase-9-distribution-service-foundation`, followed by stopping.

The [integration report](PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md) retains the
pre-freeze **MIERU NATIVE INTEGRATION READY FOR REVIEW** snapshot, including its
then-uncommitted Git state and retained development failures. This report records
the subsequent freeze. Phase 0–7 historical reports/requirements remain unchanged.

## Mieru

Status: **Experimental**.
Reference: [official enfein/mieru](https://github.com/enfein/mieru).
Version/tag: **v3.38.0**.
Full commit: `b961978c3be9dd26b94158487c760858e19d1db2`.
Go module: `github.com/enfein/mieru/v3`; upstream Go requirement 1.20.
License: GPL-3.0-or-later, unchanged official LICENSE/copyright.

## Native Integration

Protocol: **mieru**, wire key **mieru / 2 / base**. Engine: **native**.
External mita required: **NO**. No permanent child service or independent daemon.
Official server Go API is dispatched by the existing Native Engine compiler map.
No independent mieru-native ProtocolID or new EngineID.
Official source modified: **0**. Vendored adaptation: **NONE**.
Copied implementation: **NONE**. Wire reimplementation: **0**.

## Capabilities

| Capability | Frozen disposition |
|---|---|
| TCP | PASS; payload over TCP/UDP underlays |
| UDP | PASS; payload over TCP/UDP underlays |
| IPv4 / IPv6 / domain | PASS on Linux amd64 loopback |
| MultiUser | PASS; 1–16 canonical users, Alice/Bob runtime qualified |
| Stats | Inbound/Binding authenticated payload bytes and routed session counts |
| Account persistent aggregates | DEFERRED |
| Quota / Speed / MaxSessions | Not exposed; strict requests reject, metadata_only unenforced |
| HotUserUpdate / HotReload | False; affected inbound reconstructed for Binding changes |
| Multiple inbounds | PASS; listener/auth/credential/stats/shutdown isolation |
| Nondefault MTU/multiplex | Canonical/export bounds tested; full runtime qualification deferred |

Qualified runtime matrix uses MTU1500/default multiplex/default traffic pattern.
Routing is bounded direct TCP/UDP with local DNS, without a configurable egress
policy in RuntimeIntent. No richer sing-box routing-rule qualification is claimed.
Session statistics do not establish a persistent Account Usage API.

## Lifecycle

Create/Start/Health/Stop/Restart/Recovery: **PASS**.
10x: **PASS**, each TCP and UDP underlay, two simultaneous inbounds and two users.
Each cycle sends 16 concurrent mixed transfers and 4 MiB integrity traffic.
Stop A preserves subsequent B traffic; exact stable stats are checked after joins.
Listeners released: **PASS**. Goroutine leak: **NONE observed**, baseline 2 → final 2;
no retained Mieru protocol stacks. Active sessions zero after joined Close.

Per-generation protobuf/auth maps are immutable. Splicore owns actual raw sockets,
accepted connections, destinations and worker joins; Stop does not depend on process
exit. Official packet Close is deadline-based and an active Read can replace that
deadline, so owned sockets close before official Stop. Store occurs only before
Start; its documented after-Start error is not enforced by the official release.
TCP upload EOF preserves responses through destination write half-close.
Abrupt UDP peer exit has no reliable EOF; cleanup qualification is joined inbound
Close, rather than immediate peer-session disappearance.

## Global State Audit

No single global embedded server/config/user registry or signal ownership is introduced.
Each official Server owns a Mux; identical usernames with distinct passwords isolate
across inbounds. NewServer uses the official locked NilFormatter, with no enabled
logging worker, daemon/CLI loader, signal handlers, daemon flag parsing or fatal path.
The official logger test adapter imports standard testing/flag, but embedding calls
neither SetOutputToTest nor testing.Init/flag.Parse. The integration report's import
wording is clarified during freeze; no runtime code changes follow from this finding.
Synchronized cipher/replay/RNG caches remain upstream implementation details;
immutable cipher templates are cloned. Cache templates may survive Stop; credential
erasure is not claimed. Username-global upstream counters are excluded from billing.
Malformed-request sessions may remain inside Mux until lifecycle cleanup; owned socket
shutdown passes, while hardened hostile-peer resource-limit qualification is deferred.
[ADR 0020](../adr/0020-mieru-owned-native-embedding.md) owns these canonical limits.

## Transactions / Credentials

Shared Validate → Plan → Pending → Build → Start → Health → Commit → Activate:
**PASS**. Invalid settings/credential pairs, occupied ports, committed conflicts,
compile/start/health failures, commit failure and Binding replacement compensation:
**PASS**, no partial SQLite generation or pending journal residue.
Wrong and cross-inbound passwords reject authenticated traffic in managed tests.
Admission before Activate rejects connections.

Account remains protocol-neutral. Username/password uses the existing encrypted
UsernamePasswordPayload, Account/Binding/Credential resources and vault/AAD.
Account Mieru fields: **0**. Dedicated username/password storage columns: **0**.
Protected explicit export is the only credential-returning client path;
ordinary API/CLI/doctor/profile/runtime formatting remains redacted.

## Acceptance

| Gate | Fresh freeze result |
|---|---|
| Managed Mieru interop | **24/24 PASS**, complete rerun using final managed driver |
| Default race/checkptr | **PASS**, full Splicore packages plus pinned Xray integration |
| Mieru critical runtime | **PASS**, 10x/dual inbound/admission/half-close/port cleanup |
| Affected shared packages | **PASS**, common/adapter/transport default race |
| Old protocol critical regressions | **6 groups PASS** on current default-race binary |
| Windows amd64 | Full applicable tagged unit tests/build **PASS** |
| Linux amd64 WSL2 | Tagged tests/build, default race and real managed runtime **PASS** |
| Linux arm64 | Full-tag compile **PASS**; Mieru runtime **NOT CERTIFIED** |
| Docs/links/OpenAPI/live schemas | **PASS**, formal checker and fresh Mieru API fixtures |
| Secrets/diff/source boundaries | **PASS**, before staging and repeated over staged contents |

Full units/race use `with_quic,with_utls,splicore_xray_integration` on Linux;
Windows uses `with_quic,with_utls`. Native Mieru verbose default-race smoke uses
`with_quic,with_utls`; shared race tests cover `./common/... ./adapter/... ./transport/...`.
Builds use `with_quic,with_utls`, and the runtime acceptance server uses `-race`.
No disabling checkptr/race, skips to hide failures, recover, sleeps, payload retries
or global data-path lock was introduced.
Toolchains: Windows Go1.26.2/CGO0; Linux Go1.26.6/CGO1; arm64 compile CGO0.
Project Go requirement remains 1.25.5. Dependencies resolve offline during gates.

## Client / Interop Integrity

| Client | Version | Executable SHA256 |
|---|---|---|
| Official Mieru | 3.38.0 | `70d4224ecf5cd8e1fb32c0759eb386147b39c3729e2ddacc3f685a239339f699` |
| Mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` |

Both clients × Alice/Bob × IPv4/IPv6/domain × TCP/UDP underlays = 24 positive cells.
Each covers TCP/UDP, 4 MiB SHA integrity, reconnect and abnormal close. Concurrent
traffic, exact attribution, distinct credentials across two inbounds, expected
wrong/cross credentials, disable/re-enable, restart and SQLite recovery pass.
Versions and executable hashes are checked before traffic; no latest selector.
Contract/export tests, source/runtime reference probes and managed acceptance remain
separate. Official quota reference is not Splicore enforcement acceptance.
All managed children joined, private tree removed, cleanup errors empty.
Runtime namespaces contain only loopback and synthetic hosts; no external targets.

## Regression

Snell, Hysteria2, TUIC, VLESS Native and VLESS Xray: **PASS**, each one complete
pinned reference-client IPv4 critical cell with its integrity/auth/lifecycle checks.
FinalMask/Sudoku: **PASS**, full managed feature driver with negative/recovery gates.
This is fresh bounded critical regression, not a repeat of all historical matrices.
The exact Phase 6 Xray artifact remains unchanged. Vision remains deferred/unsupported.

## Storage

SQLite committed state authority: **PASS**. Recovery reconstructs the native runtime
from shared committed resources; import files are removed before managed restart.
Account/Binding identity and secret bytes survive SQLite reopen.
Protocol-specific columns/migrations: **0**. Existing migrations 0001–0004 unchanged.
Private Mieru protobuf/client config: derived artifact/runtime state, not authority.
Persistent usage: **DEFERRED**; replacement resets generation counters.

## Dependency Audit

Direct dependency added: **github.com/enfein/mieru/v3 v3.38.0**, GPL-3.0-or-later,
official server implementation. One go.mod line and two go.sum entries only.
No unintended upgrades, floating branches, replace directives, vendor or copied source.
Existing selected dependencies/licenses remain audited in the integration report and
external dependency-license-audit.json; no newly selected transitive upgrades.

CGO: no new requirement. Windows CGO0 tests/build and Linux arm64 CGO0 compile pass.
Linux amd64 native/race runtime passes with existing CGO1 toolchain, required by race.
License/copyright/notice and corresponding-source obligations remain recorded in
[license boundaries](../architecture/LICENSE_BOUNDARIES.md); no distribution is started.

## Native Engine Scalability

Central protocol switches added: **0**. Central engine branches added: **0**.
Application protocol branches: **0**. Account protocol fields: **0**.
Storage protocol columns: **0**. Special API routes: **0**.
One compiler/module registration extends the existing Native Engine; format mappings
stay local to exporters. Existing generic creation, recovery, stats and export paths
remain shared. The new UDP transport capability is a declared kind, not a protocol branch.

## Runtime Audit

sing-box upstream runtime modifications: **0**.
Official Mieru source modifications: **0**, full local source manifest unchanged.
Xray source modifications: **0**, adapter and exact existing artifact unchanged.
Wire reimplementation: **0**. Vendored/copied upstream implementation: **NONE**.
Historical Phase 0–7 reports/requirements: **13 unchanged**.

## Protected Systems / Secrets

Docker: **DO NOT QUERY / DO NOT TOUCH**, neither queried nor touched.
Redis/TeleLedger: **UNTOUCHED**. Real `D:/code/NoBrand-OneClick`: **UNCHANGED**, entry
HEAD/status/tracked hashes verified read-only. Synthetic migration design only.
Secret scan: **PASS**. Public synthetic loopback test credentials are recognizable
fixtures, with no production endpoint or real credential staged. Runtime passwords
are generated privately and scanned against logs, ordinary API/CLI/doctor, argv
and closed SQLite/WAL. Protected export envelopes are redacted for archival.
Binaries, logs, databases, configs, private keys, caches and coverage remain external.

## Acceptance Source Match

**PASS**: all **1331** Go source/test/module files exactly match the final Phase 8
acceptance manifest. Freeze edits are docs only. The final managed driver's cleanup
wrapper is included in a fresh complete 24-cell rerun, eliminating the previous
harness-only acceptance distinction. Current driver/source snapshot hashes are
retained in the external freeze manifest; no runtime change is hidden by a doc gate.

Fresh Linux default-race server SHA256:
`8ea5124821fbe05d35e06e19e3d203a91bb798e12383dc75e6c7bf0bbd0bde88`.
The acceptance records bind all current client traffic to that executable.

## Commit

Exactly one authorized Phase 8 commit contains this report.
Message: `feat(protocol): add experimental Mieru native integration`.
Sole parent: `ca48d8429abb21fcaf7ee21d68e37d1ec5d6ec4d`.
Full SHA: resolve `git rev-parse codex/phase-8-mieru-native-integration`.
The commit cannot embed its own SHA; actual full SHA and closure checks are recorded
outside Git and in the final maintainer-facing freeze report.
Explicit stage list: 46 Phase 8 paths; `git add .` is not used.
Staged stat/name-status/diff-check/content/source/secret gates precede the commit.
No amended/rebased/reset history or extra implementation commit.

## Git / Remote / Release

Final required equality: main == Phase 8 == Phase 9 HEAD.
main advances only through `git merge --ff-only codex/phase-8-mieru-native-integration`.
Working tree: **CLEAN** after the authorized closure; final refs/state recorded externally.
Ancestry: Phase 8 → Phase 7 above → Phase 6
`438b1096b9ec357cddb163cf89f78935e711bf3d` → existing frozen ancestry.
origin: **NONE**. Sole existing upstream remote unchanged.
Push: **NONE**. Tag: **NONE**. Release: **NONE**.

## Phase 9

Branch: `codex/phase-9-distribution-service-foundation`.
Base: **PHASE_8_COMMIT**. Implementation: **NOT STARTED**.
Branch creation completes this task; no Distribution, service/installer or Panel work.

## Deferred

Mieru quota exposure; unified rate enforcement; HotUserUpdate/HotReload; persistent
usage; Mieru arm64 runtime qualification; nondefault MTU/multiplex runtime matrix;
hardened hostile-peer resource limits; Panel; NoBrand production integration;
field beta and Stable designation. Previously deferred Vision/Xray platform/stats
qualification remains unchanged. These are explicit Experimental limits.

## Evidence

Fresh freeze root: `D:/splicore-validation/phase8-freeze-20261002`.
Linux source/runtime: `/root/splicore-p8-freeze-20261002`.
Entry/source manifests, acceptance-source-match.json, linux-gates.json,
windows-gates.json, verbose lifecycle log, managed-interop/interop-results.json,
managed-interop/cleanup.json, critical-regression/smoke-gates.json,
docs-gates.json, prestage/staged scope and secret scans, staged review and final
Git closure records remain external. Original integration/source/license/fuzz
evidence at `D:/splicore-validation/phase8-20261002` is preserved.

## Final Result

**PHASE 8 FROZEN**.

## Blockers

None within the bounded Experimental scope.
