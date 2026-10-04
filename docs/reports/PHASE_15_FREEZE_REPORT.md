# Splicore Phase 15 Freeze Report

- Documentation status: Historical freeze checkpoint
- Audience: Maintainers and reviewers
- Last reviewed: 2026-10-04
- Owner: Splicore maintainer
- Responsibility: Authorized Phase 15 hardening, validation and Git closure
- Lifecycle: Preserve this local Experimental freeze; platform qualification is separate

## Verdict

**PHASE 15 FROZEN**

This report records the one authorized forward commit containing this report.
It is prepared before staging and finalized by successful gates and that commit.
No feature development, publication or platform certification is authorized here.

## Freeze Identity

- Freeze commit: **this commit**, the commit containing this report.
- Message: `feat(core): harden unified runtime lifecycle and recovery`.
- Sole parent: `7be20f14ccb59112c98f2fa07c0cab20a436bd88`.
- Branch: `codex/phase-15-unified-core-hardening`.
- Exact manifest: 30 paths; 14 modified, 16 added, zero deleted.
- Actual commit hash and Git statistics are recorded externally after commit;
  no self-referential hash, amend or second commit is used.

## Base

Phase 14: `7be20f14ccb59112c98f2fa07c0cab20a436bd88`, message
`feat(client): add management providers and correct xray boundary`.
Its sole parent remains `b0de8c16e1c810cb851c400b5d03987924d5eff8`.
Entry branch and HEAD matched the accepted baseline; index was EMPTY and the
worktree held the accepted 14 modified and 15 new Phase 15 files.
Main remains at the Phase 13 parent. Prior refs and historical objects are preserved.

## Scope

Phase 15 — Unified Core Hardening. The
[ownership inventory](../development/PHASE_15_HARDENING_INVENTORY.md) audits 28
resource/lifecycle surfaces and their acquisition, activation, reference,
retirement, release, rollback and crash/restart contracts.

Splicore remains an independent native Server + Client Core. RuntimeConfig and
external ClientProfile serialization remain separate. SQLite committed state
is domain authority; snapshots, configurations and operational artifacts are
derived state. CLI/API share Application Service; `/api/v1` and existing
protocol/routing/DNS/policy/timeout semantics are preserved. Node identity and
ID-based references remain immutable; migrations are forward-only and unchanged.

Freeze-stage source edits are documentation only: this report and its development
index link. All production Go and regression sources match the accepted Review.
There are no new protocols, wire changes, dependency upgrades or production fault hooks.

## Findings

### H15-001 — HTTP shutdown ownership

Root cause: Serve could release application/SQLite before its Shutdown worker
or admitted handlers finished; `Server.Close` alone does not join handlers.
Fix: inherited request cancellation, joined Shutdown, sealed admission before
handler Wait, and propagated teardown errors. Regression:
`TestPhase15HTTPShutdownJoinsApplicationRequests`,
`TestPhase15ForcedHTTPShutdownStillJoinsHandler`,
`TestPhase15ReadinessFailureJoinsShutdown` in
[app tests](../../internal/splicore/app/hardening_test.go). PASS.

### H15-002 — Candidate ownership

Root cause: unsynchronized `Prepared.used`, missing closed-manager and expected
snapshot gates allowed race, stale publication or post-close resurrection.
Fix: candidate-only mutex, retained base pointer, expected snapshot comparison
and closed gate; rejection releases only candidate resources. Regression:
`TestPhase15CandidateConsumptionConcurrent`,
`TestPhase15CandidateCannotActivateAfterClose`,
`TestPhase15StaleCandidateCannotReplaceCurrent` in
[candidate tests](../../internal/splicore/clientruntime/hardening_test.go).
Freeze ownership race repetitions: 10. PASS.

### H15-003 — System DNS bootstrap lifetime

Root cause: systemLookup bypassed Engine.owner. Fix: owner.Begin/done joins
bootstrap to cancellation and outstanding work. Regression:
`TestPhase15SystemBootstrapCannotOutliveEngine` and existing in-flight DNS tests,
plus [health snapshot regression](../../internal/splicore/networkruntime/hardening_test.go).
PASS.

### H15-004 — Provider/RuleSet revision ownership

Root cause: an old failed fetch/parse recorded failure against the provider
current at completion. Fix: carry observed SQLite revision across I/O and only
record when it still matches. Regression: four proxy/RuleSet fetch/parse cases
and eight late-success update/delete/restart/shutdown cases in
[provider tests](../../internal/splicore/application/hardening_provider_test.go).
PASS; old completion cannot overwrite newer authority.

### H15-005 — SQLite concurrent Close

Root cause: multiple callers unlocked/closed one installation descriptor,
producing a real Read/Write race and duplicate release errors. Fix: sync.Once
joins DB Close, then installation unlock/close, with one sanitized result.
Regression: 16 simultaneous Close callers and reopen in
[SQLite tests](../../internal/splicore/storage/sqlite/hardening_test.go).
Freeze ownership race repetitions: 10. PASS.

### H15-006 — Support cancellation

Root cause: cancelled requests could continue creating/writing derived archives.
Fix: check cancellation before output, after projection, between members and
before fsync; keep partial-output cleanup. Regression: cancellation before
generation and during projection in
[support tests](../../internal/splicore/operations/hardening_test.go) and
[Linux projection tests](../../internal/splicore/operations/hardening_linux_test.go).
PASS.

### H15-007 — Native stopped admission

Root cause: stale Activate could set admission after Close. Fix: use existing
native lifecycle locks and closed gates; no payload lock or wire changes.
Regression: concurrent stopped Snell/VLESS/QUIC/Mieru activation/start/close in
[native tests](../../internal/splicore/engine/native/hardening_test.go), plus
actual native lifecycle/rollback suites. PASS.

### H15-008 — Journal crash temporaries

Root cause: abrupt exit bypassed Save defer, accumulating reserved temporaries.
Fix: after exclusive directory lock, remove only private regular `.journal-*`;
unsafe owner/type/permissions/path fails closed and releases the lock.
Regression: cleanup, directory/symlink/public-file rejection and process crash
recovery in [journal tests](../../internal/splicore/hostnetwork/hardening_crash_test.go).
PASS; unrelated operator files are preserved.

### H15-009 — Passive native diagnostics

Root cause: support projection recognized only Snell; degraded/enabled-stopped
runtime was informational and application doctor lacked runtime/provider health.
Fix: bounded native protocol enumeration and passive health checks. Regression:
`TestPhase15DiagnosticsReflectNativeProtocolsAndFailures`, process-restart
doctor and real daemon doctor/support smoke. PASS; no new remote probe or authority.

## Lifecycle / Ownership

Server/native handles, client/inbound/outbound, providers/RuleSets, routing/DNS/
policy snapshots, TUN/system journal, underlay leases, listeners/sessions,
SQLite, backup and support artifacts have explicit owners and cleanup contracts.
Start/partial-start/stop/concurrent-close/stale-activation/rollback tests PASS.
Retained sessions own old generations until socket cleanup completes; the last
reference releases adapter and lease. Complete immutable snapshots are published.
Ordered first-match, health selection and existing DNS TTL/cache bounds remain.

## Concurrency

Real candidate consumption and SQLite descriptor races are fixed and rerun.
Linux full native tags, default tags, affected shared packages and deterministic
H15 regressions PASS with race enabled and default checkptr.
Candidate locks cover consumption; lifecycle locks cover admission. No global
data-path mutex, sleep/retry masking, recover suppression or race/checkptr bypass.
Application/runtime lock ordering and owner joins are recorded in the inventory.
HTTP/provider/probe/DNS cancellation and shutdown join tests PASS.

## Crash / Recovery

Real child `os.Exit(77)` bypasses cleanup at nine runtime/provider windows:
before commit, after commit/before activation, prepare, after activation,
before old adapter retirement, proxy/RuleSet fetch and committed refresh.
Five journal cases cover partial derived write, rename, unacknowledged route
write, ambiguous interface creation and active synthetic TUN metadata.
Backup crash is after private destination creation, before source query/VACUUM;
no mid-VACUUM qualification is claimed.

Actual SQLite/WAL/installation ownership is recovered. Host records are synthetic;
kernel TUN evidence uses a separate isolated WSL namespace. Committed DB wins,
old snapshots never overwrite it, and offline provider state is reconstructed.
Ambiguous interface identity preserves ownership debt and fails closed.
Interrupted explicit backup output is preserved and rejects overwrite; the
original DB remains authority and a fresh destination succeeds. PASS.

## Resource Stability

Freeze-stage full native Linux race reproduced these bounded measurements:

| Resource, local network lifecycle x10 | Start | Peak | End |
| --- | ---: | ---: | ---: |
| Goroutines | 2 | 12 | 2 |
| FDs | 7 | 19 | 7 |
| Listeners | 0 | 1 | 0 |
| Sessions | 0 | 2 | 0 |
| Generations | 0 | 2 | 0 |
| Leases | 0 | 2 | 0 |
| Journal temporary files, crash recovery | 0 | 1 | 0 |

Pure generation/snapshot qualification runs 25 cycles: goroutines 2/2/2,
FDs 7/7/7, generations and leases 0/2/0. Network fixtures have zero output files.
Observed resources return to baseline; there is no known residual goroutine,
FD, stale generation or lease leak within this scope. Windows FD value -1 means
unmeasured. Timers/tickers are verified through scheduler/owner joins without
a numeric timer metric. No multi-hour, multi-day or production soak is claimed.

## Provider / RuleSet Coordination

Validated generation → transaction → committed state → prepare/activation remains
the control chain. Revision fences reject old success and failure completion;
manual/scheduled deduplication, cancellation, offline recovery, RuleSet reference
consistency and rollback remain. Freeze stale-completion and crash suites PASS.

## SQLite / Derived Artifacts

SQLite authority, WAL mode, transaction/revision boundaries and migration bytes
are unchanged. Migrations: NONE. Concurrent Close joins one release and reopens
correctly. Journal temporaries are nonauthority; private reserved crash files
are cleaned under exclusive ownership. Backup/restore and durable derived-write
regressions PASS. Source and distribution artifacts record honest provenance.

## Secrets / Diagnostics

Pre-stage complete changed files and actual staged blobs are scanned and reviewed:
real secret=0, unresolved=0. PSKs are generated only inside synthetic local tests;
hostile diagnostic literals are explicitly `SYNTHETIC_SECRET`.
Existing redaction tests cover passwords, tokens, PSKs, UUID credentials,
private keys and provider auth. No complete Go heap erasure is claimed.
Doctor is passive; diagnostic results never become runtime authority.
Support archives have eight fixed safe member names, private new output and
bounded redacted projections. Cancellation cleanup and real daemon support PASS.

## Native Protocol Regression

Snell, Hysteria2, TUIC, VLESS plain, VLESS TLS, VLESS REALITY, Mieru, DIRECT and
REJECT: PASS. Full tagged suites exercise current Splicore server/client
integration and actual owned-localhost TCP/UDP. Staged native/race smoke PASS.
No raw historical Xray probe is counted as Splicore feature acceptance.

## TUN / Underlay

Production egress: **55 surfaces; Unknown=0**, rerun static audit.
No new production egress surface appears. Safe synthetic route/DNS/journal/
Wintun/WinINET ownership and failure tests PASS. Review-stage isolated kernel
TUN race evidence is reused against unchanged Go source: DIRECT plus five native
adapters, IPv4/IPv6 TCP/UDP, retained generations, policy/DNS interception,
4 MiB payloads, 16 flows and 10 lifecycle/provider refresh cycles. DNS leak
TCP=0/UDP=0. No destructive host-network qualification is performed.

## Xray Boundary

- E active runtime/engine/control: **0**.
- F suspicious/unresolved: **0**.
- G external ClientProfile compatibility: **10**.
- Registry is native only; no Xray builder/process/executable/component/underlay owner.
- `format=xray` remains external serialization; RuntimeConfig != ClientProfile.
- Legacy EngineID=xray continues to fail closed; no silent native conversion.
- FinalMask and Sudoku active runtime: **0**; both are OUT OF SCOPE.
- Vision is DEFERRED/UNSUPPORTED; DoH/FakeIP remain DEFERRED.

## Validation

Raw commands, exits, counts, exact manifest, source/file hashes and build/staged
provenance remain outside Git at `D:/splicore-validation/phase15-freeze-20261004`.
Review evidence is retained separately at
`D:/splicore-validation/phase15-hardening-20261004`; logs/binaries are not committed.

### Freeze-stage rerun

| Gate | Result |
| --- | --- |
| Full Linux native tags race | PASS; 672 test/subtest/seed passes, 35 packages |
| Full Linux default tags race | PASS; existing with_utls conditions described below |
| Full Windows safe tests | PASS; 661 test/subtest/seed passes, 35 packages |
| Affected shared race | PASS |
| Candidate/SQLite ownership race x10 | PASS |
| All H15 deterministic lifecycle/recovery tests | PASS |
| Real race daemon SIGTERM/restart x10 | PASS; sessions, ports and UDS released |
| Static scope/history/domain/egress/Xray review | PASS |
| Formatting, whitespace and documentation/OpenAPI links | PASS |
| Pre-stage and actual staged blob secret scans | PASS |
| Three-platform candidate build and source/package provenance | PASS |
| Two repeated candidate builds | PASS; byte-identical artifacts/source archive |
| Staged build, H15 race, native protocol and boundary smoke | PASS |

### Review-stage evidence reused

Unchanged production/tests retain the complete implementation audit, fault
matrices, isolated kernel TUN race, routing/DNS/policy consistency, benchmark,
eight actual fuzz mutation campaigns and existing installer/distribution fault
qualification. Vet PASS is reused against unchanged Go code. No new host
install/upgrade campaign, kernel TUN run or fuzz mutation campaign is claimed
in Freeze. All 42 fuzz targets remain; seed corpus runs in the full suites.

## Build Tags

Default tags have two existing conditional skips:
`TestVLESSRealityPrivateKeyBlockingGateAndRecovery` (application) and
`TestCreationSecretAndValidationBoundaries` (protocol/vless), both requiring
`with_utls`. Full native tags `with_gvisor,with_quic,with_utls` actually execute
and pass both tests, with no test skips. No failing test is skipped or new
skip introduced; no-tests package events are separately counted.

## Distribution / Reproducibility

Fresh Freeze candidate builds target Linux amd64, Windows amd64 and Linux arm64.
Two independently created external source/output directories produce identical
packages and source archives from the final reviewed canonical source, including
this report. Existing offline content-addressed Go/module caches are reused;
no fresh-empty-cache claim is made. No old Review artifact is relabeled.
Version is `0.0.0-dev.15`; artifacts are local Experimental development candidates.
Metadata honestly records the Phase 14 base plus dirty candidate source digest,
because builds precede commit. Staged blobs equal source archive provenance;
the external post-commit record maps that exact tree to the actual freeze hash.
No future commit hash is fabricated and no binary/artifact is added to Git.
Distribution has no Xray component or obsolete argument; dependency versions
and installer behavior are unchanged.

## Platform Qualification Limits

### Windows

amd64 build, unit and safe integration PASS. Race NOT EXECUTED (CGO0).
Real TUN, auto-route and WinINET NOT CERTIFIED; unsafe activation FAIL CLOSED.
Windows FD counts are not measured.

### Linux amd64

Build, unit, race/default checkptr and isolated WSL implementation PASS.
Native Ubuntu host-network destructive qualification DEFERRED / NOT CERTIFIED.
Isolated WSL implementation evidence does not certify native system networking.

### Linux arm64

BUILD ONLY; RUNTIME NOT CERTIFIED. No long-duration production soak is certified.
These environment limits are retained and are not implementation blockers.

## Historical Integrity

Phase 0–14 history and historical reports remain unchanged, including Phase 14
and Phase 6/7 reports. All existing migration blobs remain unchanged.
sing-box upstream modifications=0; Mieru upstream modifications=0;
wire reimplementation=0; dependency changes=0. Submodule pointers are preserved.

## Git Integrity

The exact 30-path manifest is audited before explicit per-path staging; no
`git add .`, `git add -A` or broad-directory wildcard is used.
Staged set equals reviewed manifest; complete staged source and submodule
pointers equal build provenance. After the sole forward commit, its only parent
is exactly the Phase 14 base, index is EMPTY and working tree CLEAN.
All unrelated refs/main remain unchanged. No reset/rebase/amend/squash/force
operation or history rewrite is performed.

## Blockers

NONE.

## Actions Not Performed

- push: NO
- tag: NO
- release: NO
- Platform Qualification: NOT STARTED
- Phase 16: NOT STARTED
- NoBrand migration: NOT STARTED
- Docker Desktop, Redis, TeleLedger: not accessed or operated
- Third-party systems/external scans: NONE
- Second commit/amend/history rewrite: NO

**PHASE 15 FROZEN**
