# Splicore QF-001/QF-002 Qualification Fix Report

- Documentation status: Historical restricted-fix attempt
- Audience: Maintainers and fix reviewers
- Last reviewed: 2026-10-05
- Owner: Core maintainers
- Responsibility: Record the dependency/lifecycle fix attempt, compatibility blockers and executed evidence.
- Lifecycle: Update in the authorized fix stage; this is not a freeze or qualification report.

## Verdict

This verdict records the earlier restricted dependency/adapter attempt. The
subsequent broader owned Native TUN implementation and QF-003 resolution passed
review and are included in the
[Qualification Fix freeze](QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md).
The evidence below remains historical; it is not the new candidate's verdict.

**QF FIX NOT READY FOR REVIEW**

The exact official gVisor candidate and its eventfd fix are identified. The
maintainer authorized the necessary minimum-Go exception, but two integration
blockers remain:

1. `sing-tun v0.9.3` exposes types from `github.com/sagernet/gvisor`; the tested
   official candidate exposes distinct types from `gvisor.dev/gvisor`. An actual
   compiler probe rejects the candidate endpoint as `tun.GVisorTun`. An external
   official-module mapping probe is also rejected by Go because the candidate is
   used under two different module paths.
2. `sing-tun.GVisor` keeps its actual `*stack.Stack` private. Its public methods
   are Start, ResetNetwork and Close. Close does not call Destroy/Wait, and there
   is no public accessor or injection point for that actual stack. An actual
   compiler probe confirms that `GVisor.Destroy` is unavailable.

The inspected official sing-tun dev revision still has both limitations. The
current authorization requires zero upstream patches, zero private-field access,
and a minimal integration change. A complete migration needs a compatible public
adapter contract or a separately authorized adapter migration. No production
dependency or teardown change was applied in this attempt.

## Base

- Branch: `codex/qf-001-native-tun-iovec-race`.
- HEAD / frozen Phase 15 candidate:
  `75c0b0b8dedaf0e1a3d8580d6825235364963004`.
- Sole parent: `7be20f14ccb59112c98f2fa07c0cab20a436bd88`.
- Historical message: `feat(core): harden unified runtime lifecycle and recovery`.
- Entry: four existing QF-001 modified/new files, all unstaged; index EMPTY.
- The four existing files and project go.mod/go.sum retain their entry SHA256.
- This attempt adds the current report, proposed ADR and ADR navigation only.
- Historical Phase 15 freeze, qualification and QF-001/QF-002 evidence are retained.

External evidence root:
`D:/splicore-validation/qf-002-fix-20261005/`.

## Dependency Change

### Old gVisor

- **OLD_GVISOR_VERSION**:
  `github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1`.
- Exact commit: `e9989ea3436fa7e226f61a2bcd64f38fb42b23d4`.
- Module metadata timestamp: `2026-08-04T23:57:30Z`.
- This is the actual direct project requirement. The original request's
  `gvisor.dev/gvisor` label for the old dependency does not describe the worktree.
- Module checksum: `h1:IdQ7yTKkB2wv8txwshxUroPlO4npOYAV71xb7xQ7Lys=`.
- go.mod checksum: `h1:9O3SQskYuCfdHNvHEsWuEAgoyKEF74PiWp4NsNUia8g=`.

### New gVisor

- **NEW_GVISOR_VERSION**, verified candidate, not yet the project requirement:
  `gvisor.dev/gvisor v0.0.0-20261004063249-f57b8fc79db4`.
- **NEW_GVISOR_COMMIT**: `f57b8fc79db4d392e8246d07e14c0c71e237afe8`.
- Timestamp: `2026-10-04T06:32:49Z`.
- Origin: official `https://github.com/google/gvisor`, synthetic go branch.
- Module checksum: `h1:gifqG0saAEtFgFur+Ezlr8U5Nl85VwE0qaQhyweiVmQ=`.
- go.mod checksum: `h1:We1Jh3kDvpcx13qPcI0LTjx3U6pHpis/KFoU/UtJTkM=`.
- Minimum Go: **1.26.3**. The user explicitly authorized this necessary exception
  during this stage, including a compatible Windows toolchain for later gates.
- WSL already supplies Go 1.26.6. No toolchain was installed or upgraded in this
  attempt. The project still declares Go 1.25.5 pending viable integration.

Exact identity is recovered from the prior external experiment's module metadata,
go.mod/go.sum and buildinfo, not from @latest. That experiment remains at:
`D:/splicore-validation/qf-002-eventfd-20261005/`.

### Dependency Diff

Actual project diff:

| File / graph | Changes in this attempt |
|---|---|
| go.mod | 0; old pin and Go directive retained |
| go.sum | 0; entry checksum retained |
| Selected project transitive modules | 0 |
| Project replace / vendor directives | 0 |
| Upstream cached source edits | 0 |

The standalone minimum-Go probe demonstrates the necessary metadata change:
`go 1.25.5` to `go 1.26.3`. Readonly mode rejects the old directive; a subsequent
external `-mod=mod` build changes only that line and succeeds. The corresponding
diff is `logs/go-minimum-metadata.diff`. No `go mod tidy`, @latest or blanket
dependency refresh was used.

The type-compatibility scratch project uses already selected Splicore versions of
sing, netlink, x/exp, x/sync, x/sys and x/net. Its indirect entries are external
probe metadata; they are not accepted project dependency churn. The first probe
attempt encountered uncached older transitive versions; selecting the existing
project versions produced the definitive type mismatch below.

## Why Upgrade Was Required

The prior pinned-only, public-API experiment established:

| Dependency / teardown | Lifecycles | Eventfd delta |
|---|---:|---:|
| Actual old pin / full Destroy | 25 | +25 |
| Exact official candidate / current-equivalent teardown | 25 | +25 |
| Exact official candidate / full Destroy | 25 | 0 |

The old dispatcher lacks a release path even after complete NIC/link teardown.
The candidate releases StopFD only when the public link Close is reached after
reader shutdown. Dependency selection and complete lifecycle ownership must be
implemented together.

Prior authoritative evidence:
`D:/splicore-validation/qf-002-eventfd-20261005/QF_002_GVISOR_EVENTFD_LIFETIME_REPORT.md`.
These are source/runtime reference results, not new Splicore acceptance.

## QF-001

### Root Cause

The pinned `NativeTun.WritePacket` retains and mutates device-owned iovec backing
storage. Filter forwarding, asynchronous DNS return and TCP loopback can enter
that device concurrently. The syscall consumes descriptor/payload storage until
its synchronous writev return.

### Fix

The existing `preparedEndpoint` per-device channel token enforces one explicit
writer through syscall return. Its atomic stopped flag rejects new/queued writes
after shutdown starts. `ownedStack.Close` uses sync.Once and drains the admitted
writer before the existing stack/device close sequence. This implementation was
preserved byte for byte; no ownership synchronization was removed.

The current sing-tun source still reuses its iovec array. No new packet-writing
implementation has been selected that would change that requirement.

### Regression

Fresh **PASS**: five `TestQF001*` cases each executed 25 times, 125 passing
executions, default race/checkptr. Package test duration: 1.103s.

```text
go test -race -tags with_gvisor,with_quic,with_utls -count=25 -v -run '^TestQF001' ./internal/splicore/clientruntime
```

Log: `D:/splicore-validation/qf-002-fix-20261005/logs/qf001-race-25.log`.
This verifies the preserved implementation against the current old project graph,
not compatibility with the unintegrated official candidate.

## QF-002

### Root Cause

The old per-link readVDispatcher allocates `StopFD.EFD`. Stop writes a signal;
release frees packet buffers/processors; public fdbased Close is empty. None of
those operations closes EFD. The prior complete Destroy variant proves the leak
persists with NIC removed, link Close/Wait called and workers joined.

### Upstream Change

Identified upstream fixing commit:
`b11702b3c511622436e4733a7f5552b9fcdc73b0`, committed
`2026-09-28T18:37:25Z`. It adds endpoint-to-dispatcher-to-StopFD closing, dispatcher
constructor cleanup and endpoint tests, including the XDP implementation.
[Official fix commit](https://github.com/google/gvisor/commit/b11702b3c511622436e4733a7f5552b9fcdc73b0).

The tested official candidate contains the corresponding release mechanism:

- fdbased endpoint Close calls each dispatcher's close after readers are stopped.
- readVDispatcher / recvMMsgDispatcher close delegates to StopFD.Close.
- StopFD.Close closes EFD and sets it to -1; subsequent Close is a no-op.
- Restored StopFD state is invalidated instead of retaining a stale raw FD number.

Evidence: `upstream-fix-commit.json` and the directed source diffs in the external
fix-stage directory. No upstream patch was applied.

The targeted audit also records changes beyond the release mechanism: dispatcher
construction no longer allocates an unused readv dispatcher for a socket-specific
dispatcher; malformed inbound-header handling continues dispatch instead of
stopping; GSO checksum offsets change; stack clock-resolution/NIC-kind fields are
added; fdnotifier annotations change. These need actual integration regression
before candidate acceptance. rawfile writev and the public TUN opener source
diffs were captured; no local replacement implementation was introduced.

### New Lifecycle Contract

**NEW_GVISOR_TEARDOWN_CONTRACT**, exact candidate:

1. Stop packet admission and any admitted device writes according to owner rules.
2. Stop the fdbased link reader via Attach(nil); that implementation joins readers.
3. Call the **actual** stack's Destroy, which calls Close + Wait.
4. Wait joins transport/protocol workers, removes NICs, waits link workers, then
   invokes deferred public link Close outside the stack lock.
5. Link Close closes dispatcher StopFDs after they are no longer polled.
6. The caller closes its borrowed raw kernel TUN FD after link shutdown/join.

Stack Close alone aborts transport endpoints and closes protocols. It does not
perform the NIC/link release work. Stack Destroy does **not** take ownership of
the raw TUN FD passed to fdbased.New; the host device owner still closes that FD.

Audited candidate source lines: stack.go RemoveNIC 1086, Close 2064, Wait 2083,
Destroy 2117; fdbased endpoint Close 926; dispatcher close 189; StopFD.Close 69.
Source copies are in the external `official-source/` tree, with original-cache
SHA256s in `directed-source-audit.json`.

### Splicore Teardown Fix

**Not implemented: public adapter compatibility is blocked.**

Actual compiler evidence from `logs/module-path-type-compatibility.log`:

```text
*officialTun does not implement tun.GVisorTun (wrong type for method NewEndpoint)
have NewEndpoint() (gvisor.dev/gvisor/...LinkEndpoint, ...NICOptions, error)
want NewEndpoint() (github.com/sagernet/gvisor/...LinkEndpoint, ...NICOptions, error)
```

Actual external official mapping probe:

```text
gvisor.dev/gvisor@v0.0.0-20261004063249-f57b8fc79db4 used for two different module paths
(github.com/sagernet/gvisor and gvisor.dev/gvisor)
```

Actual public API probe:

```text
s.Destroy undefined (type *tun.GVisor has no field or method Destroy)
```

`sing-tun.GVisor.stack` is unexported. The public helper NewGVisorStack constructs
a new stack; it does not expose or transfer the stack that GVisor.Start created.
Current high-level integration cannot reach its actual stack Destroy/Wait through
the inspected public API.

Official dev revision `3f8acd9da65b15b03ec66c7ecdb36759ebcdcc5d`, inspected via
primary GitHub source, still uses the old module and the same Close sequence.
This is evidence about that exact revision, not an exhaustive claim that every
possible compatible upstream branch is absent.
[Inspected official adapter source](https://github.com/SagerNet/sing-tun/blob/3f8acd9da65b15b03ec66c7ecdb36759ebcdcc5d/stack_gvisor.go).

The request's sections 9, 12 and 32 require zero upstream modifications, public
lifecycle APIs and minimal adaptation. Implementing the requested fix requires
an adapter contract/migration decision beyond the demonstrated available public
surface. The required minimum-Go exception has been authorized and does not
resolve these remaining blockers.

## Teardown Sequence

Current preserved sequence:

```text
listener admission closes
 -> tunIngress stopped + staged reference cleared + context cancelled
 -> ownedStack.Close (sync.Once)
 -> preparedEndpoint rejects writes and drains admitted writev
 -> sing-tun.GVisor.Close: forwarders close, endpoint.Attach(nil), stack.Close
 -> cleanup transport endpoints Abort
 -> host lease Restore / owned NativeTun raw FD Close
 -> tracked sessions/network owners cancel and generation refs release
 -> Manager wg joins, host platform/manager close
```

Missing from the successful high-level adapter path: actual stack Wait/Destroy
and its complete NIC/link closing. The desired candidate sequence is the New
Lifecycle Contract above; it is **not** reported as integrated or tested here.

## Minimal Reproducer

| Candidate | Cycles | Eventfd Start | Eventfd End | Delta | Total FD Delta |
|---|---:|---:|---:|---:|---:|
| Old pin / full Destroy, prior reference | 25 | 1 | 26 | +25 | +25 |
| Exact official candidate / equivalent close, prior reference | 25 | 1 | 26 | +25 | +25 |
| Exact official candidate / full Destroy, prior reference | 25 | 1 | 1 | 0 | 0 |
| Project after dependency integration | NOT EXECUTED | — | — | — | — |

All prior runs used owned isolated WSL namespaces, public APIs, warmed Go poller
baseline, race/default checkptr and only caller-owned raw TUN FD closing. The
historical old-pin evidence is retained. No new project pin exists against which
to claim the required current-project reproducer x25 gate.

The scratch compatibility probes build binaries and do not run TUN traffic,
scan external targets, open live TUN fixtures or qualify resources.

## Repository Lifecycle Regression

Blocked / not added in this attempt. A compatible integration must subsequently
cover 25 complete TUN lifecycles with exact warmed eventfd/total-FD equality,
joined workers, idempotent Close, failed/partial start, admitted-write shutdown,
concurrent Close and recycled-FD safety. Existing QF-001 tests and the previously
added strict real-TUN resource assertion remain intact.

## Real TUN

This attempt: **NOT EXECUTED / joint fix gate BLOCKED**. Prior original kernel
fixture functional race/checkptr verification passed TCP/UDP/DNS, but resource
stability did not pass. The required x10 traffic/start/stop/restart acceptance
cannot be claimed against an unintegrated candidate.

## 10-Minute Stress

This attempt: **NOT EXECUTED / BLOCKED**, new workload duration **0s**.
Neither the historical interrupted qualification soak nor the prior 313.08s
QF-001 fix stress is accumulated. No 60-minute qualification was started.

## Resource Stability

No new real-TUN or stress resource sampler ran in this attempt:

| Resource | Start | Peak | End |
|---|---:|---:|---:|
| eventfds | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| total FDs | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| goroutines / link workers | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| listeners | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| sessions | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| generations | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| leases | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| journal temporaries | NOT MEASURED | NOT MEASURED | NOT MEASURED |
| RSS | NOT MEASURED | NOT MEASURED | NOT MEASURED |

Historical minimal candidate full-Destroy samples: eventfds 1/2/1, total FDs
6/8/6, goroutines 1/6/1, link workers 0/1/0. These are discrete sampled peaks
from the prior gVisor-only process, not Splicore stability acceptance.
Historical Splicore stopped FD counts 15→20 remain a failed resource gate.

## Race / Checkptr

- Fresh QF-001 targeted x25: PASS, default race/checkptr, 125 test executions.
- Standalone official candidate minimum-Go probe: race binary BUILD PASS after
  external minimum directive becomes 1.26.3; no lifecycle run in that probe.
- Linux default/full native/shared race: NOT RERUN in this attempt. Previous
  old-graph passes remain historical; new-graph regression is BLOCKED.
- New-pin race/checkptr/FD joint gate: NOT EXECUTED.
- No disabled race/checkptr, sleep, retries, panic recovery or test skipping was
  introduced as a production fix.

## Native Protocols

Snell, Hysteria2, TUIC, VLESS plain/TLS/REALITY, Mieru, DIRECT and REJECT:
new-graph regression NOT EXECUTED / BLOCKED. Previous old-graph native/shared
functional passes remain recorded in the unmodified QF-001 report.

SOCKS5 TCP/UDP ASSOCIATE, HTTP/mixed and TUN simultaneous client regression:
new-graph NOT EXECUTED / BLOCKED.

## Routing / DNS / Policy

New-graph bootstrap/proxy DNS, route snapshots, selection, UDP affinity,
cancellation and restart gates: NOT EXECUTED / BLOCKED. No routing, DNS, policy,
underlay or wire implementation changed in this attempt.

## Phase 15 Regression

H15-001 through H15-009, especially DNS cancellation, stopped handles and journal
cleanup: NOT RERUN against a new graph. Historical frozen candidate and its
report remain immutable. No graceful Destroy adaptation has been installed to
evaluate idle/active cancellation, shutdown latency or SIGKILL recovery.

## Windows

- New-graph Windows build/full safe tests: NOT EXECUTED / BLOCKED.
- Installed host Go 1.26.2 cannot satisfy candidate minimum 1.26.3. A compatible
  toolchain is authorized for later gates, but not installed in this attempt.
- Windows race: NOT EXECUTED; prerequisites were not established.
- Real/destructive Windows TUN/route/DNS/proxy tests: NOT EXECUTED.
- Windows host network mutations: 0.

## Linux arm64 Build

New-graph build: NOT EXECUTED / BLOCKED. No arm64 runtime certification claimed.

## Fuzz

All 42 existing `Fuzz*` functions under internal/splicore and cmd/splicore are
preserved. No parser, batching or decoder adaptation was made. New-graph seed
corpus/package regression is NOT EXECUTED; no new mutation campaign was run.

## Performance / Allocation

No new hot-path or real-TUN startup/shutdown benchmark ran. The unchanged QF-001
guard retains the prior fake-backend measurements: serial about 30ns/op,
parallel about 140–144ns/op, zero allocs/op. These are historical adapter-overhead
samples, not new dependency or kernel throughput performance results.

Normal/active Destroy latency, bounded Wait and cancellation interactions remain
required acceptance gates after actual public integration becomes possible.

## Underlay

Fresh static audit: **PASS**. Production egress surfaces **55**, Unknown **0**.
No production socket construction or protection behavior changed.
Evidence: external `underlay/inventory-after.json` and `.md`.

## Xray Boundary

Fresh reference audit, including added documentation:

- E runtime/control: **0**.
- F suspicious: **0**.
- G ClientProfile compatibility references: **10**.
- Vision remains DEFERRED; FinalMask/Sudoku remain out of scope.

New report/ADR references are documentation-only. There is no runtime/control
integration. The external audit records each existing/new reference category.

## Upstream Modifications

- gVisor patched source: **0**.
- sing-box upstream source edits: **0**.
- sing-tun patched source: **0**.
- Mieru upstream edits: **0**.
- wire reimplementation: **0**.
- private-field/unsafe cleanup, direct internal StopFD close: **0**.
- project fork/local replace/vendor override: **0**.

External directed source copies/diffs are evidence. The rejected external mapping
probe points to the exact official module and is not a project replacement.

## Files Changed

Preserved QF-001 files, entry bytes unchanged:

1. `tun_stack_gvisor.go` was the original path at this checkpoint. The active
   file was later replaced by the owned native runtime; the original guard is
   preserved as [qf001_legacy_guard_test.go](../../internal/splicore/clientruntime/qf001_legacy_guard_test.go).
2. [qf001_gvisor_test.go](../../internal/splicore/clientruntime/qf001_gvisor_test.go).
3. [qf001_tun_lab_linux_test.go](../../internal/splicore/application/qf001_tun_lab_linux_test.go).
4. [CLIENT_RUNTIME.md](../architecture/CLIENT_RUNTIME.md).

This attempt's repository changes:

1. This new implementation-attempt report, with NOT READY status.
2. [ADR 0036](../adr/0036-official-gvisor-eventfd-lifecycle.md), Proposed.
3. [ADR navigation](../adr/README.md), link and review date.

All remain UNSTAGED. go.mod/go.sum and all upstream/production source files are
unchanged from this attempt's entry, except the already present QF-001 source.
External probes, exact upstream metadata, directed diffs and audit outputs reside
only in the dedicated fix-stage evidence directory.

## Documentation / ADR

ADR 0036 records the required candidate/full-teardown decision, explicit Go
exception, public-API blockers, alternatives and rollback consequences. It is
Proposed and does not claim an accepted or implemented migration.
Old ADR records and PHASE_15_FREEZE_REPORT.md were not modified.

## Migrations

**NONE**.

## Blockers

1. Required official candidate's module types do not satisfy the pinned adapter
   contract; an official module alias does not provide a compiling migration.
2. Actual sing-tun-owned stack lacks a public Destroy/Wait/accessor contract.
3. A compatible adapter contract or separately scoped migration decision is
   required to implement the exact official pin with the authorized boundaries.
4. Since integration is absent, resource/lifecycle x25, real-TUN x10, TCP/UDP/DNS,
   full 10-minute stress, complete new-graph race/native/Windows/arm64/fuzz-seed
   gates have not passed.

The minimum-Go restriction was resolved by explicit user authorization; it is
not listed as an outstanding authorization blocker. Candidate toolchain readiness
must still be verified when Windows gates can run.

## Platform Qualification Status

**REMAINS PAUSED PENDING FIX REVIEW AND FREEZE**.

No qualification, fix freeze, Phase 16, release or formal platform certification
was started. Next steps require a viable adapter migration, complete fix gates,
review, an explicit fix freeze and a new frozen candidate before requalification.

## Git Actions

- staged: **NO**
- committed: **NO**
- pushed: **NO**
- tagged: **NO**
- released: **NO**
- frozen: **NO**

**QF FIX NOT READY FOR REVIEW**.
