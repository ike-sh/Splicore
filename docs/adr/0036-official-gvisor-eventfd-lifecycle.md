# ADR 0036 — Official gVisor candidate and complete eventfd ownership

- Documentation status: Accepted
- Audience: Maintainers and fix reviewers
- Last reviewed: 2026-10-05
- Owner: Core maintainers
- Responsibility: Record QF-002 lifecycle evidence, matched dependency options and migration approval boundaries.
- Lifecycle: Accepted for the local Qualification Fix / Native TUN freeze; platform qualification is separate.

## Status

Accepted by explicit maintainer REVIEW PASS and Qualification Fix Freeze
authorization, 2026-10-05. The Native TUN Runtime Implementation request expands the
earlier QF-001/QF-002 scope to Splicore production adapters and runtime. Splicore
owns device-use, stack/NIC/link lifecycle, packet ownership, flow cancellation
and complete teardown. Native ownership/resource, product race, safe Windows and
distribution gates have passed. QF-003 independently
replaced the inherited libbox profiler's private runtime ABI with public Go
profiling APIs. Repository-wide default/native race gates now pass without
changing Native TUN source or dependencies.
This decision records the implemented owned runtime, not an undecided adapter
migration. [Freeze report](../reports/QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md)
records its local checkpoint. Platform Qualification is not resumed.

## Current implementation decision

Reuse the exact official gVisor candidate below as a TCP/IP dependency. Splicore
holds the actual stack and executes its public full teardown; sing-tun no
longer owns the active client TUN netstack. A channel link and owned byte packet
bridge separate device ownership from stack ownership. This avoids the legacy
per-link StopFD while retaining strict eventfd/total-FD equality gates.

Minimum Go becomes 1.26.3 because this formally selected exact dependency
requires it. Retain sing-tun only for inherited utilities/contracts outside
the active Splicore TUN runtime. Do not copy sing-tun or sing-box implementations,
patch module caches, fork dependencies or expose backend types to the domain.
Upstream is a reusable component and reference, not architectural authority.

See [native runtime design](../architecture/NATIVE_TUN_RUNTIME.md) and
[ownership table](../architecture/TUN_RUNTIME_OWNERSHIP.md). Final evidence and
the resolved full-repository build blocker are recorded in the
[Native TUN implementation report](../reports/NATIVE_TUN_RUNTIME_IMPLEMENTATION_REPORT.md).
The matched-pair
recommendation and approval restrictions below document the earlier review;
they are superseded by this explicitly authorized implementation decision.
Their source experiments remain historical evidence, not current acceptance.

## Historical context before Native TUN implementation

The actual old dependency is `github.com/sagernet/gvisor
v0.0.0-20260727.0-sing-box-mod.1`, commit
`e9989ea3436fa7e226f61a2bcd64f38fb42b23d4`.
Its per-link StopFD lacks a closing path: 25 public full-Destroy lifetimes still
retain 25 eventfds. Current Splicore/sing-tun teardown also lacks complete stack
Wait/NIC/link release. The preserved QF-001 writer ownership fix solves a separate
shared iovec race and remains necessary for the current NativeTun implementation.

The exact tested official candidate is `gvisor.dev/gvisor
v0.0.0-20261004063249-f57b8fc79db4`, commit
`f57b8fc79db4d392e8246d07e14c0c71e237afe8`, synthetic go branch.
With complete public teardown its minimal experiment returns eventfd/total-FD
counts to warmed baseline; with equivalent current teardown it still leaks.

## Historical matched-pair proposal (superseded)

Main proposed route: an official **matched SagerNet sing-tun/gVisor pair** whose
public Close completely releases the actual owned stack/NIC/link resources.
The current frozen/latest/dev/testing pairs fail the x25 resource gate; no
qualifying exact pair is available in the inspected set. Wait for and verify
merged official lifecycle corrections before proposing exact production pins.

The exact Google candidate remains release-mechanism reference evidence. Its
different module types prevent direct adoption through the current sing-tun
adapter. Preserve explicit per-device writer admission/drain and close the
caller-owned raw TUN FD after link shutdown and worker completion.

The official candidate requires Go 1.26.3; this necessary minimum exception is
explicitly authorized. Unrelated dependency/toolchain upgrades remain out of scope.
Avoid @latest/master ambiguity; preserve exact commit and module checksums.

Upstream fixing commit is
`b11702b3c511622436e4733a7f5552b9fcdc73b0`: endpoint Close delegates through
dispatcher.close to StopFD.Close after reader shutdown. The candidate public
Stack.Destroy calls Close+Wait; Wait removes NICs, joins workers and invokes
link Close. fdbased borrows the raw TUN FD; Destroy does not own that raw FD.

## Historical public-API blockers of the old adapter

Pinned `sing-tun v0.9.3` returns and consumes old-module stack types. The official
candidate's types have a different Go identity. An actual compile probe rejects
the candidate's endpoint as `tun.GVisorTun`. An external official mapping is
rejected because the same module/version is used under two module paths.

The adapter keeps its actual stack unexported; Start/ResetNetwork/Close provide
no Destroy, Wait, stack accessor or injection point. The inspected official dev
revision `3f8acd9da65b15b03ec66c7ecdb36759ebcdcc5d` retains these limitations.
This observation does not exclude every other possible upstream branch.

Fresh readonly compile probes reproduce the named-type mismatch and missing
Destroy method. Retaining a pre-created public link endpoint and calling its
Wait/Close after Stack.Close also leaves one eventfd per cycle on every tested
pair. NewGVisorStack constructs a different stack and is not an accessor.

The authorized boundaries require zero upstream patches, no private-field
access, no local fork/replace/vendor and minimal API adaptation. Completing the
migration requires a compatible public adapter or a separately scoped adapter
migration decision. That earlier restricted stage applied no production
dependency change; the current implementation decision above supersedes it.

## Alternatives considered

- Integration-only teardown on the old pin: complete public teardown still leaks.
- Candidate dependency with unchanged teardown: the 25-lifetime experiment leaks.
- Official mapping of old and new module names: actual Go module error.
- Internal-FD surgery/private access: violates owner/API boundaries and the
  explicit fix-stage constraints.
- Public-compatible adapter migration: requires a concrete contract/scope decision
  and the same complete regression gates before acceptance.

## Historical matched-pair compatibility review

At that earlier review checkpoint, the frozen pair and Go directive matched
official sing-box v1.14.1 `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Project go.mod/go.sum diffs were empty; failed dependency graphs were external.

All four official graph experiments use actual public sing-tun Close, a
NativeTun device in a disposable WSL network namespace and the preserved
Splicore QF-001 guard. They each run 25 cycles with default race/checkptr:

| sing-tun graph | Declared SagerNet gVisor | Eventfd delta | Total FD delta |
|---|---|---:|---:|
| frozen v0.9.3 | v0.0.0-20260727.0-sing-box-mod.1 | +25 | +25 |
| latest official tag v0.9.6 | same | +25 | +25 |
| dev v0.9.7-0.20261002083955-3f8acd9da65b | same | +25 | +25 |
| official sing-box testing, same tun commit/different sing graph | same | +25 | +25 |

All build; final goroutines return 1→1 and link workers are zero. No internal
StopFD release exists in the old pin, even with full Destroy. The inspected
sing-tun Close bodies do not call actual-stack Wait/Destroy or link Close.
Idle Close latency is recorded in the review, not an active-session guarantee.

Open PR #89 head `58afdaed45d9693601223c349b54479f613a8585` was exported from
official refs/pull/89/head and tested separately: eventfd 1→26, total FD 6→31,
goroutines 1→1, link workers zero. **NOT ADOPTED**. Its nil-forwarding guard
already exists in frozen v0.9.3; it supplies neither StopFD.Close nor full stack
completion. An unmerged official-module SHA lookup rejects this revision, so
the evidence harness ran as a subpackage of the exact upstream main-module
export without upstream edits, local replace or a Splicore dependency pin.

QF-001 remains byte-identical. All five original tests pass x25 in each of the
four complete Splicore scratch graphs (500 executions); four original guard
tests pass x25 in the standalone PR harness (100 executions). These observations
do not constitute feature or platform acceptance.

## Historical lane decisions and authorization (superseded)

- Lane A today: no safe matched migration in the inspected set.
- Lane B today: **IMPOSSIBLE WITH CURRENT PUBLIC API**; actual-stack completion
  is unavailable and retained public endpoint cleanup still leaks.
- Lane C: direct official gVisor scope is **HIGH**, potentially VERY HIGH for
  general sing-tun parity; assessment only, not recommended as a QF quick fix.
  It crosses TCP lazy handshake/net.Conn, UDP NAT/PacketConn, DNS return writers,
  packet references, Linux borrowed-FD/offload and Windows channel workers.

Review verdict: **UPSTREAM SING-TUN API CHANGE REQUIRED**. This can be a
strengthened implementation/contract of existing public Close, with no private
stack accessor. It must be paired with SagerNet's actual StopFD release path.
PR #89 alone is insufficient.

Future matched migration approval must name exact merged official tun and its
declared gVisor revisions, necessary graph/Go metadata changes and minimal
ownership adaptation. No qualifying pins can be supplied today. Direct official
gVisor implementation requires **EXPLICIT BROADER MIGRATION APPROVAL**; no fork,
source patches, copied upstream internals, private access or wire reimplementation
are authorized. This ADR does not initiate that work.

## Historical migration criteria and current rollback constraint

A successful future migration must audit necessary transitive metadata, preserve
QF-001 writer ownership, measure idempotent and recycled-FD-safe teardown, then
pass resource x25, original TUN traffic, lifecycle x10, a fresh 10-minute stress,
full Linux/native/shared race and safe Windows/arm64 gates.

Also rerun native protocols and client inbound coexistence, routing/DNS/policy,
all H15 regressions, distribution/SBOM and existing fuzz seed/underlay boundaries.
Only a later explicitly frozen joint-fix candidate may resume the fresh
60-minute Platform Qualification. Native Linux/Windows qualification limitations
remain unchanged by WSL evidence.

Returning to the old dependency reintroduces the proven graceful eventfd leak;
it cannot yield a qualified candidate. Historical Phase 15 commit
`75c0b0b8dedaf0e1a3d8580d6825235364963004` and all prior reports stay immutable.
This record does not authorize upstream source edits or resume qualification.

## Review triggers and evidence

Reopen this accepted decision if the owned stack/device lifecycle, exact
dependency or packet ownership contract changes. Implementation and review
gates have passed; this freeze does not certify any additional platform.

- [Current implementation-attempt report](../reports/QF_001_QF_002_QUALIFICATION_FIX_REPORT.md).
- [Compatibility migration review](../reports/QF_002_COMPATIBILITY_MIGRATION_REVIEW.md).
- Prior ownership evidence:
  `D:/splicore-validation/qf-002-eventfd-20261005/`.
- Compile/public-API and upstream-diff evidence:
  `D:/splicore-validation/qf-002-fix-20261005/`.
- Exact graph/PR exports, public-lifecycle x25 samples, scratch QF-001 race and
  repository integrity:
  `D:/splicore-validation/qf-002-migration-review-20261005/`.
