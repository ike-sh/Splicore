# Splicore Qualification Fix / Native TUN Freeze Report

- Documentation status: Canonical local freeze record
- Audience: Maintainers and requalification reviewers
- Last reviewed: 2026-10-05
- Owner: Splicore maintainer
- Responsibility: QF-001/QF-002/QF-003, Native TUN ownership and one forward candidate
- Lifecycle: Experimental local freeze; platform qualification is separate

## Status

**QUALIFICATION FIX FROZEN**

This report is prepared before exact-path staging and belongs to the one
authorized forward commit containing it. Freeze status applies when that
commit and its external Git closure checks succeed. An uncommitted copy is
not a frozen candidate. No self-referential hash, amend or second commit is used.

The maintainer explicitly declared REVIEW PASS and authorized this local freeze.
Freeze-stage implementation changes are **NONE**: all 1492 Go/module source
files match the accepted review snapshot. Documentation records the accepted
decision and new checkpoint. This is not a new feature phase or certification.

## Freeze Identity

- Freeze commit: **this commit**, the commit containing this report.
- Message: `feat(client): own native tun runtime and fix qualification blockers`.
- Sole parent: `75c0b0b8dedaf0e1a3d8580d6825235364963004`.
- Branch: `codex/qf-001-native-tun-iovec-race`.
- Reviewed manifest: **60 paths: 22 modified, 27 added, 11 deleted**.
- Actual commit hash, insertions/deletions, staged tree identity, clean worktree,
  empty index and post-commit artifacts are recorded externally after closure.

## Historical Base

Phase 15 frozen base is `75c0b0b8dedaf0e1a3d8580d6825235364963004`, message
`feat(core): harden unified runtime lifecycle and recovery`, sole parent
`7be20f14ccb59112c98f2fa07c0cab20a436bd88`. The base commit object, existing
historical reports and other refs are preserved. No amend/rebase/reset/squash
or history rewrite is part of this freeze.

## Scope

| Class | Included scope | Paths |
|---|---|---:|
| A | preserved QF-001 ownership/race regression and test-only guard | 2 |
| B | owned Native TUN runtime, device/client integration and old hidden stack removal | 17 |
| C | canonical isolated kernel TUN traffic/resource/stress tests | 2 |
| D | packet, flow, lifecycle, device and generation regression | 9 |
| E | exact official dependency and required Go/MVS metadata | 2 |
| F | QF-003 public pprof implementation/tests and obsolete private ABI removal | 10 |
| G | architecture, ownership, Accepted ADR and canonical navigation | 10 |
| H | QF/implementation reports and this freeze record | 5 |
| I | required CI/build minimum checks | 3 |

No external validation harness, scratch module, binary, generated profile,
PCAP, raw log, upstream scratch patch or unrelated dependency is staged.
Synthetic test fixtures inside canonical regression sources are intentional.

## Architecture

Production path: Client Runtime → **Splicore Native TUN Runtime** → exact
official gVisor public APIs. Splicore creates and owns the actual stack, NIC,
link, callbacks, packet workers and forwarding endpoints. It publishes handlers
before ingress, reserves callback ownership before asynchronous dispatch,
controls admission and waits for all borrowers before complete teardown.
This is an owned implementation, not a renamed hidden-stack wrapper.

Start publishes a backend under the lifecycle operation lock. Close cancels
admission, enters Drain, interrupts borrowed device I/O, drains the writer,
closes/joins flows and workers, calls public stack Destroy and closes the link
queue. Wait completes before host journal compensation releases the raw device.
Pending TCP acceptance uses a public endpoint-registration barrier and exact
tuple Abort; established connections preserve ordinary Close/queued reply.
Manager retains application sessions, generations, routing/policy/DNS ownership.

[ADR0036](../adr/0036-official-gvisor-eventfd-lifecycle.md) is Accepted for this
implemented local checkpoint. Earlier matched-pair proposals are explicitly
historical/superseded; they are not unresolved current architecture decisions.

## QF-001

Original shared mutable iovec backing array in NativeTun.WritePacket could have
concurrent writers. The active old device/hidden-stack path is replaced with
owned bytes, per-device synchronous writer admission and coordinated reject/
drain. No global data-path mutex, sleep/retry, panic recovery or unsafe fix.
Original five regression tests remain byte-identical and pass ×25 = **125**
executions. Native writer/packet/Close/lifecycle race suite passes ×25.

## QF-002

The old abstraction did not expose complete actual-stack resource ownership,
and retained a StopFD/eventfd across lifetimes. The owned channel packet link
does not create that per-lifetime eventfd. Splicore joins workers/reserved
callbacks/flows and executes public Destroy; the journal remains raw-FD owner.
Fresh pollable-FD ×25 and real kernel TUN ×25 show FD/eventfd delta=0 and stable
goroutines. Growth by a fixed amount per lifecycle is not accepted.

## QF-003

`experimental/libbox/internal/oomprofile` is **Class C retained tooling/test**,
not a shipped Splicore feature and not an orphaned package. Its real libbox/boxdd
callers remain. The original linker rejection was
`invalid reference to runtime/pprof.parseProcSelfMaps` on Go1.26.6.
Public `runtime/pprof.Lookup(name).WriteTo(file, 0)` replaces the custom private
snapshot builder. All **14** profiler runtime/pprof bindings and corresponding
mapping/protobuf copies are removed; no private target renaming/version table.

## Dependencies

| Dependency | Frozen change / decision |
|---|---|
| official gVisor | add `gvisor.dev/gvisor v0.0.0-20261004063249-f57b8fc79db4` |
| Exact commit | `f57b8fc79db4d392e8246d07e14c0c71e237afe8` |
| Module sum | `h1:gifqG0saAEtFgFur+Ezlr8U5Nl85VwE0qaQhyweiVmQ=` |
| go.mod sum | `h1:We1Jh3kDvpcx13qPcI0LTjx3U6pHpis/KFoU/UtJTkM=` |
| grpc | `v1.79.1` → `v1.80.0`, exact candidate requirement |
| go-jose/v4 | `v4.1.3` → `v4.1.4`, exact candidate requirement |
| genproto/googleapis/rpc | `v0.0.0-20251202230838-ff82c1b0f217` → `v0.0.0-20260401024825-9d38bb4040a9`, exact candidate requirement |
| sing-tun | `v0.9.3` unchanged; reusable inherited utilities/contracts outside active client TUN |
| SagerNet gVisor | `v0.0.0-20260727.0-sing-box-mod.1` unchanged for inherited users |
| Mieru | embedded official v3.38.0 unchanged |

Every go.mod change and all eight added go.sum lines are audited; old checksum
lines remain. No unrelated upgrade, local replace, fork, floating latest pin,
vendor/cache patch or broad go-get churn. Fresh `go mod verify`: PASS.
External sing-box/sing-tun/official or SagerNet gVisor/Mieru source changes=0;
protocol wire reimplementation=0. QF-003's inherited repository source cleanup
is explicitly distinguished from external upstream-module modifications.

## Go Baseline

Minimum **Go1.26.3**, required by the selected exact official gVisor go.mod.
Verification uses **Go1.26.6** on Linux and Windows. Root go.mod, CI matrix,
PowerShell build check, canonical package check and distribution docs agree.
The minimum is necessary, not retained solely because of a temporary exception.

## Native TUN / Ownership

| Resource | Owner | Release boundary |
|---|---|---|
| Linux raw TUN FD / Wintun adapter/session | host journal/platform/ownedWintun | Runtime.Wait then exact lease restoration/End |
| actual stack / NIC | owned backend | joined flows/workers then public Destroy |
| link / egress queue | owned backend | flow/worker join, Destroy/Close and queue drain |
| packet workers | Runtime/backend | context cancel, device Interrupt and Wait |
| ingress packet payload | receive worker → stack references | copy before handoff; drop worker ref after InjectInbound |
| egress bytes / writer | link → owned queue → synchronous writer | immutable snapshot; syscall return or drain |
| TCP/UDP endpoints and callback reservations | backend tracked flow | reject/Close/Complete, callback/dispatcher join |
| application sessions | Client Manager | finishFlow and Manager join |
| backend pollers/internal resources | actual stack / process-wide Go poller | Destroy; no backend per-lifetime eventfd |
| route/address/system-proxy lease | durable host journal | exact reverse restore after borrowers join |
| DNS interception | admitted query/stream and DNS Engine | cancel/join before snapshot release |
| generation reference | Manager / per UDP DNS query or TCP stream | joined cancellation/connection cleanup, dispatcher/query return |

Owner UNKNOWN=0. [Full ownership table](../architecture/TUN_RUNTIME_OWNERSHIP.md)
and [runtime architecture](../architecture/NATIVE_TUN_RUNTIME.md) match source.
UDP DNS acquires per-query current generation; TCP retains stream generation.
The backend does not create independent underlay sockets or another control plane.
GSO, DoH and FakeIP limits remain unchanged; no new user backend selector.

## Resource Stability

Fresh fast gate: `TestNativeCompleteLifetimeFD25x` (inside package ×25).
Each invocation checks 25 complete borrowed pollable-FD lifetimes: FD **6→6**,
eventfd **1→1**, goroutines **2→2**. All logged invocations preserve strict counts.

Fresh isolated real TUN ×25, measured equivalent STOPPED state each cycle:

| Resource | Start | Peak sampled | End |
|---|---:|---:|---:|
| Goroutines | 6 | 46 | 6 |
| FDs | 14 | 39 | 14 |
| Eventfds | 1 | 1 | 1 |
| RSS KiB | 102704 | 157228 | 154140 |
| Listeners | 2 | 2 | 2 |
| Sessions | 0 | 8 | 0 |
| Generations | 1 | 1 | 1 |
| Leases | 1 | 1 | 1 |
| Host generations/interfaces | 0/0 | 1/1 | 0/0 |
| Journal temporaries | 0 | 0 | 0 |

The disabled generation/lease and journal FD belong to the stopped Manager;
closed-state comparison releases them. RSS is retained race-process memory;
this gate does not require RSS equality or certify performance. Peak is sampled,
not a continuous global maximum. No fixed lifecycle growth allowance is used.

## Race / Checkptr

| Fresh Freeze gate | Result / duration |
|---|---|
| `go test -race -count=1 -v -timeout 600s ./...` | PASS, 143.13s |
| full native `with_gvisor,with_quic,with_utls` race | PASS, 194.52s |
| canonical common/adapter/transport shared race | PASS, 35.19s |
| Native TUN package race ×25 | PASS, 15.79s |
| Original QF-001 ×25 =125 executions | PASS, 28.50s |
| QF-003 profiler race/format/labels/error tests | PASS, 7.33s |
| Windows default safe suite | PASS, 40.92s |
| Windows native safe suite | PASS, 76.18s |

Default checkptr remains enabled. No package exclusion, skip flag, race=false,
checkptr/linker-check bypass, sleep/retry workaround or panic recovery.
Windows race NOT EXECUTED: existing environment lacks CGO/race prerequisites.
Staged compile/key unit/native race/profiler/short real-TUN gates are executed
on an export of the final index before commit; closure records their exact tree.

## Real TUN

**FREEZE-STAGE RERUN**, actual kernel TUN in owned disposable WSL mount/network
namespaces, 25 measured lifetimes plus warm lifetime: PASS, 229.34s gate wall time.
Start, IPv4/IPv6 TCP/UDP, DNS TCP/UDP, route/policy/proxy DNS, Stop and Restart
are exercised. Strict each-cycle resource checks pass; external DNS escape
counters TCP=0/UDP=0. No parent host routes or Windows network settings changed.
The final staged source receives an additional short isolated original TUN/
provider smoke; its PASS is required for external commit closure.

## Stress

**REUSED FROM REVIEW**, not accumulated or renamed Freeze runtime.
Native TUN/application/client/host/module Go source is identical to that run;
entry hashes and original evidence hashes are recorded externally.
Active **10m07.717498492s**, wall **10m20.489118763s**, 369 rounds; 5904 TCP,
5904 UDP, 47232 UDP echoes, 5904 DNS replies. Workload errors=0, DNS escapes=0.
STOPPED FD14/eventfd1/goroutine6 stay stable; CLOSED FD13 matches an independent
CLOSED baseline. Original retained RSS/performance limits remain in force.
No fresh 10-minute or 60-minute Platform Qualification soak is claimed.

## Protocol Regression

Fresh full native regression includes `TestPhase11NativeSelfInteropMatrix`,
`TestNativeVLESSSecurityAndSharedNode`, `TestVLESSNonVisionDefaultRaceTraffic`
and owned engine/server/client lifecycle suites: **Snell, Hysteria2, TUIC,
VLESS plain/TLS/REALITY, Mieru, DIRECT and REJECT PASS**.
Local synthetic fixtures and existing protocol wire behavior are preserved.
Vision remains **DEFERRED / UNSUPPORTED**.

## Routing / DNS / Policy

Fresh `TestPhase12RoutingDNSPolicyAcceptance` and matcher/group/generation/DNS
regression PASS. The real TUN gate traverses TUN → routing → policy → selected
outbound and preserves DNS query/stream ownership. Domain/CIDR, Selector,
URL-Test/Fallback/Load-Balance, affinity, bootstrap/System/UDP/TCP/verified DoT,
cache and cancellation contracts remain intact.

## Phase 15 Regression

| Finding | Fresh full native coverage | Result |
|---|---|---|
| H15-001 | HTTP shutdown, forced handler join, readiness failure | PASS |
| H15-002 | closed/stale/concurrent candidate consumption, snapshot lifecycle | PASS |
| H15-003 | System bootstrap owner, health/DNS cancellation | PASS |
| H15-004 | late provider failure/success, provider/RuleSet revision | PASS |
| H15-005 | concurrent SQLite Close/install release | PASS |
| H15-006 | support cancellation and projection cleanup | PASS |
| H15-007 | stopped native handle rejects stale activation | PASS |
| H15-008 | journal temporary/permissions/symlink/process crash recovery | PASS |
| H15-009 | native diagnostics/failures/passive health | PASS |

All full-suite tests run without exclusions. Exact test/subtest evidence is
in external `regression-coverage.json`, bound to this source snapshot.

## Underlay / Xray Boundary

Fresh production egress audit: **55 surfaces, Unknown=0**.
Xray reference classification: **E active runtime/control=0, F suspicious=0,
G ClientProfile=10** (actual count). FinalMask runtime=0, Sudoku runtime=0.
No external Xray/sing-box process or artifact dependency is introduced.

## QF-003 Tooling / Compatibility

Fresh `go list -deps -json` on default/native Linux amd64, Windows amd64 and
Linux arm64: **libbox/oomprofile NOT REACHABLE**. Actual production binary nm
has zero libbox/oomprofile symbols. Fixed-identity three-platform rebuilds have
the same SHA256 as reviewed QF-003 builds: byte-identical PASS.

Six supported names remain heap/goroutine/allocs/threadcreate/block/mutex.
Fresh public writer generation and `go tool pprof -top -symbolize=none` parse:
**all PASS**. Output is **standard gzip-compressed pprof protobuf**, changed
from raw custom protobuf; `.pb` names and caller interfaces remain. Capture
allocates/compresses and is best effort under memory pressure. No forced GC or
OOM-recorder policy change. Canonical technical reports accurately record the
format change; no product CLI/help/MIME contract claims a proprietary format.

Remaining repo linknames are classified: **41** retained, one production-selected
inherited x/net HTTP/2 hook, zero production-selected repository private Go
runtime hooks. Other tags/platform hooks and dependency-owned hooks remain
separate inventories; QF-003 does not claim they have all been removed or
grant a general architecture exception. External dependency sources are intact.

## Distribution / Reproducibility

Fresh Linux amd64, Windows amd64 and Linux arm64 native builds: **PASS**.
One Splicore daemon, no external Xray/sing-box binary or patched runtime.
Actual production modules/build graphs and fixed-identity binary hashes match
the review. Comparison binaries avoid timestamp/provenance variations; no
future commit hash is invented.

After the local commit, the canonical package script is run in **two separate
clean detached worktrees of this commit**, with the same explicit development
version and commit-time SOURCE_DATE_EPOCH. Their three artifacts, metadata,
licenses/checksums and source archives are compared and recorded externally.
These are local candidate materials, not a tag, release or certification.
Real post-commit hashes and source provenance belong in the external closure
record, not an amend of this report. Scratch outputs remain outside Git.

## Platform Limits / Qualification Status

**Platform Qualification must be resumed against this new frozen commit.**

It is **NOT RESUMED** by this freeze. Old Phase 15 qualification results are
historical/reference evidence, not this candidate's qualification identity.
Every affected subsequent certification must bind to this new commit and rerun
its core campaign; only source-independent environment records may be reused.

- Real destructive Windows TUN/auto-route/WinINET qualification: PENDING.
- Native Ubuntu host-network qualification: PENDING; WSL isolation is local evidence.
- Linux arm64 runtime qualification: NOT CERTIFIED, build-only.
- Windows race: NOT EXECUTED; prerequisite limitation retained.
- No 60-minute soak, qualification resume or NoBrand migration.

## Historical / Git Integrity

The Phase 15 object and its sole parent remain immutable. Phase 14/15 and
Phase 6/7 historical freeze reports are not edited. QF implementation/review
reports keep their earlier evidence; current navigation points to this freeze.

Only the reviewed 60 exact paths are staged. Actual staged blobs must match
this manifest and pass secret scan (0 real, 0 unresolved). Index export smoke
must pass before committing. The sole parent must be the Phase 15 frozen SHA.
Successful closure requires worktree CLEAN and index EMPTY; no automatic second
commit is authorized. These postconditions are recorded externally.

## Final Qualification Fix Freeze Manifest

M=modified, A=added, D=deleted. Each path below is audited by scope and review
provenance. Content/object hashes and exact staging arguments are in the
external `freeze-manifest.json` / `staged-manifest.json` records.

| Path | Change | Class | Audit |
|---|---|---|---|
| `.github/workflows/test.yml` | M | I | required CI/build minimum checks |
| `README.md` | M | G | architecture/ownership/ADR/canonical navigation |
| `docs/DISTRIBUTION.md` | M | G | architecture/ownership/ADR/canonical navigation |
| `docs/README.md` | M | G | architecture/ownership/ADR/canonical navigation |
| `docs/adr/0036-official-gvisor-eventfd-lifecycle.md` | A | G | architecture/ownership/ADR/canonical navigation |
| `docs/adr/README.md` | M | G | architecture/ownership/ADR/canonical navigation |
| `docs/architecture/CLIENT_RUNTIME.md` | M | G | architecture/ownership/ADR/canonical navigation |
| `docs/architecture/FORK_BOUNDARY.md` | M | G | architecture/ownership/ADR/canonical navigation |
| `docs/architecture/NATIVE_TUN_RUNTIME.md` | A | G | architecture/ownership/ADR/canonical navigation |
| `docs/architecture/TUN_RUNTIME_OWNERSHIP.md` | A | G | architecture/ownership/ADR/canonical navigation |
| `docs/development/README.md` | M | G | architecture/ownership/ADR/canonical navigation |
| `docs/reports/NATIVE_TUN_RUNTIME_IMPLEMENTATION_REPORT.md` | A | H | canonical QF/implementation/freeze evidence summary |
| `docs/reports/QF_001_QF_002_QUALIFICATION_FIX_REPORT.md` | A | H | canonical QF/implementation/freeze evidence summary |
| `docs/reports/QF_002_COMPATIBILITY_MIGRATION_REVIEW.md` | A | H | canonical QF/implementation/freeze evidence summary |
| `docs/reports/QF_003_PRIVATE_RUNTIME_LINKNAME_RESOLUTION_REPORT.md` | A | H | canonical QF/implementation/freeze evidence summary |
| `docs/reports/QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md` | A | H | canonical QF/implementation/freeze evidence summary |
| `experimental/libbox/internal/oomprofile/builder.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/defs_darwin_amd64.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/defs_darwin_arm64.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/linkname.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/mapping_darwin.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/mapping_linux.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/mapping_windows.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/oomprofile.go` | M | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/oomprofile_test.go` | A | F | public pprof replacement/format regression/obsolete private ABI removal |
| `experimental/libbox/internal/oomprofile/protobuf.go` | D | F | public pprof replacement/format regression/obsolete private ABI removal |
| `go.mod` | M | E | exact official gVisor + required Go/MVS metadata |
| `go.sum` | M | E | exact official gVisor + required Go/MVS metadata |
| `internal/splicore/application/native_tun_lab_linux_test.go` | A | C | canonical isolated TUN traffic/resource/stress regression |
| `internal/splicore/application/qf001_tun_lab_linux_test.go` | A | C | canonical isolated TUN traffic/resource/stress regression |
| `internal/splicore/clientruntime/host.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/clientruntime/native_tun_test.go` | A | D | device/borrower/generation/shutdown regression |
| `internal/splicore/clientruntime/qf001_gvisor_test.go` | A | A | preserved original iovec race/ownership regression and test-only guard |
| `internal/splicore/clientruntime/qf001_legacy_guard_test.go` | A | A | preserved original iovec race/ownership regression and test-only guard |
| `internal/splicore/clientruntime/status.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/clientruntime/tun.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/clientruntime/tun_stack_gvisor.go` | D | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/clientruntime/tun_stack_stub.go` | D | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/clientruntime/tun_status_gvisor_test.go` | A | D | device/borrower/generation/shutdown regression |
| `internal/splicore/hostnetwork/capabilities.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/hostnetwork/device_linux.go` | A | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/hostnetwork/devices_test.go` | M | D | device/borrower/generation/shutdown regression |
| `internal/splicore/hostnetwork/native_device_test.go` | A | D | device/borrower/generation/shutdown regression |
| `internal/splicore/hostnetwork/platform_linux.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/hostnetwork/platform_other.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/hostnetwork/platform_windows.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/hostnetwork/wintun.go` | M | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/hostnetwork/wintun_gvisor_windows.go` | D | B | owned TUN/device/runtime integration; replace hidden old stack |
| `internal/splicore/nativetun/backend_gvisor.go` | A | B | Splicore-owned runtime/backend/packet/TCP integration |
| `internal/splicore/nativetun/backend_gvisor_test.go` | A | D | native packet/flow/lifecycle/resource regression |
| `internal/splicore/nativetun/backend_stub.go` | A | B | Splicore-owned runtime/backend/packet/TCP integration |
| `internal/splicore/nativetun/backend_stub_test.go` | A | D | native packet/flow/lifecycle/resource regression |
| `internal/splicore/nativetun/ingress_gvisor.go` | A | B | Splicore-owned runtime/backend/packet/TCP integration |
| `internal/splicore/nativetun/ingress_gvisor_test.go` | A | D | native packet/flow/lifecycle/resource regression |
| `internal/splicore/nativetun/resources_linux_test.go` | A | D | native packet/flow/lifecycle/resource regression |
| `internal/splicore/nativetun/runtime.go` | A | B | Splicore-owned runtime/backend/packet/TCP integration |
| `internal/splicore/nativetun/runtime_test.go` | A | D | native packet/flow/lifecycle/resource regression |
| `internal/splicore/nativetun/tcp_gvisor.go` | A | B | Splicore-owned runtime/backend/packet/TCP integration |
| `scripts/splicore-build.ps1` | M | I | required CI/build minimum checks |
| `scripts/splicore-package.py` | M | I | required CI/build minimum checks |

## Secret Scan

Final intended source/docs/tests/go.mod/go.sum and actual staged blobs:
**0 real secrets, 0 unresolved findings** required. Synthetic test credentials
are allowed. External reports store findings/counts without exposing secrets.

## Blockers

**NONE** after the required freeze, staged and Git closure gates pass.
Environment/platform qualification limits above remain explicit.

## Actions Not Performed

- push: NO
- tag: NO
- release: NO
- Platform Qualification: NOT RESUMED
- NoBrand migration: NOT STARTED
- history rewrite: NO

Evidence root: `D:/splicore-validation/qualification-fix-native-tun-freeze-20261005/`.
Original review/stress/raw failure evidence remains in its original directories.
The external closure record supplies actual commit identity, command exits,
hashes, staged candidate provenance and reproducible artifacts.

**QUALIFICATION FIX FROZEN**
