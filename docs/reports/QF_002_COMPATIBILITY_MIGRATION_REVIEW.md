# Splicore QF-002 Compatibility Migration Review

- Documentation status: Review evidence
- Audience: Maintainers and dependency migration reviewers
- Last reviewed: 2026-10-05
- Owner: Core maintainers
- Responsibility: Select a maintainable QF-002 migration direction without production implementation.
- Evidence root: `D:/splicore-validation/qf-002-migration-review-20261005/`

## Verdict

This report captures the earlier restricted compatibility review. Its matched
pair findings and approval boundaries are historical. The later explicitly
authorized owned Native TUN implementation supersedes that proposed migration;
the [Qualification Fix freeze](QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md)
records the new candidate. Earlier graph/Go/Git statements below refer to this
review checkpoint, not the final frozen worktree.

**UPSTREAM SING-TUN API CHANGE REQUIRED**.

Every tested official matched pair leaks **25 eventfds and 25 total FDs over
25 lifetimes**, using actual public sing-tun lifecycle calls. PR #89 has the same
result. No safe matched dependency migration is available in the inspected
release/dev/testing set as of this review.

The required upstream change can strengthen the existing public `Close`
contract internally; exporting a private stack accessor is not required. It
must be paired with a SagerNet gVisor revision containing a real StopFD release
path. Fixing only nil forwarding, or only the gVisor allocation side, is
insufficient. The already verified official Google fix provides the release
direction, not a compiling sing-tun migration.

Main recommendation: obtain and validate an **official matched SagerNet pair
with complete public Close semantics**, then seek approval for that exact pair.
This review stops before implementation. Platform Qualification remains paused.

## Frozen Base

| Item | Exact identity |
|---|---|
| Phase 15 frozen HEAD | `75c0b0b8dedaf0e1a3d8580d6825235364963004` |
| Sole parent | `7be20f14ccb59112c98f2fa07c0cab20a436bd88` |
| Branch | `codex/qf-001-native-tun-iovec-race` |
| Derived sing-box baseline | official `v1.14.1`, `1ac1a339cb1223e9c70eae14c44411c75033c02d` |
| sing-tun | `v0.9.3`, `be4ce8d320a5e466a42322b46b40fffadfc1510e` |
| SagerNet gVisor | `v0.0.0-20260727.0-sing-box-mod.1`, `e9989ea3436fa7e226f61a2bcd64f38fb42b23d4` |
| Project Go declaration | `1.25.5` |
| Relevant TUN tag | `with_gvisor`; full scratch probes also use `with_quic,with_utls` |

Baseline alignment: **A. EXACTLY ALIGNED** for the sing-tun/gVisor pair and Go
directive. The fresh official tag go.mod agrees with frozen and current
Splicore. This statement does not claim that every other Splicore dependency
or source file equals upstream.
[Official sing-box v1.14.1 manifest](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/go.mod).

## Current Worktree

Entry and final HEAD/branch are unchanged; index is **EMPTY**. At entry:

```text
 M docs/adr/README.md
 M docs/architecture/CLIENT_RUNTIME.md
 M internal/splicore/clientruntime/tun_stack_gvisor.go
?? docs/adr/0036-official-gvisor-eventfd-lifecycle.md
?? docs/reports/QF_001_QF_002_QUALIFICATION_FIX_REPORT.md
?? internal/splicore/application/qf001_tun_lab_linux_test.go
?? internal/splicore/clientruntime/qf001_gvisor_test.go
```

The attachment described experimental go.mod/go.sum changes. **Actual entry
diffs for both files are empty**. Previous rejected graphs are external probes;
there is no production upgrade to preserve or revert. This review preserves
the QF-001 implementation/tests and previous report byte for byte.

`entry.json`, `snapshot/entry.diff`, copied entry files and frozen manifests
preserve the starting state. Existing eventfd/fix evidence is hashed in the
entry manifest. Historical qualification evidence is checked against its
preserved manifest; QF-001 evidence is retained and separately hashed.
No previous report is overwritten.

This review changes only this report, Proposed ADR 0036 and its navigation text.
All new experiments reside outside the repository. A frozen source export has
only the three explicitly recorded QF-001 source/test files copied into it;
candidate graphs use separate external `-modfile` files.

## Current Dependency Topology

### sing-tun

**DEPENDENCY_TOPOLOGY_BEFORE**: frozen/current root directly requires
`github.com/sagernet/sing-tun v0.9.3`; that module declares the matching SagerNet
gVisor pin. The root selects `github.com/sagernet/sing v0.9.4` by MVS, above
sing-tun's declared minimum. Actual adapter: `tun.NewStack("gvisor", ...)`.

Fresh discovery found latest official tag **v0.9.6**, current official dev
`3f8acd9da65b15b03ec66c7ecdb36759ebcdcc5d`, and sing-box testing
`2ff3985c0a8fd628ab10b9ec9cd3d37512909c57`. Dev and testing use the same tun
commit but different sing versions, so both graphs were exercised separately.
GitHub releases API returned no release objects; v0.9.6 is the latest published
tag, not an invented newer release.

### sagernet/gvisor

Frozen/current and every selected tun candidate declare
`github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1`.

- Commit: `e9989ea3436fa7e226f61a2bcd64f38fb42b23d4`.
- Module sum: `h1:IdQ7yTKkB2wv8txwshxUroPlO4npOYAV71xb7xQ7Lys=`.
- go.mod sum: `h1:9O3SQskYuCfdHNvHEsWuEAgoyKEF74PiWp4NsNUia8g=`.
- Module Go minimum: `1.25.0`.

No arbitrary tun/gVisor combination was tested. Inspection of official tun
main/wip also found this pin; stable is an older Go 1.20/2024 gVisor line,
not a newer migration candidate. This review does not claim exhaustive runtime
coverage of every historical tag or experimental branch.

### Go

Project declaration remains **1.25.5**. Experiments used **Go 1.26.6 linux/amd64**,
CGO enabled, GOMAXPROCS 4, WSL Ubuntu 24.04/kernel 6.6.87.2. Host Windows has
**Go 1.26.2**. No toolchain installation or project minimum change occurred.

The already authorized minimum **1.26.3** exception remains available for the
verified official candidate; it is not rescinded merely because current
SagerNet pairs declare a lower minimum. A future decision must record its
actual selected graph; later Windows migration gates must verify Go >=1.26.3
under the already authorized baseline.

**FAILED_EXPERIMENT_TOPOLOGY**, historical and preserved externally:

| Probe | Exact attempted graph / result |
|---|---|
| Type compatibility | old tun/SagerNet graph plus `gvisor.dev/gvisor v0.0.0-20261004063249-f57b8fc79db4`; `NewEndpoint` signature mismatch |
| Official module alias | same official module used for two module paths; Go resolver rejection |
| Actual-stack access | `(*tun.GVisor).Destroy` does not exist |
| Go minimum | external 1.25.5 readonly build requires metadata update; changing only its directive to 1.26.3 builds |

Official candidate commit: `f57b8fc79db4d392e8246d07e14c0c71e237afe8`, timestamp
`2026-10-04T06:32:49Z`, minimum Go 1.26.3. Sum
`h1:gifqG0saAEtFgFur+Ezlr8U5Nl85VwE0qaQhyweiVmQ=`; go.mod sum
`h1:We1Jh3kDvpcx13qPcI0LTjx3U6pHpis/KFoU/UtJTkM=`. It is not the current root
requirement. Exact historical error logs remain under
`D:/splicore-validation/qf-002-fix-20261005/logs/`.

## Module Identity Blocker

`github.com/sagernet/gvisor/...` and `gvisor.dev/gvisor/...` resolve different
packages and declarations. Matching spelling/layout does not make their
defined types identical. A method implementing an interface must have the
required signature, including its return types. Structural resemblance of
endpoint interfaces does not make these `NewEndpoint` method signatures equal.
[Go specification: type identity](https://go.dev/ref/spec#Type_identity).

Fresh external readonly compile probe, default race/checkptr, rejects:

```text
*officialTun does not implement tun.GVisorTun (wrong type for method NewEndpoint)
have NewEndpoint() ("gvisor.dev/gvisor/pkg/tcpip/stack".LinkEndpoint,
                   "gvisor.dev/gvisor/pkg/tcpip/stack".NICOptions, error)
want NewEndpoint() ("github.com/sagernet/gvisor/pkg/tcpip/stack".LinkEndpoint,
                   "github.com/sagernet/gvisor/pkg/tcpip/stack".NICOptions, error)
```

Fresh public-access probe also rejects `s.Destroy undefined (type *tun.GVisor
has no field or method Destroy)`. Exact source/manifests and full diagnostics
are in external `module-path-probe/`, `public-destroy-probe/` and
`logs/*-fresh.log`.

The preserved alias error is: `gvisor.dev/gvisor@v0.0.0-20261004063249-f57b8fc79db4
used for two different module paths (github.com/sagernet/gvisor and
gvisor.dev/gvisor)`. That mapping trick was not repeated or proposed as a
production solution.

## Lane A — Matched SagerNet Pair

All rows below use the exact same external harness, the actual NativeTun
constructor/Start and public sing-tun Stack Start/Close. The unchanged
Splicore QF-001 guard owns the endpoint writer. Each process uses a disposable
`unshare --net` namespace, verifies it differs from its parent, warms process
poller/constructor resources, and executes **25 cycles** with GSO disabled.
Splicore's active Linux TUN setup uses this non-GSO path.

Define **G** = `v0.0.0-20260727.0-sing-box-mod.1` below.

| sing-tun | gvisor | Go | Build | Eventfd Δ25 | FD Δ | Adaptation |
|---|---|---|---|---:|---:|---|
| frozen `v0.9.3` / `be4ce8d320a5` | G | tun/G 1.25.0; root 1.25.5 | PASS | +25 | +25 | No source adaptation; FAIL resource gate |
| latest tag `v0.9.6` / `ddaa4ca25e3b` | G | tun/G 1.25.0 | PASS | +25 | +25 | No source adaptation; FAIL resource gate |
| dev `v0.9.7-0.20261002083955-3f8acd9da65b` | G | tun/G 1.25.0 | PASS | +25 | +25 | No source adaptation; FAIL resource gate |
| sing-box testing, same tun commit | G | box root 1.25.5 | PASS | +25 | +25 | Separate declared sing graph; FAIL resource gate |

The latest tag full commit is `ddaa4ca25e3bcb776d6ce81f4477b3becb5426de`.
Dev full commit is `3f8acd9da65b15b03ec66c7ecdb36759ebcdcc5d`.
Each row builds the lifecycle harness with `-race -tags with_gvisor` and
Splicore clientruntime/hostnetwork/application with native tags. All four
Splicore scratch graphs compile without source adaptation. Their go.mod/go.sum,
selected module graphs, checksums and per-pair metadata are retained externally.

Declared sing selections in the harness:

| Graph | sing |
|---|---|
| frozen | `v0.9.4`, official box graph |
| v0.9.6 | `v0.8.12-0.20260717023913-84ab32b56cb8`, own declaration |
| dev | `v0.9.5-0.20260917142815-f37989cadbf0`, own declaration |
| testing | `v0.9.7-0.20260929150544-6f21f2425a95`, official box testing graph |

For Splicore compile/race probes, frozen selections remain in the scratch
modfiles unless the upstream candidate requires a higher MVS selection;
testing explicitly uses its declared sing selection. No unrelated production
graph changes occurred.

### Resource and shutdown observations

| Graph | Eventfd start/end | FD start/end | Goroutines start/end | Final link workers | Public Close min/median/max (µs) |
|---|---:|---:|---:|---:|---:|
| frozen | 1 / 26 | 6 / 31 | 1 / 1 | 0 | 104.39 / 121.89 / 207.76 |
| v0.9.6 | 1 / 26 | 6 / 31 | 1 / 1 | 0 | 98.47 / 116.86 / 185.37 |
| dev | 1 / 26 | 6 / 31 | 1 / 1 | 0 | 102.12 / 118.44 / 157.79 |
| testing | 1 / 26 | 6 / 31 | 1 / 1 | 0 | 94.29 / 127.39 / 211.20 |

Snapshots are recorded before allocation, while active, immediately after
actual public Close, after separate caller-owned public endpoint Wait/Close,
and after device owner Close. Public Close reaches exactly one literal nil
detach, **zero link Close calls and zero link Wait calls** through the observed
endpoint. Additional public endpoint cleanup is explicitly separate and still
leaks. No internal eventfd is closed by the harness. Each cycle retains one
new distinct eventfd identity; all 25 remain in the final process sample.

These are idle lifecycle shutdown measurements, not active-session latency
guarantees. The QF-001 wrapper supplies idempotency; this does not prove raw
upstream Close is concurrently safe or idempotent. Process exit eventually
reclaims leaked FDs and is not an acceptance mechanism. Observer exit 0 means
the experiment completed; every resource verdict is **FAIL**.

### Close and compatibility audit

Frozen/latest/dev/PR Close bodies are equal: forwarders close, endpoint detaches,
the private actual stack receives Close, and cleanup endpoints Abort. None calls
its actual stack Wait/Destroy. With the old gVisor pin, fdbased Close is empty
and StopFD has no Close method. The earlier full-Destroy experiment still
leaks +25, proving that adding Wait alone on this pin cannot fix QF-002.
[Official dev lifecycle source](https://github.com/SagerNet/sing-tun/blob/3f8acd9da65b15b03ec66c7ecdb36759ebcdcc5d/stack_gvisor.go).

Constructors, GVisorTun endpoint/PacketBuffer types, Handler callbacks and
Stack Start/ResetNetwork/Close signatures remain usable in the tested Linux
Splicore path. No candidate offers the missing actual-stack completion contract.
Dev adds options and changes default NewStack selection to the upstream Go
stack; Splicore explicitly selects gvisor. Darwin BatchRead gains headroom
parameters. Dev also changes forwarding stages and removes the local-interface
exclusion from UDP NAT setup. These are **C: behavioral/platform changes to
review**, even where compilation needs no A/B adaptation. No wire equivalence
or broad platform acceptance is claimed from these probes.

The GSO linuxTUNEndpoint has its own BatchRead loop; its Attach(nil) updates a
dispatcher rather than supplying a public join for that loop. This separate
future teardown concern was source-audited, not exercised or fixed. It must
not be silently included in a non-GSO lifecycle pass.

Reproduction command and all raw samples: external `main.go`, `owner.go`,
`run-review.py`, `candidates/`, `logs/*-lifecycle-x25.jsonl`,
`candidate-summary.json`. `source-audit.json` and directed diffs record exact
source hashes and the compatibility observations.

## PR #89 Evidence (NOT ADOPTED)

**NOT ADOPTED**. Official pull request is open/unmerged at discovery.

- Head: `58afdaed45d9693601223c349b54479f613a8585`.
- Current API base: `837976228ca2d772647a215c46384094311b5aaf`.
- Head parent: `98e457e39c90754d2751226bc31bfce48b8b40aa`.
- Head timestamp: `2026-09-03T13:06:25Z`.
- Provenance: fetched official `SagerNet/sing-tun` **refs/pull/89/head**; verified
  FETCH_HEAD equals API head, then exported the exact unmodified source tree.
- Head's own gVisor requirement: **G**; Go 1.25.0.
- Build with default race/checkptr: **PASS**.
- Eventfd x25: **1→26 (+25)**; total FD **6→31 (+25)**.
- Goroutines **1→1**, final link workers **0**.
- Public Close min/median/max: **95.65 / 122.50 / 228.19 µs**.
- Resource gate: **FAIL**.

The head commit adds a nil-forwarding guard and two tests. Frozen v0.9.3 already
has the same guard; the directed diff against it adds comments only in that
function. The PR does not add StopFD.Close, actual stack Wait/Destroy, or link
resource release. It identifies a detach direction for older source, and does
**not** identify a complete fix for this frozen QF-002 instance.
[PR #89](https://github.com/SagerNet/sing-tun/pull/89),
[exact head diff](https://github.com/SagerNet/sing-tun/commit/58afdaed45d9693601223c349b54479f613a8585).

The current PR comparison also includes older Android-related ancestry because
dev was force-pushed. Those files are not treated as part of the narrow head
fix. Both current comparison and exact head-to-parent diff are preserved.

The unmerged SHA is not resolvable as a normal official-module requirement:
Go reports `unknown revision 58afdaed45d9693601223c349b54479f613a8585`.
Instead, the evidence harness is an added subpackage of the exact exported
upstream **main module**, using external `-modfile` metadata. Its upstream
source/manifests are unchanged. No local replace, module rename, fork,
vendor patch or Splicore pin was introduced. Full Splicore compilation against
an unresolvable official module version is **NOT EXECUTED**; four extracted
unchanged QF-001 guard tests ran x25 in that standalone harness.

Evidence: `pr89-provenance.json`, `discovery/pr89*.json`, `discovery/pr89.patch`,
`pr89-source/`, `run-pr89.py` and `logs/pr89-*` in the external evidence root.

## Lane B — Public Adapter

**LANE B IMPOSSIBLE WITH CURRENT PUBLIC API** for the tested graphs.

The public Stack contract offers Start, ResetNetwork and Close. GVisor owns the
actual stack privately. Public NewGVisorStack helpers construct a **different**
stack; they do not return the stack created by GVisor.Start. An adapter cannot
call Destroy/Wait on the actual stack through that interface.

Splicore can publicly retain its pre-created link endpoint, serialize writers
and call that endpoint's Wait/Close. This experiment does exactly that after
observing actual Stack.Close, and retains +25 eventfds. The old endpoint Close
contains no release logic. Taking ownership of a second newly constructed
stack or using finalizers would not repair this object's teardown.

No reflection, unsafe, linkname, private accessor, direct internal-FD close,
fork, source patch or copied internal implementation is a valid adapter solution
within this review's constraints. No Lane B production adapter was written.

## Lane C — Direct gVisor

**Scope assessment only: HIGH**, potentially **VERY HIGH** if expanded into
general sing-tun parity. It is not recommended as a QF quick fix.

The verified official candidate's bare-stack full Destroy experiment has
eventfd Δ25=0; that proves a usable release mechanism, not a complete Splicore
integration. Earlier current-equivalent Close still produced +25.
[Official eventfd fix](https://github.com/google/gvisor/commit/b11702b3c511622436e4733a7f5552b9fcdc73b0).

Actual sing-tun services surrounding the current adapter:

| Service | Audited upstream surface | Splicore binding / migration obligation |
|---|---|---|
| Stack/NIC/protocol setup | stack_gvisor.go | IPv4/IPv6, TCP/UDP/ICMP, route table, spoofing/promiscuous flags, SACK/buffer/recovery settings |
| Link and device integration | tun_linux_gvisor.go; Darwin/Windows counterparts | fdbased borrowed FD, checksum/offload/MTU, GSO BatchRead, platform reader interruption and join |
| Packet classification/filter | stack_gvisor_filter.go; flow_dispatch.go and flow helpers | JudgeFlow, broadcast handling, DNS classification, return writer lifetime; general Port/NAT modes are broader than current Splicore use |
| TCP adaptation | stack_gvisor_tcp.go, stack_gvisor_lazy.go, stack_gvisor_tcp_conn.go | public TCP forwarder, lazy handshake/rejection/cancellation, net.Conn deadlines/half-close, waiter/error translation, buffer ownership |
| UDP adaptation | stack_gvisor_udp.go; udp_nat.go, udp_nat_cleanup.go | source/destination flow ownership, N.PacketConn/N.PacketWriter callbacks, packet references, NAT limits/timeouts/mapping/filtering/reset |
| DNS hooks | flow_dns.go; UDP forwarder/backwriter | owned DNS request copy before asynchronous callback; return writer valid through reply/cancellation; TCP DNS keeps framing behavior |
| ICMP/rejection | stack_gvisor_icmp.go; flow_reject.go | Splicore currently rejects non-TCP/UDP via JudgeFlow; preserve that policy and error behavior without introducing new capability |
| Lifecycle | GVisor.Close, forwarder/NAT Close | stop admission, reject/drain writes, stop/join actual link and transport workers, remove NIC, Close internal StopFD, finally owner closes raw device |
| Network reset | ResetNetwork/Purge | retire cached flow/NAT state without crossing snapshot generations |
| Error and buffer conversion | lazy/TCP/UDP adapters, gonet | preserve translated net errors, deadlines, callback CloseHandler, refs/DecRef and pool release timing |

Current `tunIngress.JudgeFlow` uses Accept/Reject and UDP DNS hijack. Loopback
address options are not populated; Port/NAT passthrough and general flow rewrite
facilities are not activated by Splicore's current adapter. The inventory
distinguishes dependency capabilities from features that must be preserved;
it is not permission to add those optional features.

Affected existing files/packages, estimated from actual imports and ownership:

| Package / files | Expected change or review |
|---|---|
| clientruntime: tun_stack_gvisor.go, tun_stack_stub.go | own official stack/link types; preserve QF-001 guard and failed-start unwind; tag boundary |
| clientruntime: tun.go, host.go | adapter/handler contract, DNS writer and session ownership, lifecycle ordering |
| hostnetwork: wintun_gvisor_windows.go | official PacketBuffer/channel types, receive copy, DecRef, interrupt/cancel/join and queue draining |
| hostnetwork: platform_linux.go, platform_windows.go, platform_other.go, wintun.go, capabilities.go | device abstraction/raw-FD ownership and interruption contract; capabilities/build gates; retain route/journal ownership |
| engine/native: platform.go, snell.go, quic.go, vless.go | compatibility review: tun Options/monitor/FlowTracker appear in derived upstream interfaces; these imports do not imply owning a TUN datapath |
| application/clientruntime/hostnetwork tests | real TUN resource/traffic fixture, generation retirement, failed start, safe Windows workers, cancellation/stopped handles |
| distribution/tooling/docs | dependency/SBOM/build matrix, Go minimum, ADR, lifecycle and qualification boundaries |

Inventory: **14 existing production files** directly import sing-tun or
SagerNet gVisor across three integration packages; application is an additional
regression consumer. The upstream reference surface is **26 files / 5,607
lines**, including stubs/platform files. This is a measured inspection surface,
**not** an estimate of lines to copy or a requirement to migrate every helper.
Approximately ten contract groups span device I/O, endpoint, writer, stack
lifecycle, flow decisions, TCP, UDP, DNS return, reset and error/buffer handling.

Reusing exported SagerNet TCP/UDP forwarders with official stack types hits the
same module identity barrier. UDPForwarder currently bridges a private Range
iterator with upstream go:linkname; copying that implementation is specifically
invalid here. A future direct route must establish replacements using **public
official gVisor APIs** while preserving behavior, with no copied upstream code
and no wire reimplementation. Public TUN Read/Write can remain useful, but
NativeTun's raw FD is not supplied by the current GVisorTun contract; a direct
fdbased owner boundary is not a mechanical import rename.

Risks include lazy TCP handshake/close behavior, UDP affinity and DNS reply
lifetimes, cancellation during teardown, write admission versus borrowed-FD
reuse, platform offload/checksum behavior, Wintun worker joins, allocations and
safe failure unwind. Linux/Windows require separate implementations/tests;
arm64 needs a compile gate. Unsupported platform status is not changed by this
assessment. No direct-gVisor production integration was implemented.

**EXPLICIT BROADER MIGRATION APPROVAL REQUIRED** before any Lane C implementation.

## QF-001 Preservation

Entry bytes of tun_stack_gvisor.go, qf001_gvisor_test.go and
qf001_tun_lab_linux_test.go are unchanged in the real repository. The writer
token remains per device through synchronous WritePacket return; stopped is
atomic; Close is once-only and drains admitted writes before device release.
No synchronization was removed because of candidate timing.

| Scratch graph | Scope | race ×25 |
|---|---|---|
| frozen | all five original TestQF001 tests | PASS, 125 executions |
| v0.9.6 | all five original TestQF001 tests | PASS, 125 executions |
| dev | all five original TestQF001 tests | PASS, 125 executions |
| testing | all five original TestQF001 tests | PASS, 125 executions |
| PR head | four original writer/close/error test bodies, standalone harness | PASS, 100 executions |

Total: **600 passing executions**, default race/checkptr. PR's standalone module
does not contain the full Splicore generation-manager integration test; that
test passed in all four complete scratch graphs. No original test was changed,
skipped or disabled. All five lifecycle binaries also use default race/checkptr;
no race report or checkptr failure occurred in these runs.

Command for complete scratch graphs:

```text
go test -mod=mod -modfile <external candidate>/splicore.go.mod -race \
  -tags with_gvisor,with_quic,with_utls -count=25 -v -run '^TestQF001' \
  ./internal/splicore/clientruntime
```

Real TUN traffic x10, active-session stress and full regression were not run in
this architecture review. These idle resource and ownership observations are
not Splicore Feature Acceptance or Platform Qualification.

## Recommended Route

**One main route: official SagerNet matched upstream lifecycle correction,
followed by an explicitly reviewed paired dependency migration.**

Required upstream outcomes:

1. SagerNet gVisor incorporates the real stop-eventfd release/failed-constructor
   cleanup direction represented by Google fix
   `b11702b3c511622436e4733a7f5552b9fcdc73b0`.
2. sing-tun's actual public Close owns complete stack/NIC/link shutdown and
   completion, including the actual internal stack, not a newly created helper
   stack. Borrowed TUN FD remains the platform owner's responsibility.
3. The matched pair is published at merged official exact revisions, has no
   private-access requirements, and passes the same public-lifecycle x25
   resource gate plus QF-001 race x25 before production adoption is proposed.

PR #89 alone is not that outcome. No upstream message, issue or PR was posted
in this review. The known fix direction and current blockers support this
recommendation; availability/timing of a future official pair is unknown.

### Future regression scope estimate

| Gate | Future matched pair | Direct official gVisor alternative |
|---|---|---|
| QF-001 race ×25 | all ownership/generation cases; retain guard | same, plus new buffer/worker interfaces |
| Eventfd/FD lifecycle ×25 | actual public adapter, equal warmed start/end counts, idempotent/concurrent Close, partial start and recycled FDs | same, direct actual-stack owner plus platform interruption |
| Original real TUN ×10 | TCP/UDP/DNS, stop/restart and resources | same, plus callback/packet/error equivalence |
| Fresh 10-minute stress | active traffic, cancellation and resource tracking | same plus new hot-path allocation/latency comparison |
| Linux full/default race | complete supported project scope | same plus new adapter tests |
| Native tags/shared race | with_gvisor,with_quic,with_utls and affected shared packages | same plus dual module/platform boundary |
| Windows safe | supported toolchain, build/full safe tests; real host limits retained | same plus Wintun endpoint and worker tests |
| Linux arm64 | native tags build; runtime only if native environment exists | same |
| Native protocols/inbounds | Snell, Hysteria2, TUIC, VLESS plain/TLS/REALITY, Mieru, DIRECT/REJECT; SOCKS5 TCP/UDP, HTTP/mixed and TUN coexistence | same |
| Routing/DNS/policy | bootstrap/proxy DNS, snapshots, UDP affinity, reset, cancellation, selection and restart | same plus return-writer lifetime equivalence |
| Phase 15 | H15-001 through H15-009, stopped handles, DNS cancellation and journal cleanup/recovery | same |
| Distribution | build/package/artifact/SBOM/toolchain and existing supported matrix | same plus dependency/type/size changes |
| Fuzz seeds/underlay/boundaries | existing 42 fuzz targets, seed tests, egress ownership and native-only architecture | same; any parsing adaptation needs its own gates |
| Later Platform Qualification | new frozen joint-fix candidate; fresh 60-minute run only after review/freeze authorization | same |

These are future gates, **NOT EXECUTED** as broad acceptance in this review.
WSL namespace evidence remains limited; it does not qualify native Ubuntu
auto-route or destructive Windows networking. Existing qualification limits
remain in force.

## Required Authorization

This review is complete within its authorized scope. **No production migration
is currently authorized by this review**, and no approval is requested for an
unavailable hypothetical version.

For a later matched-pair implementation request, identify and authorize:

- exact **merged official sing-tun version/commit** passing public Close x25;
- exact **declared github.com/sagernet/gvisor version/commit** passing StopFD release;
- only necessary transitive metadata changes, with an explicit graph diff;
- the already authorized Go >=1.26.3 minimum exception if needed by selection;
- minimal TUN ownership/lifecycle adaptation and the regression scope above.

There is no exact qualifying SagerNet pair to fill those pins today. The
previous official Google candidate and Go exception do not authorize module
mapping, an unmerged pin, a fork, or direct integration scope expansion.

For Lane C: **EXPLICIT BROADER MIGRATION APPROVAL REQUIRED**, covering the
assessed adapter/platform/callback boundaries. Upstream source modifications
must remain zero, copied third-party implementation zero, wire reimplementation
zero. It is not the recommended main route of this review.

## ADR 0036

[ADR 0036](../adr/0036-official-gvisor-eventfd-lifecycle.md) remains **Proposed**.
Updated with the matched-pair/PR runtime failures, exact discovery identities,
public-adapter limitation, direct-route cost, main upstream route and future
authorization/regression conditions. The earlier standalone official candidate
is retained as reference evidence, not a final architecture selection.

## Repository Integrity

- Source implementation changed this review: **NO**.
- Project go.mod/go.sum changed this review: **NO**; entry diffs empty.
- QF-001 production/test bytes: **PRESERVED**.
- Previous reports/evidence: **PRESERVED**.
- sing-tun/gVisor upstream source patches: **0**.
- Fork/local replace/vendor override/private accessor introduced: **0**.
- New wire/network capability: **0**.
- Host network mutations: **0**; kernel TUN fixtures only in disposable namespaces.
- Staged: **NO**; committed: **NO**; pushed: **NO**.
- Tagged/released/frozen: **NO**; index: **EMPTY**.
- HEAD/parent/branch: unchanged from Frozen Base.

Final external integrity JSON and SHA256 evidence manifest record these checks,
the exact PR export and retained source/manifests. The original failed module
resolution experiment is retained alongside the subsequent main-module PR
observation. It is not hidden or treated as a successful dependency pin.

## Platform Qualification (PAUSED)

**PAUSED** pending joint fix implementation, complete acceptance, review and an
explicit fix freeze. No new qualification soak, Phase 16, release, tag or
production implementation was started. Stop after this migration review.
