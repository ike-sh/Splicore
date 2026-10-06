# PHASE 17 FROZEN

# Splicore Phase 17 Independent Core Transition Freeze Report

## Verdict

Implementation Review: **PASS**. Final Independent Re-Review: **PASS**.
Consolidated implementation/review freeze: **PASS**. Known implementation
blockers: **NONE KNOWN**. Platform qualification: **NOT RE-RUN**.
Historical qualification: **PARTIALLY PASSED**. This candidate is
**NOT REQUALIFIED / NOT PLATFORM QUALIFIED YET**.

Freeze metadata date: 2026-10-07 (Asia/Shanghai). External evidence directory
retains its 20261006 transaction start date; results include actual UTC times.

## Commit identity

- Phase 17 Freeze Commit: **the commit containing this report**.
- Message: `feat(core): establish independent core with native shadowsocks`.
- Sole parent: `b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c`.
- Branch: `codex/phase-16-native-shadowsocks`.
- Exactly one consolidated forward commit; no standalone Phase 16 commit.

Resolve the full immutable commit identity after this transaction:

```text
git log -1 --format=%H -- docs/reports/PHASE17_INDEPENDENT_CORE_FREEZE_REPORT.md
```

A committed report cannot contain its own future object hash. The resolved
`PHASE_17_FREEZE_COMMIT`, parent count, final clean status and post-commit gates
are recorded externally in
`D:/splicore-validation/phase17-consolidated-freeze-20261006/PHASE17_FREEZE_FINAL_REPORT.md`
and `summary.json`. This preserves the exactly-one-commit and CLEAN requirements.

## Consolidated scope and Phase 16 record

This freeze consolidates:

- Phase 16 Native Shadowsocks / Shadowsocks 2022.
- Phase 17 Independent Core Decoupling.
- Review Fix Round 1.
- Review Fix Round 2.
- Review Fix Round 3.
- Canonical freeze documentation and ADR 0037/0038 acceptance metadata.

**Phase 16 changes were consolidated into the Phase 17 Independent Core Transition freeze commit.**
Phase 16 remains a formal development record with status
**PHASE 16 IMPLEMENTATION REVIEWED**. Its original implementation report and
failed checkpoints are preserved; no separate Phase 16 hash is invented.
Explicit manifests include Phase 16/17 implementation/tests, removed inherited
surfaces, dependency/build ownership, documentation and required attribution.
Raw validation evidence and build artifacts remain outside Git.

## Module identity and SagerNet audit

Before: `github.com/sagernet/sing-box`.
After: `github.com/ike-sh/Splicore`.
No local replace, alternate module identity or compatibility module shim.

| Surface | Result |
|---|---:|
| Source imports, all Go files/build tags | 0 |
| Direct modules | 0 |
| Full module graph | 0 |
| Binary modules, all three platforms | 0 |

Historical names in licenses, NOTICE and source provenance remain lawful
attribution and are preserved.

## Protocol matrix

| Protocol | Server | Client | TCP | UDP |
|---|---|---|---|---|
| Shadowsocks | actual | actual | actual | actual |
| Shadowsocks 2022 | actual | actual | actual | actual |
| Snell | actual | actual | actual | actual |
| Hysteria2 | actual | actual | actual | actual |
| TUIC | actual | actual | actual | actual |
| VLESS | actual | actual | actual | actual |
| Mieru | actual | actual | actual | actual |

DIRECT and REJECT remain active routing actions. No protocol is added during freeze.

### Shadowsocks / Shadowsocks 2022

Six Phase 16 methods: `aes-128-gcm`, `aes-256-gcm`,
`chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`,
`2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`.
Reviewed Server/Client/TCP/UDP and 28-row external bidirectional interoperability
are preserved, with Account/Credential, Binding, Node, Provider, API/CLI,
backup/restore, routing, DNS, policy and Native TUN integration.

### Snell / Hysteria2 / TUIC / VLESS

Snell v6 external interoperability PASS (three v6 rows within nine accepted rows).
Hysteria2 padding uses `crypto/rand`; the pinned AperNet QUIC sender is constructed
and reset with `reno=true`. Public CUBIC/BBR selector: NONE; canonical docs agree.
TUIC Close/live deadline/parent shutdown/sibling isolation remain reviewed.
VLESS plain/TLS/REALITY accepted interoperability is PASS; Vision remains
DEFERRED/UNSUPPORTED.

## Independent architecture and Mieru

Splicore owns protocol integration, runtime lifecycle, packet lifecycle, routing,
DNS, policy, accounts/credentials, API/CLI, SQLite authority and Native TUN.
Independent third-party libraries are implementation dependencies behind owned
boundaries; no external core production subprocess or copied SDK tree is added.

`protocol/mieru` is the Splicore-owned inbound/server and outbound/client/session
integration boundary. Independent `github.com/enfein/mieru/v3 v3.38.0` is reused
as an official library, with protected underlay/resolver injection.
Mieru upstream modifications: **0**.

## Findings closure

| Finding | Freeze state |
|---|---|
| R17-001 | CLOSED |
| R17-002 | CLOSED |
| R17-003 | CLOSED |
| RR17-001 | CLOSED |
| RR17-002 | CLOSED |
| VLESS_PARTIAL_FRAME | CLOSED |
| VLESS_ASSOCIATION_REGISTRY | CLOSED |

## Packet lifecycle contract

The final reviewed implementation covers child Close interruption, live write
deadlines, parent shutdown, sibling isolation, bounded writer ownership, worker
join and safe cross-goroutine frame/address ownership. Actual mechanics differ
by transport:

| Backend | Child Close | Dynamic Deadline | Parent Close | Sibling Isolation | Worker Join | Result |
|---|---|---|---|---|---|---|
| VLESS | cancels and unregisters; failed active Write joined | Queue live timer interrupts actual Write | stream/children closed; handlers+writer joined | zero commit survives; poisoned parent terminates siblings | one parent writer; callback+worker joins | PASS |
| TUIC | Queue caller/admission cancellation | live Queue operation deadline | QUIC closes send queue; writer+peer workers joined | separate child contexts; stream mode cancels private uni stream | one bounded parent datagram writer | PASS |
| HY2 | Queue caller/admission cancellation | live Queue operation deadline | QUIC/HTTP3/socket close; writer+children joined | separate queues on shared datagram parent | one bounded parent datagram writer | PASS |
| SS | child cancellation, target close, owner unregister | outbound socket deadline; server child context cancellation | listener/socket close, reply writer+relays joined | independent child/target ownership | bounded parent reply writer; relay joins | PASS |
| SS2022 | same native owner paths as SS | same owned socket/child mechanisms | same shutdown joins | authenticated session/target ownership | shared reply worker joined | PASS |
| Snell | closes raw logical packet stream | native socket deadlines; handshake completed in constructor | native stream owner closes and joins handlers | independent raw streams; reusable TCP callbacks join before handoff | no detached packet write worker | PASS |
| Mieru | complete packet owner closes SDK session and waits writer | Queue live deadline around snapshotting SDK operation | clientio tracks complete owner; Close interrupts session and joins | private owned SDK sessions; copied destination/bytes | session writer+adapter/relay joins | PASS |

### VLESS terminal partial frame and registry

Positive-byte failed/short wire writes make the framing stream terminal;
later WriteTo cannot falsely succeed or continue a corrupt frame. Zero wire
commit preserves valid retry/sibling isolation. An admitted VLESS error return
joins the actual Write and its cancellation callback; no asynchronous tail
survives. Poisoning a shared parent terminates all affected siblings.

Closed children synchronously unregister using delete-if-same-owner. Old Close
cannot delete a same-ID replacement. Capacity remains 128. Parent shutdown marks
closed and detaches the map under lock; child Close, transport IO and worker joins
occur outside the registry lock. Verified real same-parent churn: **10,000 PASS**,
registry/active zero after every close and each 1,000-session batch. Registry
competition: **625,000 cycles PASS**, final retained owners zero.

## Review evidence — REUSED VERIFIED EVIDENCE

Final Independent Re-Review: **PASSED**, all seven findings CLOSED, no new blocker.
Authoritative report:
`D:/splicore-validation/phase17-final-rereview-20261006/PHASE17_FINAL_REREVIEW_REPORT.md`.
Reviewed source manifest: 1,113 files; SHA256
`20518050931238fe4a25711e1119bef6a29e9048b5140f38a874307dbd2e040c`.
Freeze entry matches exactly. Final-review evidence seal: **83 files verified**.
Fix Round 3 evidence seal: **1,820 files / 294,204,961 bytes verified** by the final
review. No reviewed implementation changes occur during freeze.

Fresh final-review original reproducers: **1,000/1,000 PASS**, failures/timeouts 0.
Targeted race **x25 PASS**, ten top-level tests and 700 leaf cases, race reports 0.
Verified default tests, default/native/shared races, checkptr ON, 14 mutation fuzz
targets, interoperability, real isolated TUN x25, mixed stress and lifecycle
stress are reused. Freeze does not claim to rerun these long gates.

| Interoperability matrix | Accepted rows | Result |
|---|---:|---|
| SS / SS2022 | 28 | PASS |
| Snell (includes v6) | 9 | PASS |
| Hysteria2 | 12 | PASS |
| TUIC | 12 | PASS |
| VLESS plain | 4 | PASS |
| VLESS TLS | 4 | PASS |
| VLESS REALITY | 12 | PASS |
| Mieru unchanged isolated full repeat | 24 | PASS |

Twelve failed attempts remain preserved. Mieru's first 4MiB timeout remains a
failed campaign; the complete unchanged isolated 24-row repeat is the accepted
evidence. No failed aggregate is relabeled PASS.

### TUN and stress

Real isolated kernel TUN x25: PASS. Every stopped sample: goroutines 29, FD 22,
eventfd 1, sessions 0; goroutine/FD/eventfd deltas 0. Generations/leases return to
1; host generations/interfaces/journal temporaries 0. Route/rule snapshots and
TUN interface absence are checked each cycle.

Mixed workload: **10m14.040676552s**, 14 rounds, unexpected errors 0, final
G29/FD22/eventfd1/sessions0; direct DNS TCP/UDP leakage 0/0.
Lifecycle/cancellation workload: **10m0.001377892s**, 3,045,703 local registry
cycles and 30,457 controlled partial-write races; end registry/active/pending
writers 0, goroutines 2, unexpected errors 0. This is local ownership evidence,
not millions of external wire sessions or platform qualification.

Windows safe tests: REUSED PASS, owned loopback guard 300 / closed 300;
host network configuration modified=false. Historical review logs and cleanup
records are retained externally. No Windows destructive campaign is run.

## Freeze quick gates

Fresh current-tree gates: `go mod verify`, `go list ./...`, all-tag source-import
audit, full module graph, native three-platform builds, binary identity metadata
and Underlay auditor: **PASS**. Go 1.26.6, module minimum 1.26.3, native tags
`with_gvisor,with_quic,with_utls`; readonly modules and offline caches.

Secret scan: **real=0, unresolved=0**; synthetic fixture hits classified.
Implementation source hashes must match the final review byte for byte in the
worktree, staged clean snapshot and final commit. Only explicitly listed freeze
documentation/status metadata can differ. Historical unchanged documentation
checkout CRLF is compared with its unchanged Git blob using LF equivalence;
no implementation/build byte normalization is accepted. Explicit staging uses
process-local `core.autocrlf=false`, preserving reviewed CRLF build scripts,
including the two interop helpers whose ordinary status had hidden normalization.

The staged future tree is exported without an intermediate commit. The same quick
gates and a separate secret scan run on that isolated staged snapshot before
commit. Post-commit quick gates and final Git identity run after the sole commit.
Actual commands, exit codes, timings and gate summaries live under the external
freeze root in `pre-stage/`, `staged/`, `staged-scan/` and `post-commit/`.
The external final report is authoritative for transaction completion and the
resolved hash; no second commit or amend is used to insert a self hash here.

## Dependencies, upstream and attribution

Root LICENSE remains byte identical to the parent; NOTICE derivative attribution
is preserved. Actual notice directory: `licenses/third-party/` (the project
equivalent of `third_party/licenses`). **95 notice files for 69 selected modules**
are verified byte identical to cached LICENSE/copyright/NOTICE/AUTHORS texts.
The historical WinDivert embedded resource and its license remain preserved.

SagerNet dependencies: **0**. External upstream source patches: **0**.
Mieru upstream modifications: **0**. gVisor upstream modifications: **0**.
quic-go upstream modifications: **0**. `go mod verify` validates unchanged
independent module-cache sources. The pinned official AperNet fork is an upstream
dependency, not a local source patch. No legal attribution is removed.

## Platform builds, Underlay and Xray boundary

| Platform | Native production build | Runtime qualification |
|---|---|---|
| Linux amd64 | PASS | Current freeze NOT REQUALIFIED |
| Windows amd64 | PASS | Destructive qualification PENDING |
| Linux arm64 | PASS | NOT CERTIFIED / BUILD ONLY |

All three binaries identify `github.com/ike-sh/Splicore`; SagerNet modules absent.
Underlay Unknown: **0** (71 production / 133 test surfaces).
Xray classified audit: **E=0, F=0, G=10**, with all ten original classified
format/rejection rows verified against current source. Production-only G=5 is
a narrower historical count. FinalMask runtime=0, Sudoku runtime=0;
Vision DEFERRED/UNSUPPORTED. Xray runtime/dependencies are absent.

## Platform Qualification

Historical candidate: `b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c`.
Historical status: **PARTIALLY PASSED**, unchanged.
Current freeze: **NOT REQUALIFIED / NOT PLATFORM QUALIFIED YET**.
Qualification rerun: **NOT RE-RUN**. Known implementation blockers: **NONE KNOWN**.

| Gap | Preserved state | Qualification boundary |
|---|---|---|
| GAP-01 | OPEN | Qualified long-duration goroutine measurement unavailable on the historical frozen packaged daemon; earlier soak interval goroutines missing. Short current tests do not close it. |
| GAP-02 | OPEN | Windows destructive real-network safe target unavailable; Windows race compiler prerequisite also absent. |
| GAP-03 | OPEN | Native Ubuntu host-network target unavailable; isolated WSL kernel TUN is supplemental evidence. |
| GAP-04 | BUILD ONLY | Linux arm64 actual runtime target unavailable; runtime NOT CERTIFIED. |

Canonical historical report:
`D:/splicore-validation/platform-requalification-20261005/PLATFORM_REQUALIFICATION_FINAL_REPORT.md`.
Protected SHA256:
`18065f3ca3c5f34f5ac8d8e0d52b34a80218f7a6f4ab418f256467c80996bba7`.
No new qualification defect is inferred from these evidence/target gaps.

## Git state and actions

Final branch: `codex/phase-16-native-shadowsocks`.
Final commit: containing commit resolved as above and recorded externally.
Required final working tree: **CLEAN**. Required final index: **EMPTY**.
Exact final observations and intended/staged manifests are retained externally.

| Action | State |
|---|---|
| Local forward commit | YES — exactly one |
| Push / force push | NO |
| Tag / release | NO |
| Rebase / amend / squash / history rewrite | NO |

## Public GitHub / NoBrand / next state

Public GitHub: **UNCHANGED**; public release baseline remains the user-supplied
v0.1.0. No public action or verification request is made during this local freeze.
NoBrand: **NOT ACCESSED**. Next development: **NOT STARTED**.
Phase 18, Trojan and VMess work is not started.

# PHASE 17 FROZEN

Implementation blockers: **NONE KNOWN**.
Platform qualification: **PARTIALLY PASSED historically / NOT RE-RUN for this freeze**.
