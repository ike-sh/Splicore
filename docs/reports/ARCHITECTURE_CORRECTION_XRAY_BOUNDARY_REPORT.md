# Splicore Xray Boundary Architecture Correction Report

Documentation status: Architecture correction acceptance report
Audience: Maintainer and reviewers
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Architecture supersession, native regression and distribution evidence
Lifecycle: Ready for review; unfrozen

## Maintainer Decision

Splicore role: **Independent Server + Client Core**.
Xray role: **External runtime owned by future NoBrand orchestration**.

[ADR 0035](../adr/0035-xray-runtime-removed-from-core.md) supersedes the historical
Phase 6/7 runtime direction. Those implementations remain historical facts;
their reports, ADRs and frozen Git history are unchanged. Phase 14 work is
retained and remains unfrozen.

Evidence root: `D:\splicore-validation\xray-boundary-20261004`.
Entry Git state, 2,104 source hashes and a complete source backup were recorded
before edits in `entry-git.json`, `entry-files.json` and `entry-source.tar.gz`.
Prior accepted Phase 14 artifacts remain in their original evidence directory.

## Before Correction

| Surface | Previous implementation |
| --- | --- |
| Xray engine | Registered server/client runtime alongside native |
| Xray child | Supervisor, PID/generation, restart/health, config ownership |
| FinalMask / Sudoku | Bounded Experimental server feature and sensitive export |
| Distribution | Optional pinned artifact metadata and installer engine operation |
| Underlay | Child socket/resolver protection and process verification |

## After Correction

Registered Engines: **native**. Generic Protocol != Engine remains a domain
abstraction. It does not imply ownership of third-party cores.

| Surface | Corrected state |
| --- | --- |
| Xray runtime / binary / process management / distribution | ABSENT |
| Supervisor, renderer, artifact installer, runtime health/PID schemas | REMOVED |
| Xray-specific underlay and unused child infrastructure | REMOVED |
| FinalMask / Sudoku | OUT OF SCOPE FOR SPLICORE |
| Ordinary plain VLESS external-client configuration exporter | Retained; independent of server engine |
| External runtime required for normal Splicore | NO |

Remaining Xray identifiers are explicit rejection/upgrade compatibility and
the ordinary external client format. No registered runtime, hidden renderer,
artifact loader or child launcher remains. Superseded runtime/mask tests were
removed; retained native security/lifecycle tests were adapted.

## Native VLESS

Server: **PASS**. Client: **PASS**. Plain/TLS/REALITY flow-none: **PASS**.
Vision: **DEFERRED / UNSUPPORTED**, explicitly rejected.

`TestNativeVLESSSecurityAndSharedNode` and
`TestNativeVLESSIPv6OutboundLifecycle` run in the complete owned race suite,
covering IPv4/IPv6/domain TCP/XUDP, 4 MiB integrity, independent leases sharing
one node, UUID/trust/SNI/REALITY public-key/short-ID rejection and recovery.
The adapted native VLESS reference harness also passes 20 complete local
production-artifact cells with pinned mihomo 1.19.30 and sing-box 1.14.1 clients:
plain 4, TLS 4, REALITY 12. These reference clients are test tools outside the
Splicore service, not runtime dependencies.

## Native Protocol Matrix

All protocols remain **Experimental**. No wire implementation changed.

| Protocol | Server TCP/UDP payload | Client TCP/UDP payload | IPv4/IPv6/domain | Security/transport |
| --- | --- | --- | --- | --- |
| Snell | PASS / PASS | PASS / PASS | PASS | Existing v5/v6 semantics; PSK |
| Hysteria2 | PASS / PASS | PASS / PASS | PASS | QUIC/TLS, explicit CA |
| TUIC v5 | PASS / PASS | PASS / PASS | PASS | QUIC/TLS, UUID/password |
| VLESS native | PASS / XUDP PASS | PASS / XUDP PASS | PASS | Plain/TLS/REALITY, flow-none |
| Mieru | PASS / PASS | PASS / PASS | PASS | Embedded official TCP/UDP transport |
| DIRECT / REJECT | N/A | PASS | Existing route semantics | Builtins |

Fresh installed service smokes cover all five native protocols, including Mieru
TCP and UDP underlays. Client checks include SOCKS TCP/UDP, local IPv6 UDP,
4 MiB per adapter and 16 concurrent mixed TCP/UDP associations. The owned TUN
lab separately exercises all five native adapters. HTTP/mixed ingress and
REJECT retain their complete application tests. The
[capability matrix](../architecture/CAPABILITY_MATRIX.md) remains authoritative
for qualifications and policy support.

## Distribution

Single core artifact: **splicore**, one **splicore.service**.
Mieru: embedded Go module. External Xray required: **NO**.
Package contains Xray: **NO**. Installer downloads Xray: **NO**.

Linux amd64/arm64 and Windows amd64 artifacts are rebuilt offline with the same
comparison settings: Go 1.26.6, CGO=0, version `0.0.0-dev.1`, epoch `1791062400`,
`-mod=readonly -trimpath -buildvcs=false`, tags `with_quic,with_utls,with_gvisor`.
The Linux amd64 package and corresponding source archive repeat deterministically.
All manifests and member hashes are verified; no optional Xray pin/checksum,
download script, executable or runtime directory requirement is present.

Measured entry versus corrected acceptance candidate, in bytes:

| Artifact | Before | Corrected | Delta |
| --- | ---: | ---: | ---: |
| Linux amd64 binary | 61,828,642 | 61,470,573 | -358,069 |
| Linux amd64 package | 30,273,165 | 30,105,365 | -167,800 |
| Linux arm64 binary | 58,521,408 | 58,220,688 | -300,720 |
| Linux arm64 package | 28,182,743 | 28,026,786 | -155,957 |
| Windows amd64 binary | 54,995,456 | 54,717,440 | -278,016 |

This comparison uses the preliminary corrected artifact whose production Go
source equals the final candidate. Final documentation/provenance changes can
change compressed sizes; `after-sizes.json` records the exact final sizes and
hashes. `candidate-final/update.json` identifies the final complete source
snapshot; `package-final-gates.json` records reproducibility. Artifacts are local
review material only, not published or released.

## API / CLI

Xray runtime resources/status/doctor: **NONE**. Capability engine pairs are native
only; no FinalMask/Sudoku runtime claims. Process status, engine feature and
child underlay schemas are removed. Typed unavailable-engine creation rejects
`unsupported_engine_for_protocol`; explicit mask options reject
`unsupported_engine_feature`. CLI has no artifact/engine install operation.

Ordinary VLESS external-client format export remains separate from runtime
ownership and carries no server EngineID. Live installed API/CLI responses,
six client/network stage snapshots and active TUN/host responses pass current
OpenAPI schemas. Old pre-upgrade responses are checked against the exact
prior Phase 14 candidate schema. Historical source references resolve against
frozen HEAD without editing historical documents; current references resolve
against current files.

## Underlay

Xray-specific paths: **REMOVED**. Production egress Unknown: **0**.
`underlay-final/inventory-after.json` reviews 55 production surfaces, covering
DIRECT, DNS/bootstrap, health, native Snell/HY2/TUIC/VLESS/Mieru clients, native
server targets and provider HTTP fetch. Native endpoint leases, old generations,
shared refs, dynamic DNS, cleanup debt and reused TUN ownership remain.
The kernel TUN lab observes DNS leakage counters `{udp:0,tcp:0}`.

## Provider / Import

Normal native VLESS: **PASS**. FinalMask/Sudoku/Xray annotations: **Unsupported**.
Silent downgrade: **NO**. Preview is non-applicable; apply rejects and creates
no runnable stripped node or outbound. Retired annotations are recognized before
canonical decoding, while ordinary candidate document size limits are retained.

Phase 14 imports, proxy and RuleSet providers, stable identity, encrypted storage,
preview/apply transactions, API/CLI and provider authority remain. The Phase 14
application race campaign passes **10 times**, including initial fetch, reorder,
rename, credential rotation, remove/stale, failed refresh, empty feed, ETag,
proxy fetch and RuleSet behavior. Installed acceptance preserves ten provider
nodes, two providers, generation, tags/metadata and offline traffic across
restart, failed-upgrade rollback and reinstall. No Xray artifact is supplied
to corrected native/provider/TUN acceptance.

## Storage

Schema remains **8**. Engine fields are generic; no Xray-only table exists,
so no additional forward schema migration is required. Historical migrations,
including the preexisting Phase 14 migration, are unchanged.

Migration/startup and installer preflight reject retired engine/mask records,
including disabled records, with an explicit diagnostic. Checks happen before
forward migration or executable/database replacement. No relabel, deletion or
silent conversion occurs. Upgrade-only bootstrap and installation receipt
decoders accept bounded legacy metadata; normal serve/package decoding rejects it.
Sanitization occurs after coherent stopped-service backup and successful preflight.

Successful upgrade from the accepted native-only Phase 14 experimental package:
**PASS**. Database rows, master key, host state and identity retained.
Upgrade from a real active historical Xray inbound: **EXPLICIT SAFE REJECT PASS**.
The old service/child runs only in the separate rejection fixture using prior
pinned local bytes. Rejection retains rows, binary, unit, receipt, bootstrap,
key and version, and restarts the original service. Remove retired records using
the previous experimental build before upgrading. Minimal storage rejection
tests additionally verify whole database bytes and migration history unchanged.

## Regressions

| Gate | Result / scope |
| --- | --- |
| Linux owned complete tests, default race/checkptr | PASS, with production tags and without tags |
| Windows owned complete tests | PASS; Windows Go 1.26.2, no Windows race qualification |
| Native server/client and VLESS security | PASS |
| Routing/DNS/Selector/URL-Test/Fallback/Load-Balance | PASS; installed six lifecycle stages |
| Kernel TUN, provider TUN, dynamic DNS/generations/shared refs/reuse | PASS; isolated WSL namespaces, default race/checkptr |
| Wintun/WinINET/Windows underlay ownership fixtures | PASS; no real host activation |
| Providers | PASS, application race 10x and installed offline recovery |
| Shared affected dialer/DNS/route/protocol/client I/O race | PASS |
| go vet, existing fuzz targets, Python syntax | PASS |
| Fresh no-Xray install and native-only experimental upgrade | PASS |
| Active retired-state preflight rejection | PASS, no silent loss |
| Restart/SIGKILL recovery/failed migration rollback | PASS |
| Uninstall/state retention/reinstall/safe purge | PASS |
| Doctor/support secret and artifact inventory | PASS |
| Underlay inventory and live OpenAPI/docs | PASS |

Owned test commands are recorded verbatim in gate JSON files. No race/checkptr
suppression, test skipping, panic recovery or payload-wide global lock was added.
The six Phase 14 fuzz targets run 10 seconds each; remaining existing core fuzz
targets run 3 seconds each under race with production tags. This is bounded
local fuzz evidence, not exhaustive verification.

Acceptance harness failures are preserved, then corrected at their cause:
new database fixture modes on Linux, a Windows fixture path separator, the old
eight-server/child assumption, the historical Xray fixture's explicit binary
path, and a 108-byte Unix socket path in the reference harness. These failures
were not retried or suppressed to manufacture a pass.

Qualification limits remain: isolated WSL evidence does not certify native
Ubuntu 24.04 auto-route or actual Windows system networking. Linux arm64 is
build-only. The outer nested-systemd lab may report stop timeout/failed
bookkeeping; cleanup independently verifies MainPID=0 and an empty cgroup,
then resets only that owned transient lab unit. No Windows host network or
third-party target was accessed.

## Runtime Audit

sing-box source modified: **0 inherited runtime files**.
Mieru source modified: **0**, verified against all 416 official module files in
both Windows and WSL caches. Xray source present: **NO**. Wire modified: **0**.
`go.mod`/`go.sum` are unchanged; no Xray Go module/source copy exists. The actual
linked dependency inventory and license notices remain included. Source audit
checks 1,276 protected files and 78 historical report/ADR/workflow/migration
files, and verifies the final package source matches the complete worktree.

Server+Client+TUN service process-tree evidence: **one Splicore cgroup process,
zero children**. Mieru remains embedded. Doctor/support contain no stale Xray
private runtime configuration, child PID or artifact requirement. Support
archive members and safe evidence are scanned for supplied synthetic credentials
and private keys; observed plaintext credential/private-key findings: **0**.

## Historical

Phase 0–13 history/reports: **UNCHANGED**.
Phase 6/7 Xray direction: **SUPERSEDED**, not erased.
The prior Phase 14 report and all its existing work are preserved; allowed
adaptations follow the corrected runtime boundary. Historical migration hashes
and prior accepted artifacts are unchanged.

## NoBrand

Real repository accessed/modified: **NO**.
Future role: deploy independent Splicore OR independent Xray according to
protocol/mode; NoBrand owns pin/hash verification and lifecycle orchestration.
Only Splicore's [integration design](../integration/NOBRAND_MIGRATION.md) changes.

## Git

Branch: `codex/phase-14-client-management-providers`.
HEAD/main: `b0de8c16e1c810cb851c400b5d03987924d5eff8`, unchanged.
Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
No history rewrite or Phase 14 freeze. The original uncommitted work was backed
up and retained; `source-audit-candidate-final.json` checks history/index/scope.

## Final Result

**XRAY BOUNDARY CORRECTION READY FOR REVIEW**

## Blockers

**None for local architecture-correction review.** Platform qualification limits
above remain; no stable/public-release or native host certification is claimed.
