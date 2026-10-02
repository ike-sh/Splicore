# Splicore Phase 8 Mieru Native Integration Report

- Documentation status: Report
- Audience: Maintainers and acceptance reviewers
- Last reviewed: 2026-10-02
- Owner: Project maintainers
- Responsibility: Phase 8 actual source, runtime, integration and regression evidence.
- Lifecycle: Preserve recorded scope and failures; revise only for this candidate review.

## Baseline

Phase 7 Freeze: `ca48d8429abb21fcaf7ee21d68e37d1ec5d6ec4d`.
Branch: `codex/phase-8-mieru-native-integration`. Entry CLEAN; candidate is
intentionally uncommitted. HEAD/main/all refs unchanged; index empty. Sole upstream
remote remains SagerNet/sing-box, no origin. Historical Phase 0–7 reports unchanged.
Evidence root: `D:/splicore-validation/phase8-20261002`, Linux candidate:
`/root/splicore-p8-20261002/source`; no binaries/config/state/logs staged in source.

## Mieru Reference

Repository: [official enfein/mieru](https://github.com/enfein/mieru).
Version: **v3.38.0**, official non-prerelease published 2026-09-24T23:03:15Z.
Commit: **b961978c3be9dd26b94158487c760858e19d1db2**.
Annotated tag: `4462e0ef9495bae5bb34a8406b9e92761da59618`.
Go module: `github.com/enfein/mieru/v3`; Go requirement: 1.20.
License: GPL-3.0-or-later from API copyright headers and GPLv3 LICENSE.
Release API, peeled tag, module Origin and immutable source manifest independently
verified before implementation; no assumption based on previous chat version.
Module sum: `h1:+DuixHFoCGEYEopoEg8fHmDJ5Ak30PuXuf1GIh2Xpu0=`.
Official client archive SHA256:
`71d5db9b6583f75e00c7143a7570ec5965f11535fda567d691ad4a7d0e98ca1c`.
Verified against release asset digest and official checksum file. Executable version
and SHA independently checked by the managed driver before traffic.

## Integration Strategy

| Option | Code / maintenance | Globals/config | Users/stats/shutdown | Decision |
|---|---|---|---|---|
| External | Supervisor, config renderer, owned child | Process isolated; daemon state boundary | Requires daemon control/polling; process exit | Oracle only; not final architecture |
| Embedded | Official package plus private translation | Shared caches/logger/metrics; private protobuf | UserContext; Stop alone insufficient | Feasible after isolated prototype |
| Native ownership | 691 lines across five new production registration/module/codec/runtime/export files, plus six small composition/format/dependency edits | Immutable per-generation server config; per-Mux auth | Own raw sockets, sessions, direct relay and one payload meter; joined Close | **Chosen B→C** |

No wire, crypto, handshake, framing or multiplex implementation is rewritten.
Official module/API pin determines update cost; ownership/global-state behavior
must be re-audited at every pin change. [ADR 0020](../adr/0020-mieru-owned-native-embedding.md).

## Embedding Audit

Global state: synchronized cipher templates, replay caches, RNG and username-global
metrics exist. Immutable cipher templates are cloned; per-Mux authentication registry
is isolated. Splicore never bills upstream global counters. Cipher cache survives
Stop; complete credential erasure is not claimed. Logger: official NewServer uses
locked NilFormatter; no logger/metrics worker enabled by embedding. Signals/CLI
loader/daemon flag registration: not invoked by the embedding path. The official
logger test adapter indirectly imports standard testing/flag; its test output and
testing.Init/flag.Parse are not used here (clarified during freeze source audit).
os.Exit helpers
exist in pkg/log but are not called by this embedding path. No copied mita main.

Server lifecycle: Store before Start only; fresh Server per generation. Actual Store
does not enforce the interface's documented after-Start rejection, so ownership
enforces it. Official Stop alone does not satisfy raw socket/session cleanup.
Packet Close is deadline-based; an active Read can replace it. Adapter closes actual
owned raw packet sockets before Stop and joins workers. Accept parser errors retain
internal sessions until Mux cleanup; all raw sockets remain owned for shutdown.
Hostile-peer resource exhaustion protection is not newly qualified by this phase.
Multiple instances and default race/checkptr pass. Blocking embedding issues: none
within the bounded default-profile scope; no upstream adaptation layer required.

## Source Changes

Official Mieru source modified: **0** (full source manifest equal).
Vendored/copied source: **NONE**. sing-box upstream runtime files changed: **0**.
Source additions stay in Splicore-owned modules/registries/exporters/tests/scripts/docs.
Dependency: one direct official module, two go.sum entries; no upgrades or broad tidy.

## Architecture

Protocol: **mieru / 2 / base**. Engine: **native**, existing compiler map.
Account: shared; Binding: shared; Credential: existing encrypted generic
UsernamePasswordPayload. No domain/storage schema/migration changes. ClientProfile:
existing shared type, typed endpoint/credentials/transport and bounded options;
no private protobuf, daemon config, actual listener or Engine fields.

Canonical settings: required tcp/udp underlay, optional MTU 0/default1500 or
1280–1500, optional default/off/low/middle/high multiplex; default traffic pattern.
One IP listener, one separate IPv4/IPv6/domain DisplayEndpoint. 1–16 users,
distinct names/usernames, pair supplied or safely generated. Unknown/duplicate/null
settings and unrepresented TLS fields reject. Direct TCP/UDP egress with local DNS
is the bounded adapter scope; RuntimeIntent currently has no configurable routing
policy. This does not qualify richer sing-box routing-rule integration.

## Capabilities

| Capability | Actual Phase 8 disposition |
|---|---|
| TCP / UDP | Both underlays and payload types qualified |
| IPv4 / IPv6 / domain | Default profile qualified on Linux amd64 localhost |
| MultiUserNative / NativeStats / PerUserStats | Yes, authenticated payload and routed sessions |
| QuotaNative / SpeedLimitNative / MaxSessions | Not exposed; strict policy rejects |
| HotUserUpdate / HotReload | False; affected inbound restart only |
| Nondefault MTU/multiplex | Canonical/export bounds validated; full runtime matrix covers MTU1500/default multiplex only |
| Stable / general persistent usage / field beta | Not claimed; Experimental review candidate |

## Multiple Inbounds

Inbound A TCP and B UDP run together with Alice/Bob names but different passwords.
Concurrent traffic: PASS. User, credential and exact payload meter isolation: PASS.
Cross-inbound credential: expected reject. Native ten-cycle tests separately run
two inbounds per underlay; joined Stop A preserves subsequent B traffic. Binding
reconcile replacing A leaves B working in actual managed API/runtime acceptance.

## Lifecycle

Create/Start/Health/Stop/Restart/Recovery: PASS. Admission before Activate is rejected.
Apply request cancellation does not own runtime lifetime. Stop closes raw listeners,
accepted sessions, destinations and sockets; workers join under caller deadline.
Upload EOF preserves the destination response through TCP half-close regression.
10x cycle: PASS on TCP and UDP, two inbounds, 16 mixed transfers and 4 MiB per cycle.
Goroutines baseline **2**, final **2**, no Mieru stack retained. Active sessions zero
after joined Close. A forcibly exited UDP peer has no reliable EOF and may retain
its server session until upstream idle expiry or inbound Close; no polling/sleep is
used to convert that transport behavior into a cleanup PASS.

## Transaction

Shared Validate/Plan/Pending/Build/Start/Health/Commit/Activate: PASS. Invalid settings
and credentials, occupied port, committed second-inbound conflict, injected compile/
start/health failures, commit storage failure and binding replacement compensation:
PASS. Failed operations leave no committed resources or pending journal leak.
No protocol-specific application branch, SQL or HTTP handler is added.

## SQLite

Authority: PASS, committed shared resources only. Recovery: PASS, same Inbound and
Binding IDs and Alice/Bob secret bytes after reopen; imported files removed before
managed daemon restart. Generated Mieru config authority: **NO**. Closed DB/WAL
plaintext password scan: PASS. No new database column/migration.

## Multi-user

Alice: PASS. Bob: PASS. Wrong password: EXPECTED REJECT for both official/Mihomo.
Cross-inbound credentials: EXPECTED REJECT for both. Binding disable removes Alice
from reconstructed runtime; saved config rejects; re-enable allows traffic again.
No live mutable user-map update; per-generation maps immutable.

## Stats

Inbound/Binding: authenticated payload bytes, each event updates both counters once.
TCP wraps the authenticated stream after response negotiation. UDP meters payload
after official association/framing wrappers, excluding headers. Sessions: routed
TCP/UDP associations; accepted-but-unrouted/auth failures excluded. Account persistent
aggregate is still deferred, as for existing native protocols; do not claim a new
Usage API or persisted counter epoch. Runtime replacement resets generation counters.
Upstream username-global meters are validation/reference only, never summed into
Splicore accounting. Double-counting: **NO**, exact known payload sums verified.
Live atomics are independent snapshots; stable exact sums verified after joined Close.

## Native Quota

Official support: YES. Rolling Days window, total upload+download, integer MiB `>`
comparison at session admission; an admitted session can exceed the threshold.
Global username counters survive server replacement; daemon metrics persistence is
a different contract. Real independent reference test: 1-day/1-MiB Alice quota allows
a 2-MiB bidirectional session, rejects next Alice admission, leaves Bob working.
Default race/checkptr: PASS. This is **source/runtime reference evidence**, not
Splicore feature acceptance. Splicore exact-byte lifetime TrafficPolicy mapping:
**not compatible; QuotaNative not exposed yet**. Native rate limit: none found.
Strict policy rejects; explicit metadata_only is persisted but unenforced.

## ClientProfile

Endpoint: DisplayEndpoint only. Credential: authorized generic username/password.
Options: underlay/MTU/multiplex. Runtime internals leaked: **NO**. Ordinary JSON and
formatting redact credentials; runtime support formatting also redacts private state.

## Exporters

Official Mieru 3.38.0: SUPPORTED profile-core client config, consumer supplies local
SOCKS/RPC settings. Mihomo 1.19.30: SUPPORTED fragment with MTU1500 only.
sing-box 1.14.1: UNSUPPORTED, no Mieru outbound. Surge/URI/Xray/unknown version:
UNSUPPORTED. Explicit binding_id required for multi-user exports. Unsupported TLS/
security/options fail closed. No invented client schema or URI.

## Interoperability

**Managed Splicore acceptance: 24 positive cells PASS**, distinct from embedding
and upstream quota probes. Linux network namespace contains only loopback.
Pinned clients and their actual version output are checked before traffic:

| SHA ID | Client/version | Executable SHA256 |
|---|---|---|
| M1 | Official Mieru 3.38.0 | 70d4224ecf5cd8e1fb32c0759eb386147b39c3729e2ddacc3f685a239339f699 |
| H1 | Mihomo 1.19.30 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 |

Each SHA ID resolves to the full verified executable digest above.

| Client | Version | SHA ID | User | Endpoint | Underlay | TCP | UDP | Result |
|---|---|---|---|---|---|---|---|---|
| mieru | 3.38.0 | M1 | Alice | 127.0.0.1 | tcp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Bob | 127.0.0.1 | tcp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Alice | 127.0.0.1 | tcp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Bob | 127.0.0.1 | tcp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Alice | ::1 | tcp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Bob | ::1 | tcp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Alice | ::1 | tcp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Bob | ::1 | tcp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Alice | localhost | tcp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Bob | localhost | tcp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Alice | localhost | tcp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Bob | localhost | tcp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Alice | 127.0.0.1 | udp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Bob | 127.0.0.1 | udp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Alice | 127.0.0.1 | udp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Bob | 127.0.0.1 | udp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Alice | ::1 | udp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Bob | ::1 | udp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Alice | ::1 | udp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Bob | ::1 | udp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Alice | localhost | udp | PASS | PASS | PASS |
| mieru | 3.38.0 | M1 | Bob | localhost | udp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Alice | localhost | udp | PASS | PASS | PASS |
| mihomo | 1.19.30 | H1 | Bob | localhost | udp | PASS | PASS | PASS |

Server is the current `splicore-race-default`, SHA256
`27ce4ef96f64ae026f1d48f09aa4be845100107c5033abda0147aa5fd042f5f0`. All Go source/module hashes match the
candidate build/test manifest. No external targets or permanent servers.

## Stress

Concurrency: 16 mixed Alice/Bob TCP/UDP transfers per client/endpoint/underlay pair,
plus two-inbound parallel traffic. 4 MiB SHA integrity in every positive cell: PASS.
Reconnect, abrupt client close followed by new traffic, recovery/restart and
cross-inbound isolation: PASS. Owned child joins and private config/key/database
cleanup: PASS in final evidence; no retries of failed payloads.

## Race

Linux default race: PASS with `-race -count=1 -tags
with_quic,with_utls,splicore_xray_integration` over all internal/splicore and cmd/splicore
packages, using the exact existing Xray artifact. Default checkptr: PASS. Native
10-cycle adapter default race: PASS. Affected common/adapter/transport shared package
default race: PASS. Managed runtime binary built with default race/checkptr: PASS.
No race/checkptr disabling, skips, panic recover, global data-path mutex, sleeps or
retry masking introduced. Vision remains deferred by its existing managed gates;
this phase does not modify that upstream dependency.

Fuzz: canonical/credential creation import final 20-second campaign **812,265**
executions; profile/exporter campaign **552,230** executions, PASS. No official
crypto/wire fuzzing or rewrite. Tests and fuzz caches stay external.

## Regressions

| Protocol | Fresh current candidate result | Actual scope |
|---|---|---|
| Snell | PASS | One complete pinned-client IPv4 cell, TCP/UDP, 16 concurrency, 4 MiB/reconnect/abrupt close |
| HY2 | PASS | One complete pinned-client IPv4 cell with its TLS/UDP/concurrency/integrity checks |
| TUIC | PASS | One complete pinned-client IPv4 cell with its TLS/UDP/concurrency/integrity checks |
| VLESS Native | PASS | One complete native REALITY pinned-client IPv4 cell |
| VLESS Xray | PASS | One complete plain flow-none Xray pinned-client IPv4 cell |
| FinalMask/Sudoku | PASS | Full managed feature driver including negatives/recovery/dual placement |

These are fresh critical regressions, not a claimed repeat of the full historical
Phase 7 matrix. All owned package tests and pinned Xray integration tests also pass.
Historical drivers/reports/evidence unchanged; external bounded wrappers select
the first complete regression cell without changing repository drivers.

## Dependency Audit

New Go dependency: only official Mieru v3.38.0. GPL-3.0-or-later is compatible with
the existing GPL-3.0-or-later derivative boundary. Preserve authors/copyright,
LICENSE/NOTICE and corresponding-source/build obligations when conveying builds.
No third-party source copied or notice text replaced; no release authorized.
Actual server import graph selected modules:

| Module | Selected version | License | Baseline upgrade |
|---|---|---|---|
| github.com/enfein/mieru/v3 | v3.38.0 | GPL-3.0-or-later | new module |
| github.com/google/btree | v1.1.3 | Apache-2.0 | none |
| golang.org/x/crypto | v0.54.0 | BSD-3-Clause | none |
| golang.org/x/sys | v0.47.0 | BSD-3-Clause | none |
| google.golang.org/protobuf | v1.36.11 | BSD-3-Clause | none |
| golang.org/x/net | v0.57.0 | BSD-3-Clause | none |
| golang.org/x/text | v0.40.0 | BSD-3-Clause | none |
| google.golang.org/grpc | v1.79.1 | Apache-2.0 | none |
| google.golang.org/genproto/googleapis/rpc | v0.0.0-20251202230838-ff82c1b0f217 | Apache-2.0 | none |

The first five modules are the actual apis/server import graph; remaining four
are existing selected upstream module requirements, audited separately. The
embedding path has no daemon/gRPC import. Concrete LICENSE/NOTICE/AUTHORS file
digests and baseline selected-version comparison: dependency-license-audit.json.
CGO: no new dependency requirement. Windows build and arm64 cross-compile use
CGO_ENABLED=0; Linux amd64 default/race builds use the existing CGO_ENABLED=1
toolchain configuration (race requires CGO). Root license/notice unchanged.

Comparable Linux amd64 full-tag unstripped builds under the same toolchain/flags:
Phase 7 **37,550,201 bytes**, Phase 8 **47,322,936 bytes**; increase
**9,772,735 bytes (9.32 MiB, 26.03%)**.
Cached build measurements: baseline 19.33 s, current 14.78 s, race build 15.75 s.
These are warm-cache gate times, not cold-build performance benchmarks.

| Artifact | Bytes | SHA256 |
|---|---|---|
| splicore | 47322936 | 4aecc1523b9e79924924ca956104262fb3c0a35c2c04c778a50d9298e2c6dd28 |
| splicore-race-default | 65716446 | 27ce4ef96f64ae026f1d48f09aa4be845100107c5033abda0147aa5fd042f5f0 |
| splicore-phase7-baseline | 37550201 | 6368c0c10c812400a76c6d417d41f16a2eb2307edfc4963185e33597e7a4b1a0 |
| splicore-linux-arm64 | 44620852 | f8f3caa3a8058e52e99bede7986981eaebfd0218e53b827bcb16b12d826c70ef |
| Windows amd64 | 45131264 | 87fd1196d6d3230a4f80540496320f7a043940f6b3e4a5dfca31753825900fc9 |

## Scalability

Central protocol switch cases added: **0**. Application protocol branches: **0**.
DB protocol columns/migrations: **0**. Account protocol fields: **0**. Special API
routes: **0**. Native Engine and generic creation/Binding/export/recovery remain
shared; local exporter switches map target formats. Phase8 composition registers
Mieru and reuses Phase7 without mutating historical maps.

## Security

Password: encrypted in existing vault; safe generation; explicit protected export
only. Ordinary API, logs, CLI, doctor, process argv, closed SQLite/WAL live-secret
scans: PASS. Private support/runtime formatting: PASS. No private protobuf/settings
object returned by public profiles. Managed configs reside in 0700 dirs/0600 files,
children joined and private trees deleted on exit. Upstream cipher-cache erasure
and hardened malicious-peer resource limits are not claimed.

## Platform

Windows amd64: full-tag unit tests/build PASS, native 10-cycle loopback PASS.
Linux amd64 Ubuntu-24.04 WSL2: full runtime, default race/checkptr, interop,
shared regressions, leak tests and builds PASS. Linux arm64: final full-tag compile
PASS; runtime NOT QUALIFIED (no actual arm64 runtime environment).
Source project Go 1.25.5 requirement; validation toolchains Go 1.26.2 (Windows), Go 1.26.6 (Linux).

## Docker

Touched: **NO**. Queried: **NO**. DO NOT QUERY / DO NOT TOUCH preserved.
Redis/TeleLedger unchanged.

## NoBrand

Real D:/code/NoBrand-OneClick changes: **NONE**, tracked hashes, HEAD/status equal.
Synthetic mapping: name, listener, display endpoint, transport/MTU/multiplex,
account_name and generic username/password credential. No quota enforcement mapping;
metadata_only is explicit. [Migration](../integration/NOBRAND_MIGRATION.md).

## Documentation

Canonical architecture/context/SDK/Engine/capability/client/interop/storage/security/
testing/API/OpenAPI/license/migration/roadmap documents updated. New Mieru contract,
workflow and ADR 0020 added. Stage 1 reference and Stage 2 prototype results remain
distinct from Stage 3 managed native acceptance; field beta/Stable deferred.
Historical Phase 0–7 reports: **UNCHANGED** (13 report/requirements hashes checked).
Formal Markdown links/metadata/OpenAPI, canonical fixture and live Mieru response validation: **PASS**.

## Files changed

Production additions: protocol/mieru module and creation codec, Native MieruCompiler,
exporter mapping and Phase8 registration. Small existing edits: app/CLI composition,
Native UDP capability, official export format, go.mod/go.sum. Added protocol/native/
export/application tests, synthetic migration fixture and managed interop driver;
formal docs checker accepts mieru live schemas. Canonical docs and this new report.
Exact path list: external final-scope-audit.json; no upstream runtime source changed.

## Development failures retained

- Initial recovery test used random binding sort order as user identity. Corrected
  to match both actual identities/credentials; failed default-race log retained.
- Initial native tests compared live interleaved atomic snapshots; exact assertions
  now use joined Close. Official client fixture owns raw UDP sockets for Stop.
  One Windows unspecified UDP bind returned WSAENOBUFS; loopback family binding
  fixed the local oracle fixture. Prior failed logs retained.
- Initial managed Mihomo cells could begin before tunnel.OnRunning, although SOCKS
  was listening. Official v1.19.30 source confirms listener→provider/GC→running
  order. Private synchronous same-config PUT now waits for its executor mutex before
  first payload; no failed payload retried and no sleep added.
- Requiring zero active sessions immediately after UDP client process exit was
  not a valid peer-EOF contract. Owned inbound Close/join is the cleanup assertion;
  exact payload tests remain. The failed premature-quiescence evidence is retained.
- TCP relay review found upload EOF truncated response. Narrow half-close correction
  has a destination-waits-for-EOF regression test. No wire implementation changed.
- Quota reference initially reused server quota fields in client config, correctly
  rejected by upstream; client projection now copies only name/password. Failed
  setup log retained. This test never exposes quota as Splicore capability.

## Evidence index

External root contains entry Git/source/NoBrand manifests, release/tag/module pins,
official-source-manifest.json, SOURCE_AUDIT.md, embedding/native lifecycle logs,
linux-gates.json, final-extra-gates.json, windows-full-unit.log,
managed-interop-final/interop-results.json and cleanup.json,
official-quota-reference.log, dependency-license-audit.json,
critical-regression-final/smoke-gates.json, final-platform-build-artifacts.json,
candidate/final source manifests and final-scope-audit.json. Safe live responses
and export envelopes redact secret content before archival. No downloadable client
binaries or runtime private configs are committed to Git.

## Git

Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
No Git history repair/change. Candidate left uncommitted for review.

## Final Result

**MIERU NATIVE INTEGRATION READY FOR REVIEW**.

## Blockers

None within the bounded Experimental candidate scope.
Experimental limits above are explicit and not Stable/platform guarantees.
