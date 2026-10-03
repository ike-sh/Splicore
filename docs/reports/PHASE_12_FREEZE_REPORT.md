# Splicore Phase 12 Freeze Report

- Documentation status: Historical
- Audience: Maintainers and subsequent TUN integration developers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Authorized Phase 12 checkpoint, source match and Git closure.
- Lifecycle: Preserve this freeze snapshot; subsequent work uses a new phase report.

## Baseline

Phase 11: `5397f8e6ef8e28981099b14b9e09400593048b7e`.
Message: `feat(client): expand protocol outbounds and SOCKS UDP`; sole parent
Phase 10 `463cb8ea4fc497d684b0f4ff8923015009d1187e`. Actual Git history and the
[Phase 11 freeze report](PHASE_11_FREEZE_REPORT.md) were checked locally.

Entry branch: `codex/phase-12-routing-dns-policy`, HEAD == main == Phase 11,
index EMPTY. The 58 expected Phase 12 paths and complete source matched final
acceptance provenance byte-for-byte; no unknown commit, remote or unrelated file.
origin NONE; sole upstream remote unchanged. The maintainer explicitly authorized
exact-file staging, ONE Phase 12 commit, main fast-forward and a clean Phase 13
branch, then stop. No reset/clean/restore/stash/rebase/amend/history rewrite.

## Status

Routing: **Experimental**. DNS: **Experimental**. Policy: **Experimental**.
Phase 12: **FROZEN** after closure gates and the authorized Git operations.
The [acceptance report](PHASE_12_ROUTING_DNS_POLICY_REPORT.md) is unchanged; its
READY FOR REVIEW and stage/commit NONE statements describe acceptance time.
No Stable/public release or additional platform qualification is implied.

## Routing

Rule types: domain exact/suffix/keyword, strict canonical IPv4/IPv6 CIDR,
inclusive single port/range 1..65535, TCP/UDP, LocalInbound UUID and RuleSet.
Regex/protocol/process/package/Wi-Fi/Geo inference remain DEFERRED.
Rule ordering: first match wins; nonempty categories AND, values within category
OR; domain predicates share one OR category; enabled set references OR their
matches and AND with other categories. No map iteration selection.
Final/default: ordered rules, local selected outbound, network final, legacy default.

RuleSet: inline/local canonical managed, immutable UUID, mutable name, operator
content revision and enabled/disabled state. Remote providers DEFERRED. Compiled
representation is derived from SQLite. DIRECT/REJECT: typed builtin actions,
no ProtocolID or fabricated RemoteNode. TCP REJECT fails SOCKS connect; UDP drops
without remote flow. First-rule pre-resolution REJECT avoids DNS.

Snapshot: owned complete compiled graph, prepared before SQLite commit, then atomic
publication. Atomic swap: PASS. No packet/session SQLite reads or route=nil interval.
TCP keeps original adapter; UDP retains old graph and per-group terminal affinity,
including new destination flows in that association. New sessions use new snapshot.
Explicit stop/restart/listener removal retain their termination contract.

## Policy Groups

Selector: exact typed persisted member, atomic transaction without daemon restart;
unknown allowed, known unhealthy fails without silent alternate. URL-Test: real
outbound HTTP/HTTPS response, configured expected status and bounded body; minimum
measured latency, ordered initial ties, healthy prior choice retained within tolerance.
Fallback: first healthy ordered member, primary down→secondary, recovered primary
used for new selection; all-down unavailable, no implicit DIRECT.
Load-Balance: **round-robin ONLY**; atomic counters and one terminal per group per
UDP association, never per-packet rotation. TCP selects once.
Group nesting supported, depth eight. Direct/indirect cycle detection: PASS.
UDP affinity: PASS. DIRECT explicit; REJECT cannot qualify automatic strategies.

Health: unknown/healthy/unhealthy, timestamp/latency/fixed error. Newer passive
failure overrides older active healthy; later active success restores. Passive
success cannot replace an active measurement. Successful payload close does not
poison health. Changes affect new selections, never forcibly migrate good sessions.
Samples/cache are observations, not SQLite authority. Four scheduler workers,
queue16/256 probed memberships; cancellation closes and joins, ticker stops.
HTTP/HTTPS operator target only; no public default/credentials/redirect/environment
proxy; body cap4097 bytes. Retired DNS owners are included in shutdown cancellation.

## DNS

System: SUPPORTED, explicit DIRECT/OS resolver, uncached without TTL.
UDP: SUPPORTED, inherited raw transport. TCP: SUPPORTED, one owned framed exchange.
DoT: SUPPORTED, verified CA/server name and bounded framing; TLS negatives PASS.
DoH: **DEFERRED**, inherited HTTPS response allocation needs a bounded review.
FakeIP: **DEFERRED TO TUN PHASE**, reverse mapping/lifetime contract absent in SOCKS.

Independent DNS rules select resolver by ordered domain exact/suffix/keyword/sets.
Proxy DNS: explicit Outbound/Group detour, no silent DIRECT fallback.
DNS leak gate: PASS with actual direct/proxy resolver query counts.
Dependency loop: PASS. Node/resolver/probe domains use separate System/DIRECT or
IP-only DIRECT UDP/TCP bootstrap, never their dependent destination/group resolver.
Original node domain remains canonical; only build copy receives IP.

Cache: bounded generation LRU0..4096; resolver/terminal/strategy/domain/qtype key,
positive minimum answer TTL, negative minimum SOA TTL/minimum, no SERVFAIL caching.
Owned message copies and narrow locks, no network I/O under cache lock. Flush API/
CLI invalidates in-flight refill without restart. Bounded counters use configured IDs.
Strategies: ipv4_only/ipv6_only/prefer_ipv4/prefer_ipv6/dual, maximum32 addresses.
Routing retains original domain and evaluates first actual dial candidate in strategy
order. Explain evaluates supplied metadata without DNS/outbound I/O or secret output.

## Architecture and Storage

RouteRule != PolicyGroup; RuleMatch != RouteAction; Outbound != PolicyGroup;
RemoteNode != Outbound; DNSRule != RouteRule; DNSServer != RemoteNode.
Public schema is canonical Splicore intent, not raw sing-box route/DNS JSON.
SQLite authority; compiled graph/health/cache derived artifacts. Generic
client_network_profiles(singleton,document), migration0006, DatabaseSchema6.
Protocol-specific route/DNS DB columns:0; new binaries/services:0.

Application/API/CLI share strict bounded validate/plan/prepare/commit/activate and
revision/HMAC/audit. Reference deletes reject; failure leaves old traffic/graph.
Route/policy/DNS/selector updates use same transaction. Corrupt committed graph
degrades client, preserves DB and keeps server/control live. Stats: bounded rule
hits/group selection/health/DNS query-cache/per-server counts, no domain labels.

## Scope Audit

| Category | Frozen owned implementation |
| --- | --- |
| A. Route Domain | Typed rules/matches/actions/profiles independent of protocol |
| B. Rule Matcher | Ordered compiled domain/prefix/port/network/local predicates |
| C. RuleSet | Inline/local ID/revision/status, bounded shared DAG validation |
| D. Snapshot | Prepare/commit/atomic publication, retained generation leases |
| E. DIRECT / REJECT | Builtin actions, no fake Node/protocol |
| F. Selector | Persisted typed choice, shared transaction |
| G. URL-Test | Actual outbound HTTP measurement, latency/tolerance |
| H. Fallback | Ordered health and all-down failure/recovery |
| I. Load-Balance | Atomic RR and private UDP association affinity |
| J. Health Scheduler | Four workers/bounded queue/cancel/join/passive integration |
| K. DNS Domain | Independent resolver/rule/profile/cache intent |
| L. DNS Runtime | System/UDP/TCP/verified DoT, existing adapter detours |
| M. DNS Cache | Context/TTL isolation and generation-safe flush |
| N. DNS Dependencies | Explicit bootstrap for node/resolver/probe endpoints |
| O. Transactions | Complete graph activation, reference/cycle/rollback safety |
| P. API / CLI | Generic protected network resources and canonical round trip |
| Q. Storage | Generic aggregate/migration0006/schema6; no protocol columns |
| R. Tests / Performance | A–H/race/lifecycle/negative/fuzz/linear-scan benchmarks |
| S. Docs / ADR | Canonical contracts, accepted ADR0024–0026, freeze navigation |
| T. Phase 12 Report | Unchanged acceptance snapshot plus this closure record |

Freeze edits eight existing documentation files and adds this report. Accepted
functional source/tests/scripts/packaging and migration0006 stay unchanged.
No logs/DB/cache/key/bundle/binary/fuzz/validation artifacts enter staging.

## Acceptance

| Gate | Result |
| --- | --- |
| Linux full owned default race/checkptr | PASS;33 packages/194 top-level tests |
| A–H routing/DNS/policy scenarios | PASS; actual Application/SOCKS and installed core |
| Concurrent lifecycle10x | PASS; graph/selector/health/cache/RR/retired query shutdown |
| Shared DNS/TLS/jsonstrict/clientio race | PASS |
| Windows complete tests/native build | PASS; no Windows race claim |
| Linux and three-platform builds | PASS; arm64 build only |
| Network-free canonical/compile fuzz | PASS; no wire/TLS/QUIC fuzz |
| Performance | PASS for bounded Experimental scope; measured below |
| Package/source consistency | PASS; repeated local Linux package/source identical |
| Install/restart/crash/upgrade/rollback/reinstall | PASS; fresh owned six-stage campaign |
| Client six adapter TCP/UDP regressions | PASS;24 adapter/target cells per campaign |
| Server regressions | PASS; eight frozen server fixtures, including Sudoku |
| Docs/links/OpenAPI/live API and CLI schemas | PASS |
| Repository/staged/evidence secret and whitespace audits | PASS |

Original final acceptance is preserved. Fresh full owned race/checkptr, affected
shared race, ten-repeat lifecycle, Windows test/build, fuzz/vet/docs, package and
installed smoke records are in the freeze evidence directory. No sanitizer
suppression, skip, panic recovery or sleep/retry masking. Only owned loopback
fixtures and previously pinned reference artifacts; no downloads/external targets.

## Performance

Actual accepted Go1.26.6/Linux amd64/Ryzen7 5700X/GOMAXPROCS4 benchmark:

| Rules | Compile ns/op | Compile B/op | Compile allocs/op | Worst-miss match ns/op | Match B/op / allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 419,581 | 673,653 | 7,013 | 29,887 | 0 / 0 |
| 10,000 | 3,870,323 | 6,870,507 | 70,020 | 315,330 | 0 / 0 |

Memory is allocation per compile, not retained heap/RSS. This excludes full
Application/storage/adapter preparation. Ordered worst-miss remains O(N).
No invented latency threshold or extreme-scale claim; acceptable as the measured,
bounded Experimental scope. Original performance evidence unchanged.

## Acceptance Source Match

Accepted complete source SHA256:
`4220854b7a701602ce848d69861e943f9bdbf63d89df0aa2337a18dfe477d2e9`.
Every accepted functional/test/script/package byte matches in the working tree.
Freeze permits only eight documentation edits plus this report. Complete freeze
manifest/package digest is recorded separately externally. Git's existing
core.autocrlf=input normalizes CRLF when staging; staged source is checked against
the corresponding normalized accepted text, without changing repository settings.
Precommit build provenance honestly records Phase11 HEAD/source_dirty:true.

## Security

Repository/docs/tests/generated schemas and staged source: PASS. Literal matches
are classified as unchanged frozen or explicit synthetic test data, never treated
as production credentials. PEM private-key material/runtime artifacts are excluded.
Installed status/doctor/support secret scans PASS, including decompressed bundle.
No new credential-bearing DNS/route/policy fields or protocol-specific REST family.
route explain has no I/O; dns lookup is explicit. No external target access.

## WSL Teardown

Outer experimental unit stop timeout: **RECORDED**. MainPID: **0**. cgroup:
**EMPTY**. Residual owned Splicore/Xray processes: **NONE**.
Classification: **TEST HARNESS / OUTER UNIT TEARDOWN LIMITATION**.
Accepted evidence and fresh cleanup records retained. Clean outer-init termination
is not claimed; this does not classify Splicore graceful shutdown as fully failed.

## Platform

Ubuntu24.04 WSL2 amd64: **QUALIFIED Experimental**. Windows: **BUILD/TEST PASS**.
Windows race: **NOT EXECUTED**. Linux arm64: **BUILD ONLY/runtime NOT CERTIFIED**.
No Windows service qualification, TUN/system proxy qualification or upgraded status.
Pinned Xray26.3.27 and official embedded Mieru3.38.0 unchanged.

## Runtime Audit

sing-box upstream:0. Mieru source:0. Xray source/artifact:0. Wire:0.
Dependencies:0 unexpected changes; go.mod/go.sum unchanged. Historical Phase0–11
reports and frozen migrations0001–0005 unchanged; accepted migration0006 unchanged.
NoBrand HEAD/status/source unchanged. Docker NOT QUERIED/NOT TOUCHED.

## Commit

Exactly ONE authorized Phase12 commit. Message:
`feat(client): add routing DNS and policy engines`.
Sole parent: `5397f8e6ef8e28981099b14b9e09400593048b7e`.
PHASE_12_COMMIT: resolve `git rev-parse codex/phase-12-routing-dns-policy`.
The same commit cannot embed its own SHA. Full SHA and actual files/insertions/
deletions are recorded externally in commit.json/final-freeze.json and final reply.
No amend, merge commit, rewritten history, push, tag or release.

## Git

main == Phase12 == Phase13 HEAD == PHASE_12_COMMIT.
main advances only by `git merge --ff-only codex/phase-12-routing-dns-policy`.
Working tree CLEAN; index EMPTY. Unrelated refs/remotes/tags unchanged.
origin NONE; Push NONE; Tag NONE; Release NONE.

## Phase 13

Branch: `codex/phase-13-tun-system-integration`. Base: PHASE_12_COMMIT.
Implementation: **NOT STARTED**. Branch creation is the final authorized action;
only read-only final equality/cleanliness checks follow. Stop before implementation.

## Deferred

TUN/system proxy/DNS hijack, FakeIP/DoH/regex/protocol-process inference/Geo data,
remote RuleSet/subscriptions/proxy providers/node import/GUI/Panel, Vision,
client FinalMask/Sudoku, Xray half-close qualification, Windows race, arm64 runtime,
NoBrand migration and existing server deferrals.

## Evidence

Acceptance: `D:/splicore-validation/phase12-20261003/final-acceptance.json`.
Freeze: `D:/splicore-validation/phase12-freeze-20261003`.
Owned lab: `/root/splicore-p12-freeze-20261003/service-lab`.
Entry/source/scope/secret/staged/commit/ref manifests, commands, packages, traffic,
schemas and cleanup stay external; prior acceptance/historical reports preserved.

## Final Result

**PHASE 12 FROZEN** after all gates and the authorized single-commit Git closure.

## Blockers

None within the qualified Experimental Phase12 scope.
