# Splicore Phase 12 Routing DNS Policy Report

- Documentation status: Historical
- Audience: Maintainers and reviewers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Phase 12 implementation, measured acceptance and explicit limits.
- Lifecycle: Uncommitted review record; Phase 0–11 reports remain immutable.

## Baseline

Phase 11 Freeze: `5397f8e6ef8e28981099b14b9e09400593048b7e`.
Parent Phase 10: `463cb8ea4fc497d684b0f4ff8923015009d1187e`.
Branch: `codex/phase-12-routing-dns-policy`; entry CLEAN/index EMPTY.
HEAD/main/refs and sole upstream remote are unchanged; origin is absent.

PHASE_12_BASELINE_CLIENT_GATE: PASS before implementation. Full owned Linux tests
with default race/checkptr, pinned Xray and DIRECT/six client adapter TCP/UDP
fixtures passed in 102.14 seconds. Evidence: baseline-client-race.json/.log.
All evidence is external: `D:\splicore-validation\phase12-20261003`.
Runtime reference probes are separate from Splicore feature acceptance.

## Status

| Engine | Status | Acceptance |
| --- | --- | --- |
| Routing Engine | Experimental | PASS |
| DNS Engine | Experimental | PASS for System/UDP/TCP/verified DoT |
| Policy Engine | Experimental | PASS for Selector/URL-Test/Fallback/round-robin |

These are local development artifacts for review, with no production certification
or public release.

## Routing

Rule ordering: ordered first match wins; map iteration never selects a route.
Match semantics: nonempty categories AND; values within a category OR. Exact/suffix/
keyword form one domain category. Empty match is unconditional. Set references OR
enabled set matches and AND with other categories. Actions reference immutable IDs.

| Field/action | Implementation/result |
| --- | --- |
| Domain exact | ASCII case insensitive, one trailing dot normalized; PASS |
| Domain suffix | Exact domain or suffix at label boundary; PASS |
| Domain keyword | Valid bounded substring; PASS |
| Domain regex | DEFERRED |
| IPv4 CIDR | Strict canonical prefix parse, compiled once; PASS |
| IPv6 CIDR | Same semantics, actual ::1→TUIC traffic; PASS |
| Ports | Inclusive single/range, 1..65535, start≤end; PASS |
| TCP/UDP | Explicit network metadata; PASS |
| Local Inbound | Immutable listener UUID independent of server Inbound; PASS |
| RuleSet | Inline/local, UUID/name, enabled/disabled, operator content revision; PASS |
| Final route | Rules, local selected outbound, network final, legacy default |
| DIRECT | Typed builtin, no fabricated RemoteNode; PASS |
| REJECT | TCP SOCKS connect failure, UDP drop without remote flow; PASS |

Protocol inference is DEFERRED: SOCKS has no qualified inference contract. Invalid
domain/CIDR/port/reference, cycles and unsafe deletes fail validation without panic.

## Routing Runtime

Snapshot: owned immutable config/maps/prefixes plus synchronized observations;
no per-connection SQLite. Compile complete graph/adapters/listeners before commit.
Atomic swap: PASS; failed build/bind/commit releases candidate and keeps old graph.
Existing sessions: TCP retains adapter; UDP retains old graph and per-group terminal
affinity, including new destination flows after replacement. New sessions use new
generation. Explicit stop/restart, listener removal and shutdown close sessions.

Bounds: 10k route rules, 128 sets, 20k combined matches, 256 values per match, 16
set nesting edges, 2 MiB document. Shared DAG paths memoized; ordered scan is linear.

## Policy Groups

| Strategy | Selection/failure | Result |
| --- | --- | --- |
| Selector | Persist exact selection; unknown allowed, known unhealthy fails without alternate | PASS |
| URL-Test | Completed healthy HTTP sample, minimum latency, ordered initial ties, retain healthy prior choice within tolerance | PASS |
| Fallback | First healthy in order; all-down unavailable; recover to primary for new selections | PASS |
| Load-Balance | Atomic round-robin only; unknown eligible when unprobed, unhealthy excluded | PASS |

Group nesting: supported, depth eight; direct/indirect cycle detection PASS.
64 groups/129 members; Outbound/Group/explicit DIRECT/REJECT. REJECT cannot qualify
automatic strategies. UDP affinity: PASS, private group→terminal map per association.
TCP binds once. Health changes do not migrate established sessions.

## Health

Passive: adapter lease owns timestamped health. Failed dial/no usable response fails;
closing after usable payload does not poison health. Newer passive failure overrides
older active healthy; later active success restores. Passive success cannot qualify
an active group without completed HTTP measurement.

Active: real HTTP GET through adapter; HTTPS verifies TLS. Measurement covers
bootstrap if needed, connect/TLS/headers/bounded body, configured expected status.
Latency: integer milliseconds. State: unknown/healthy/unhealthy, last probe/latency/
fixed safe error. Health/automatic choice are observations, never SQLite authority.

Scheduler: four workers, queue16, 256 probed memberships; one coordinator/ticker,
immediate round, interval1..86400s/timeout1..10s. Cancel closes and joins. Lifecycle
lock orders Start/Add versus Stop/Wait; narrow group locks, atomic RR/counters,
payload I/O unlocked. Identical reachable graphs/unchanged adapters alone inherit
samples. 10x: PASS.

Probe: operator HTTP/HTTPS only; no public default, userinfo, redirect, environment
proxy, credentials or response-body logging. Body read cap4097 bytes.

## DNS

| Capability | Result |
| --- | --- |
| System | PASS; explicit DIRECT, OS resolver, uncached without TTL |
| UDP | PASS; inherited bounded raw DNS transport |
| TCP | PASS; one owned exchange, existing 16-bit framing |
| DoT | PASS; verified TLS dialer/framing; wrong CA/name negatives PASS |
| DoH | DEFERRED after inherited transport audit |
| DNS rules | Ordered exact/suffix/keyword/RuleSet→resolver; PASS |
| Proxy DNS | Actual Outbound/PolicyGroup detour and resolver counts; PASS |
| Direct DNS | Explicit DIRECT and resolver counts; PASS |
| Cache | Bounded isolated generation LRU with TTL/negative TTL; PASS |
| Cache flush | API/CLI, no restart, no refill from old in-flight query; PASS |
| FakeIP | DEFERRED TO TUN PHASE after audit |

Strategies: ipv4_only/ipv6_only/prefer_ipv4/prefer_ipv6/dual; server then profile.
Dual returns A then AAAA, preferences reorder both, only modes query one type.
Maximum32 addresses. Cache key includes resolver UUID/terminal detour/strategy/
domain/qtype. Positive TTL=min answer TTL; negative=min SOA TTL/minimum; no SERVFAIL
cache. Message copies owned. Capacity0..4096, servers32/rules256; counters have only
configured ID cardinality. TCP/DoT avoid inherited multiplexer extra reuse queries.

## DNS Safety

Bootstrap resolution: System/DIRECT or IP-only DIRECT UDP/TCP. Node/resolver/probe
names use bootstrap, never destination rules/dependent groups. Original node domain
stays in SQLite; ephemeral build copy gets IP. Bootstrap resolver/strategy/timeout
change rebuilds affected domain adapters. Failure aborts mutation/degrades client
startup while preserving server/control and canonical state.

Dependency loop detection: PASS; self-proxied/domain bootstrap, missing references
and group/set cycles reject. Detour failure never silently falls back DIRECT.
DNS leak test: PASS with separate owned resolver counters. TLS verification: DoT
trust and server-name checked, skip verification cannot be represented.

DoH audit: dns/transport/https.go allocates by unbounded Content-Length/ReadAll;
needs bounded transport review before reuse. Canonical validation rejects DoH.
FakeIP audit: inherited router/store/cache require TUN reverse mapping/ownership
contract absent in SOCKS. These audits changed no upstream source.

## Routing + DNS Integration

Domain preservation: original domain separate from resolved IP. Resolved IP match:
first address actually dialed in strategy order; no alternate retry/Happy Eyeballs.
Policy group DNS detour: terminal chosen once per query, PASS. Health probe resolution:
bootstrap only. Disabled managed DNS preserves Phase11 resolution semantics.
First-rule pre-resolution REJECT avoids DNS; later rules may need it to preserve
earlier IP priority. Explain uses supplied metadata/resolved IPs, no DNS/outbound
I/O or hit counters. Unavailable group returns matched rule/group, available=false;
invalid metadata still fails.

## API

Protected /api/v1 routes/route-rules/rule-sets/policy-groups/dns/servers/dns/rules/
dns/profile, CRUD/If-Match/global revision. Actions: routes/explain, group select,
dns/lookup/cache flush; observations: policy-groups/status, dns/cache/status.
Aggregate replace uses client/validate/plan/apply. Strict bounded JSON, duplicate/
unknown fields, methods/query parameters guarded. Protocol-specific APIs: NONE.
Individual CRUD/reference/unavailable explain tests PASS. Actual installed replies
validate against OpenAPI: six adapter matrices, six network stage statuses, eight
new response schema shapes. RuleSet revision is the existing decimal-string type.

## CLI

route status/explain; policy list/status/select/validate/plan/apply; dns list/status/
lookup/flush/validate/plan/apply; rule-set/route-rule list/validate/plan/apply;
network export/validate/plan/apply. Application handles every mutation. Exported
canonical Config validates/plans/applies unchanged. Lookup explicitly queries and
returns resolver/strategy/addresses/cache-hit. Explain performs no I/O. PASS in
control tests and installed qualification.

## Storage

Generic table: client_network_profiles(singleton,document), new0006_network_profiles.sql,
strict JSON aggregate under existing revision/transaction/audit. DatabaseSchema=6;
ABI/config schemas unchanged. Protocol-specific columns:0. SQLite authority: PASS.
Runtime artifacts: NON-AUTHORITATIVE, memory-only, require no persistent cache file.
Old migrations0001–0005 byte-identical. Schema5→6/reopen/persistence/rollback tests
PASS. Corrupt/duplicate/unknown/broken references preserve DB and report client
degraded/client_committed_state_invalid; server/control stay live, no auto-delete.

## Transactions

Route/policy/DNS: validate→plan→prepare complete graph→SQLite commit/revision/HMAC/
audit→atomic activation. Selector persists without daemon restart. Bulk100 rules/
group/DNS update uses one transaction. Rollback: PASS, injected commit failure keeps
old traffic/revision/graph. Reference safety: PASS for Outbound/Group/set/resolver
delete/missing, cycles and invalid selection. Rename retains IDs.

## Recovery

systemd restart/crash/upgrade/failed migration rollback/reinstall: PASS. Routes,
sets/groups/selector/DNS restore from SQLite, traffic PASS. Five post-install stages
assert exact graph recovery and empty runtime cache before traffic. Health/compiled
cache is not authority; no runtime files must survive restart.

## Full Acceptance Scenarios

| Scenario | Real Splicore acceptance | Result |
| --- | --- | --- |
| A | Owned suffix→Selector→Snell; other named domain→DIRECT | PASS |
| B | IPv4 CIDR→HY2, IPv6 CIDR→TUIC echo | PASS |
| C | Three real outbound HTTP samples/minimum latency/tolerance | PASS |
| D | Owned HY2 binding down→Snell/recovery→HY2; all-down error in runtime tests | PASS |
| E | Exact RR distribution and two-destination UDP association affinity | PASS |
| F | Proxy/direct split, resolver counts prove no unexpected direct query | PASS |
| G | Live TCP/UDP plus atomic100 rules/group/DNS, old graph survives/new TCP→TUIC | PASS |
| H | Server/client coexistence; server IDs/child PIDs unchanged by graph update | PASS |

Application/SOCKS A–H run ten times with Linux default race/checkptr. Installed
service runs A–H in initial/restart/crash-recovery/upgrade/rollback/reinstall stages.
Owned fixtures: IPv4/IPv6 TCP, two UDP echoes, direct UDP/proxy TCP DNS, HTTP; eight
server fixtures coexist. Namespace has only loopback, no external targets/downloads.

## Performance

Linux amd64, Go1.26.6, Ryzen7 5700X, GOMAXPROCS4, benchtime200ms:

| Rules | Compile ns/op | Compile B/op | Compile allocs/op | Worst-miss match ns/op | Match B/op / allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 419,581 | 673,653 | 7,013 | 29,887 | 0 / 0 |
| 10,000 | 3,870,323 | 6,870,507 | 70,020 | 315,330 | 0 / 0 |

Memory: total benchmark allocation per compile, not retained heap/daemon RSS.
Compilation benchmark excludes full Application/SQLite/adapter preparation. Ordered
worst-miss is O(N), about0.030/0.315ms here; extreme-scale performance unqualified.
Evidence: phase12-performance.json/.log.

## Race

Default full Linux owned race: PASS114.71s, checkptr DEFAULT/PASS.
Command: `go test -race -v -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore`.
Shared race: ./dns/... ./common/tls ./internal/splicore/jsonstrict
./internal/splicore/engine/clientio PASS. Snapshot/selector/health/cache/RR/shutdown
covered. go vet PASS. No suppression/skip/sleep/retry masking/panic recovery.
Latest lifecycle campaign includes retired DNS-owner and control tests, PASS102.36s.
Windows race: NOT EXECUTED (no supported local CGO/GCC race toolchain).

## Lifecycle

Routing10x: PASS. DNS10x: PASS. Scheduler10x: PASS. Lifecycle test itself creates ten
engines, campaign repeats ten times. Concurrent Start/Stop/Close and blocked HTTP
cancellation join; bounded worker peak exactly4; closed owner rejects new work.
Goroutine growth bounded against fixture baseline, tracked sockets close/ticker stops.
This is bounded test evidence, not general process-wide leak certification.
Manager tracks retired owners: shutdown cancels pending DNS API query after graph
replacement; regression passes ten race runs without waiting its normal timeout.

## Fuzz

Network-free canonical validation: PASS57,495 executions, eight new interesting
inputs (ten with seeds). Domain/CIDR/ports/group/DNS through bounded JSON decoder.
Rule compile: PASS63,352 executions, ninety-six new inputs (ninety-eight with seeds).
Requested5s each/four workers, reported fuzz phase≈6s. No TLS/QUIC/wire/network fuzz.
Evidence: phase12-fuzz-domain/phase12-fuzz-compile logs.

## Client Regressions

Snell/native, HY2/native, TUIC/native, VLESS/native flow-none, VLESS/Xray flow-none,
Mieru/native TCP/UDP transports: SOCKS TCP PASS, SOCKS UDP PASS. DIRECT TCP/UDP PASS.
Installed matrix: IPv4/IPv6/domain,4MiB per adapter,16 concurrent UDP, mixed TCP/UDP,
pinned owned reference servers, six stages. Client data path embedded; zero external
client runtime processes. Frozen official Xray artifact unchanged.

## Server Regressions

Snell/HY2/TUIC/VLESS native/VLESS Xray/FinalMask-Sudoku/Mieru: PASS. Eight installed
fixtures run32KiB TCP echoes; UDP echoes for frozen Snell/HY2/TUIC/Mieru matrix.
Installed VLESS server smoke remains TCP; full owned tests retain existing UDP scope.
No new protocol/wire/deferred capability inferred from routing results.

## Distribution

Package: linux/amd64,linux/arm64,windows/amd64 builds PASS. Development manifests,
packages/source archives external. Repeated linux amd64 package/source byte-identical.
Final digest/provenance in review-package-gates.json and review-a/b/repeat manifests,
not embedded here to avoid source-report self-reference.

Installed service PASS: non-root/CAP_NET_BIND_SERVICE only/private DB/key/runtime,
doctor/restart/crash child cleanup/normal upgrade/schema7 DDL-fault rollback/retained
uninstall/reinstall/support secret scan/symlink-mount purge safety/final purge.
Fault migration only in external source copy; production migrations unchanged.
Outer WSL lab stop may report unit Result=timeout; recorded host-lab limitation.
MainPID0/empty or absent cgroup proves no owned process remains.
Exact final artifacts: review-service-gates.json and service-lab-review evidence.
Failed/candidate campaigns preserved separately as diagnostic evidence.

## Platform

Ubuntu24.04 amd64: full runtime/default race/checkptr/package/service PASS, Go1.26.6.
Pinned Xray26.3.27 SHA256:
`8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.
Windows amd64: full ordinary tests PASS99.05s, real localhost A–H/SOCKS/DNS PASS,
build PASS; Go1.26.2/CGO0. Race NOT EXECUTED, Windows service unqualified.
Linux arm64: compile/build ONLY, runtime NOT CERTIFIED.

## Architecture Metrics

| Metric added | Count |
| --- | ---: |
| Central protocol switches | 0 |
| Outbound protocol branches | 0 |
| Protocol-specific route fields | 0 |
| Protocol-specific DNS fields | 0 |
| Protocol-specific DB columns | 0 |
| New services | 0 |
| New binaries | 0 |
| Upstream runtime files changed | 0 |

New protocol-independent domain/runtime packages and one generic SQLite table;
same daemon/registry/Application/API/CLI. Typed strategy/DNS transport switches
express policy, not outbound protocols. go.mod/go.sum/dependency sources unchanged.

## Files Changed

New domain/networkpolicy and networkruntime; clientruntime network integration and
profile graph; application/api/transport/cli network controls; strict JSON bounds;
SQLite aggregate/migration0006/schema version and tests. Canonical architecture/
context/client/routing/DNS/policy/storage/security/API/OpenAPI/CLI/testing/operations/
capabilities/navigation/README, ADR0024–0026, report/docs checker, installed network
smoke driver. Exact changed paths/source hashes: final-audit.json.
Historical reports/old migrations/upstream protocol runtime untouched.

## Deferred

TUN/auto-route/system proxy/DNS hijack, GeoIP/GeoSite, remote RuleSet providers,
subscriptions/proxy providers/node import, FakeIP/DoH/regex/process-package-WiFi
inference, GUI/Panel/NoBrand migration. Vision rejects all engines; client masks
deferred; Xray TCP half-close NOT QUALIFIED. Docker never queried/touched;
no third-party system/scan/external target access.

## Git

Stage NONE; Commit NONE; Push NONE; Tag NONE; Release NONE. No history rewrite.
HEAD/main/refs/remotes/NoBrand identity/source equal entry. Reports Phase0–11 and
migrations0001–0005 unchanged. Work remains unstaged for review.

## Final Result

ROUTING DNS POLICY READY FOR REVIEW

## Blockers

None for the qualified Experimental Phase12 scope. Deferred/platform limits remain.

## Evidence Index

| External record | Responsibility |
| --- | --- |
| entry.json | Frozen baseline/protected source/NoBrand/refs |
| baseline-client-race.json/.log | PHASE_12_BASELINE_CLIENT_GATE |
| phase12-full-default-race-final.json/.log | Latest full owned race/checkptr |
| phase12-lifecycle-10x.json/.log | A–H/control/RR/cache/scheduler/retired query10x |
| phase12-shared-race.json/.log | Affected inherited/shared packages |
| phase12-windows-full.json/.log | Full Windows ordinary tests/local acceptance |
| phase12-vet/performance/fuzz records | Static analysis/measured benchmarks/fuzz |
| review-package-gates.json | Final source/artifact hashes/reproducibility |
| review-service-gates.json | Final artifact distribution/cleanup |
| service-lab-review/network/*-result.json | Installed A–H/recovery six stages |
| final-docs-live.json | Canonical docs/OpenAPI/actual response schemas |
| final-audit.json | Final protected source/refs/index/upstream/NoBrand comparison |
