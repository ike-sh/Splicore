# DNS Model

- Documentation status: Canonical
- Audience: Runtime, API and security developers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Resolver intent, bootstrap dependencies, cache and ownership.
- Lifecycle: Update with implemented transports and runtime evidence.

## Experimental transports and rules

DNSServer, DNSRule, DNSProfile and DNSCachePolicy are independent canonical types.
SQLite stores intent; compiled rules/transports/cache are artifacts. System, UDP,
TCP and verified DoT are Experimental. System requires explicit DIRECT, empty
endpoint/TLS and uses the OS resolver. UDP/TCP specify host/port. DoT adds verified
ClientTLS public trust/server name. TLS skips/server private keys cannot be represented.
DoH is DEFERRED: inherited HTTPS DNS transport allocates from unbounded Content-Length
or reads an unbounded body. It needs a bounded transport review.

UDP reuses the existing raw transport. TCP/DoT use one owned connection and existing
bounded 16-bit DNS framing/TLS dialer, avoiding extra A/AAAA reuse probes.
Detour is Outbound, Group or explicit DIRECT; failure never falls back to another
resolver or DIRECT. DNS rules independently select resolver, first-match domain
exact/suffix/keyword/managed RuleSet. They do not select a traffic route.

Strategies: ipv4_only, ipv6_only, prefer_ipv4, prefer_ipv6, dual. Server overrides
profile. Dual returns A then AAAA; preferences reorder those answers; only strategies
query only their type. At most 32 addresses. Empty answers/errors fail.

## Bootstrap and routing interaction

Bootstrap must be System/DIRECT or IP-only DIRECT UDP/TCP. Node, resolver endpoint
and probe hostnames use only bootstrap, never destination rules/dependent groups.
Validation rejects self-proxied/domain bootstrap, missing references and graph cycles.
Original Node endpoint remains in SQLite; only an ephemeral build copy receives an IP.
Changing bootstrap resolver/strategy/timeout rebuilds affected domain adapters.
Bootstrap failure aborts mutation; startup degrades the client while retaining control.

Disabled DNS preserves Phase 11 adapter semantics. Enabled DNS centrally resolves
destinations, keeping original domain metadata. Routing evaluates the first actual
dial candidate in strategy order. Alternate address retry/Happy Eyeballs is not added.

## Cache, stats and lifetime

A generation owns an isolated bounded LRU. Key: resolver UUID, terminal detour,
effective strategy, normalized domain, qtype. Positive TTL is minimum answer TTL;
negative TTL is min(SOA TTL, SOA minimum). No SERVFAIL caching. System is uncached
because the OS supplies no TTL. Capacity 0..4096; expired entries do not answer.
Flush invalidates older in-flight refill. New snapshots start with empty cache.

Timeout 1..10 seconds, 32 servers, 256 DNS rules. Atomic query/hit/miss/failure and
per-server counts have no per-domain labels. Cache owns message copies; narrow locks
never wrap I/O. Query/socket owner cancels, closes and joins. DNS lookup performs a
real query; route explain performs none.

## FakeIP audit

Inherited FakeIP depends on router reverse mapping and store/cache ownership.
SOCKS lacks the full translation contract: DEFERRED TO TUN PHASE. No fake addresses,
DNS hijack or system resolver change is exposed.
See [routing](ROUTING_MODEL.md), [policy](POLICY_MODEL.md),
[ADR 0026](../adr/0026-dns-bootstrap-dependency.md) and the
[report](../reports/PHASE_12_ROUTING_DNS_POLICY_REPORT.md).
