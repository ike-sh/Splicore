# Routing Model

- Documentation status: Canonical
- Audience: Client, runtime and control-plane developers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Match semantics, route snapshots and connection ownership.
- Lifecycle: Update with routing changes and qualification.

## Experimental Phase 12 contract

Canonical RouteRule, RuleMatch, RouteAction, RouteProfile and RuleSet
are independent of protocol/engine/DNS. Actions: outbound/group with immutable UUID,
direct, reject. DIRECT/REJECT require no Node; legacy direct outbound ID remains valid.

Ordered rules: first match wins. Nonempty categories AND; exact/suffix/keyword form
one domain OR category; values within each other category OR. Empty match is unconditional.
Domains are ASCII case insensitive, strip one trailing dot and honor suffix label
boundaries. IPv4/IPv6 CIDRs must be canonical. Inclusive port ranges: 1..65535.
Networks TCP/UDP; source metadata LocalInbound UUID. RuleSet references OR enabled
matches, recursively AND with other categories. Disabled sets do not match.
Inline/local set content revision is operator supplied; concurrency uses global revision.
Missing references/cycles reject.

If no rule matches: LocalInbound.selected_outbound, then RouteProfile.final, then
legacy Route.default_outbound. Rules override local selection. REJECT never dials.

## DNS interaction

Managed DNS preserves original domain, resolves through independent DNS rules and
selects the first address in configured strategy order. Match original domain plus
that actual dial candidate. An IPv6 answer cannot select an IPv4 dial merely because
both occurred. Explain can evaluate caller supplied resolved_ips without resolution
or network I/O. A first-rule REJECT matched before resolution rejects without DNS;
later rules need resolution because earlier IP rules may take precedence.
Explain does not count hits.

## Transactions and lifetime

Validate → Plan → prepare complete graph/adapters/listeners → SQLite commit →
atomic publication. No per-connection SQL. Failure releases candidates and keeps
the previous snapshot. Existing TCP/UDP retain their generation and selected adapter.
New flows in an old UDP association use its old graph/affinity. Listener removal,
explicit stop/restart and shutdown retain their termination contract.
Retired schedulers stop/join; retained DNS/adapters close after final session release.

## Bounds and performance

10,000 route rules, 128 sets, 20,000 combined matches, 256 values per match, 16 set
nesting edges and 2 MiB canonical network document. Compilation owns maps/prefixes.
Validation/evaluation memoizes shared DAG paths. Ordered scans remain linear in rule
count; exact domains use per-rule maps and CIDRs parse once. Synthetic 1k/10k compile,
worst-miss latency and allocation evidence are in the Phase 12 report.

Regex, protocol inference, process/Wi-Fi rules, Geo data and remote RuleSet fetching
are deferred. No TUN/interception/system route changes.
See [DNS](DNS_MODEL.md), [policy](POLICY_MODEL.md), [client](CLIENT_RUNTIME.md)
and [ADR 0024](../adr/0024-routing-snapshot-match-semantics.md).
