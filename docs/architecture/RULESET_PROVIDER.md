# Remote RuleSet Providers

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Remote rule formats, bounded compile and atomic canonical publication.
- Lifecycle: Update with implemented contracts and qualified evidence.

## Implemented scope

RuleSetProvider is a typed remote update resource independent of ProxyProvider.
It owns one immutable canonical RuleSet ID. Source/auth/security, scheduler, global
revision, transaction and generation mechanisms are shared [provider infrastructure](PROVIDER_MODEL.md).
Ordinary client mutation cannot overwrite/delete provider-owned rules or forge their
ownership. Routes/DNS refer to the immutable RuleSet ID, never provider name.

| Explicit format | Bounded supported contract |
| --- | --- |
| canonical-rules | `{"schema_version":1,"rules":[RuleMatch...]}`; complete existing matcher validation. |
| mihomo-domain | payload exact domains and `+.domain` suffix entries. |
| mihomo-ipcidr | payload IPv4/IPv6 CIDR. |
| mihomo-classical | DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR and IP-CIDR6 only. |

Mihomo [content contract](https://wiki.metacubex.one/config/rule-providers/content/)
was audited. Rule actions, no-resolve hints, unsupported matchers and local inbound/
recursive RuleSet references reject. YAML has the same duplicate/alias/depth guards
as node import. MRS and sing-box binary/full rule-set import are deferred.

## Atomic update and limits

Download → parse complete → validate all rules → compile complete dependent network
graph → preview → prepare → commit one canonical revision → publish snapshot.
No in-place mutation of a serving matcher/slice. Active sessions retain old generation
and affinity; future sessions select the new snapshot. Failure leaves last-good rules
and generation intact and records fixed provider error classification.

Body and decompressed input 2 MiB, at most 10000 RuleMatch entries; existing field
count/depth/regex/CIDR/network compile bounds also apply. Input-size/rule budgets bound
compile memory; there is no unbounded streaming apply. Empty RuleSets always reject
because current canonical RuleSet requires at least one rule, even if a provider sets
empty_is_authoritative. Mass-removal threshold applies by rule count, default 50%.
Delete preview blocks rules referenced by routes/DNS/other canonical sets. No implicit
DIRECT fallback. SQLite backup/offline restart restores last-good rules without fetch.
