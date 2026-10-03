# ADR 0026 — DNS Bootstrap Dependency

- Documentation status: Canonical
- Audience: Core and security maintainers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Explain DNS dependency/cache isolation.
- Lifecycle: Supersede when resolver graph semantics change.

Status: Accepted for the Phase 12 Experimental local freeze.

Node/resolver/probe names use explicit separate System or IP-only DIRECT UDP/TCP
bootstrap, never a dependent destination detour. Reject obvious loops before adapters
are constructed; original endpoints stay canonical. Independent DNS rules select
resolver/detour. Owned generation cache keys server/member/strategy/name/type, respects
TTL and flush invalidation. System has no TTL and is uncached. Query sockets cancel/join.
DoT reuses verified TLS/bounded DNS framing. DoH awaits bounded response review;
FakeIP awaits TUN reverse translation.
Contract: [DNS Model](../architecture/DNS_MODEL.md).
