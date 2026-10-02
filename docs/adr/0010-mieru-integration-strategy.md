# ADR 0010 — Mieru reference to native embedding

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0010 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Historical staged decision realized by the Phase 8 Experimental local freeze.
[ADR 0020](0020-mieru-owned-native-embedding.md) records the source audit and actual ownership decision.

## Context

Mieru requires native data-plane integration eventually. Official v3.38.0 exposes apis/server with listener factories, authenticated UserContext and lifecycle contracts; duplicating mita CLI/persistence is unnecessary.

## Decision

Stage 1 pins external reference interoperability. Stage 2 prototypes official embedded package APIs with identity, UDP, policy and lifecycle tests. Stage 3 implements native Splicore inbound and qualifies clients/field beta. No implementation or dependency is added in Phase 0.

## Alternatives

Permanent exec mita conflicts with the long-term native target. Copying daemon code leaks state authority and increases merge/license work. Direct embedding without prototype overlooks Store-after-Start restrictions and Stop leaving existing connections open.

## Consequences

Need fresh handles on restart, tracked session cleanup, private protobuf translation and global logger/metrics isolation review. Official daemon quota documentation is not proof of embedded API enforcement. Prefer upstream hooks if required capabilities are absent.

## Future Review

Stages 1–3 have bounded implementation/qualification evidence in Phase 8.
Review at every official module pin or lifecycle/global-state change; no Stable claim.

Details: [architecture specification](../architecture/MIERU_INTEGRATION.md).
