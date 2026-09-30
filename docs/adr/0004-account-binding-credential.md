# ADR 0004 — Account, Binding and Credential separation

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0004 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Protocols authenticate differently and may lack shared multi-user infrastructure. Account is a logical proxy identity; Operator is a separate control principal. Shared display names or PSKs cannot safely establish per-account attribution.

## Decision

Account contains identity/status/expiry only. Binding grants one Account access to one logical Inbound and references a compatible owned Credential. Credentials are schema-versioned secret material; server shared keys are separate inbound-owned records. Stable Binding IDs label runtime users.

## Alternatives

Protocol credential columns on Account require migrations for each protocol. One account per protocol breaks aggregate entitlement/usage. Sharing an unauthenticated key cannot provide individual quota; expand per-binding listeners or reject the deployment.

## Consequences

Alice can hold Snell/VLESS/TUIC/future Mieru bindings without Account schema changes. Credential rotation and history are independent. Native multi-user capability and target client support must both be qualified; account model does not depend on either.

## Future Review

Review additional simultaneous credentials per Binding or overlapping Entitlements only after explicit composition and rotation semantics are needed.

Details: [architecture specification](../architecture/DOMAIN_MODEL.md).
