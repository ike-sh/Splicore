# ADR 0008 — Application services and local API boundary

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0008 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Future CLI/Panel/controllers need the same contracts; HTTP handlers directly editing SQLite bypass invariants and recovery. Public subscription access has a different credential/permission scope.

## Decision

Place API v1 transports outside application/domain. Linux CLI uses HTTP over a protected UDS with peer control identity; future TLS uses explicit control authentication. Subscription public listener/tokens remain separate. Revision/idempotency/operation semantics govern all mutations.

## Alternatives

In-process ad hoc CLI SQL creates a second writer model. Immediate public unauthenticated REST is unsuitable. Reusing Clash/upstream daemon schemas exposes runtime details and does not supply Account/transaction contracts.

## Consequences

OpenAPI is a contract skeleton, not server code. Reads are redacted; apply is a durable 202 operation with 409 stale revision and 428 missing precondition. Offline CLI still needs the same ownership lock/application coordinator.

## Future Review

Review Windows transport, future RBAC and public TLS exposure before enabling them; local socket permissions already constitute control authorization.

Details: [architecture specification](../api/API_V1_DESIGN.md).
