# ADR 0011 — Stable mergeability and drift control

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0011 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Splicore must continue benefiting from upstream networking/security fixes. Early package moves, branding churn and copies of private protocol implementations produce recurring conflicts.

## Decision

Keep source history and tags, maintain a baseline ledger and patch inventory, compare official stable releases, prefer merges with narrowly justified selective ports, then run build/unit/interop/migration/field-beta gates. Isolate product modules and translate at adapters.

## Alternatives

Auto-following testing/latest commit breaks stable qualification. Squashing upstream obscures provenance. A permanent independent network rewrite multiplies maintenance costs. Selective ports are allowed only with explicit source mapping and accurate baseline claims.

## Consequences

Hotspots are option/Box/auth/router/stats/listener/TLS/QUIC; own modules/composition are lower risk. No automatic update reaches NoBrand until stable qualification/pin changes. A short patch budget exposes drift.

## Future Review

Review at every stable candidate and whenever adapter code needs a new upstream hook; propose reusable extensions upstream where feasible.

Details: [architecture specification](../architecture/UPSTREAM_SYNC.md).
