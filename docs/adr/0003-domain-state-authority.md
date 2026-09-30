# ADR 0003 — Single domain state authority

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0003 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Live config YAML plus arbitrary SQLite edits creates two competing truths. API/CLI/import concurrency, secrets and usage need durable revisions. Upstream runtime JSON and bbolt cache lack the required domain model.

## Decision

SQLite committed generation owns domain state; bootstrap YAML owns only process settings. Declarative documents are validate/plan/apply commands with ownership keys and explicit destructive intent. Runtime and client profiles derive from a committed generation, never pending candidate data.

## Alternatives

File authority is reasonable for immutable runtime deployments but conflicts with mutable API state/accounting. Bidirectional file/DB synchronization needs conflict resolution and introduces unsafe reload races. A sole DB authority is preferred for this product.

## Consequences

Imports require stable mappings, revision/plan fences and idempotency; NoBrand must not directly edit DB or private runtime JSON. Bootstrap database-path changes are process-level controlled operations. Operational cache remains separate.

## Future Review

Review for explicit read-only deployment modes or future multi-node control; preserve one authority even if storage changes.

Details: [architecture specification](../architecture/CONFIG_STATE_AUTHORITY.md).
