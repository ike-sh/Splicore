# ADR 0007 — SQLite WAL and driver qualification

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0007 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

A single-server core needs transactional domain records and durable operation/accounting history without a service database dependency. Deployment targets include static CGO=0 Linux amd64/arm64 builds.

## Decision

Use SQLite WAL behind repository ports; prefer modernc.org/sqlite subject to Phase 1 performance/lock/crash/backup/migration tests. Bound writer/read pools, apply per-connection pragmas, use durable commits, local filesystem, checksummed forward-only migrations and coherent backups.

## Alternatives

mattn/go-sqlite3 is a mature CGO alternative with explicit compiler/libc cross-build requirements. Flat files lack multi-entity concurrency. PostgreSQL adds an unnecessary deployment service initially. No dependency is introduced in Phase 0.

## Consequences

Driver is replaceable at adapter boundary. Pin driver and matching libc versions together; performance is measured, not assumed. WAL backup cannot copy state.db alone. Post-migration rollback restores a compatible checkpoint rather than arbitrary down migrations.

## Future Review

Select exact driver version/key provisioning before Phase 1 implementation; revisit if measured workloads exceed SQLite single-writer capacity.

Details: [architecture specification](../architecture/STORAGE_MODEL.md).
