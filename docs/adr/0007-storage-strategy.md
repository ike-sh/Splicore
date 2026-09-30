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

Phase 1 implementation amendment for review: select modernc.org/sqlite v1.59.0
and matching libc v1.75.7 (SQLite 3.53.4; Go 1.25.0 requirement). v1.60.1 requires
Go 1.26 and was rejected to preserve the repository minimum. Windows/Linux amd64
runtime and arm64 compile qualification apply to Foundation only; production
power-loss/load/key recovery gates remain deferred. A four-connection bounded
pool and serialized short writer callbacks implement the initial repository.

Driver is replaceable at adapter boundary. Pin driver and matching libc versions together; performance is measured, not assumed. WAL backup cannot copy state.db alone. Post-migration rollback restores a compatible checkpoint rather than arbitrary down migrations.

## Future Review

Review the pinned driver and deployment key provisioning before production credential use; revisit if measured workloads exceed SQLite single-writer capacity.

Details: [architecture specification](../architecture/STORAGE_MODEL.md).
