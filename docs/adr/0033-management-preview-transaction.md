# Management Preview and Transaction Model

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Phase 14 implemented decisions and alternatives.
- Lifecycle: Update with implemented contracts and qualified evidence.

## Status

Accepted for the authorized Experimental Phase 14 local freeze, 2026-10-04.

## Decision

Use the existing Application/repository/manager transaction boundary for every bulk
import/provider update. A read-only preview caches a bounded complete candidate with
single-use token, expiry and global revision. Apply validates credentials, prepares
dependent runtime, then commits resources/validators in the same transaction.
Preparation or commit failure aborts candidate ownership and leaves old serving intent.
No partial per-entry write or importer-owned runtime. Metadata/304 avoids runtime churn.
SQLite-before-Activate semantics preserve existing degraded-host recovery behavior.
Tradeoffs: plans are in-memory and invalid after restart; unrelated committed mutations
require a new preview; there is no durable plan replay or remote source cache.
See [Import](../architecture/IMPORT_MODEL.md) and [transactions](../architecture/TRANSACTION_MODEL.md).
