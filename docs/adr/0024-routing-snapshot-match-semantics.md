# ADR 0024 — Routing Snapshot and Match Semantics

- Documentation status: Canonical
- Audience: Core maintainers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Explain routing snapshot choices.
- Lifecycle: Supersede when routing semantics change.

Status: Accepted for the Phase 12 Experimental local freeze.

Ordered first-match rules, AND categories/OR values and ID-based typed actions
compile to owned immutable generations. Prepare precedes commit; atomic publication
follows it. TCP/UDP retain old generations. IP rules evaluate the actual dial candidate
with original domain preserved. Explanation performs no I/O. This fits existing
transactions/ownership. Linear scans are accepted under bounds and 1k/10k measurements.
Engine JSON or per-packet SQL would couple authority to backend/mutable data path.
Contract: [Routing Model](../architecture/ROUTING_MODEL.md).
