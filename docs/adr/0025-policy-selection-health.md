# ADR 0025 — Policy Selection and Health

- Documentation status: Canonical
- Audience: Core maintainers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Explain typed health/affinity choices.
- Lifecycle: Supersede when policy semantics change.

Status: Accepted for the Phase 12 Experimental local freeze.

Separate typed Selector/URL-Test/Fallback/RR settings; actual outbound HTTP active
measurement. Newer passive failure precedes older active success. Persist authoritative
selector, keep automatic samples ephemeral. Four workers/bounded queue cancel/join.
Cycles reject. TCP binds once; UDP owns terminal affinity. Retired schedulers stop
while sessions retain adapters. No global payload mutex, implicit DIRECT or migration.
Contract: [Policy Model](../architecture/POLICY_MODEL.md).
