# ADR 0009 — Internal Xray compatibility engine

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0009 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Some special wire features may need an Xray fork; reimplementing them to achieve a single binary can increase protocol/security/maintenance risk. Exact FinalMask/Sudoku provenance is not established here.

## Decision

Reserve XrayCompatibilityEngine as a supervised private child after its future gate. Splicore owns rendering, trusted binary identity, lifecycle/health/logs/stats and shutdown. No raw Xray JSON/service management appears in public config/API.

## Alternatives

Permanent installer-managed per-protocol systemd services reproduce prior complexity. Linking/reimplementing all special engines creates invasive dependencies. Process separation gives a clearer execution boundary, but is not an automatic licensing exemption.

## Consequences

One main systemd service contains native protocols and owned children. Polling counters cannot promise strict cross-engine policy without proven identity/enforcement hooks. Unknown fork features remain unsupported; no child or code added now.

## Future Review

Identify reference fork/license/version/wire tests and strict-policy hooks before enabling FinalMask/Sudoku or a supervisor.

Details: [architecture specification](../architecture/ENGINE_MODEL.md).
