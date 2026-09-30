# ADR 0001 — Upstream stable baseline

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0001 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Accepted for Phase 0. Date: 2026-10-01 (Asia/Shanghai).

## Context

Splicore requires a reproducible release foundation and intact upstream merge history. The empty workspace was cloned with full history; the published v1.14.1 release is neither draft nor prerelease. A default testing branch must not determine the fork baseline.

## Decision

Use SagerNet/sing-box v1.14.1 at full SHA 1ac1a339cb1223e9c70eae14c44411c75033c02d. Keep upstream as the only remote. Create main and codex/phase-0-architecture from that commit. Record module, toolchain, ancestry and command evidence; preserve failures rather than modifying source.

## Alternatives

Testing/alpha/RC/nightly/HEAD provide a moving or unqualified base. Shallow clone loses ancestry needed for sync/blame. Orphan/squash loses provenance. None satisfies the specified stable gate.

## Consequences

Upstream code and package identity are temporarily retained. Linux complete CI passes in a suitable isolated environment; Windows integration limitations and additional vet findings remain recorded. Architecture review does not imply Splicore release qualification.

## Future Review

Review when deliberately selecting a newer stable release, using the documented compare/merge/tests/interop/migration/field-beta sequence.

Details: [architecture specification](../architecture/UPSTREAM_BASELINE.md).
