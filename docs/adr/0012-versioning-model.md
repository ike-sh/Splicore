# ADR 0012 — Independent product/schema/API identities

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0012 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Product SemVer, database migrations, public config, source ABI and API compatibility evolve on different schedules. A single version integer cannot describe upgrade safety or client qualification.

## Decision

Expose Splicore version, full commit/dirty state, build time, Go/platform, upstream baseline, Config Schema, DB Schema, Protocol ABI and API version independently. Channels are stable/beta/nightly; qualified client pairs have explicit evidence identities.

## Alternatives

Using upstream version as product version obscures domain changes. Equating DB/config/API versions blocks independent evolution. Calling newest HEAD stable bypasses regression and field-beta gates.

## Consequences

Upgrade manifests declare supported schema ranges and artifact digests; diagnostics identify actual build and state. Protocol ABI is a source contract, not dynamic plugin ABI. Phase 0 creates no formal product version/tag/release.

## Future Review

Review incompatible contract/schema changes and qualified release-channel policies before publication; additive API evolution remains inside v1.

Details: [architecture specification](../architecture/VERSION_MODEL.md).
