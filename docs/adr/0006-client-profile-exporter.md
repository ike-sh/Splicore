# ADR 0006 — Canonical ClientProfile and exporters

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0006 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Server runtime config includes engine internals/private keys and cannot safely serve as client configuration. Multiple target clients differ by versions, wire features and supported authentication.

## Decision

Protocols build engine-neutral authorized ClientProfiles from committed state; Exporter Registry renders Mihomo/sing-box/Surge/URI/JSON. Bundle selection and Subscription token management remain separate. Target-version feature checks are mandatory before rendering.

## Alternatives

Direct YAML concatenation in runtime adapters duplicates auth/endpoint logic. Exposing upstream outbound structs leaks unstable schema. Silent feature omission produces apparently valid but insecure/incompatible configs; structured exclusion/rejection is required.

## Consequences

New exporters do not change Account/Usage models. Snell userkey and v5/v4 mapping need exact client qualification. Real third-party traffic tests, not golden output alone, clear stable compatibility gates.

## Future Review

Review new target formats/client versions and profile schema changes with fixture migration and interoperability evidence.

Details: [architecture specification](../architecture/CLIENT_COMPATIBILITY.md).
