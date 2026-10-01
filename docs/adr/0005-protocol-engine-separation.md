# ADR 0005 — Protocol and Engine separation

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: ADR 0005 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Wire compatibility is a client-facing promise; runtime implementation choice is not. Some feature profiles may require an external engine, and compiled capabilities do not imply qualified policy enforcement.

## Decision

Compile-time Protocol Registry owns settings/credentials/runtime intent/profile/probes. Engine Registry compiles and supervises actual native or compatibility runtime. Effective capabilities depend on protocol version/features, engine, build tags/platform and qualified clients. Account/Subscription/Exporter do not branch on Engine.

## Alternatives

A protocol equals a process model leaks Xray/Mita implementation into subscriptions. A single god factory lacks policy/capability contracts. Dynamic Go plugins impose platform/toolchain and security coupling; source registration is preferred.

## Consequences

Engine translators can change without replacing domain tables. Unsupported strict quota/rate or client features reject in validation; internal library UpdateUsers is not proof of safe hot updates. Metadata distinguishes compiled/unqualified/beta/qualified.

## Future Review

Review ABI/source contract changes and needed runtime hooks with actual new protocol prototypes; binary plugin loading is outside the current design.

Details: [architecture specification](../architecture/PROTOCOL_SDK.md).

## Phase 5 realization

[ADR 0016](0016-vless-engine-server-secrets.md) realizes separate protocol/engine
selection and native/xray implementation declarations for vless. Contract tests
prove neutral domain intent without running Xray. The richer future engine and
policy contracts retain their proposed status.
