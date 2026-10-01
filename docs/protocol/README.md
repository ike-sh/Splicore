# Protocol and Engine Documentation

- Documentation status: Canonical
- Audience: Protocol, engine and client integration developers
- Last reviewed: 2026-10-02
- Owner: Protocol maintainers
- Responsibility: Protocol extension navigation and qualification boundaries.
- Lifecycle: Update when a protocol specification or qualification path changes.

## Current Phase 5 implementation candidate

Snell v5/v6, Hysteria2 and TUIC v5 are implemented experimentally. See [Snell support](SNELL.md),
[Hysteria2 support](HYSTERIA2.md), [TUIC support](TUIC.md), [interop matrix](../testing/INTEROP_MATRIX.md) and
[Phase 4 report](../reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md). Phases 0–4 are
locally frozen. Phase 5 adds [VLESS/REALITY](VLESS.md), with native TCP/XUDP and
separate engine placement. Vision is deferred/unsupported; every managed input/export rejects it. Other directions below are planned.

Other Splicore protocol integrations are **architecture targets**. Inherited
upstream implementations remain baseline code outside the managed Snell/HY2/TUIC/VLESS adapters.
This index points to existing bounded specifications in `architecture/`;
no mass file relocation is needed.

## Read and change in this order

1. [Protocol SDK](../architecture/PROTOCOL_SDK.md): registry keys, ports, schemas and effective capabilities.
2. [Engine model](../architecture/ENGINE_MODEL.md): private execution; Protocol is separate from Engine.
3. [Domain](../architecture/DOMAIN_MODEL.md) and [policy](../architecture/POLICY_USAGE.md): authenticated Binding identity and shared enforcement.
4. [ClientProfile/exporters](../architecture/CLIENT_COMPATIBILITY.md): endpoint/auth/features projected to target clients.
5. [Interop matrix](../testing/INTEROP_MATRIX.md) and [test strategy](../testing/TEST_STRATEGY.md): exact-client traffic and failure gates.

## Specialized design paths

- [Mieru roadmap](../architecture/MIERU_INTEGRATION.md): pinned API research, reference tests, prototype and native adapter stages.
- [Native protocol guidelines](../architecture/NATIVE_PROTOCOL_GUIDELINES.md): wire spec, independent reference, security and qualification.
- [Runtime lifecycle](../architecture/RUNTIME_LIFECYCLE.md): handles, listener ownership and future children.
- [Security boundaries](../architecture/SECURITY_BOUNDARIES.md): secrets, bounded inputs and executable trust.

FinalMask/Sudoku remain future compatibility profiles requiring exact fork/spec
provenance. They are not assumed capabilities of stock Xray. Mieru research
does not qualify user updates, complete shutdown or strict policy hooks.

## Decisions and review

- [ADR 0005](../adr/0005-protocol-engine-separation.md): protocol/engine separation.
- [ADR 0006](../adr/0006-client-profile-exporter.md): profile/exporter boundary.
- [ADR 0009](../adr/0009-xray-compatibility-engine.md): future private compatibility engine.
- [ADR 0010](../adr/0010-mieru-integration-strategy.md): staged Mieru integration.

These decisions remain proposed. Significant capability/port/wire changes update
the owning canonical spec and relevant API/profile contracts, with an ADR when
the durable choice warrants one. New settings do not become Account credential
columns. Unsupported policy or client features reject explicitly. See
[policy](../DOCUMENTATION_POLICY.md) and [architecture map](../architecture/README.md).

- [ADR 0016](../adr/0016-vless-engine-server-secrets.md): candidate engine placement and generic server-secret boundary.
