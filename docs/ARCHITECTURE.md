# Splicore Architecture

- Documentation status: Canonical
- Audience: Core developers and architecture reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Overall boundaries, dependency direction, invariants and implementation gates.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current Phase 2 implementation

Phase 2 implements the Account → Binding → Credential → Inbound → native Snell → stats → ClientProfile/export path. Snell v5/v6 is experimental; other runtime directions below remain proposed. See [support](protocol/SNELL.md) and [report](reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md). Upstream runtime changes remain zero.

Design maturity: Phase 1 Foundation is implemented and frozen. Domain, storage,
application, API and CLI have tests. Phase 2 realizes only managed Snell runtime
and exporters with experimental client qualification.
Decision status lives in the [ADR index](adr/README.md); historical validation
scope lives in the [Phase 0 report](PHASE_0_ARCHITECTURE_REPORT.md).

Navigation: [docs index](README.md) → this overview →
[bounded specification map](architecture/README.md) → relevant specifications and ADRs.

Splicore is an independent, modular server proxy core. sing-box supplies the
network foundation; stable Splicore domain contracts own identity, authorization,
policy, state and operations. API, CLI, subscriptions and future Panel use those
contracts, never upstream runtime JSON as their public model.

```text
Splicore
├── Application / Control Plane
│   ├── Account / Binding / Credential
│   ├── Subscription / Policy / Usage
│   ├── Transaction / Revision / Audit
│   └── API transports / CLI
├── Protocol Registry
│   ├── Snell / Hysteria2 / TUIC / VLESS
│   └── Mieru / new native protocols (future)
├── Engine Registry
│   ├── Native
│   └── Xray Compatibility (future)
├── Canonical ClientProfile / Exporter Registry
├── SQLite domain storage
└── sing-box derived network foundation
```

## Dependency rules and package plan

Execution flows `Transport → Application → Domain → Ports → Adapters`.
Compile-time dependencies point toward domain/ports: adapters implement inward
contracts; domain must not import SQL drivers, HTTP, sing-box options, protobuf,
Panel or installer scripts. This distinction prevents ports from depending on
their implementations.

Implemented Phase 1 directories:

| Area | Packages and responsibility |
|---|---|
| Entry | `cmd/splicore`, composition root `internal/splicore/app` |
| Domain | `internal/splicore/domain/{identity,access,policy,secret}`: values, ownership, policy and redaction |
| Application | `internal/splicore/application`: shared reads, Account commands and revision coordination |
| Ports | `internal/splicore/ports`: repository, runtime intent, protocol/engine/exporter and cipher contracts |
| Registries | `internal/splicore/registry`: immutable explicit composition for protocols, engines and exporters |
| Adapters | `internal/splicore/storage/sqlite`, `internal/splicore/secretvault`, `internal/splicore/api`, `internal/splicore/transport`, `internal/splicore/cli` |
| Client / process | `internal/splicore/clientprofile`, `internal/splicore/config`, `internal/splicore/version` |

These are bounded modules, not one god package and not a hundred precreated
micro-packages. Split application services further only when ownership or imports
justify it. Protocol/network adapters do not import HTTP handlers. Compile-time
registration uses explicit composition; no Go `.so` loading.

## Fixed distinctions

* Account identifies a proxy user; Operator identifies a control principal.
* Binding grants an Account access to an Inbound; Credential stores authentication material.
* Node is installation identity; Inbound is logical service; Listener is actual bind;
  DisplayEndpoint is what a client reaches. Egress, TLS SNI and REALITY target are separate.
* Protocol defines wire behavior; Engine supplies implementation. Protocol version,
  transport, security and extension feature identify compatibility. Engine selection is internal.
* Runtime configuration is generated private data. ClientProfile is a separate client contract.
* SQLite committed domain generation is the only domain authority. Bootstrap YAML
  owns process settings, not Accounts. Imports are commands, not live files.
* Native services share one process and one `splicore.service`; special engines are supervised children.

## Reading guide

1. Read [current development constraints](DEVELOPMENT_CONTEXT.md).
2. Use the [architecture map](architecture/README.md) for domain, storage,
   transaction, lifecycle, client, security and upstream specification ownership.
3. Use the [protocol/engine index](protocol/README.md) and [API index](api/README.md)
   for those contract layers and their related qualification gates.
4. Read the relevant [ADRs](adr/README.md) for alternatives and decision status.
5. Follow the [development workflow](development/README.md) and
   [documentation policy](DOCUMENTATION_POLICY.md) when making changes.

The [original report](PHASE_0_ARCHITECTURE_REPORT.md) and
[requirement traceability](PHASE_0_REQUIREMENTS.md) are historical snapshots;
maintained specifications above own the current design.

## Implementation gates

Phase 1 establishes identity, domain/application ports, SQLite generation storage,
pending/committed/failed journaling and local read API contracts. The explicit
Foundation scope defers native reference traffic, entitlement, usage, imports,
runtime compensation and full audit persistence. The combined registry package
avoids empty per-protocol directories; real adapters can be split when introduced.
It does not automatically qualify all protocols. Public stable support requires
third-party traffic tests and usable policy enforcement. No Mieru, Panel, new
wire protocol, FinalMask/Sudoku port or external supervisor is implemented here.
