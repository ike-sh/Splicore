# Splicore Architecture

- Documentation status: Canonical
- Audience: Core developers and architecture reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Overall boundaries, dependency direction, invariants and implementation gates.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Design maturity: proposed architecture, ready for maintainer review. All contracts
below are designs, not implemented features or claims of protocol qualification.
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

Proposed Phase 1 directories, **not created in Phase 0**:

| Area | Packages and responsibility |
|---|---|
| Entry | `cmd/splicore`, composition root `internal/splicore/app` |
| Domain | `internal/splicore/domain/{identity,access,policy,subscription}`; usage value types in policy |
| Application | `internal/splicore/application`: resource commands, import, operations, revision coordination |
| Ports | `internal/splicore/ports`: repository, runtime, clock, secrets, accounting, exporter contracts |
| Protocol | `internal/splicore/protocol/{registry,snell,hysteria2,tuic,vless}` |
| Engine | `internal/splicore/engine/{registry,native,xray}`; xray reserved until its stage |
| Adapters | `internal/splicore/storage/sqlite`, `internal/splicore/runtime`, `internal/splicore/api`, `internal/splicore/diagnostic` |
| Client | `internal/splicore/clientprofile`, `internal/splicore/export/{mihomo,singbox,surge,uri,json}` |

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
transaction recovery and local API contracts with one native reference protocol.
It does not automatically qualify all protocols. Public stable support requires
third-party traffic tests and usable policy enforcement. No Mieru, Panel, new
wire protocol, FinalMask/Sudoku port or external supervisor is implemented here.
