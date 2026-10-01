# Splicore Architecture

- Documentation status: Canonical
- Audience: Core developers and architecture reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Overall boundaries, dependency direction, invariants and implementation gates.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current Phase 3 implementation

The Account → Binding → Credential → Inbound → Native Engine → stats → ClientProfile/export
path now supports experimental Snell v5/v6 and Hysteria2. HY2 adds generic encrypted
passwords, multiple Bindings, static TLS and owned QUIC/UDP admission. One Native
Engine dispatches protocol compilers; exporters dispatch protocol keys. Create
transactions share pending/build/start/health/commit/activate coordination.
Binding revocation reconstructs only its Inbound, closes its sessions and restores
the committed projection on failure. See [HY2 support](protocol/HYSTERIA2.md),
[composition decision](adr/0014-hysteria2-runtime-composition.md) and
[report](reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md). Upstream runtime changes remain zero.

Design maturity: Phase 1 Foundation is implemented and frozen. Domain, storage,
application, API and CLI have tests. Phase 2 realizes managed Snell; Phase 3 adds
bounded Hysteria2 with experimental client qualification. Durable accounting,
quota/rate enforcement and other runtime directions remain deferred.
Decision status lives in the [ADR index](adr/README.md); historical validation
scope lives in the [Phase 0 report](PHASE_0_ARCHITECTURE_REPORT.md).

## Phase 3 extensibility disposition

**NON-BLOCKING TECHNICAL DEBT**, reviewed for the local experimental freeze.
HY2 required generic password persistence, multi-Binding projections, CA trust,
stats and shared transaction contracts. Account/Binding contain no protocol fields;
credentials remain typed and encrypted; SQLite committed state remains authority.
Protocol and Engine registries are used by preparation/recovery, and client exports
use protocol-key dispatch over separate ClientProfiles. Neither module imports SQL
or HTTP. CLI/API mutations use the same Application Service; offline validation uses
its side-effect-free decoder. There is one shared create coordinator and one generic
replacement path, although some generic methods still live in protocol-named files.

Outside normal extension points the change cost is **MEDIUM**: most shared edits
establish previously missing multi-user/TLS/password contracts, with bounded command
dispatch growth. A third protocol can reuse the domain, journal, projection, compiler
and exporter contracts without an architectural rewrite. It still incurs avoidable
registration/command boilerplate and one storage allowlist edit in the present design.

Counts exclude tests, comments, method names and credential-kind dispatch. There are
**2 central protocol-related Go switches**, both HTTP route switches in
`internal/splicore/api/snell.go:44,64`; **8 central protocol-choice/allowlist if sites**:
CLI `inbound.go:53,59,86,96,110,121`, API `snell.go:13`, SQLite `runtime.go:217`.
Runtime compile/recovery/projection protocol switches: **0**; central Engine-choice
switches: **0**; exporter protocol switches: **0**. Protocol-local format switches:
**2**, in `exporter/snell.go:60` and `exporter/hysteria2.go:29`; protocol modules
themselves have **0** switches. Each module and each exporter has one protocol-key
validation if, rather than central dispatch. Composition separately has two
placeholder-filter ifs in `registry/phase2.go:17` and `registry/phase3.go:19`.

The single new HY2-specific **core** branch is SQLite's display allowlist extension.
At the transport edges HY2 adds six CLI conditional sites and five API sites/cases
(prefix guard, route group, three operation cases); composition adds one filter.
The three generic password cases in domain validation and SQLite encode/decode are
credential-kind branches, not HY2 or Engine dispatch. Migration 0003 restores the
existing Snell single-Binding trigger from 0002; no new HY2 SQL branch/column appears.

| Current debt / affected files | Why acceptable for Phase 3 | Refactor trigger and target |
|---|---|---|
| Typed per-protocol documents/resource builders and transport commands: `application/{snell,hysteria2}.go`, `internal/splicore/api/snell.go`, `internal/splicore/cli/inbound.go`, `transport/{snell,hysteria2}.go` | Protocol-specific validation stays explicit; stateful commands share service, revision fences and create coordinator | Phase 4, before copying a third protocol's public command dispatch: introduce a registered validated creation-command port, retaining typed protocol validation and existing API compatibility |
| Display mutation protocol allowlist: `internal/splicore/storage/sqlite/runtime.go` | Restricts the two implemented profiles; generic SQL does not interpret TLS or Engine settings | Phase 4, when TUIC needs display mutation: put availability/ownership checks in the Application Service/registered contract and make the repository update protocol-neutral |
| Phase3 calls Phase2 then replaces a placeholder: `internal/splicore/registry/phase3.go` | Immutable duplicate-checked registries remain real dispatch points; no runtime bypass | Phase 4 composition: assemble explicit module/compiler/exporter entries directly, without extending the phase-call chain; retain historical composition fixtures |
| Generic lifecycle/projection/export/Binding methods remain in `internal/splicore/application/snell.go` / `internal/splicore/application/hysteria2.go` | Shared implementations already exist; filenames do not create a second authority or coordinator | Phase 4, when touching these methods for TUIC: move shared code into bounded runtime/command files, preserving transaction and recovery behavior |

These are Phase 4 work constraints, not permission to start TUIC during this freeze.
A new protocol requiring broad lifecycle duplication, Engine branches in domain/
storage/export or protocol columns in Account/Binding would reopen a **BLOCKING**
architecture review. See [ADR 0014](adr/0014-hysteria2-runtime-composition.md) and
the [freeze audit](reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md#phase-3-freeze-disposition-and-validation).

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
