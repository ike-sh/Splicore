# Splicore Architecture

- Documentation status: Canonical
- Audience: Core developers and architecture reviewers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Overall boundaries, dependency direction, invariants and implementation gates.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Frozen runtime baseline

The Account → Binding → Credential → Inbound → Native Engine → stats → ClientProfile/export
path supports experimental Snell v5/v6, Hysteria2, TUIC v5 and native VLESS/REALITY.
Phases 0–11 are locally frozen; Phase 5 supports flow-none VLESS/REALITY. Vision
is DEFERRED / UNSUPPORTED and rejected before runtime construction or export. HY2 adds generic encrypted
passwords, multiple Bindings, static TLS and owned QUIC/UDP admission. One Native
Engine dispatches protocol compilers; exporters dispatch protocol keys. Create
transactions share pending/build/start/health/commit/activate coordination.
Binding revocation reconstructs only its Inbound, closes its sessions and restores
the committed projection on failure. See [HY2 support](protocol/HYSTERIA2.md),
[composition decision](adr/0014-hysteria2-runtime-composition.md) and
[report](reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md). Upstream runtime changes remain zero.

Design maturity: Phase 1 Foundation is implemented and frozen. Domain, storage,
application, API and CLI have tests. Phase 2 realizes managed Snell; Phase 3 adds
bounded Hysteria2; Phase 4 adds TUIC and shared creation/TLS/QUIC support. Durable accounting,
quota/rate enforcement and other runtime directions remain deferred.
Decision status lives in the [ADR index](adr/README.md); historical validation
scope lives in the [Phase 0 report](PHASE_0_ARCHITECTURE_REPORT.md).

## Phase 3 extensibility disposition

Original creation-command, storage allowlist, phase-chain and shared-method debt
counts remain in the immutable [Phase 3 report](reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md#phase-3-freeze-disposition-and-validation).
Phase 4 resolves those four triggers below; historical compositions remain fixtures.

## Phase 4 third-protocol realization

[ADR 0015](adr/0015-tuic-shared-control-plane.md) owns rationale. Modules implement
CreationCodec and typed settings/credentials/runtime/client projection. One service
builds resources and binds protocol/document/revision in HMAC; pending/start/health/
commit/admission and recovery/compensation are shared. Generic API/CLI dispatch by
registered ID. Legacy Snell/HY2 wrappers remain; no TUIC-specific Application branch.

[Direct composition](../internal/splicore/registry/phase4.go) registers Snell v5/v6,
HY2, TUIC and deferred VLESS; one native compiler map and format/protocol exporter
maps. Generic lifecycle/plan/views/export/Binding methods have bounded common files.
SQL display updates have no protocol allowlist; service checks resource/module.

| Infrastructure | Ownership |
|---|---|
| Snell only | PSK/version mapping; pinned service; TCP accept/admission |
| HY2 only | Password auth; HY2 service parameters/profile |
| TUIC only | UUID/password auth; v5/cubic/native/no-0RTT; TUIC factory |
| HY2/TUIC shared | TLS trust/load/snapshot, Box/router, UDP/admission/health/close grace, immutable user map, meters |
| All protocols shared | Domain/AEAD, creation port/resources, HMAC/journal/commit/recovery/compensation, metadata/export authorization, ClientProfile and registries |

TUIC adds 0 central protocol switch cases, 0 Engine selection branches, 0 TUIC
Application branches, 0 storage columns/migrations, 0 Account fields and 0 central
ClientProfile special cases. Composition entries are registrations, not branches.
Protocol-neutral action switches and legacy Snell compatibility paths remain.
Format switches stay local to exporters. No 80% duplicated HY2/TUIC control plane.

Factories preserve pinned wire/options/auth without upstream edits. Shared envelope
helpers own endpoint/name/policy rules; module owns credential semantics. Fourth
TLS/QUIC protocol adds module/codec, small factory, exporters, composition, fixtures,
tests/docs. Different listener requires a bounded adapter; storage/identity/transaction
remain shared. General Account mutation/rotation/accounting need reviewed contracts.
See [report](reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md) for measured gates.

Navigation: [docs index](README.md) → this overview →
[bounded specification map](architecture/README.md) → relevant specifications and ADRs.

Splicore is an independent, modular client/server proxy core. sing-box supplies the
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
│   └── Mieru / new native protocols
├── Engine Registry
│   ├── Native
│   └── Xray Compatibility (owned child)
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
  transport, security and extension feature identify compatibility. Engine placement
  is a separate bounded command field and resolved API/domain identity.
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
third-party traffic tests and usable policy enforcement. Panel and new wire protocols remain deferred; Mieru is Experimental in Phase 8. FinalMask/Sudoku use the bounded Phase 7 feature contract. The Phase 6 external supervisor
is described below.

## Phase 5 fourth-protocol realization

[ADR 0016](adr/0016-vless-engine-server-secrets.md) and [VLESS](protocol/VLESS.md)
own the candidate boundary. [Phase5 composition](../internal/splicore/registry/phase5.go)
registers one VLESS identity with plain/TLS/REALITY feature profiles. Shared engine
selection and engine metadata permit multiple implementations per protocol. Native
is executable; Phase6 fills xray with the owned child adapter. Domain validation
stays neutral; each compiler enforces placement and effective capabilities compose
protocol/engine support. Historical Phase5 retains its placeholder fixture.

Generic private_key payloads extend the existing inbound-owned credential model.
Schema 4 adds only the kind CHECK; no protocol columns or Account fields. A separate
runtime secret port recovers encrypted server material. ClientProfile includes UUID,
public key, short ID and SNI; excludes private key, target, listener and engine.

VLESS adds 0 central protocol switches, 1 generic native placement guard, 0 Application
protocol branches, 0 protocol-specific storage columns, 0 Account fields and 0 central
ClientProfile cases. Engine-selector/implementation-list plumbing is generic. Phase 4
creation/shared QUIC debt stays resolved; TCP ownership is a bounded adapter. Existing
wire/TLS implementations and dependencies remain unchanged. Vision's upstream checkptr
and Read/Write defects are isolated by typed rejection at all managed boundaries;
no dependency or shared concurrency patch is carried. See [ADR 0017](adr/0017-defer-vision-dependency-safety.md)
and the [final report](reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md).

## Phase 6 dual engine realization

One VLESS canonical projection selects native or an external pinned Xray process;
Account/Binding/Credential/Endpoint/ClientProfile/exporters and SQLite remain shared.
No Xray source or runtime JSON schema enters the public model. The existing
Start/Health/Commit/Activate lifecycle also governs the child: Splicore owns the
public TCP gate and forwards unchanged bytes to its private loopback listener.
Artifact permissions, process ownership, failure handling, node availability and
unsupported stats/policy limits follow [ADR 0018](adr/0018-xray-owned-child-engine.md).

## Phase 7 specialized feature realization

[Phase7 composition](../internal/splicore/registry/phase7.go) reuses Phase6 and adds
the existing VLESS exporter for Xray client JSON. Typed transport requirements and
engine features remain outside Account/Binding/Endpoint. Generic settings JSON and
encrypted inbound Password reuse existing storage; no migration. Feature validation
precedes artifact probing and pending. Runtime compile snapshots config bytes and
uses the original child supervisor, admission and recovery. A narrow client secret
port authorizes password projection while excluding server private keys before
decryption. No new protocol ID, central protocol switch, engine exporter branch,
supervisor or wire implementation. [ADR 0019](adr/0019-xray-specialized-feature-boundary.md).

Phase 7 is locally frozen under the [freeze report](reports/PHASE_7_FREEZE_REPORT.md).
Both features remain Experimental. Phase 8 adds the official embedded Mieru adapter.

## Phase 8 owned native embedding

Phase 8 is locally frozen under the [freeze report](reports/PHASE_8_FREEZE_REPORT.md).
Mieru remains Experimental; Phase 9 freezes the local distribution foundation.

[Mieru](protocol/MIERU.md) registers a module/CreationCodec, MieruCompiler in the
existing Native Engine, ClientProfile/exporters and Phase8 composition. Zero central
protocol switch cases, Application protocol branches, DB columns/migrations,
Account fields or special API routes. Official server/session code owns wire;
Splicore owns raw sockets, generations, identity and one attributed payload path.
Direct TCP/UDP egress is the bounded current adapter scope, with no configurable
egress policy in RuntimeIntent. [ADR 0020](adr/0020-mieru-owned-native-embedding.md)
records global logger/cache/metrics and shutdown constraints. No upstream runtime edits.

## Phase 9 distribution boundary

The [distribution contract](DISTRIBUTION.md) owns layout, package provenance and
future NoBrand pinning. One hardened systemd unit uses a dedicated non-login user;
SQLite and the original master key remain authoritative. Local package operations
serialize separately from the runtime directory, snapshot a stopped database and
replace files atomically. Optional Xray stays pinned and managed by the same child
owner. Operations/diagnostics do not add protocol capability or wire behavior.
[ADR 0021](adr/0021-linux-local-distribution.md) records these proposed decisions.

## Phase 10 client runtime

Phase 10 is locally frozen under its [freeze report](reports/PHASE_10_FREEZE_REPORT.md).
Client Runtime remains Experimental. Phase 11 expands the existing adapter registry.

One daemon owns Server Runtime and Client Runtime with shared Application, domain,
registry, vault, stats, transactions, API, CLI and SQLite. RemoteNode is separate
from Outbound and server Account; LocalInbound is separate from remote-facing
Inbound. Committed ProfileState is separate from exported ClientProfile and runtime
configuration. The first embedded slice is Local SOCKS5 TCP → immutable route →
DIRECT or Snell/native → remote server → target. Client failure isolation preserves
server/API operation. See [client runtime](architecture/CLIENT_RUNTIME.md),
[routing](architecture/ROUTING_MODEL.md) and [ADR 0022](adr/0022-client-runtime-domain.md).
No additional binary/service, central client protocol switch or upstream wire edit.

## Phase 11 client outbound expansion

The existing registry adds HY2/native, TUIC v5/native, VLESS flow-none/native or
Xray, and official embedded Mieru/native alongside Snell. One canonical VLESS node
can back two outbounds with different engines. ClientTLS contains public trust and
REALITY public fields only. Protocol-owned option decoders are reused; exporter
strings never become runtime input. No new engine, supervisor, protocol switch,
Application protocol branch or database migration is added.

SOCKS5 UDP associations own a loopback socket, TCP control connection and bounded
per-target packet flows. Immutable adapter leases retain established TCP sessions
and avoid rebuilding unrelated adapters. Phase 11 closed affected UDP associations
on route/adapter changes; Phase 12 graph updates retain their old generation and
affinity. Explicit stop/restart and listener removal still close sessions.
See [ADR 0023](adr/0023-client-udp-ownership.md) and the
[Phase 11 report](reports/PHASE_11_CLIENT_OUTBOUND_EXPANSION_REPORT.md) and
[local freeze](reports/PHASE_11_FREEZE_REPORT.md). Phase 12 freezes the
Experimental routing/DNS/policy scope described below.

## Phase 12 independent network graph

ProfileState.network contains canonical RouteRule/RuleMatch/RouteAction/RouteProfile,
RuleSet, typed PolicyGroup and independent DNS models. Application compiles the complete
graph before existing SQLite commit/revision/audit and atomically publishes it.
Data paths read owned snapshots, retaining TCP/UDP affinity through updates.
DNS bootstrap cuts endpoint/probe dependencies; caches/health are ephemeral.
No protocol-specific routing/DNS/storage field, new binary or service is added.
Contracts: [routing](architecture/ROUTING_MODEL.md), [DNS](architecture/DNS_MODEL.md),
[policy](architecture/POLICY_MODEL.md); [Phase 12 report](reports/PHASE_12_ROUTING_DNS_POLICY_REPORT.md)
and [local freeze](reports/PHASE_12_FREEZE_REPORT.md), which preserves the earlier
acceptance boundary. Current TUN/system integration is described below; FakeIP and DoH remain deferred.

## Phase 13 host integration

[System integration](SYSTEM_INTEGRATION.md) adds typed TUN/HTTP/mixed ingress to the
existing immutable client graph. SQLite schema 7 stores host intent; a private journal
owns reversible operational mutations. See [local inbound](architecture/LOCAL_INBOUND_MODEL.md),
[Linux](PLATFORM_LINUX.md), [Windows](PLATFORM_WINDOWS.md) and the source audit.
Unified underlay runtime wiring, Wintun partial ownership and WinINET exact restore
implementation blockers are closed. Phase 13 is locally frozen under its
[freeze report](reports/PHASE_13_FREEZE_REPORT.md); all capabilities remain
Experimental. Real Windows activation is guarded and native-platform qualification
remains pending. Underlay protection preserves logical routing/DNS/policy selection.
