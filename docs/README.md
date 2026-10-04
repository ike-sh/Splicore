# Splicore Documentation

- Documentation status: Canonical
- Audience: Developers, maintainers and integration authors
- Last reviewed: 2026-10-03
- Owner: Documentation maintainers
- Responsibility: Complete navigation to Splicore specifications, decisions and history.
- Lifecycle: Update when owned documents are added, retired or change responsibility.

## How to read this documentation

**Canonical** identifies the maintained source for a topic. It does not mean
proposed functionality is implemented. Phase 0 establishes designs and baseline
research; Phases 0–11 are locally frozen. Phase 2 implements experimental Snell with real
Mihomo/sing-box interoperability. Phase 3 adds experimental Hysteria2 with
trusted-CA multi-user TCP/UDP interoperability; Phase 4 implements experimental TUIC v5 with shared TLS/QUIC and
registered creation commands. Phase 5 adds a native VLESS/REALITY candidate with
separate engine placement; Vision is deferred/unsupported and fails closed.
Other adapters remain deferred.
No stable Splicore runtime has been released. **Historical** documents
and **Generated** evidence preserve what was observed at a particular time.
**Draft** is work that has not yet become an authoritative design.

```text
README.md                           project introduction
  -> docs/README.md                 complete technical navigation
      -> docs/DEVELOPMENT_CONTEXT.md   current constraints
      -> docs/ARCHITECTURE.md        architecture overview
          -> architecture/README.md   bounded specifications
          -> protocol/README.md       protocol and engine specifications
          -> api/README.md            contract and API semantics
          -> adr/README.md            decisions and alternatives
      -> development/README.md      maintenance and validation workflow
      -> historical reports         frozen acceptance snapshots
```

## Architecture

- [Architecture overview](ARCHITECTURE.md): boundaries, dependency direction and implementation gates.
- [Architecture specification map](architecture/README.md): topic ownership and bounded specifications.
- [Fork boundary](architecture/FORK_BOUNDARY.md): package, command and adapter strategy.
- [Runtime lifecycle](architecture/RUNTIME_LIFECYCLE.md): startup, shutdown and owned children.
- [Transactions](architecture/TRANSACTION_MODEL.md): generation fences, recovery and audit.
- [Version model](architecture/VERSION_MODEL.md): independent product, schema and API identities.

## Architecture Decision Records

[ADR index](adr/README.md) lists all 29 decisions and their individual status.
ADR 0001 is accepted for Phase 0; 0002–0015 remain proposed for maintainer review.
ADR 0016 records the foundation boundary; ADR 0017 defers Vision with explicit re-enable gates.
Decision acceptance is separate from implementation and interoperability qualification.

## Domain Model

- [Domain model](architecture/DOMAIN_MODEL.md): entities, ownership and authorization relationships.
- [Policy and usage](architecture/POLICY_USAGE.md): accounting units, ceilings, reset and crash uncertainty.
- [Configuration and state authority](architecture/CONFIG_STATE_AUTHORITY.md): bootstrap, import and committed state.

## Protocol / Engine

- [Snell support](protocol/SNELL.md): implemented profile and client contracts.
- [Hysteria2 support](protocol/HYSTERIA2.md): multi-user, TLS, QUIC/UDP and restart limits.
- [TUIC support](protocol/TUIC.md): v5 UUID/password and shared TLS/QUIC.

- [Protocol and engine index](protocol/README.md): extension path and qualification gates.
- [Protocol SDK](architecture/PROTOCOL_SDK.md): registry, proposed ports and effective capabilities.
- [Engine model](architecture/ENGINE_MODEL.md): native translation and owned private Xray compatibility.
- [Mieru integration](architecture/MIERU_INTEGRATION.md): pinned research and three-stage native roadmap.
- [Future native protocols](architecture/NATIVE_PROTOCOL_GUIDELINES.md): specification, security and testing requirements.

## API

- [API index](api/README.md): machine contract and semantic documentation responsibilities.
- [API v1 design](api/API_V1_DESIGN.md): control transport, authorization and operation semantics.
- [OpenAPI contract skeleton](api/openapi-skeleton.yaml): Foundation reads, managed protocol operations and marked deferred paths, schemas and responses.

## Storage

- [Storage model](architecture/STORAGE_MODEL.md): driver qualification, durability, migrations and backup.
- [Database ERD](architecture/DATABASE_ERD.md): entities, relationships, constraints and ownership.
- [Transaction model](architecture/TRANSACTION_MODEL.md): coordination outside database atomicity.

[0001_initial](../internal/splicore/storage/sqlite/migrations/0001_initial.sql)
preserves schema 1 history. [0002_snell](../internal/splicore/storage/sqlite/migrations/0002_snell.sql)
adds schema 2; [0003_password](../internal/splicore/storage/sqlite/migrations/0003_password.sql)
adds generic password credentials in schema 3; [0004_private_key](../internal/splicore/storage/sqlite/migrations/0004_private_key.sql)
adds generic inbound-owned private keys in schema 4. The full ERD remains a future target.

## Client Compatibility

- [ClientProfile and exporters](architecture/CLIENT_COMPATIBILITY.md): client projection and target/version checks.
- [Subscriptions](architecture/SUBSCRIPTION_MODEL.md): scoped token access and authorized profile selection.
- [Interoperability matrix](testing/INTEROP_MATRIX.md): third-party traffic qualification, Snell verified cells and deferred profiles.

## Testing

- [Phase 2 workflow](development/PHASE_2_SNELL.md): commands and external clients.
- [Phase 2 report](reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md): actual verification.
- [Phase 3 workflow](development/PHASE_3_HYSTERIA2.md): pinned HY2 clients and synthetic TLS.
- [Phase 3 report](reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md): HY2 qualification and regression results.
- [Phase 4 workflow](development/PHASE_4_TUIC.md): native campaigns and third-protocol gates.
- [Phase 4 report](reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md): TUIC acceptance and extension audit.

- [Test strategy](testing/TEST_STRATEGY.md): unit, contract, failure, migration and release gates.
- [Interop matrix](testing/INTEROP_MATRIX.md): protocol/client coverage and evidence requirements.
- [Historical upstream validation](architecture/UPSTREAM_BASELINE.md): actual scoped results, including failures.

## Diagnostics

[Diagnostics](architecture/DIAGNOSTICS.md) owns the diagnostics design;
[support bundles](SUPPORT_BUNDLE.md) documents the implemented local, bounded,
redacted distribution contract.

## Integration

[NoBrand-OneClick migration](integration/NOBRAND_MIGRATION.md) describes a future
integration and field-testing path. NoBrand is not Splicore's product identity;
no installer or existing deployment is modified here.

## Upstream

- [Current provenance](UPSTREAM.md): baseline identity and non-affiliation.
- [Sync procedure](architecture/UPSTREAM_SYNC.md): candidate review, merge and qualification.
- [Historical baseline ledger](architecture/UPSTREAM_BASELINE.md): Phase 0 commands and observed results.
- [Historical source map](architecture/UPSTREAM_ARCHITECTURE_MAP.md): source findings pinned to v1.14.1.
- [Attribution notice](../NOTICE.md): independent derivative identity.

## Security

- [Security boundaries](architecture/SECURITY_BOUNDARIES.md): secrets, transports, imports and child trust.
- [License boundaries](architecture/LICENSE_BOUNDARIES.md): provenance and distribution review boundaries.
- [Original license](../LICENSE): unchanged upstream license text.

## Development

- [Development context](DEVELOPMENT_CONTEXT.md): current phase and durable constraints.
- [Development index](development/README.md): recovery, change workflow and validation.
- [Foundation workflow](development/FOUNDATION.md): implemented commands, bootstrap, builds and tests.
- [Foundation dependency audit](development/DEPENDENCIES_PHASE_1.md): driver selection and dependency/licenses.
- [Phase 1 Foundation Report](reports/PHASE_1_FOUNDATION_REPORT.md): scoped implementation acceptance.
- [Documentation policy](DOCUMENTATION_POLICY.md): ownership, authorities, ADRs and history rules.

## Historical Reports

- [Phase 0 Architecture Report](PHASE_0_ARCHITECTURE_REPORT.md): original architecture acceptance snapshot.
- [Phase 0 requirement traceability](PHASE_0_REQUIREMENTS.md): original brief coverage, frozen.
- [Phase 0 evidence](architecture/evidence/README.md): historical/generated command outputs, not current CI state.
- [Documentation Finalization Report](reports/PHASE_0_DOCUMENTATION_FINALIZATION_REPORT.md): documentation audit and scoped validation.

The original architecture report stays at its established path. Future completed
reports belong in `reports/`; do not precreate empty phase or release reports.

## Inherited upstream documentation

Inherited configuration, client, installation, migration and changelog pages
remain sing-box documentation. They do not describe an implemented Splicore public
contract. Preserve their names and content; use the Splicore entries above for
this project's designs. Upstream documentation site configuration is unchanged.

- [VLESS support](protocol/VLESS.md): native TCP/XUDP, REALITY secret boundaries and Vision deferral.
- [Phase 5 workflow](development/PHASE_5_VLESS.md): isolated validation and exact gates.
- [Initial Phase 5 report](reports/PHASE_5_VLESS_REALITY_NATIVE_VERTICAL_SLICE_REPORT.md): historical Vision safety failures.
- [Phase 5 final report](reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md): non-Vision acceptance and fresh evidence.
- [Phase 5 local freeze](reports/PHASE_5_FREEZE_REPORT.md): authorized checkpoint for Phase 6.

- [Phase 6 Xray workflow](development/PHASE_6_XRAY.md): pinned artifacts, dual placement and runtime gates.
- [Xray owned child decision](adr/0018-xray-owned-child-engine.md): process/admission/artifact ownership.
- [Phase 6 duality report](reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md): actual 40-cell acceptance, regressions and platform limits.

## Phase 7 specialized Xray features

- [Phase 7 workflow](development/PHASE_7_XRAY_EXTENSIONS.md): bounded typed FinalMask/Sudoku contract and reproducible managed gates.
- [ADR 0019](adr/0019-xray-specialized-feature-boundary.md): unchanged official artifact, feature composition and secret ownership.
- [Phase 7 report](reports/PHASE_7_XRAY_VLESS_EXTENSIONS_REPORT.md): actual managed traffic, regressions, gates and deferred qualification.
- [Phase 7 freeze](reports/PHASE_7_FREEZE_REPORT.md): authorized local checkpoint, unchanged acceptance source and Phase 8 branch only.

## Phase 8 navigation

[Mieru contract](protocol/MIERU.md), [workflow](development/PHASE_8_MIERU.md), [implementation ADR](adr/0020-mieru-owned-native-embedding.md), [capability matrix](architecture/CAPABILITY_MATRIX.md), [report](reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md).

[Phase 8 freeze](reports/PHASE_8_FREEZE_REPORT.md) records the local Experimental
checkpoint. Phase 9 distribution and service is locally frozen under its
[freeze report](reports/PHASE_9_FREEZE_REPORT.md). No public release is published.

## Phase 9 distribution and service

- [Installation](INSTALLATION.md), [upgrade](UPGRADE.md) and [uninstall](UNINSTALL.md).
- [Operations](OPERATIONS.md) and [redacted support bundles](SUPPORT_BUNDLE.md).
- [Distribution / future NoBrand contract](DISTRIBUTION.md).
- [ADR 0021](adr/0021-linux-local-distribution.md): local pinned service foundation.
- [Phase 9 report](reports/PHASE_9_DISTRIBUTION_SERVICE_FOUNDATION_REPORT.md): installed-service acceptance, reproducibility and platform limits.
- [Phase 9 freeze](reports/PHASE_9_FREEZE_REPORT.md): authorized local checkpoint and clean client-runtime branch preparation.

## Phase 10 Client Runtime

- [Client Runtime](architecture/CLIENT_RUNTIME.md), [routing](architecture/ROUTING_MODEL.md) and [CLI](CLI.md).
- [ADR 0022](adr/0022-client-runtime-domain.md): identity separation and shared daemon.
- [Phase 10 report](reports/PHASE_10_CLIENT_RUNTIME_FOUNDATION_REPORT.md): implementation, local acceptance and limits.
- [Phase 10 freeze](reports/PHASE_10_FREEZE_REPORT.md): authorized local checkpoint, ownership audit and Phase 11 branch preparation.
- Phase 10 is FROZEN; its report preserves the original TCP/DIRECT/Snell boundary.

## Phase 11 Client Outbound Expansion

- [Client Runtime](architecture/CLIENT_RUNTIME.md) and [capability matrix](architecture/CAPABILITY_MATRIX.md): loopback SOCKS5 TCP/UDP and six registered outbound pairs.
- [ADR 0023](adr/0023-client-udp-ownership.md): accepted association ownership and adapter leases.
- [Phase 11 acceptance](reports/PHASE_11_CLIENT_OUTBOUND_EXPANSION_REPORT.md): actual payload, lifecycle, installed-service and platform evidence.
- [Phase 11 freeze](reports/PHASE_11_FREEZE_REPORT.md): authorized checkpoint, source match and Phase 12 branch preparation.
- Client remains Experimental. Vision and client FinalMask/Sudoku are deferred;
  Xray TCP half-close is NOT QUALIFIED, Windows race is NOT EXECUTED and arm64
  runtime is NOT CERTIFIED. The historical Phase 11 report preserves its boundary;
  routing/DNS/policy are the Experimental Phase 12 scope below. TUN and NoBrand
  migration remain deferred. No public release.

## Phase 12 local freeze

[Routing](architecture/ROUTING_MODEL.md), [DNS](architecture/DNS_MODEL.md),
[policy](architecture/POLICY_MODEL.md) and [acceptance report](reports/PHASE_12_ROUTING_DNS_POLICY_REPORT.md).
[Freeze report](reports/PHASE_12_FREEZE_REPORT.md): authorized checkpoint, source
match, fresh gates and clean Phase 13 branch preparation. Routing/DNS/policy remain
Experimental; System/UDP/TCP/verified DoT and round-robin are the qualified scope.
That freeze preserves the Phase 12 boundary. Phase 13 progress is tracked below.

## Phase 13 TUN and system integration

- [Local inbound model](architecture/LOCAL_INBOUND_MODEL.md): shared SOCKS/HTTP/mixed/TUN runtime.
- [System integration](SYSTEM_INTEGRATION.md): route ownership, private operational journal and recovery.
- [Linux](PLATFORM_LINUX.md) and [Windows](PLATFORM_WINDOWS.md): supported paths, blocked activation and qualification limits.
- [Source audit](development/PHASE_13_TUN_AUDIT.md): pinned upstream capabilities and ownership decisions.
- [Phase 13 report](reports/PHASE_13_TUN_SYSTEM_INTEGRATION_REPORT.md): local acceptance evidence and exact remaining blockers.
- [Windows blocker closure](reports/PHASE_13_WINDOWS_BLOCKER_CLOSURE_REPORT.md): closed ownership blockers and preserved Windows campaign evidence.
- [Underlay closure](reports/PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md): actual client/server/DNS/child wiring, retained generations and final source-bound acceptance.
- [Phase 13 freeze](reports/PHASE_13_FREEZE_REPORT.md): authorized Experimental checkpoint, unchanged functional source and clean Phase 14 branch preparation.
- [Recovery](RECOVERY.md) and [testing](TESTING.md): safe operational and qualification boundaries.

Phase 13 is locally FROZEN. Real Windows TUN/auto-route/WinINET and native Ubuntu
host-network qualification remain pending; Windows activation stays guarded.
Phase 14 implementation has not started. Subscriptions/providers remain deferred.
