# Splicore Documentation

- Documentation status: Canonical
- Audience: Developers, maintainers and integration authors
- Last reviewed: 2026-10-01
- Owner: Documentation maintainers
- Responsibility: Complete navigation to Splicore specifications, decisions and history.
- Lifecycle: Update when owned documents are added, retired or change responsibility.

## How to read this documentation

**Canonical** identifies the maintained source for a topic. It does not mean
proposed functionality is implemented. Phase 0 establishes designs and baseline
research; Phase 1 Foundation is frozen, with runtime/interop still deferred.
The Phase 2 branch is prepared; implementation has not started.
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

[ADR index](adr/README.md) lists all 12 decisions and their individual status.
ADR 0001 is accepted for Phase 0; 0002–0012 remain proposed for maintainer review.
Decision acceptance is separate from implementation and interoperability qualification.

## Domain Model

- [Domain model](architecture/DOMAIN_MODEL.md): entities, ownership and authorization relationships.
- [Policy and usage](architecture/POLICY_USAGE.md): accounting units, ceilings, reset and crash uncertainty.
- [Configuration and state authority](architecture/CONFIG_STATE_AUTHORITY.md): bootstrap, import and committed state.

## Protocol / Engine

- [Protocol and engine index](protocol/README.md): extension path and qualification gates.
- [Protocol SDK](architecture/PROTOCOL_SDK.md): registry, proposed ports and effective capabilities.
- [Engine model](architecture/ENGINE_MODEL.md): native translation and future private Xray compatibility.
- [Mieru integration](architecture/MIERU_INTEGRATION.md): pinned research and three-stage native roadmap.
- [Future native protocols](architecture/NATIVE_PROTOCOL_GUIDELINES.md): specification, security and testing requirements.

## API

- [API index](api/README.md): machine contract and semantic documentation responsibilities.
- [API v1 design](api/API_V1_DESIGN.md): control transport, authorization and operation semantics.
- [OpenAPI contract skeleton](api/openapi-skeleton.yaml): Foundation reads and marked deferred paths, schemas and responses.

## Storage

- [Storage model](architecture/STORAGE_MODEL.md): driver qualification, durability, migrations and backup.
- [Database ERD](architecture/DATABASE_ERD.md): entities, relationships, constraints and ownership.
- [Transaction model](architecture/TRANSACTION_MODEL.md): coordination outside database atomicity.

[0001_initial](../internal/splicore/storage/sqlite/migrations/0001_initial.sql)
owns actual schema 1 history; the complete ERD remains a future target.

## Client Compatibility

- [ClientProfile and exporters](architecture/CLIENT_COMPATIBILITY.md): client projection and target/version checks.
- [Subscriptions](architecture/SUBSCRIPTION_MODEL.md): scoped token access and authorized profile selection.
- [Interoperability matrix](testing/INTEROP_MATRIX.md): third-party traffic qualification, currently planned / NOT RUN for Splicore.

## Testing

- [Test strategy](testing/TEST_STRATEGY.md): unit, contract, failure, migration and release gates.
- [Interop matrix](testing/INTEROP_MATRIX.md): protocol/client coverage and evidence requirements.
- [Historical upstream validation](architecture/UPSTREAM_BASELINE.md): actual scoped results, including failures.

## Diagnostics

[Diagnostics](architecture/DIAGNOSTICS.md) owns Foundation CLI checks and future
local, bounded, redacted support bundles.

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
