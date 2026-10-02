# Architecture Specification Map

- Documentation status: Canonical
- Audience: Core developers and architecture reviewers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Route architectural changes to the bounded specification that owns them.
- Lifecycle: Update when specification boundaries or navigation change.

Begin with the [overview](../ARCHITECTURE.md) and [current context](../DEVELOPMENT_CONTEXT.md).
Canonical documents distinguish implemented Foundation from **proposed runtime design**, not qualified
Splicore functionality. [ADRs](../adr/README.md) own rationale and decision status;
[policy](../DOCUMENTATION_POLICY.md) governs updates.

## Maintained specifications

| Topic | Owning document | Maintainer role / responsibility |
| --- | --- | --- |
| Package and product boundary | [Fork boundary](FORK_BOUNDARY.md) | Core: adapter insertion, namespace and command transition. |
| Domain | [Domain model](DOMAIN_MODEL.md) | Core: entities, ownership and authorization relationships. |
| Accounting and policy | [Policy / Usage](POLICY_USAGE.md) | Core: payload units, ceilings, resets and uncertainty. |
| State | [Config authority](CONFIG_STATE_AUTHORITY.md) | Core: bootstrap/import/committed projection boundaries. |
| Protocol | [Protocol SDK](PROTOCOL_SDK.md) | Protocol: ports, registry and effective capabilities. |
| Execution | [Engine model](ENGINE_MODEL.md) | Engine: translation, native and future compatibility adapters. |
| Runtime | [Lifecycle](RUNTIME_LIFECYCLE.md) | Core / Engine: startup, shutdown, recovery and owned children. |
| Storage operations | [Storage model](STORAGE_MODEL.md) | Storage: driver gates, WAL, migration and backup mechanics. |
| Logical data structure | [ERD](DATABASE_ERD.md) | Storage / Core: relationships, ownership and constraints. |
| Mutations | [Transaction model](TRANSACTION_MODEL.md) | Core: journal, generations, compensation, concurrency and audit. |
| Client projection | [Client compatibility](CLIENT_COMPATIBILITY.md) | Client: profiles, exporters and target/version rejection. |
| Export access | [Subscription model](SUBSCRIPTION_MODEL.md) | Client / Core: token lifecycle, scope and selection. |
| Mieru | [Integration roadmap](MIERU_INTEGRATION.md) | Protocol: pinned API research and native qualification stages. |
| New wire protocols | [Native guidelines](NATIVE_PROTOCOL_GUIDELINES.md) | Protocol: specification, security and implementation gates. |
| Security | [Security boundaries](SECURITY_BOUNDARIES.md) | Security: secrets, transport, import and child trust. |
| Diagnostics | [Diagnostics](DIAGNOSTICS.md) | Core: check contracts and safe local bundles. |
| Versions | [Version model](VERSION_MODEL.md) | Core: separate product/schema/API/qualification identities. |
| Attribution | [License boundaries](LICENSE_BOUNDARIES.md) | Project: upstream and dependency provenance review. |
| Upstream maintenance | [Sync procedure](UPSTREAM_SYNC.md) | Upstream: compare, merge, patch inventory and qualification. |

## Related contracts and gates

- [API index](../api/README.md): machine surface and transport/operation semantics.
- [Protocol index](../protocol/README.md): extension reading order and client gates.
- [Testing strategy](../testing/TEST_STRATEGY.md) and [interop matrix](../testing/INTEROP_MATRIX.md).
- [NoBrand integration](../integration/NOBRAND_MIGRATION.md): future deployment/import boundaries.
- [Development workflow](../development/README.md): change review and validation.

## Pinned historical research

- [Upstream baseline ledger](UPSTREAM_BASELINE.md): Phase 0 source/toolchain/results snapshot.
- [Upstream architecture map](UPSTREAM_ARCHITECTURE_MAP.md): v1.14.1 source observations.
- [Evidence](evidence/README.md): generated captures supporting those observations.

Preserve these snapshots on a future baseline change. Update [current provenance](../UPSTREAM.md)
and create new scoped baseline/source evidence; do not silently rewrite old test results.

## Phase 8 current specifications

[Managed capability matrix](CAPABILITY_MATRIX.md) and [Mieru native contract](../protocol/MIERU.md) refine the retained [roadmap](MIERU_INTEGRATION.md).

## Client runtime specifications

- [Client Runtime](CLIENT_RUNTIME.md): canonical resources, native adapters, lifetime and recovery.
- [Routing model](ROUTING_MODEL.md): default/selected snapshot and DNS semantics.
