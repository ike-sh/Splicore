# API Documentation

- Documentation status: Canonical
- Audience: API, CLI and integration developers
- Last reviewed: 2026-10-01
- Owner: API maintainers
- Responsibility: Contract authority, semantic references and API change workflow.
- Lifecycle: Update with contract ownership or API scope changes.

## Current Phase 3 implementation

OpenAPI marks 13 implemented routes: two Foundation queries, seven existing
runtime/Snell operations, three HY2 operations and Binding enable/disable.
Export is explicitly secret-returning and supports explicit Binding selection;
reads redact credentials. Generic resource/subscription/import routes remain deferred.

## Current state and authority

The API has a **Foundation implementation** of the System and Capabilities reads.
Marked Snell/HY2 operations are experimental; other routes remain proposed.
The [OpenAPI 3.1 skeleton](openapi-skeleton.yaml) is
the machine authority for paths, methods, parameters, schemas,
responses and HTTP security descriptions. JSON syntax is valid YAML. Its
version is a contract marker, not a product release. Each operation records its
implementation maturity. The Foundation test transport is Windows httptest;
the runnable production control transport is protected Linux UDS.

[API v1 design](API_V1_DESIGN.md) owns transport/authentication boundaries,
pagination and numeric semantics, mutation preconditions, asynchronous operation
behavior and future scope. It does not maintain a duplicate endpoint reference.
Planned CRUD/token-reveal work is not an existing route.

## Related specifications

- [Domain model](../architecture/DOMAIN_MODEL.md): resources and ownership.
- [State authority](../architecture/CONFIG_STATE_AUTHORITY.md): imports and committed reads.
- [Transactions](../architecture/TRANSACTION_MODEL.md): revision, idempotency, health and commit outcome.
- [Security](../architecture/SECURITY_BOUNDARIES.md): peer/control identity and secret redaction.
- [Subscriptions](../architecture/SUBSCRIPTION_MODEL.md): separate public access and token scope.
- [ADR 0008](../adr/0008-api-boundary.md): API/application boundary rationale; proposed.

## Maintenance

Change OpenAPI when the surface changes. Update semantic Markdown when behavior
or security changes; both must agree. Future runtime implementation must conform
to the contract and include applicable contract tests. Validate OpenAPI 3.1,
all references, unique operation IDs and redacted read schemas before review.
Transport permissions/peer authentication need implementation tests; schema
validation alone cannot qualify them.

See [documentation policy](../DOCUMENTATION_POLICY.md),
[development workflow](../development/README.md) and [all docs](../README.md).
