# API Documentation

- Documentation status: Canonical
- Audience: API, CLI and integration developers
- Last reviewed: 2026-10-02
- Owner: API maintainers
- Responsibility: Contract authority, semantic references and API change workflow.
- Lifecycle: Update with contract ownership or API scope changes.

## Current Phase 5 implementation candidate

OpenAPI marks Foundation/runtime/Snell/HY2/Binding operations and generic
registered protocol validate/plan/apply routes, including VLESS. Phase 5 exposes
separate protocol and engine identities plus per-protocol engine implementations.
Export is explicitly secret-returning and supports explicit Binding selection;
reads redact credentials. Generic resource/subscription/import routes remain deferred.

## Current state and authority

The API has a **Foundation implementation** of the System and Capabilities reads.
Marked Snell/HY2/generic creation operations are experimental; other routes remain proposed.
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

## VLESS contract boundary

CreationDocument includes typed VLESS settings, UUID users and write-only optional
server_secret.private_key. Engine is a bounded selector; plans/inbound reads expose
resolved engine independently of protocol identity. Capabilities list native and
unavailable xray for vless, with actual build-dependent REALITY support. Vision is
DEFERRED / UNSUPPORTED. Canonical flow permits only none; Vision create/import requests
return typed not_implemented (HTTP 501), exports return unsupported_export (HTTP 422).
Ordinary inbound settings remain redacted and contain no credential payloads.
Scoped export may reveal UUID/public key/short ID/SNI; never server private key,
internal target or actual listener. URI uses vless-uri content_shape. Live safe
responses and synthetic request schemas are checked with the current OpenAPI.
