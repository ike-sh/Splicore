# API Documentation

- Documentation status: Canonical
- Audience: API, CLI and integration developers
- Last reviewed: 2026-10-03
- Owner: API maintainers
- Responsibility: Contract authority, semantic references and API change workflow.
- Lifecycle: Update with contract ownership or API scope changes.

## Current Phase 6 implementation candidate

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
implemented xray for vless, with actual build-dependent REALITY support and
separate node_status availability/reference/installed version. Vision is
DEFERRED / UNSUPPORTED. Canonical flow permits only none; Vision create/import requests
return typed not_implemented (HTTP 501), exports return unsupported_export (HTTP 422).
Ordinary inbound settings remain redacted and contain no credential payloads.
Scoped export may reveal UUID/public key/short ID/SNI; never server private key,
internal target or actual listener. URI uses vless-uri content_shape. Live safe
responses and synthetic request schemas are checked with the current OpenAPI.

## Safe engine diagnostics

System engines and capabilities engine_implementations.node_status distinguish
build support from the last node validation result. Optional Xray absence is
unavailable without changing native health. Inbound runtime is optional safe
PID/generation/start/path/health/exit metadata; config content is never returned.
Doctor/capabilities/status report the same service projections. Xray usage counters
remain zero with native_stats/attributed_payload unsupported and per_user_stats=false.

Strict VLESS/Xray quota or rate requests return `unsupported_policy_for_engine`
(HTTP 422) from validate/plan/apply and offline CLI validation. Malformed policies
remain `invalid` (HTTP 400); explicit metadata_only never claims enforcement.

## Local service/distribution operations

Phase 9 introduces local service/package/backup/support CLI commands, with no
new network API routes. See [installation](../INSTALLATION.md),
[operations](../OPERATIONS.md) and [bundle contract](../SUPPORT_BUNDLE.md).
Optional Version.source_digest/build_tags expose exact build provenance in the
existing system response; the machine schema is updated with those fields.

## Phase 10 client surface

OpenAPI marks node/outbound/local-inbound CRUD, credential rotation, route,
client runtime/lifecycle and client validate/plan/apply as `phase10`. These run in
the same control plane; generic server resource CRUD/subscriptions remain deferred.
System adds separate server_runtimes/client_runtime projections. Capability roles
express inbound/outbound support; exact proxy adapters are reported in client status.
Credentials are write-only inputs and absent from read schemas. See
[client CLI](../CLI.md), [client runtime](../architecture/CLIENT_RUNTIME.md) and
[control semantics](API_V1_DESIGN.md#phase-10-client-control-semantics).

## Phase 11 client expansion

Existing generic node/outbound APIs support six registered protocol/engine pairs.
No protocol-specific route is added. Public client TLS fields, bounded adapter options,
credential-pair inputs, role-specific capability dimensions and eight decimal-string
client counters are documented in the machine schema. Server RuntimeStats is unchanged.
Local SOCKS UDP status is `supported`; session kind is `tcp` or `udp_association`.
See [control semantics](API_V1_DESIGN.md#phase-11-client-observations).
