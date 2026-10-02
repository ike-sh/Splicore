# API v1 design

- Documentation status: Canonical
- Audience: API, CLI and integration developers
- Last reviewed: 2026-10-01
- Owner: API maintainers
- Responsibility: Transport, security and operation semantics; OpenAPI owns endpoint surface.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Design maturity: Foundation queries and experimental Snell/Hysteria2/TUIC operations
are implemented and marked in OpenAPI. Other paths remain deferred. Protected
local UDS access authorizes control; no public network bearer surface is enabled.

Managed protocol operations accept at most 64 KiB strict JSON. Apply checks compact-JSON HMAC
and decimal global revision and returns 200 only after health and durable commit.
Plans expire on daemon restart/state change. This bounded synchronous API has
no generic Idempotency-Key/If-Match promise; requirements below apply to future
generic routes. Metadata is one bounded committed snapshot (at most 64 Inbounds).
Display mutation checks resource/global revisions without changing runtime.
Export POST is explicitly secret-returning; default GET/doctor/journal/errors have
no PSK/UUID/password/private-key contents. Unsupported client combinations return 422. Counters are decimal strings.
Occupied listeners return `port_conflict` (409) with a fixed safe message through
API and CLI; this differs from a revision conflict.

HY2 creation accepts 1–16 users, static TLS file references/public CA and optional
explicit metadata-only policies. Generic export requires `binding_id` for multiple
Bindings and rejects disabled/unavailable identities. Ordinary views include
`bindings` with per-Binding counters and `policy_enforced:false`; legacy top-level
Account/Binding IDs appear only for single-Binding views. Private keys are neither
returned nor stored in SQLite. Binding mutation checks global/Binding revisions,
journals and reconstructs only its Inbound; all of its sessions are interrupted.
It returns 200 after health/commit, without a whole-daemon restart. Failure restores
the prior committed projection or reports recovery required. See [HY2](../protocol/HYSTERIA2.md).

Transport → Application Service → Domain + repository/runtime ports. HTTP handler
performs parsing/auth/serialization only. Local CLI defaults to HTTP over Unix
socket `/run/splicore/splicore.sock`; daemon transport and future Panel invoke the
same application commands. Offline CLI takes ownership lock and the same
application/journal path; it cannot casually edit SQLite. Linux UDS permissions
and peer identity make Phase 1 suitable without opening public API. Windows
Foundation tests use httptest with an explicitly injected HTTP client; no
production Windows or network management listener is implemented.

Future HTTP/TLS shares `/api/v1`, adds control principal authentication/authorization
and separate exposure configuration. `http://localhost` in the OpenAPI servers
list is a logical HTTP origin over UDS, **not** a default TCP listener. Socket
access is authentication in local mode; bearer security is the future network mode.
Subscription token API lives on a separate opt-in public origin/listener.

## Contract authority and read semantics

The [OpenAPI skeleton](openapi-skeleton.yaml) owns the proposed endpoint surface,
methods, parameters, schemas and responses. This Markdown owns design/security
and behavioral semantics; it does not duplicate the endpoint reference. See the
[API index](README.md) for the change workflow. Contract presence does not imply
an implemented endpoint, and future additions must enter OpenAPI before being
treated as part of the surface.

Pagination is cursor-based on committed generation with bounded limit; include
snapshot revision and reject expired/incompatible cursors. No offset traversal
across a changing domain snapshot. Usage window UTC `[from,to)`, bounded range;
byte counts and revisions serialize as decimal strings to avoid JS precision loss.
GET returns quoted revision ETag; never returns password/PSK/token/key payload.

## Mutation semantics and future CRUD

Resource create/PATCH/disable/delete, Binding assignment/credential rotation,
Entitlement changes and Subscription issue/rotate/revoke all call application
commands and the same validate/plan/journal/apply/health/commit coordinator.
Runtime-impacting mutation responses are 202 operations; success means durable
commit only when operation says committed. Pending IDs/reserved resources are not
visible as granted access. Deletion plans report session/usage/subscription impact.
Non-runtime ancillary updates (e.g. last_used_at) use bounded repository transactions.

Apply requires `If-Match` quoted global base revision and `Idempotency-Key`; body
contains plan_id + base_revision + plan_digest. Stale revision/different payload
same key → 409; missing precondition → 428; malformed → 400; domain/capability
violation → 422; unknown → 404; unauthorized → 401/403; busy/rate-limited → 429;
unavailable recovery/DB → 503. Successful apply never returns 200 before health.
Plan expires, pins input/build identity, and cannot bypass a changed global generation.

Structured problem includes code/message/request_id, field violations, current
revision and operation reference; omit secret inputs. Authentication failures
must not leak account/token existence. Audit uses authenticated principal,
not caller-supplied actor string. Bound JSON depth, body size and request duration.

Future secret issue creates an operation then protected short-lived reveal result
for the initiating principal; retry returns same operation, not newly minted secret.
One-time reveal endpoints need explicit delivery/retry/expiry contract before adding
to OpenAPI. Raw secret credential input is write-only; routine GET never reveals it.
No subscription/admin token equivalence, commerce/RBAC suite or raw engine API.

## Phase 4 registered commands

/api/v1/creation/{protocol}/validate|plan|apply resolves compiled CreationCodec, with
uniform plan/applied shapes. Snell/HY2 legacy endpoints and methods remain compatible.
/api/v1/tuic/validate|plan|apply aliases use generic shapes. Protocol is HMAC-bound;
cross-protocol replay rejects. TUIC UUID/password supplied together or omitted to
generate; account_enabled:false disables Account at creation, enabled:false Binding.
Metadata omits both secrets; explicit export returns them. No HTTP runtime import.
[OpenAPI](openapi-skeleton.yaml) and [TUIC](../protocol/TUIC.md) own exact contracts.

## Phase 7 engine features

Existing registered VLESS validate/plan/apply accepts typed settings.engine_options
for one FinalMask TCP Sudoku mask: plain/flow-none/prefer_ascii/padding0–3, engine=xray.
Native/TLS/REALITY reject unsupported_engine_feature (422); Vision remains
not_implemented (501), malformed/unknown/null fields invalid (400). Rejection is
before availability, secret materialization and pending. No raw Xray config API.
Optional write-only transport_secret.password imports the exact shared seed;
omission generates. Ordinary responses omit it. Authorized format=xray, version
26.3.27 export returns sensitive xray-outbound content. Masked other formats reject
unsupported_export (422). Capabilities expose engine_features with scope and client
support; node_status.features/System engine features report last artifact availability.
Doctor adds safe feature checks. No endpoints or Account/Binding schema changes.
[Workflow](../development/PHASE_7_XRAY_EXTENSIONS.md) and OpenAPI own exact fields.
