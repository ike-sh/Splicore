# API v1 design

- Documentation status: Canonical
- Audience: API, CLI and integration developers
- Last reviewed: 2026-10-04
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

## Current native engine boundary

The active registry and successful API representations contain native only.
Xray engine pairs reject `unsupported_engine_for_protocol`; mask options reject
without conversion. Vision remains `not_implemented`. Capability/System expose
no external version/health/PID/artifact or mask feature descriptors. Ordinary
plain VLESS external-client JSON export is independent of runtime ownership.
Imports classify Xray/FinalMask/Sudoku as Unsupported and create no stripped node.
[ADR 0035](../adr/0035-xray-runtime-removed-from-core.md).

## Phase 8 generic Mieru operations

Existing `/api/v1/creation/{protocol}/{validate,plan,apply}` selects `mieru` with
the bounded [canonical contract](../protocol/MIERU.md); no Mieru-specific route.
Capability API returns mieru/native, experimental multi-user TCP/UDP and attributed
payload stats. Quota/speed/session enforcement remain unsupported; user mutations
restart only that inbound. Export format mieru requires exact 3.38.0; Mihomo
1.19.30 requires MTU 1500. Password appears only in protected explicit export,
never generic reads. OpenAPI documents optional credential-pair generation and
rejects unsupported settings/formats/version combinations in runtime validation.

## Phase 9 local operations

No HTTP route is added. Package/service/backup/support operations are local CLI
commands with filesystem and root/owner checks described by
[distribution](../DISTRIBUTION.md). System Version optionally adds source_digest
and build_tags for exact build provenance; OpenAPI remains the field authority.
Doctor and the [support bundle](../SUPPORT_BUNDLE.md) use safe local summaries;
raw journal, DB/config and engine JSON never become API or bundle responses.

## Phase 10 client control semantics

Client resource CRUD and lifecycle use the existing protected `/api/v1` transport.
GET replies return typed canonical state and ETag with the shared committed revision.
Mutation CRUD requires `If-Match: "<revision>"`; stale revision returns 409. Collection
reads are bounded arrays (no pagination/query parameters in this phase). Unknown
paths return 404; wrong methods return 405 with Allow. Request JSON is strict and
bounded to 2 MiB for client/network commands (server creation remains 64 KiB). The endpoint determines resource/action/ID; callers cannot override
those fields in CRUD bodies. Generic validate/plan/apply accepts ClientMutation,
with HMAC digest/global revision as the existing optimistic concurrency boundary.

Create/rotate accepts explicit write-only CredentialInput. Reads expose credential
IDs and canonical node data, never decrypted payloads. The machine contract owns
exact paths/schemas. Runtime health is passive; available is not an active probe.
Client and server share one global revision/journal. Client build/bind/commit failure
compensates candidates while preserving committed intent and existing server runtimes.
See [CLI](../CLI.md) and [client runtime](../architecture/CLIENT_RUNTIME.md).

## Phase 11 client observations

Credential pair writes use the existing generic input: kind `uuid_password` or
`username_password`, value a strict JSON string with the canonical two fields. No
secret is returned in node/outbound reads. ClientSecurity adds public ClientTLS;
adapters validate the protocol/transport/security/options combination. Options are
schema 1, strict bounded JSON objects of at most 16 KiB, never engine configuration.

ClientTrafficStats has decimal-string upload/download payload bytes, TCP total/active
sessions, UDP total/active associations and upload/download packets. A session's kind
distinguishes streams from associations. LocalInbound, Outbound, Node and Session are
views of the same payload; adding views would double count. UDP headers/control bytes
are excluded. Passive health belongs to the current adapter lease and uses a fixed
redacted error. Existing ETag, If-Match, journal and apply semantics remain shared.

## Phase 12 network API

The protected existing Application/API owns routes, route-rules, rule-sets,
policy-groups, dns/servers, dns/rules and dns/profile. Collections GET/POST;
individual IDs GET/PUT/DELETE. Routes/profile GET/PUT; policy-groups/{id}/select POST
with typed selected action. Mutations use If-Match and the common plan/apply transaction.
Body wrappers are route_rule/rule_set/policy_group/dns_server/dns_rule/route_profile/
dns_profile/selected; endpoint determines resource/action/ID.

POST routes/explain takes original domain/IP, optional resolved_ips, destination
port/network/local inbound; no DNS or outbound I/O. POST dns/lookup explicitly queries.
GET dns/cache/status and POST dns/cache/flush expose bounded observations/flush.
GET policy-groups/status exposes selected/member health/count. Aggregate network
replace uses existing client/validate, client/plan, client/apply with ClientMutation.
See the machine OpenAPI contract for exact paths/schemas; no protocol-specific API.

## Phase 14 management API

| Path below /api/v1 | Methods / result |
| --- | --- |
| imports/preview, nodes/import-preview | POST ManagementRequest → redacted ManagementPreview. |
| imports/apply | POST token + decimal-string revision → existing ClientResult. |
| nodes/batch-preview | POST IDs + enable/disable/delete/tag/metadata action → preview. |
| nodes/export | POST selected IDs/provider_id/all, format/version and explicit reveal_secrets → protected content + compatibility details. |
| providers, rule-set-providers | GET safe metadata; POST create preview. |
| providers/{id}, rule-set-providers/{id} | GET safe resource; PUT config-update preview; DELETE removal preview. |
| .../{id}/refresh-preview, .../{id}/refresh | POST {} → preview / complete transactional refresh. |

Collections enforce immutable provider kind for all paths. Management bodies are strict
JSON, max 4 MiB; no query parameters. Endpoint determines operation/ID for resource
routes. Source URL/auth is write-only; update omits Source to retain encrypted settings.
Generation/status/diagnostics/url_display are read-only and cannot be supplied as nonzero
config values. All preview plans use single-use random token + committed revision +
five-minute expiry, not If-Match; stale apply returns 409. GET node/outbound existing
resources include provenance/tags/state/provider ownership, never secret payloads.
Tags are node attributes with generic batch replacement, not protocol-specific resources.
No new public subscription output path. Exact schemas are in the machine contract.
