# API v1 design

- Documentation status: Canonical
- Audience: API, CLI and integration developers
- Last reviewed: 2026-10-01
- Owner: API maintainers
- Responsibility: Transport, security and operation semantics; OpenAPI owns endpoint surface.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Design maturity: contract skeleton, no HTTP server/CLI implementation. OpenAPI describes
the initial read/import workflow; resource mutations and token management are
specified as later additions using the same operation contract.

Transport → Application Service → Domain + repository/runtime ports. HTTP handler
performs parsing/auth/serialization only. Local CLI defaults to HTTP over Unix
socket `/run/splicore/splicore.sock`; daemon transport and future Panel invoke the
same application commands. Offline CLI takes ownership lock and the same
application/journal path; it cannot casually edit SQLite. Linux UDS permissions
and peer identity make Phase 1 suitable without opening public API. Windows
needs named-pipe adapter or explicitly configured authenticated loopback transport.

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
