# Mieru native integration roadmap

- Documentation status: Canonical
- Audience: Protocol and runtime developers
- Last reviewed: 2026-10-01
- Owner: Protocol maintainers
- Responsibility: Pinned Mieru API research and staged native integration qualification.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Research only. No Mieru clone/code/dependency/executable is added to this project.
Reference: official stable **v3.38.0**, published 2026-09-24T23:03:15Z, peeled commit
`b961978c3be9dd26b94158487c760858e19d1db2` (annotated tag object
`4462e0ef9495bae5bb34a8406b9e92761da59618`). This is a research reference, not a
chosen Splicore runtime dependency or qualification result.

## Actual package boundary

Official `github.com/enfein/mieru/v3/apis/server` already supplies an embedding
API, so copying `mita` daemon code is unnecessary. `Server` composes Load/Store,
Start/Stop/IsRunning and Accept. `ServerConfig` contains private appctlpb config
and optional stream/packet listener factories. `apis/common/listen.go` accepts
`net.Listener`/`net.PacketConn` factories; `apis/common/user_context.go:UserContext`
exposes UserName from the accepted connection.

`apis/server/server.go` creates `pkg/protocol` mux, sets server users, endpoints,
MTU and traffic pattern, starts it and parses a SOCKS5 request from each accepted
connection. `pkg/cipher`, replay/congestion/sockopts, protocol framing and metrics
remain Mieru implementation concerns; `pkg/appctl`/CLI persistence/control must
not become Splicore authority. API validates unsupported native egress settings;
Splicore should own routing of the accepted destination request.

Important observed limits: Store after Start returns ErrStoreServerConfigAfterStart;
repeat Start has undefined behavior; Stop makes server nonreusable and explicitly
does not terminate established connections. Recreate handles for update/restart,
and independently track/close/drain authenticated sessions. Do not claim hot user
updates or complete shutdown from Stop alone. API initialization also affects
package logging: embedding must check global logger/metrics side effects and race behavior.

| Concern | Adapter plan / qualification needed |
|---|---|
| TCP/UDP | listener factories connect to native listener ownership; distinguish underlay TCP/UDP from proxied UDP sessions |
| auth/users | username+password kind; map authenticated UserName to generation-scoped Binding ID, not Account display name |
| quota | official mita documents per-user usage/quotas, but embedded API does not imply identical enforcement; Splicore owns aggregate accounting and strict admission |
| destination/UDP | Accept returns stream plus SOCKS5 request requiring response/handshake; inspect official request/UDP-association wrappers and translate to sing network handlers without bypassing identity/policy |
| MTU/traffic pattern | preserve validated upstream parameters/wire behavior; expose typed client-relevant profile fields, benchmark both underlays |
| stats/logs | qualify per-user meter units/global registry isolation; prefer authenticated payload metering when units differ |
| lifecycle | fresh instance per configuration; bounded accept loops, cancellation, Close of active sessions, no goroutine/socket leaks |
| config | translate Splicore spec to private protobuf; no public protobuf/API dependency |

## Stage 1 — external reference and interoperability

Pin official client/mita version/digest outside the production core. Establish
TCP/UDP/IPv4/IPv6/domain/auth/traffic-pattern/MTU/reconnect/large-transfer fixtures,
per-user isolation and measurement units. External reference is a test oracle,
not permanent `exec mita` architecture. Qualify Mihomo only for a tested version.

## Stage 2 — embedded package prototype

Use official apis/server in an isolated experiment after licensing/dependency
review. Demonstrate listener factories, authenticated Accept → destination router,
UDP association translation, strict policy hooks, graceful/forced session cleanup,
global state isolation and failure/restart/race tests. Keep experiment behind a
flag; prototype does not imply stable support. If API lacks a needed hook,
prefer an upstream API proposal over invasive vendoring.

## Stage 3 — native Splicore inbound

Implement native protocol compiler and inbound lifecycle adapter, register through
own composition, construct ClientProfiles/exporters, integrate unified accounting
and transaction/recovery, pass interop and field beta, then qualify stable.
No separate mita service; existing wire behavior preserved. Failure of Stage 2
leaves Mieru unsupported pending adapter/API work, not a silent permanent sidecar.

Primary sources: [server API](https://github.com/enfein/mieru/blob/b961978c3be9dd26b94158487c760858e19d1db2/apis/server/interface.go),
[implementation](https://github.com/enfein/mieru/blob/b961978c3be9dd26b94158487c760858e19d1db2/apis/server/server.go),
[listener factories](https://github.com/enfein/mieru/blob/b961978c3be9dd26b94158487c760858e19d1db2/apis/common/listen.go),
[user context](https://github.com/enfein/mieru/blob/b961978c3be9dd26b94158487c760858e19d1db2/apis/common/user_context.go),
[operation reference](https://github.com/enfein/mieru/blob/v3.38.0/docs/operation.md),
[protocol specification](https://github.com/enfein/mieru/blob/v3.38.0/docs/protocol.md).
