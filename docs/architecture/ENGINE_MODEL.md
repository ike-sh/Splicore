# Engine model

- Documentation status: Canonical
- Audience: Engine and runtime developers
- Last reviewed: 2026-10-02
- Owner: Engine maintainers
- Responsibility: Private native/compatibility execution contracts and enforcement limits.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Current registry keys `native`, `xray`; xray denotes the Experimental owned external child.
Future external keys require their
own reviewed implementation. Protocol and wire extensions describe client behavior;
Engine choice is an explicit bounded creation selector and resolved API/domain field. Accounts, Subscription and
Exporter do not branch on Engine names. Administrators may inspect resolved
placement in a plan but public protocol settings contain no raw engine config.

Phase 5 shares one native Compile and Start/Health/Activate/Close/Stats contract
for Snell, Hysteria2, TUIC and VLESS, dispatched by protocol key. Each Inbound owns one minimal private Box and direct route;
Phase6 fills Xray with an external child adapter. [ADR 0013](../adr/0013-snell-runtime-composition.md)
documents owned TCP admission/raw socket cleanup and static platform context.
Upstream constructors/auth/framing/crypto/version semantics remain unchanged.
The richer interfaces below remain proposed future contracts.

[ADR 0014](../adr/0014-hysteria2-runtime-composition.md) records HY2 composition
of the exact pinned service/TLS constructors with an owned UDP socket. Reads drop
before commit. User updates reconstruct the affected Inbound; no unsafe live
UpdateUsers call occurs. Session and payload meters use immutable Binding IDs.
The bounded 100 ms close grace permits QUIC notifications before socket release;
replacement interrupts all users on that Inbound and resets its counters.

```go
type Engine interface {
    Metadata() EngineMetadata
    Supports(RuntimeIntent, HostCapabilities) []Violation
    Compile(RuntimeIntent, GenerationContext, SecretReader) (PreparedRuntime, error)
    Prepare(context.Context, PreparedRuntime) (RuntimeHandle, error)
}
type RuntimeHandle interface {
    Apply(context.Context) error
    Health(context.Context, []ProbeSpec) HealthResult
    ObserveUsage(context.Context, UsageSink) error
    Drain(context.Context, Deadline) error
    Close(context.Context) error
}
```

These are proposed ports. Coordinator owns commit/rollback and revision fences;
handles own implementation side effects and report reconstructible identity.
Capabilities define update/restart/restore support. No promise of atomic live
modification from this interface.

## Native

One process contains sing-box-derived network managers and registered native
inbounds. Native engine compiles domain projection to private option.Options,
uses registries and wraps authenticated routing for policy and accounting. It
owns generation handles; own startup coordinator supplements Box lifecycle.
Snell/Hysteria2/TUIC/VLESS first; Mieru/new protocols only after their gates.

## Xray compatibility

Internal adapter renders version-pinned child configuration, validates with that
exact child, supervises lifecycle, health, logs, stats and bounded restart/backoff,
and provides engine version/digest evidence. FinalMask/Sudoku are future feature
profiles requiring an identified fork/spec and qualified client, not inferred
capabilities of stock Xray. No code or executable is added in Phase 0.

Ports: public listeners assigned explicitly; private management endpoints loopback
or protected socket; child-only rendered files 0600 under private state directory.
No public Xray configuration or child management API. Credentials and tokens never
appear in argv/environment/logs. Child process uses allowlisted environment and
absolute trusted executable; no shell. Linux process group and parent-death/cgroup
handling prevent orphans; Windows job objects are the platform equivalent.

A future stats adapter maps generation/child epoch/user label to stable Binding ID.
Counter polling alone cannot guarantee hard quota, expiry cutoff, shared speed or
session limits. Validate rejects strict policy combinations without proven
identity/enforcement hooks. Restart must reconcile counters and never decrement
persisted usage. Child crash affects its bindings and health; it does not authorize
fallback to a different wire feature.

Reserve ExternalEngine as a contract, not a general user-controlled command runner.
See [runtime lifecycle](RUNTIME_LIFECYCLE.md), [policy limits](POLICY_USAGE.md),
[Xray API source](https://xtls.github.io/config/api.html).

## Shared QUIC realization

HY2/TUIC use one shared owned handle for Box/router, static TLS, UDP admission/health/
cancellation/close grace, immutable Binding mapping and meters. Factories own exact
upstream auth/options and construct users before Start. No unsafe live UpdateUsers,
wire copy or upstream modifications. [ADR 0015](../adr/0015-tuic-shared-control-plane.md).

## VLESS placement realization

EngineMetadata lists protocol IDs. Capabilities expose native/xray entries for the
same vless identity. Default native selection is shared registry plumbing; xray is
compiled and runtime implemented in Phase6; its last node artifact validation is
reported separately. Historical Phase5 retains the unimplemented slot.
The native engine rejects another placement. Account/Binding/Subscription/profile
and exporters gain no engine cases. The operator provides the pinned external
binary; the adapter renders only private generation artifacts.

Native VLESS uses pinned sing-vmess service, existing TLS/REALITY constructors,
owned TCP admission/raw sockets and Binding meters. A bounded target reachability
probe does not establish TLS target health. Vision is deferred/unsupported with explicit
protocol and native compiler hard gates; no upstream patch is carried. [Support](../protocol/VLESS.md),
[decision](../adr/0016-vless-engine-server-secrets.md).

## Implemented child lifecycle

[ADR 0018](../adr/0018-xray-owned-child-engine.md) bounds the proposed external
contracts above. Actual Engine remains Metadata/Capabilities/Supports/Compile,
with optional EngineAvailability and RuntimeObserver ports. Handle implements
Start/Health/Activate/Close/Stats plus adapter Stop/Wait. Build/node availability,
reference/installed version and safe PID/generation/exit status are explicit.
Public listener admission opens only after SQLite commit; expected private listener
ownership and process exit determine health. Child logs are discarded with bounded
metadata. Manual recovery only; no automatic restart/backoff policy is implemented.
Xray stats adapter is DEFERRED; zero counters are unsupported placeholders.
User reconcile restarts the affected child. HotUserUpdate=false and strict policies
fail closed. Exact reference and platform qualification: [workflow](../development/PHASE_6_XRAY.md).

The external VLESS selection preserves domain rejection of strict policy and
returns UnsupportedPolicyForEngine (`unsupported_policy_for_engine`, HTTP 422)
before binary availability or pending state. Native retains its existing invalid
request contract; metadata_only is explicit and remains unenforced.
