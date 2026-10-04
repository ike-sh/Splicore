# Engine model

- Documentation status: Canonical
- Audience: Engine and runtime developers
- Last reviewed: 2026-10-04
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
Snell/Hysteria2/TUIC/VLESS and Experimental Mieru are registered; new protocols require their own gates.

## Xray compatibility

Internal adapter renders version-pinned child configuration, validates with that
exact child and supervises lifecycle, health and safe status. Restart is manual;
Xray attributed stats remain unsupported. Phase 7 bounds FinalMask/Sudoku to
the independently audited official v26.3.27 source and existing exact artifacts.
[ADR 0019](../adr/0019-xray-specialized-feature-boundary.md) defines the typed scope.

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

## Specialized feature availability

FinalMask/Sudoku descriptors scope TCP/plain/flow-none and exact client support;
EffectiveCapabilities intersects protocol/engine descriptors with owned snapshots.
node_status.features reports last exact artifact validation independently of build
support. Wrong version/hash/missing binary means unavailable. API/CLI/doctor expose
safe feature IDs/reasons. Settings choose a bounded single Sudoku mask; Compile
renders streamSettings.finalmask.tcp with the encrypted shared password. The same
supervisor and immutable config snapshot handle start, close and regeneration.
See [workflow](../development/PHASE_7_XRAY_EXTENSIONS.md).

## Phase 8 embedded adapter

The existing Native Engine also dispatches MieruCompiler. A private official Server
per generation replaces daemon config ownership. Splicore owns admission, actual raw
socket Close, session/destination teardown and worker joins. Per-inbound immutable
username→Binding maps and payload atomics isolate auth/stats; global upstream meters
are never billed. Standard direct TCP/UDP routing is the bounded current scope.
No extra EngineID, hot user update or permanent child. [ADR 0020](../adr/0020-mieru-owned-native-embedding.md).

## Native client outbound ownership

The existing `native` engine supports inbound and outbound roles. SnellOutboundFactory
owns a private embedded Box and inherited Snell adapter, with the owned static
platform monitor composition and local DNS transport for remote node domains. No
external client process, new EngineID or wire implementation. Outbound generations
retain adapters until their sessions release them; failed candidates close independently.
Phase 11 uses the same Xray Engine instance, Handle, process owner/reaper and
artifact registry for server and client roles. Client generations expose only a
private loopback SOCKS TCP/UDP projection; no public relay listener or client unit.
Native HY2/TUIC/VLESS each own an embedded Box. Official Mieru Client owns a private
profile/mux, while the adapter owns logical and underlay sockets and cancels/joins
its injected operations. The SDK exposes no join for client underlay RunEventLoop;
its raw sockets are closed and repeated lifecycle stack checks qualify exit. See [client runtime](CLIENT_RUNTIME.md).

## Underlay capability boundary

Network-capable Native and Xray constructors require the daemon's explicit factory
in their runtime context, including the no-TUN capability. Native box construction
wraps official outbound/DNS registries with isolated NetworkManager contexts; final
server targets use an explicit protected DIRECT outbound. VLESS plain/TLS/REALITY
use the same protected capability; Vision remains rejected under ADR 0017.
Mieru v3.38.0 hooks cover TCP/UDP underlays and final server targets.

Xray v26.3.27 remains the pinned official artifact. EngineUnderlayPlan binds actual
runtime generation and PID before publication; the sole reaper joins process/socket
cleanup before releasing ownership. Linux journaled UID/main-table bypass also
protects existing child sockets. Loopback system stubs reject before TUN activation
or required launch. Windows has no qualified child protection and fails closed.
No public Xray JSON or upstream modifications are introduced.
See [ADR 0031](../adr/0031-unified-underlay-protection.md).
