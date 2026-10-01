# Engine model

- Documentation status: Canonical
- Audience: Engine and runtime developers
- Last reviewed: 2026-10-01
- Owner: Engine maintainers
- Responsibility: Private native/compatibility execution contracts and enforcement limits.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Registry keys `native`, `xray-compatibility`; future external keys require their
own reviewed implementation. Protocol and wire extensions describe client behavior;
Engine choice is private planning/diagnostic data. Accounts, Subscription and
Exporter do not branch on Engine names. Administrators may inspect resolved
placement in a plan but public protocol settings contain no raw engine config.

Phase 2 implements native Compile and owned Start/Health/Activate/Close/Stats
for Snell only. Each Inbound owns one minimal private Box and direct route;
Xray remains a placeholder. [ADR 0013](../adr/0013-snell-runtime-composition.md)
documents owned TCP admission/raw socket cleanup and static platform context.
Upstream constructors/auth/framing/crypto/version semantics remain unchanged.
The richer interfaces below remain proposed future contracts.

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

Stats adapter maps generation/child epoch/user label to stable Binding ID.
Counter polling alone cannot guarantee hard quota, expiry cutoff, shared speed or
session limits. Validate rejects strict policy combinations without proven
identity/enforcement hooks. Restart must reconcile counters and never decrement
persisted usage. Child crash affects its bindings and health; it does not authorize
fallback to a different wire feature.

Reserve ExternalEngine as a contract, not a general user-controlled command runner.
See [runtime lifecycle](RUNTIME_LIFECYCLE.md), [policy limits](POLICY_USAGE.md),
[Xray API source](https://xtls.github.io/config/api.html).
