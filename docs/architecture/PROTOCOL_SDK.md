# Protocol SDK and capability registry

- Documentation status: Canonical
- Audience: Protocol and adapter developers
- Last reviewed: 2026-10-02
- Owner: Protocol maintainers
- Responsibility: Proposed protocol ports, compiled registry and effective capabilities.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Compile-time registry keyed by `(protocol_id, wire_version, feature_profile)`.
Reject duplicate keys and unsupported ABI at composition. Metadata includes
schema version, credential kinds, maturity, provenance and qualified client pairs.
Capabilities are effective intersections of protocol, Engine implementation,
build tags/platform and requested settings; absence means unsupported, not unknown=true.

## Implemented contracts

[Ports](../../internal/splicore/ports/ports.go) own ABI 1 interfaces;
[runtime ports](../../internal/splicore/ports/runtime.go) add transient explicit
credentials, Start/Health/Activate/Close/Stats and durable journal phases.
[Phase 2 composition](../../internal/splicore/registry/phase2.go) explicitly
registers Snell v5/v6. [Phase 3 composition](../../internal/splicore/registry/phase3.go)
adds Hysteria2, one shared native compiler map and protocol-dispatched exporters.
[Phase 4 composition](../../internal/splicore/registry/phase4.go) directly assembles
TUIC and previous modules. [Phase5 composition](../../internal/splicore/registry/phase5.go)
adds VLESS plain/TLS/REALITY; Phase6 implements its xray slot. Prior compositions stay fixtures.

The Phase 3 freeze records bounded command/composition/display-allowlist growth as
[non-blocking technical debt](../ARCHITECTURE.md#phase-3-extensibility-disposition).
Phase 4 resolves these with registered creation, direct composition and shared support;
the Protocol/Engine/runtime and ClientProfile contracts remain reusable.

[Snell module](../../internal/splicore/protocol/snell/snell.go) validates strict
version settings, portable PSKs, one Binding and account-owned Credential, without
HTTP, SQLite or NoBrand dependencies. It generates random PSKs and builds neutral
RuntimeIntent/ClientProfile. Native userkey support exists but managed multi-user
is deferred. See [Snell support](../protocol/SNELL.md) for effective capabilities.

[Hysteria2 module](../../internal/splicore/protocol/hysteria2/hysteria2.go) owns
bounded password/TLS validation, native multi-user identity and independent
ClientProfile SNI/endpoint projection. It has no SQL/HTTP/NoBrand dependency.

| Managed profile | TCP | UDP payload / transport | MultiUserNative | NativeStats / PerUserStats | HotUserUpdate | Users mutation | Policy enforcement |
|---|---|---|---|---|---|---|---|
| Snell v5/v6 | yes | yes / no | false | yes / false | false | unavailable | none |
| Hysteria2 wire 2 | yes | yes / yes | true, 16 configured | yes / true | false | Inbound restart | none |
| TUIC v5 base | yes | yes / yes | true, 16 configured | yes / true | false | Inbound restart | none |

All three are Experimental and support IPv4/IPv6/domain display endpoints. HY2 requires
static TLS and one explicit CA, reused by TUIC; obfs/masquerade/URI remain deferred. Stats mean
authenticated payload and routed sessions, not durable Account billing.

Conceptual typed ports below are **design notation**, not production declarations.
The concrete value types will be defined in domain/ports before implementation.

```go
type Protocol interface {
    Metadata() ProtocolMetadata
    Capabilities(CapabilityContext) CapabilitySet
    ValidateInbound(InboundSpec) []Violation
    NormalizeInbound(InboundSpec) (InboundSpec, error)
    CreateCredential(context.Context, CredentialRequest, SecretWriter) (CredentialRef, error)
    ValidateCredential(CredentialDescriptor) []Violation
    BuildRuntime(AuthorizedInboundProjection) (RuntimeIntent, error)
    BuildClientProfile(AuthorizedBindingProjection, SecretReader) (ClientProfile, error)
    HealthPlan(RuntimeIntent) []ProbeSpec
}
```

BuildRuntime produces neutral runtime intent; the Engine compiler owns concrete
upstream options/protobuf/Xray config. HealthPlan declares protocol-specific probes;
the runtime handle/engine executes them. Avoid a Protocol interface that owns
processes or imports HTTP/SQLite. Secret access is explicit and scoped, never
Account fields; client export uses permitted secret material while API reads stay redacted.

Native compiler uses existing `adapter/inbound.Register[option.XOptions]` constructors
and an own registry passed via `box.Context`. Protocol/domain registry is richer
than upstream's factory registry; neither replaces the other. Compile one generation
into options and Binding-ID names plus an immutable auth identity mapping.

## Capability shape

```json
{
  "protocol": "vless", "wire_version": "0", "feature_profile": "reality",
  "availability": "compiled", "qualification": "unqualified",
  "transport": {"tcp": true, "udp_payload": true, "ipv4": true, "ipv6": true},
  "identity": {"multi_user_native": true, "attributed_payload": "requires_adapter"},
  "policy": {"quota": "adapter_pending", "rate": "adapter_pending"},
  "mutation": {"users": "restart", "listener": "restart"},
  "clients": [], "evidence": []
}
```

Illustrative example only. Distinguish UDP payload from UDP transport; domain
endpoint reachability from local bind; native quota/speed/stats from adapter
enforcement; TLS/REALITY from independent transport options. Capability includes
native_stats units, max credentials/listeners, hot_user_update semantics,
session-drain/revocation behavior, platform/build requirements and exporter feature sets.
No hot updates claimed merely because an internal library exposes UpdateUsers.

Baseline observations: all four target protocols have user support (Snell v5/v6
conditional); Hysteria2/TUIC need with_quic, REALITY needs with_utls. Shared
Splicore quota/rate functionality is not implemented. Snell single-key mode cannot
attribute Accounts sharing that key; per-binding listeners or client-qualified
multi-user `userkey` are required.

## Minimal new protocol workflow

1. Write wire specification/provenance and credential/settings schemas.
2. Implement Protocol validation/normalization, credentials, runtime intent and profiles.
3. Implement native Engine compiler/inbound adapter; external compiler only if justified.
4. Register in own composition and declare effective capabilities, limitations and ABI.
5. Add fixtures, contract/fuzz/lifecycle tests and third-party or independent-reference interop.
6. Add format-specific exporter mappings only for features a target client supports.

Account, Usage, Subscription tables/API stay unchanged. Protocol extension payloads
are schema-versioned and bounded, not unvalidated arbitrary JSON. Go plugin `.so`
is excluded: OS support, exact toolchain/package-build coupling, deployment,
unload/security and race tooling complicate a static server. Protocol ABI is an
internal source contract version, not a promise of binary plugin compatibility.
Source: [Go plugin restrictions](https://pkg.go.dev/plugin).

## Registered creation realization

[Creation ports](../../internal/splicore/ports/creation.go) expose optional codec/draft
validation and typed generation. Registry resolves compiled codecs; Application owns
resource IDs/policies/persistence/lifecycle. Generic API/CLI need no protocol switch.
Legacy typed methods remain compatible.

[TUIC module](../../internal/splicore/protocol/tuic/tuic.go) owns UUID/password, bounded
v5 settings and neutral ClientProfile. [Support](../protocol/TUIC.md) records limits.

## VLESS and engine selection realization

[VLESS module](../../internal/splicore/protocol/vless/vless.go) owns typed settings,
UUID, flow enum, public REALITY material and neutral projections. [Creation selection](../../internal/splicore/registry/selection.go)
validates the separate engine field and rejects unavailable/unbound implementations
before resources or runtime side effects. Capabilities list engine implementations
per protocol independently of ProtocolKey. Client compatibility is bounded to the flow-none
surface. Vision returns typed rejection and is never generated by projections/exporters.

Optional ServerMaterializer generates/derives inbound secret material before pending.
RuntimeIntent carries typed ServerCredentials; recovery/reconcile uses an explicit
server-secret repository port. ClientProfile and its authorization port gain no server
secrets. Module validation is engine-neutral; native and Xray compilers enforce
placement independently. [ADR 0016](../adr/0016-vless-engine-server-secrets.md).

## Effective placement capabilities

Protocol capabilities describe the bounded canonical surface. Engine capabilities
limit implementation support. The shared EffectiveCapabilities intersection drives
engine_implementations features; node_status is a separate artifact validation result.
Native statistics must not imply Xray statistics. Engine selection changes neither
credential kinds nor ClientProfile; client exporters have no engine branch.
Vision remains rejected at creation/runtime/render/export boundaries for both engines.

## Engine feature capability matrix

| Pair | REALITY | FinalMask/Sudoku | Vision | Masked UDP |
|---|---|---|---|---|
| vless/native | Yes, with_utls | Unsupported | Unsupported | Unsupported |
| vless/xray standard | Yes, with_utls and exact artifact | Explicit selection only | Unsupported | N/A |
| vless/xray masked | Unsupported combination | Experimental plain TCP Sudoku, prefer_ascii, padding0–3 | Unsupported | Not qualified |

EngineFeatureValidator is an optional codec port after generic placement selection,
before availability/pending. Feature descriptors include transport/security/flow,
UDP qualification and exact supported clients. Unknown support fails closed.
Canonical engine_options uses concrete transportmask structs; no arbitrary raw
runtime JSON. Password is an encrypted inbound-owned shared credential, selected
through ClientSharedSecretRepository only after Account/Binding authorization.
ClientProfile transport requirements carry the client-needed secret without an
Engine ID. Schema/domain Account/Binding remain unchanged. [ADR 0019](../adr/0019-xray-specialized-feature-boundary.md).
