# Protocol SDK and capability registry

- Documentation status: Canonical
- Audience: Protocol and adapter developers
- Last reviewed: 2026-10-01
- Owner: Protocol maintainers
- Responsibility: Proposed protocol ports, compiled registry and effective capabilities.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Compile-time registry keyed by `(protocol_id, wire_version, feature_profile)`.
Reject duplicate keys and unsupported ABI at composition. Metadata includes
schema version, credential kinds, maturity, provenance and qualified client pairs.
Capabilities are effective intersections of protocol, Engine implementation,
build tags/platform and requested settings; absence means unsupported, not unknown=true.

## Foundation implementation

[ports](../../internal/splicore/ports/ports.go) owns the concrete source ABI 1
contracts; [registry](../../internal/splicore/registry/registry.go) constructs
immutable maps with sorted iteration, duplicate/ABI rejection and typed unknown
errors. Registration is explicit in Foundation composition, never init/.so.
Implementations must keep their own returned values safe for concurrent reads.

Metadata-only Snell 6, Hysteria2 2, TUIC 5 and VLESS 0 entries return
NotImplemented for validation/runtime/profile operations. They report
not_compiled/unqualified for the Splicore runtime adapter, independently of the
retained upstream command. All effective traffic capabilities are false or
unsupported; no upstream observation becomes a qualified Splicore claim.
Grouped typed capabilities express transport versus UDP payload, endpoint
families, identity/stats, policy, mutation, TLS/REALITY and qualified clients.
VLESS uses actual wire version 0 from sing-vmess v0.2.8 vless/protocol.go; the
former illustrative version 1 was not a wire specification.
Future credential creation, normalization and probe execution ports are deferred
until adapters need them; explicit credential access remains mandatory.

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
