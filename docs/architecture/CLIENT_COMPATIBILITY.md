# ClientProfile and exporter architecture

- Documentation status: Canonical
- Audience: Client and exporter developers
- Last reviewed: 2026-10-01
- Owner: Client maintainers
- Responsibility: ClientProfile projection, exporter responsibility and client/version checks.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

```text
Committed authorized Binding + Inbound endpoint/security/settings
 → Protocol.BuildClientProfile
 → Canonical ClientProfile
 → Exporter(target client + version + supported features)
 → rendered config / URI / bundle
```

Phase 1 implements the canonical profile value and Exporter contract/registry.
Mihomo, sing-box, Surge, URI and JSON entries all return NotImplemented with no
rendered bytes. Profile carries no Engine or server runtime configuration.
Default JSON omits credential payload; secret access is explicit for future
authorized exporters. No exporter or actual client traffic is qualified.

Canonical profile contains profile ID, protocol ID/wire version/feature profile,
DisplayEndpoint, typed client authentication, TLS (SNI/ALPN/trust/public key/short ID),
transport and protocol options, display metadata and schema version. It contains
no Engine ID, sing-box option struct, Xray struct or Mita protobuf. Private server
keys, actual listener address and runtime generation internals are excluded.
Credential reveal is authorized and transient; profiles/configs are sensitive output.

Exporter registry: `mihomo`, `sing-box`, `surge`, `uri`, `json`; bundle assembler
composes export entries and target group rules separately. Reserve Loon/Stash/
Shadowrocket/Quantumult X without claiming compatibility. Protocol adapters own
profile construction; target exporters own format field mappings/escaping and
feature/version checks. Subscription service owns selection/auth/tokens, not YAML.

| Target | Contract |
|---|---|
| Mihomo | YAML node mapping with known client/version capability; do not silently drop userkey/security/UDP options |
| sing-box | client outbound JSON mapping, with explicit version range and fields; runtime server JSON is not reused |
| Surge | version/edition-specific node mapping and protocol support; licensed reference tests where available |
| URI | separate protocol-specific grammar/encoding parsers; no invented standard URI for unsupported features |
| JSON | Splicore versioned canonical profile representation, explicitly not universal client JSON |
| bundle | selected profiles + target group/rule policy assembled deterministically |

Unsupported combination returns structured `unsupported_client_feature`. Optional
partial bundles require explicit `allow_partial`, list exclusions/reasons, and do
not silently claim full support. A subscription's formats list is an allowlist,
not evidence that every selected protocol is exportable in all formats.

Snell v5 server/v4 client mapping follows upstream's documented non-QUIC behavior;
Snell v6/multi-user userkey requires independently tested client support. If a
client lacks multi-user authentication, use a separately planned compatible
single-user listener or exclude/reject it; never drop userkey and claim account
isolation. REALITY target differs from client SNI and public endpoint.

Deterministic golden output is a contract check; it does not prove real traffic.
Stable release qualification requires [interop matrix](../testing/INTEROP_MATRIX.md)
with actual pinned third-party clients, TCP/UDP/auth/reconnect/transfer and failure
cases. A protocol supporting only a Splicore client is a new native protocol with
its own specification, not a compatible replacement for an existing protocol.
