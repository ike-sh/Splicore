# ClientProfile and exporter architecture

- Documentation status: Canonical
- Audience: Client and exporter developers
- Last reviewed: 2026-10-02
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

Phase 2 implements Snell ClientProfile and Mihomo/sing-box/Surge exporters.
Default profile JSON/formatting redacts PSK. Export is explicitly secret-returning.
No server runtime struct/Engine ID enters the profile; no Snell URI is invented.

Phase 3 adds password auth, explicit CA/SNI/h3 TLS and QUIC/UDP projection for
[Hysteria2](../protocol/HYSTERIA2.md). Default formatting redacts password too.
Mihomo 1.19.30 receives a `mihomo-config-fragment` containing proxies with a
non-leaf CA SHA-256 fingerprint, SNI and skip-cert-verify=false. The runtime serves
the configured CA; this pinned verifier checks chain/validity/SNI. sing-box 1.14.1
receives a `sing-box-outbound` with explicit CA, SNI and insecure=false. Both pass
real TCP/UDP with Alice/Bob over all three endpoint types. Surge is unsupported;
URI is deferred. Export envelopes include `content_shape`; multi-user export must
select `binding_id`. Policy metadata and server private keys never enter profiles.

| Server | Pinned client | Mapping / qualification |
|---|---|---|
| v5 no obfs | Mihomo 1.19.30 | explicit v4 client, TCP/UDP PASS |
| v5 no obfs | sing-box 1.14.1 | explicit v4 client, TCP/UDP PASS |
| v6 default | sing-box 1.14.1 | exact v6, TCP/UDP PASS |
| v5/v6 | Surge Mac 6.7.0 / iOS 5.20.0 | v4/v6 contract only; live NOT RUN |
| v6 | Mihomo 1.19.30 | UnsupportedExport |

Envelope fields report server_version/client_wire_version/compatibility; v5→v4
avoids unsupported Surge QUIC Proxy Mode. Unknown clients/features return
unsupported_export (HTTP 422). Exported nodes/outbounds use validated raw IPv6
host fields with separate ports; PSKs reject delimiter injection. Surge's host/port
contract is inferred from its official grammar, without parser/runtime validation.
See [Snell support](../protocol/SNELL.md) and [interop](../testing/INTEROP_MATRIX.md).

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

## TUIC v5 realization

[TUIC](../protocol/TUIC.md) projects typed UUID/password, independent endpoint/SNI/CA,
h3/QUIC/UDP and v5/cubic/native/no-0RTT options. Pinned Mihomo1.19.30 and sing-box1.14.1
keep verification enabled and omit v4 token. Surge rejects; URI deferred. Engine
structs/server keys never enter ClientProfile. [Actual results](../reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md).

## VLESS / REALITY candidate

VLESS ClientProfile projects display endpoint, typed secret UUID, canonical flow,
TCP/XUDP, SNI and either explicit CA or REALITY public key/selected short ID. Server
private key, target, actual listener and engine are absent. Mihomo 1.19.30 and
sing-box 1.14.1 use their pinned VLESS fields; REALITY clients use chrome uTLS.
Default-race flow-none traffic covers all REALITY endpoint types/users. Vision is
DEFERRED / UNSUPPORTED: profiles, exporter descriptions/content and URI imports reject it.
Initial Vision functional passes and safety failures remain historical evidence. [Actual matrix](../testing/INTEROP_MATRIX.md).

URI supports a bounded plain/REALITY dialect with strict UUID, brackets, query and
fragment escaping; client URI import remains unqualified. Explicit-CA TLS URI and
Surge reject with UnsupportedExport. A blocking test traverses all client/API exports
and requires the server private key to be absent. [VLESS](../protocol/VLESS.md).

## VLESS engine equivalence

Native/Xray placement produces the same canonical ClientProfile from equivalent
Binding/UUID/Endpoint/security intent. The same Mihomo, sing-box and URI exporter
renders both. Engine identity never enters client config. TLS explicit-CA URI and
Surge remain unsupported; Vision remains rejected. Reference versions and actual
traffic evidence are recorded in the [matrix](../testing/INTEROP_MATRIX.md).

## FinalMask / Sudoku client requirements

ClientProfile keeps endpoint/UUID/TCP core and adds typed transport requirements.
Its password is a client-needed shared secret, excluded from JSON/formatting and
returned only by authorized exporter output. It never contains REALITY private keys.
The existing VLESS exporter maps requirements to the target format, with no Engine ID branch.

| Masked client / format | Version | Status |
|---|---|---|
| Xray JSON outbound | 26.3.27 | Supported for plain TCP, Sudoku prefer_ascii/padding0–3 |
| Mihomo | 1.19.30 | Unsupported |
| sing-box | 1.14.1 | Unsupported |
| Surge | Any | Unsupported |
| VLESS URI | Any | Unsupported |
| Unknown Xray version | Any other | Unsupported |

format=xray returns content_shape=xray-outbound. No standard VLESS fallback drops
the mask. FinalMask describes the framework with Sudoku only; other masks/chains
and TLS/REALITY combinations reject. Masked UDP/XUDP is NOT QUALIFIED. Standard
VLESS exporters remain shared across native/xray. [Workflow](../development/PHASE_7_XRAY_EXTENSIONS.md).

URI fm is CONTRACT ONLY for the audited NoBrand source/reference dialect. It is
not implemented by Splicore's masked URI exporter/import and has no managed runtime
interop qualification. That exporter continues to reject masked profiles explicitly.

## Phase 8 Mieru clients

Mieru 3.38.0 profile core (`mieru-client-config`) and Mihomo 1.19.30 proxies
fragment (`mihomo-config-fragment`, MTU 1500 only) qualify TCP/UDP, both underlays,
Alice/Bob and IPv4/IPv6/domain endpoints. Export selects DisplayEndpoint and explicit
binding_id; default JSON/formatting redact credentials. No server protobuf leaks.
sing-box 1.14.1 has no Mieru outbound; Surge/URI/Xray/unknown versions reject.
[Contract](../protocol/MIERU.md), [matrix](../testing/INTEROP_MATRIX.md).
