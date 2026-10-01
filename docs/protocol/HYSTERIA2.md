# Managed Hysteria2 profile

- Documentation status: Canonical
- Audience: Protocol, runtime, client and integration developers
- Last reviewed: 2026-10-01
- Owner: Protocol maintainers
- Responsibility: The bounded Phase 3 Hysteria2 contract and its limitations.
- Lifecycle: Update with managed HY2 options, credentials, capabilities or qualification changes.

## Scope and provenance

Hysteria2 is experimental. The managed profile uses sing-box v1.14.1
(`1ac1a339cb1223e9c70eae14c44411c75033c02d`) and its pinned sing-quic v0.7.0
Hysteria2 service. There is no Splicore wire, QUIC, congestion-control or TLS
implementation. [ADR 0014](../adr/0014-hysteria2-runtime-composition.md) describes
the owned socket composition and restart semantics. The
[Phase 3 report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md) owns actual
test outcomes, tool versions and exact evidence, including Snell regression.

Baseline source audit: [stock inbound](../../protocol/hysteria2/inbound.go),
[options](../../option/hysteria2.go), [stock outbound](../../protocol/hysteria2/outbound.go),
[baseline tests](../../test/hysteria2_test.go),
[service](https://github.com/SagerNet/sing-quic/blob/v0.7.0/hysteria2/service.go)
and [UDP implementation](https://github.com/SagerNet/sing-quic/blob/v0.7.0/hysteria2/packet.go).
The native password map selects an authenticated user; no username is transmitted.
Stock options also contain obfuscation, masquerade, bandwidth, advanced QUIC and
realm options. They remain outside the managed schema and reject as unknown fields.

## Capabilities

| Capability | Managed profile |
|---|---|
| TCP payload | Supported over QUIC streams |
| UDP transport / payload | Both supported; separately tested |
| Display endpoint | IPv4, IPv6 or DNS, with independent port |
| Native multi-user | 1–16 configured Bindings per Inbound; distinct passwords |
| Password generation | 32 random bytes encoded as 43 base64url characters |
| TLS | Required, static leaf/key files, one explicit CA, TLS 1.3 / h3 |
| Authenticated stats | Inbound and immutable Binding-ID payload bytes / routed sessions |
| HotUserUpdate | false; stop/reconstruct the affected Inbound |
| HotReload / listener mutation | Unavailable |
| Quota / speed / max-session enforcement | Unsupported |
| obfs / masquerade / hopping / realm / URI | Deferred |
| Qualification | Experimental; never Stable |

The shared Native Engine resolves protocol compilers from a map. Format exporters
resolve protocol keys from a map. The application coordinates lifecycle and
repository ports; protocol modules have no SQL, HTTP or NoBrand dependency.

## Canonical creation document

Use `schema: 1`, `name`, IP `listener`, independent `display_endpoint`,
`settings.tls` and a `users` array. Each user has `account_name`, optional
`password`, optional `enabled` (default true), and optional `traffic_policy`.
Omitting password generates it during apply; explicit null/empty/invalid values
reject. Supplied passwords are 12–255 UTF-8 bytes without whitespace/control
characters. Duplicate names or passwords within one Inbound reject.

TLS fields are `server_name` (DNS identity), `certificate_file`,
`private_key_file` (absolute local references), and `ca_certificate` (one public
CA PEM). Files must be regular, bounded to 64 KiB, and resolve without symlinks.
Linux private keys and their parent directory must have private permissions and
belong to the runtime owner. Runtime construction verifies the keypair, validity,
server usage, chain and SNI against the configured CA. It uses an inline snapshot,
with no inherited file watcher; changed TLS material requires an explicit future
operation or restart. A missing/bad file blocks recovery without a fallback.

The four independent meanings are:

| Field | Meaning |
|---|---|
| Listener | Actual local UDP bind; never derived from public endpoint |
| DisplayEndpoint | Client dial address/port; no listener or egress mutation |
| TLS server_name | Client verification/SNI; no implicit address substitution |
| Certificate SAN | Identity proven by the configured certificate |

Traffic policies require explicit `policy_mode: "metadata_only"`. Per-user
quota/upload/download values persist in domain TrafficPolicy records referenced
by Binding overrides. Views and plans say `policy_enforced: false`. Native
HY2 bandwidth negotiation is a connection-level congestion/bandwidth hint,
not Account speed enforcement. This profile uses BBR and ignores client bandwidth
hints; policy values never enter native options or exports. Payload may exceed
the stored quota/rate values; that is not enforcement qualification.

## Transaction and recovery

Both implemented protocols share pending → build → start → health → SQL commit
→ admission. Candidate UDP reads drop packets until durable commit, including
TLS/auth packets. UDP conflicts are typed `port_conflict`; failed construction,
start, health or commit closes the candidate and fails its journal record.
Only known create/replace journal operations can be recovered automatically.

Binding enable/disable checks global and Binding revisions, builds an immutable
candidate user map, journals replacement, closes the old Inbound, starts the
candidate with admission closed, commits the enabled flag, then admits traffic.
It closes every existing session on that Inbound, including other users. It
does not restart the daemon or other Inbounds. Failure reconstructs the old
committed projection; failure to reconstruct leaves a degraded runtime requiring
recovery. Never call the unsynchronized library UpdateUsers during traffic.

Shutdown cancels authenticated QUIC sessions while retaining a writable owned
socket for a bounded 100 ms grace interval, then closes the service, socket and
Box routing. This allows close notifications before socket release; it is not a
promise of lossless delivery on arbitrary networks. Clients must reconnect.
SQLite alone supplies committed resources/credentials after restart; TLS file
references must still resolve. Imported documents and generated client configs
are never recovery authorities.

## Stats and secret boundary

Bytes count authenticated routed payload, excluding TLS/QUIC/auth framing.
Sessions count routed TCP streams and UDP associations, not QUIC handshakes.
Views expose aggregate and per-Binding values. Each Account in this slice has
one Binding, so its usage is that Binding's usage; shared cross-Inbound Account
aggregation and durable billing remain deferred. Counters reset on Inbound
replacement/recovery and are not durable quota meters.

Passwords use the generic encrypted Credential kind `password` with an Account
owner and typed payload. There are no HY2 fields on Account. Ordinary GET,
doctor, errors and journals never reveal passwords or TLS keys. Inbound settings
are redacted. Authorized client export is explicitly secret returning and requires
`binding_id` when multiple Bindings exist; disabled/unavailable users reject.
Private-key contents stay out of SQLite and every ClientProfile/export.

## Export contracts

| Target | Version | Content shape / trust |
|---|---|---|
| sing-box | 1.14.1 | `sing-box-outbound`; explicit CA, SNI, h3, insecure=false |
| Mihomo | 1.19.30 | `mihomo-config-fragment` containing proxies; non-leaf CA pin, SNI, skip-cert-verify=false |
| Surge | Any | UnsupportedExport |
| URI | Any | Deferred; no invented URI |

Mihomo's [CA fingerprint verifier](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/component/ca/fingerprint.go)
verifies leaf chain, validity and SNI when the pin matches a non-leaf certificate.
The runtime sends the configured CA with the leaf/chain; the exporter pins that
CA, never the leaf. This avoids a pinned-client startup issue: proxy construction
captures a CA pool before [ApplyConfig resets it](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/hub/executor/executor.go).
Merely emitting top-level `tls.custom-certifactes` parses but does not qualify
trusted-CA traffic for a static proxy in that version. Leaf pinning is unsuitable
because that verifier's leaf-pin path does not check SNI. Unknown versions and
unsupported profile features reject; exported config never quietly disables trust.

See the [interop matrix](../testing/INTEROP_MATRIX.md),
[workflow](../development/PHASE_3_HYSTERIA2.md) and
[synthetic migration fixture](../../tests/fixtures/nobrand/hysteria2.json).
