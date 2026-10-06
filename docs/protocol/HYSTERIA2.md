# Managed Hysteria2 profile

- Documentation status: Canonical
- Audience: Protocol, runtime, client and integration developers
- Last reviewed: 2026-10-06 (Phase 17 Review Fix Round 1)
- Owner: Protocol maintainers
- Responsibility: The current bounded managed Hysteria2 contract and its limitations.
- Lifecycle: Update with managed HY2 options, credentials, capabilities or qualification changes.

## Scope and provenance

Hysteria2 is experimental. Splicore owns the application
[wire codec](../../protocol/hysteria2/wire/codec.go) and
[connection/stream/datagram backend](../../protocol/hysteria2/backend/server.go).
QUIC and HTTP/3 use the independent pinned `github.com/apernet/quic-go`
`v0.63.1-0.20261004180939-a10df75c260c`; TLS uses Go's TLS implementation.
Splicore does not implement cryptographic primitives or congestion control.
The [native inbound](../../internal/splicore/engine/native/hysteria2.go) owns
the admitted UDP socket, immutable credential map, routing and counters.
Each [outbound flow](../../protocol/hysteria2/backend/client.go) owns its socket,
QUIC transport and HTTP/3 transport; its Close joins receiving work and releases
those resources. The server tracks parent connections, child associations and
workers, cancels them on shutdown, and joins them before completing Close.

[ADR 0014](../adr/0014-hysteria2-runtime-composition.md) and the
[Phase 3 report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md) describe
historical composition and evidence. The
[Phase 17 report](../reports/PHASE17_SINGBOX_DECOUPLING_REPORT.md) records the
current independent implementation and development validation.
The native password map selects an authenticated user; no username is transmitted.
Obfuscation, masquerade, bandwidth, advanced QUIC and realm options remain outside
the managed schema and reject as unknown fields.

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
| obfs / masquerade / hopping / realm | Unsupported |
| URI import | Bounded hy2/hysteria2 import; SNI and verified TLS only |
| Congestion-control selector | Unavailable; backend default Reno mode |
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
HY2 bandwidth headers do not implement Account speed enforcement. This profile
uses the pinned QUIC backend's default sender in Reno mode; no BBR sender is selected.
The client advertises `Hysteria-CC-RX: 0`; the server responds `auto` and does not
use client bandwidth hints to select a different congestion controller.
Policy values never enter native options or exports. Payload may exceed
the stored quota/rate values; that is not enforcement qualification.

Managed inbound settings contain TLS only. Native outbound options must be an
empty object. Neither API nor CLI exposes a HY2 `cubic` or `bbr` selector.
HY2 URI CC parameters and external sing-box `congestion_control` / Mihomo
`congestion-controller` fields reject as unsupported, including `cubic` and
`bbr`. Import reports `unsupported_client_capability`; fields are not silently
discarded. This existing rejection contract is covered by regression tests.
The pinned backend calls `congestion.NewCubicSender` with `reno=true` both at
construction and path reset. Despite the type name, its congestion avoidance
and loss response therefore use the Reno branches; this is not evidence of
active CUBIC. Splicore does not replace this sender. TUIC's separate fixed
`cubic` option does not configure HY2. No accepted HY2
configuration is changed by this documentation correction.

HTTP authentication and TCP request/response padding uses `crypto/rand.Reader`.
Length ranges remain [256, 2048), [64, 512), and [128, 1024), respectively;
content remains the 62-character alphanumeric alphabet. Length sampling and
content rejection sampling avoid modulo bias. Random-source errors propagate
or reject authentication; there is no noncryptographic fallback.

## Transaction and recovery

Managed protocol lifecycles share pending → build → start → health → SQL commit
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
recovery. Credentials are immutable snapshots for each constructed generation.

Shutdown closes admission, cancels authenticated QUIC sessions, closes the
listener, transport and owned socket, and waits for the parent and child workers.
There is no managed 100 ms grace interval or inherited Box routing owner.
Clients must reconnect; shutdown is not a lossless-delivery guarantee.
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

Phase 17 mixed-stress resource evidence samples goroutines, FDs, eventfds,
listeners, routed sessions, client generations, leases and RSS at workload
boundaries. Short HY2 flows can finish between samples; an active-TCP value of
zero does not imply no TCP traffic. SocketFDs, host-generation and interface
helper peak fields are not measured maxima. End-state cleanup is measured
directly. These limits affect resource/performance observability, not framing,
padding, packet correctness or the separately checked payload tests. They are
not RTT or congestion-control measurements, and do not certify a platform.

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
| URI export | Any | Deferred; URI import is a separate bounded contract |

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
