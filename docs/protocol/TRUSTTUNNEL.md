# Native TrustTunnel

- Documentation status: Canonical
- Audience: Core, protocol and integration developers
- Last reviewed: 2026-10-18
- Owner: Protocol maintainers
- Responsibility: Native TrustTunnel configuration, lifecycle and qualification limits.
- Lifecycle: Update when configuration or demonstrated interoperability changes.

## Scope

The experimental `trusttunnel/1/base` protocol provides native client/outbound
and server/inbound TCP and UDP tunneling over authenticated HTTP/2 or HTTP/3.
`auto` races HTTP/3 against a delayed HTTP/2 attempt. Build with `with_quic` for
HTTP/3 and auto; HTTP/2 also works without that tag. Protocol modes do not expose
a generic QUIC or generic HTTP/3 transport to other protocols.

Production uses Go TLS, the existing `golang.org/x/net/http2` and pinned
`github.com/quic-go/quic-go` dependency. No official TrustTunnel executable or
other proxy Core is a production dependency. The public protocol, configuration
and deep-link documents are pinned at
`48f424c0874eb6f6374ee84492c5cd55aa04dca9`; the official reference pair is
endpoint v1.1.0 and client v1.1.11. Official production implementation source was
not used. Hysteria and NaiveProxy remain separate protocol implementations.

## Inbound creation

The generic API creation, CLI `inbound validate/plan/apply --protocol
trusttunnel`, account, Binding, credential, profile and runtime interfaces are
used unchanged. For example, a canonical creation document is:

```json
{
  "schema": 1,
  "name": "TrustTunnel service",
  "listener": {"host": "0.0.0.0", "port": 443},
  "display_endpoint": {"host": "vpn.example.com", "port": 443},
  "settings": {
    "mode": "auto",
    "tls": {
      "server_name": "vpn.example.com",
      "certificate_file": "/etc/splicore/server.pem",
      "private_key_file": "/etc/splicore/private/server.key",
      "ca_certificate": "<CA certificate PEM>"
    },
    "connect_timeout": "30s",
    "idle_timeout": "10m",
    "udp_idle_timeout": "120s",
    "max_streams": 512,
    "max_sessions": 64,
    "max_flows": 256,
    "icmp": false
  },
  "users": [{"account_name": "Alice", "username": "alice"}]
}
```

Omitting a user's password generates one through the existing credential
generator. Passwords and usernames are distinct from Account and Binding IDs.
Each accepted session is pinned to one authenticated Binding. Changing users
requires reconstructing the inbound; strict quota, speed and account session
policy enforcement are unsupported and reject through the existing policy
capability checks. Metadata policy remains explicitly unenforced.

TLS files follow existing snapshot validation and private key permissions.
`http2` owns a TCP listener, `http3` a UDP listener, and `auto` both on the
configured endpoint. TLS and authentication must succeed before any target dial.
Server session/handler/UDP limits are finite; `max_streams` is also the global
accepted handler limit. Session limit range is 1–1024; stream range 4–512;
flow range 1–4096. Missing/duplicate/invalid Basic credentials return 407.

## Outbound configuration

Use a native RemoteNode with protocol `trusttunnel`, wire version `1`, feature
profile `base`, security kind `tls`, and a separately owned username/password
Credential. `transport.kind` is `tcp` for http2/auto and `udp` for http3.
Other protocol transport extensions and custom header maps are rejected.

The node options are:

```json
{
  "mode": "auto",
  "addresses": ["192.0.2.10:443", "[2001:db8::10]:443", "vpn.example.com:443"],
  "custom_sni": "cover.example.com",
  "insecure_skip_verification": false,
  "disable_ipv6": false,
  "connect_timeout": "30s",
  "health_check_timeout": "7s",
  "fallback_delay": "1s",
  "idle_timeout": "10m",
  "udp_idle_timeout": "120s",
  "max_streams": 256,
  "max_flows": 256
}
```

Addresses are canonicalized, deduplicated and limited to 16. Omission uses the
node endpoint. Each mode tries addresses within one bounded setup budget; an
address cannot consume the complete remaining budget when more addresses remain.
Names use the existing protected resolver policy. Resolution is per session
attempt, not per TCP CONNECT. HTTP/3 uses the existing numeric packet socket
factory and its IPv4 preference for dual stack names.

The node TLS server name is the certificate verification identity. A custom SNI
changes ClientHello only; certificate chain and hostname validation still use
the original TLS identity. System CA and explicit CA/certificate trust are
supported. Invalid trust material fails. `insecure_skip_verification` is an
explicitly dangerous, node scoped override; its default is false. Failure never
enables it or any DIRECT route. Authenticated CONNECT uses no replayable 0-RTT.
The default user agent is `Splicore TrustTunnel`; overrides are bounded to 512
bytes and reject header injection.

## Streams, health and recovery

Each client instance owns at most one active authenticated session and one setup
race. Immutable instance configuration separates endpoint, credentials, TLS
trust, SNI and mode identities without a process global pool. H3 starts first;
H2 starts after the fallback delay, or immediately after a nonsecurity H3
failure. The first authenticated, verified, healthy session wins; the other
attempt is canceled, joined and closed. A certificate/auth failure observed
before a winner is terminal. A late failure cannot invalidate an already
verified winner using the same configured identity and trust policy.

TCP uses one CONNECT per logical stream. Library flow control and private bounded
32 KiB read buffers provide backpressure. Logical deadlines do not change the
shared transport deadline; a partial timed out write terminates that stream.
Legal empty H3 DATA frames preserve subsequent data and EOF; repeated empty
reads use a cancelable pause with bounded memory and CPU use.
Client upload half-close preserves the response. With the net/http H2 server,
target response EOF ends the complete logical CONNECT after flushing its tail,
because net/http does not expose independent response END_STREAM. H3 exposes
separate stream write closure. Closing one stream preserves siblings.

`_check` uses a configurable seven second default response timeout. Concurrent
checks coalesce; valid endpoint data satisfies liveness while a check is
pending. Session loss prevents new stream admission and closes its children.
New admissions share controlled recovery backoff: one second initially, factor
1.3, capped at 30 seconds. Recovery is admission driven; there is no background
reconnect loop without demand, no automatic payload replay and no direct
fallback. Explicit Close cancels races, health work and recovery waits, closes
children and joins owned workers. Empty reserved muxes do not pin an idle
session forever.

## UDP and routing

One `_udp2` CONNECT per session carries asymmetric specified frames: client
frames include a one byte application name length and optional application
name; replies omit both. IPv4 uses zero leading padding; IPv6 `::1` remains
IPv6. The datagram maximum is 65507 bytes; lengths are validated before allocation.
Partial headers, partial bodies and concatenated frames are stream parsed.

Each client association pins its destination and has a bounded 16 datagram
receive queue. Queue exhaustion terminates that association with capacity error.
Mapped IPv4 destinations use the same canonical identity as IPv4. Mux teardown
stops new admissions and retires its flow map before blocking cleanup.
At most 64 pending writes serialize through a shutdown aware gate; excess
concurrent writers receive capacity error before frame allocation. A partial frame failure
terminates its mux. There is no goroutine or timer per datagram. A retired source
port is not reused within a mux, preventing delayed replies reaching a later
association. After 64511 admissions on one mux it returns capacity error; creating
a new client/session provides a fresh mux. One sweeper expires idle flows. The
server tracks bounded source/destination four tuples, with one protected target
socket/reader each, and joins every reader on owner shutdown.

UDP's explicit default idle timeout is 120 seconds, following the protocol
document. The pinned endpoint configuration documents 300 seconds. This is local
lifecycle policy and does not change wire interoperability.

Inbound forwarding uses the existing Native Engine `ServerTarget` protected
socket owner, resolver and relay, with immutable Binding traffic attribution.
It has no separate DNS or forwarding engine and does not implement the official
endpoint's private network ACL. The existing inbound model does not supply an
outbound rule evaluator here; client runtime routing continues to own outbound
selection. Host egress protection applies to resolved numeric sockets, including
private, mapped IPv4 and hostname targets. UDP hostname targets are resolved once
by the Core and later writes remain pinned to that association's original or
resolved destination. No claim of official private network policy parity is made.

## ICMP status

ICMP is **implemented / not yet fully qualified**. The fixed request/reply wire
records, bounded correlation table and `_icmp` stream are implemented. The
client remaps ID/sequence pairs without reuse on a stream and restores caller
IDs, so late replies cannot satisfy newer calls. The server has four workers,
a queue of 64 and three second request limits. Duplicate/beyond capacity input
terminates its reserved stream. Native raw echo forwarding rewrites identifiers
and verifies source, family, reply ID/sequence and randomized data. TTL/hop limit
is honored. Missing raw socket privileges produce an explicit runtime failure;
there is no privilege escalation. ICMP is off by default.

The native backend currently forwards echo replies only. Router unreachable/time
exceeded responses and official client TUN to Splicore ICMP remain unqualified.
ICMP is available through the protocol session API and the opt in server backend;
the Core's generic TCP/UDP outbound interface does not expose an ICMP method.
Mock tests alone do not confer an official interoperability claim.

## Deep links and reference boundaries

The existing URI importer accepts static `tt://?` and documented legacy `tt://`
TLVs, versions 0–2. Static URI export emits version 1 for the pinned stable
client. The official endpoint export is parsed by Splicore, and the pinned
official client setup wizard imports Splicore's static export. Static connection
fields include address lists, TLS trust, custom SNI and explicit insecure mode.
Auto mode and nonrepresentable local options reject export instead of losing
semantics. Names are metadata. URI input is limited to 96 KiB, decoded TLVs to
64 KiB and certificates to 48 KiB/16 certificates; duplicate non-address fields
use the last value, repeated addresses append, and unknown tags are ignored.

Subscription URLs, DNS upstream policy, anti-DPI, ClientRandom prefix and
ClientRandom authentication keys are parsed by the bounded codec but rejected
as runnable profiles. They do not create a second subscription/DNS/TLS engine.
Version 2 subscription runtime and optional TLS extensions are not qualified.
The pinned v1.1.11 wizard rejects version 2 and has no client export CLI option.

Official reference limitations remain explicit payload failures: empty UDP
times out at the official peers; the official client also buffers a lone ASCII
`Z` while identifying traffic. Official self interoperability reproduces both.
Native peers support both payloads. These failures are not counted as passing
payload checks.

**Phase29 H3 EOF qualification remains BLOCKED.** In controlled official H3
experiments, a request ending in nonempty DATA followed by FIN can leave the
target TCP send direction open despite local reliable QUIC send completion.
The experimental client sends a legal final empty DATA frame through the
bounded writer before the real send-direction FIN. Isolated controls then
complete target EOF, including when DATA is acknowledged before FIN. Empty
DATA without FIN does not produce target EOF. This sequence is not a sufficient
fix: the complete official campaign still fails after health checks, including
an IPv6 case that receives all 16384 response bytes but no response EOF.
Further controlled failures observe target TCP EOF and normal local send
completion while the client QUIC receive final offset remains unknown until
its original deadline. Direct generic RequestStream APIs also reproduce this
response failure without Splicore adapters or health checks. The official
implementation remains a black box; its internal cause is unproven.
No timeout, payload or EOF check is relaxed, and this candidate cannot be
frozen until the full mandatory campaign and independent review pass.

Large UDP must be qualified in an isolated network namespace
on hosts with the recorded WSL fragmentation boundary; a host timeout is not a
passing observation.

HTTP/1.1 TrustTunnel, official TLS/browser fingerprint parity, anti-DPI parity,
post quantum fingerprint parity, GUI, kill switch, subscription service,
reverse proxy, metrics dashboard and automatic certificate management are not
claimed. Linux arm64 build coverage is not real hardware qualification.
