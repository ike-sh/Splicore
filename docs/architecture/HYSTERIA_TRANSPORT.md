# Hysteria transport

Hysteria is a specialized native QUIC transport for the Hysteria2 protocol,
version 2. TLS 1.3 and ALPN `h3` are required. REALITY, Hysteria v1 and arbitrary
VLESS/VMess/Trojan composition are rejected. This is not a generic QUIC transport.

## Ownership

The transport owns QUIC/TLS, HTTP/3 authentication and masquerade, raw streams
and unreliable datagrams, immutable connection admission, socket lifetimes and
connection reuse. Hysteria2 owns TCP requests/responses, targets, UDP session and
fragment wire semantics, routing and Binding/Account identity attribution.

Managed credentials remain in the existing credential model. A transport never
creates another account database. Successful `/auth` admits a connection once;
another credential cannot switch its identity. Ordinary HTTP requests and
rejected authentication use the configured masquerade handler.

Each outbound instance owns one compatible connection manager. Its configuration
snapshots destination/socket factory, credential, TLS identity and QUIC settings.
Concurrent dials share one initialization; failed authentication is never cached.
Streams and UDP sessions share the connection, while closing one child preserves
siblings. Closed connections are reclaimed and subsequent dials reconnect.
Closing the outbound owner closes idle connections and stops keepalive.

Authentication padding uses 256 through 2047 ASCII bytes (`[256,2048)`).
Length and character selection use cryptographic rejection sampling without
modulo bias. Random-source failure aborts the authentication transaction.

## Configuration

Inbound `settings.stream_transport` and client `transport` use:

```json
{
  "kind": "hysteria",
  "hysteria": {
    "version": 2,
    "udp_idle_timeout": 60,
    "quic": {
      "congestion": "reno",
      "initial_stream_window": 8388608,
      "max_stream_window": 8388608,
      "initial_connection_window": 20971520,
      "max_connection_window": 20971520,
      "max_idle_timeout": 30,
      "keep_alive_period": 0,
      "max_incoming_streams": 256,
      "disable_path_mtu_discovery": false
    }
  }
}
```

Omitting `hysteria` uses version 2 defaults. An explicit settings object requires
`version: 2`. UDP idle timeout is seconds: zero selects 60; nonzero values are
2–600. QUIC idle timeout is seconds: zero selects 30; nonzero values are 4–120.
Keepalive is disabled by default; an explicit value is 1 through half the idle
timeout. Stream admission defaults to 256 and accepts 8–4096. Windows are bytes,
bounded at 1 GiB; maximums must cover initial values. PMTU discovery is handled
by the library. No real network performance or hardware qualification is implied.

Existing TLS-only managed inbound settings and Hysteria2 client `kind: quic`
remain deterministic legacy spellings for this same implementation. New profiles
and imports use `hysteria`. Protocol options remain `{}`. Server settings do not
become client settings during export. Ecosystem exports support the default
transport; explicit custom tuning requires the native configuration surface.

## Congestion and bandwidth

`quic.congestion` accepts `reno` (retained default), `bbr`, `brutal` and
`force-brutal`. Native BBR and Brutal plug into the existing AperNet QUIC
controller interface. No additional QUIC library or proxy runtime is used.
BBR uses a delivery bandwidth / minimum RTT model, STARTUP, DRAIN, PROBE_BW
and PROBE_RTT states, paced sending and a bounded flight window. It follows the
BBR v1 model with an independent native implementation; this is not a claim of
bitwise equivalence to the Linux or reference implementation. Packet samples
are bounded at 65536; all custom sender windows are capped at 64 MiB.

Brutal's `quic.brutal_up` and `quic.brutal_down` are local upload and download
rates. They accept unsigned integer decimal **bits per second**, with `bps`,
`kbps`, `mbps`, `gbps`, `tbps` or short `k`, `m`, `g`, `t` suffixes, ignoring case
and permitting spaces between the integer and unit. Empty or zero means zero.
Nonzero values range from 524288 bps (65536 bytes/s) through 1 tbps. Fractions,
negative values, unknown suffixes and overflow reject. Conversion divides by
eight and rounds down explicitly. The wire `Hysteria-CC-RX` and controller
rates are unsigned **bytes per second**. The native grammar is a documented
subset of the reference configuration vocabulary.

The client advertises its Down; its sender uses its Up capped by numeric server
RX, where server RX zero means unlimited. Server `auto`, or client Up zero,
selects BBR fallback. The server sender uses client RX capped by its own Up;
client RX zero selects BBR. A Brutal server advertises its Down. Adaptive Reno
and BBR advertise client `0` and server `auto`. Nonzero rate options alongside
Reno or BBR reject instead of being ignored.

`force-brutal` requires positive local Up and always selects the native Brutal
sender at that rate, ignoring peer RX limits and `auto`. Its Down advertisement
retains ordinary receive semantics. It does not force the peer's sender.
This follows Xray's local forced upload rule; official Hysteria uses bandwidth
and congestion configuration rather than the same mode name. Brutal uses token
bucket pacing, a bounded RTT flight window and loss compensation after at least
one second and 50 packets; compensation is bounded at twice the requested rate.
These are correctness features, with no throughput or hardware qualification.

Read-only per-owner diagnostics record requested mode, peer advertisement,
selected controller, effective rate and actual sent/ACK/loss counters.
Configured Account speed policies remain metadata and do not select a controller.

## HTTP/3 masquerade

Inbound `hysteria.masquerade` supports:

| Type | Settings |
| --- | --- |
| omitted, `404` | Standard 404 response |
| `string` | `content`, optional `status` (default 200), bounded `headers` |
| `file` | `directory`, served through an owned filesystem root |
| `proxy` | HTTP/HTTPS `url`, optional `rewrite_host` and explicit `insecure` |

Static status 233 and Hysteria response headers are rejected. File serving stays
within its root, including symlinks. Reverse proxies use bounded reusable buffers,
connection/header limits, request cancellation and owned idle connection cleanup.
Hysteria admission headers are removed before forwarding to a web upstream.
Masquerade settings are server-only.

## Bounds and unsupported wrappers

Connections per listener are bounded at 256; UDP sessions per connection at 128;
UDP target sockets per session at 128. Datagram dispatch queues are bounded;
overload drops datagrams. Reassembly retains at most 128 partial packets,
4096 payload bytes and 255 fragments per packet, for 5 seconds. Idle sessions
release state and target sockets; reusing an expired Session ID creates a new
session. The current managed UDP payload maximum remains 4096 bytes.

Fragmentation accounts for the address/header and adapts to the library's
reported datagram payload limit. A missing fragment drops the entire packet.
UDP remains unreliable; there is no application retransmission.

FinalMask supplies TCP transformations separately. Native Salamander, Gecko
and UDP port hopping run below QUIC as described below. Generic QUIC and XHTTP
H3 remain outside this transport.


## UDP obfuscation and port hopping

Packet ownership follows QUIC → Gecko/Salamander → optional hopping → the
existing protected UDP socket. There is no external proxy executable or
upstream Hysteria runtime dependency. TLS, HTTP/3 authentication, TCP streams,
QUIC Datagram sessions and congestion control remain in their existing layers.

Client native transport example (all interval values are integer seconds):

```json
{"kind":"hysteria","hysteria":{"version":2,
 "obfs":{"type":"gecko","password":"REPLACE_WITH_SHARED_SECRET",
         "min_packet_size":512,"max_packet_size":1200},
 "udp":{"ports":"1234,5000-6000,65534-65535",
        "min_hop_interval":5,"max_hop_interval":10}}}
```

`obfs.type` accepts `none`, `salamander`, or experimental `gecko`. Salamander
requires a password and forbids Gecko size fields. Passwords are 1–1024 bytes.
Gecko defaults to 512/1200 bytes, measured as **final UDP datagram size** including
its 8-byte salt and 5-byte frame header. Its minimum is at least 14, maximum
at least 163 (enough for a 1200-byte Initial across eight nonempty fragments),
maximum >= minimum, maximum <= 2048. Explicit invalid or zero size values reject.
Short QUIC headers use plain Salamander framing even in Gecko mode, and are
not subject to Gecko fragment padding sizes. Long headers use 2–8 fragments;
secure entropy chooses chunk boundaries, padding lengths and padding contents.
Each fragment has a fresh salt and independent BLAKE2b-256 mask. There is no
plaintext fallback for mismatched obfuscation or passwords.

Gecko reassembly keys include source address and message ID. Bounds per socket:
512 retained IDs globally, 256 per source, 2 MiB buffered chunks, 4096-byte
reconstructed packets, two-second TTL. Completed/conflicting IDs retain bounded
empty tombstones through their TTL to reject duplicate delivery and ambiguous
collisions. Sender IDs start randomly and cycle without reuse for two seconds;
exhaustion fails the write. One sweeper per Gecko socket expires state. Close
clears state and joins the sweeper. These are implementation bounds, not wire
negotiation. Salamander shares no mutable hash or caller packet storage.

Obfuscated carriers use 1200-byte initial QUIC packets and disable PMTU discovery.
Salamander adds exactly eight bytes, so a full QUIC packet occupies 1208 UDP
payload bytes. Hysteria Datagram fragmentation retains peer/path capacity
adaptation. Wrappers expose only PacketConn: UDP OOB, GSO and batching acceleration are intentionally hidden.
Each transformed datagram is submitted separately, with underlying deadlines.
All Hysteria carriers expose only PacketConn through a final socket ownership
gate. Close stops new writes, interrupts and joins admitted writes, then releases
the socket; late QUIC close-queue replies cannot call a released socket. This
also hides UDP acceleration on unobfuscated Hysteria carriers.

`udp.ports` accepts individual ports, ranges and mixed comma-separated sets.
Ranges are stored as sorted merged intervals, bounded by ports 1–65535, with
uniform sampling over unique eligible ports. The first port is random; each
scheduled hop selects a different port when more than one exists. `hop_interval`
is fixed, defaults to 30 seconds and has minimum 5. Alternatively both
`min_hop_interval` and `max_hop_interval` select a fresh random duration for each
hop; minimum >= 5 and maximum >= minimum. Intervals must fit in a Go duration
(at most 9223372036 seconds). Modes cannot coexist; interval fields without ports
reject. Explicit zero interval fields reject. Single-port configurations need no
scheduler. Close wakes I/O and joins the scheduler.

The existing protected socket and resolver select one IP. There is no DNS query
per hop and no IP hopping. Incoming replies must match that IP/zone and an
eligible port, including previous ports; all return the stable logical peer to
QUIC. Other peers reject. Long-lived streams, UDP sessions and authentication
remain on the same QUIC connection. Managers snapshot all settings per instance;
no global pool exists. Packet identity comparisons hash canonical settings,
including obfs password, size parameters, port set and interval policy.

### Linux server ranges

Server transport uses `udp.server_port_range`, for example `"20000-50000"`, with
the numeric UDP listener bound to its first port (20000). It is server-only and
cannot coexist with client ports or intervals. Native client profiles retain
obfuscation and project the public server range as `udp.ports`; server-only
masquerade and congestion tuning remain excluded.

Linux uses nftables deterministically, requiring `nft` and CAP_NET_ADMIN.
Each listener creates a unique `inet splicore_hy2_<random>` table, then installs
an atomic transaction of address/family-scoped UDP redirect rules in prerouting
and output hooks. Wildcard listeners restrict redirects to local destinations.
The remainder of the range redirects to the first port. Installation failure
rolls back the owned table. Graceful shutdown removes only that table; cleanup
errors are returned. Concurrent listeners own separate tables. An ungraceful
process kill can leave its table; operators can identify and remove that exact
owned table. No host ruleset flush or shell expansion is used. IPv4 and IPv6 are
supported. An IPv6 wildcard range redirects IPv6 only; configure an IPv4
listener for an IPv4 range. Non-Linux rejects built-in range startup; externally managed
nftables/iptables destination NAT or an equivalent UDP redirector also works.

### Share and HTTP/3 boundaries

Standard `hy2://` and `hysteria2://` import/export preserve multi-port authorities,
percent-encoded auth, `sni`, `obfs=salamander|gecko`, and `obfs-password`.
URI export requires system TLS trust. Native canonical configurations preserve
all supported settings. Standard URIs do not represent interval tuning or Gecko
size tuning: export rejects these instead of losing them or inventing query
parameters. Existing pinned Mihomo/sing-box exporters accept default transport;
custom obfs/hop configurations require native or representable URI export.
Unsupported URI TLS pins, ECH and insecure TLS remain rejected.

With obfuscation, the wire is no longer ordinary QUIC/HTTP3. A standard raw
HTTP/3 client cannot access an obfuscated listener's masquerade. Without
obfuscation, existing HTTP/3 masquerade behavior remains available.

References: [official protocol](https://v2.hysteria.network/docs/developers/Protocol/),
[URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/),
[port hopping](https://v2.hysteria.network/docs/advanced/Port-Hopping/).
