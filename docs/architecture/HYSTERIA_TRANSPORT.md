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

FinalMask currently implements TCP transformations. Salamander, Gecko and UDP
port hopping are not implemented and are rejected. Their future location is
outside QUIC, between the carrier and the UDP socket. Generic QUIC and XHTTP H3
remain outside this transport.
