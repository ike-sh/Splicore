# Shared stream transports

VMess AEAD, VLESS flow-none and Trojan standard use the common stream transport
layer. Protocol authentication and TCP/UDP framing remain owned by the protocol.

| Profile | Raw | WebSocket / HTTPUpgrade / gRPC |
| --- | --- | --- |
| VMess AEAD | Plain or TLS | Plain or TLS |
| VLESS flow-none | Plain, TLS or supported REALITY | Plain or TLS |
| Trojan standard | TLS | TLS |
| Other protocol families | Their existing transport | Rejected |

`internal/splicore/domain/streamtransport` defines bounded intent;
`internal/splicore/streamtransport` supplies dialing and listener wrapping.
Client node/profile `transport` and server `stream_transport` use the same model:

```json
{"kind":"ws","path":"/core","host":"proxy.example","headers":{"X-Client":"owned"}}
```

```json
{"kind":"grpc","service_name":"CoreService","host":"proxy.example"}
```

Absence preserves raw transport. Unknown or unsupported fields/profiles are
rejected before runtime; they do not fall back to raw. Server custom headers are
not accepted. HTTP path defaults to `/`; gRPC service defaults to `GunService`
and registers normal `/<service>/Tun`, without TunMulti, early data or Mux.Cool.
Each listener has a single protocol/transport; automatic port demultiplexing is
not provided. Existing VLESS XUDP behavior remains protocol-owned.

Physical dial endpoint, TLS SNI and HTTP Host/gRPC authority are distinct.
HTTP wrappers use `http/1.1`; gRPC uses `h2`; incompatible ALPN is rejected.
With no explicit authority, the gRPC authority defaults to explicit TLS name,
then endpoint. Managed TLS profiles require an explicit server name.
New REALITY/wrapper combinations and Vision are rejected.

WebSocket accepts binary frames as a byte stream. HTTPUpgrade uses an HTTP/1.1
101 upgrade and then raw bytes, retaining buffered payload exactly once.
gRPC uses the normal bidirectional Tun/Hunk stream. Underlay dialing is injected,
with no ambient proxy lookup. Socket/deadline/cancellation ownership belongs to
the runtime generation; closing a transport releases its workers and children.

| Bound | Value |
| --- | --- |
| Path / host / service | 2048 / 255 / 128 bytes |
| Custom headers | 32 entries; 8 KiB aggregate |
| WebSocket received message | 1 MiB |
| gRPC message | 1 MiB plus framing allowance |
| Outbound chunk | 32 KiB |
| Admission timeout | 5 seconds |

Transport authority/path/header values and credentials are excluded from ordinary
diagnostic projections. See [API](../api/README.md) and [capabilities](CAPABILITY_MATRIX.md).
