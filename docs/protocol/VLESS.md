# Native VLESS and Vision

Splicore owns VLESS v0 framing and TCP session lifetime. UUID belongs to an
Account Credential and a Binding selects the listener. Protocol, engine, security,
transport and flow remain separate. The sole runtime engine is `native`.

## Supported profiles

| Flow | Raw TCP | WebSocket / HTTPUpgrade / gRPC | Payload |
| --- | --- | --- | --- |
| `none` | Plain, explicit CA TLS, REALITY | Plain or explicit CA TLS | TCP and existing XUDP |
| `xtls-rprx-vision` | TLS 1.3 or REALITY | Rejected | TCP only |

REALITY requires `with_utls`. Unknown flows, the outbound-only historical
`xtls-rprx-vision-udp443` alias, Vision without security, and Vision over HTTP
transports reject before runtime construction. A wire request must match the
configured flow and an admitted UUID. There is no flow downgrade.

Inbound settings retain `security`, `flow`, `transport: "tcp"`, and
`packet_encoding: "xudp"`. `stream_transport` selects the shared transport.
Client nodes use `transport`, `security`, and protocol options containing the same
flow. `packet_encoding` retains the existing schema discriminator; Vision does
not enable packet sessions. Its ClientProfile advertises TCP only.

```json
{
  "security": "tls",
  "flow": "xtls-rprx-vision",
  "transport": "tcp",
  "packet_encoding": "xudp",
  "stream_transport": {"kind": "tcp"},
  "tls": {
    "server_name": "proxy.example",
    "certificate_file": "/etc/splicore/cert.pem",
    "private_key_file": "/etc/splicore/key.pem",
    "ca_certificate": "<explicit PEM CA>"
  }
}
```

The example is the `settings` object of a managed VLESS creation document.
The full document contains `schema`, `name`, `listener`, `display_endpoint`,
`settings` and `users` with `account_name` and a UUID credential. Use
`splicore inbound validate --protocol vless --file /private/vless.json`, then
plan/apply through the [CLI](../CLI.md) or [local API](../api/README.md).
Certificate/key files must be private and readable by the Core account; the
CA placeholder must be replaced with one actual PEM CA certificate. TLS keys never enter
ClientProfile. REALITY uses an inbound-owned X25519 private key, public key,
explicit DNS server name, short IDs and independent target endpoint. Public keys
are canonical raw URL-safe base64 with 32 decoded bytes. Short IDs are even hex,
0–16 characters, zero-padded to eight bytes; duplicates reject. The first admitted
ID is projected to clients. An omitted list selects the all-zero ID.

Display endpoint, listener, SNI and REALITY target are independent. Client
profiles contain the display endpoint, authorized UUID, explicit CA or REALITY
public key/short ID/SNI. Server private keys and target endpoints stay server owned.

For protected cover destinations, point REALITY's target at a configured
[local tunnel guard](LOCAL_TUNNEL_GUARD.md). The guard admits exact visible SNI
through native route policy and dials only its fixed configured destination.
Optional `server_names` accepts up to 16 distinct DNS names and must include
`server_name`; this handshake policy is separate from guard route admission.

## Flow and underlay composition

Vision owns padding, bounded framing and TLS traffic detection. A supported
inner TLS 1.3 ServerHello and complete inner application records allow the direct
copy command. Other traffic stays inside outer security. Separate reader/writer
state and synchronized TLS detection preserve full duplex operation. Security
reads stop at record boundaries; owned plaintext is drained before direct copying.
The implementation accesses no private TLS buffers with reflection or unsafe.

Outbound order is VLESS → optional Vision → transport → TLS/REALITY →
[FinalMask TCP chain](../architecture/FINALMASK.md) → native socket. Direct Vision
copies retain the entire mask underlay. First configured mask is innermost.
Static TLS verifies explicit trust and SNI. REALITY authentication uses the
existing admitted uTLS library; its default current TLS key shares are preserved.
This TLS key exchange is independent of VLESSENC, which is unsupported.

## Lifecycle and diagnostics

Users are immutable per runtime generation. Handshakes are bounded to five
seconds. REALITY starts with a two-second target reachability probe; this proves
reachability rather than target TLS compatibility. Shutdown cancels admission,
closes unauthenticated and authenticated connections, interrupts mask delays and
joins owned workers. TCP EOF and both half-closes preserve opposite-direction
drain. Counters cover authenticated routed payload and sessions per generation.
Hot user updates require reconcile/restart; quota/rate/session policies remain
limited by capability validation.

Normal reads and diagnostics redact credentials and mask settings. Explicit
canonical configuration export/backup retains operator-supplied mask intent.
Sudoku passwords select an obfuscation table, not authentication credentials.

## Sharing and compatibility limits

The bounded plain/REALITY URI dialect preserves Vision's explicit flow and rejects
unrepresentable TLS CA trust and mask settings. Flow-none Mihomo/sing-box
exports retain their supported profiles; Vision JSON projections are rejected.
Exporters reject masks rather than producing an unmasked node. Splicore has no
full Xray server configuration importer. `engine_options`, Xray runtime records
and legacy `finalmask` annotations are rejected.

Xray-core v26.9.9 has a server-side CloseWrite panic with REALITY when fragment
is the innermost mask. Avoid that exact peer combination. Its non-Vision TLS
server fully closes after target EOF, limiting upload after server EOF with that
peer. Native Splicore preserves half-close in either fragment/Sudoku order.
See [FinalMask restrictions](../architecture/FINALMASK.md).

This implementation is experimental. Real-world server/hardware deployment is
not yet qualified. Linux arm64 is BUILD ONLY.
