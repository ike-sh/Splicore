# Native VLESS and Vision

- Documentation status: Experimental native implementation
- Audience: Operators and Core developers
- Responsibility: VLESS intent, flow negotiation, security and interoperability limits

Splicore owns VLESS v0 framing and TCP session lifetime. UUID belongs to an
Account Credential and a Binding selects the listener. Protocol, engine, security,
transport and flow remain separate. The sole runtime engine is `native`.

## Supported profiles

| Flow | Raw TCP | WebSocket / HTTPUpgrade / gRPC | Payload |
| --- | --- | --- | --- |
| `none` | Plain, explicit CA TLS, REALITY | Plain or explicit CA TLS | TCP and existing XUDP |
| `xtls-rprx-vision` | TLS 1.3, REALITY, or enabled VLESS Encryption | Rejected | TCP only |

REALITY requires `with_utls`. Unknown flows, the outbound-only historical
`xtls-rprx-vision-udp443` alias, Vision without TLS/REALITY/encryption, and Vision over HTTP
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
    "certificate_file": "/protected/server.pem",
    "private_key_file": "/protected/server.key",
    "ca_certificate": "<explicit PEM CA>"
  }
}
```

The TLS example shows settings intent; use the existing protected TLS material
contract and creation document for actual deployment. TLS keys never enter
ClientProfile. REALITY uses an inbound-owned X25519 private key, public key,
explicit DNS server name, short IDs and independent target endpoint. Public keys
are canonical raw URL-safe base64 with 32 decoded bytes. Short IDs are even hex,
0–16 characters, zero-padded to eight bytes; duplicates reject. The first admitted
ID is projected to clients. An omitted list selects the all-zero ID.

Display endpoint, listener, SNI and REALITY target are independent. Client
profiles contain the display endpoint, authorized UUID, explicit CA or REALITY
public key/short ID/SNI. Server private keys and target endpoints stay server owned.

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
This TLS key exchange is independent of [native VLESS Encryption](VLESS_ENCRYPTION.md).
The optional encryption layer runs after outer security and before VLESS decoding.

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
unrepresentable TLS CA trust and mask settings. Existing qualified Mihomo/sing-box
flow-none exporters remain; new Vision JSON projections are rejected until
qualified. Exporters reject masks rather than producing an unmasked node.
Splicore has no full Xray server configuration importer. Retired `engine_options`,
Xray runtime records and historical `finalmask` annotations remain rejected.

Wire reference: XTLS/Xray-core `v26.9.9`, commit
`52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`. It is an external test peer only.
Plain, TLS/Vision, REALITY/Vision, header-custom and Sudoku carry actual proxied
application bytes in both directions. The official reference has a server-side
`CloseWrite` panic with REALITY when fragment is the innermost mask; that upstream
runtime defect limits that exact official peer combination. A separately built
external oracle adding only fragment half-close delegation verifies its wire
compatibility. The reference's non-Vision TLS server fully closes after target
EOF; it cannot qualify upload after server EOF. Native Splicore preserves
half-close in either fragment/Sudoku order. Linux amd64 is runtime tested;
Linux arm64 is BUILD ONLY.

Historical dependency safety failures remain in
[ADR 0017](../adr/0017-defer-vision-dependency-safety.md). The native replacement
decision is [ADR 0042](../adr/0042-native-vless-vision-and-finalmask.md). Historical
reports retain their original results and do not describe the current runtime.
