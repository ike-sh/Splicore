# Protocol and feature capabilities

Protocol profiles are experimental. Native is the runtime engine; protocol
identity does not imply ownership of another Core process.
The v0.6.5 release contract covers Linux and Windows amd64. Qualification
of a profile is limited to its tested behavior and peers. [v0.6.5 scope](../releases/v0.6.5.md)

| Protocol/profile | Server and client payload | Security/transport |
| --- | --- | --- |
| Shadowsocks AEAD / SS2022 | TCP / UDP | Edition-specific symmetric credentials |
| Snell v4/v5/v6 | TCP / UDP | PSK; v5 DRS and QUIC Proxy retain profile restrictions |
| Standard WireGuard | TCP / UDP via endpoint | Userspace on Windows/Linux; Linux kernel restoration ISOLATED_NOT_QUALIFIED |
| Hysteria2 | TCP / UDP | Specialized Hysteria transport; mandatory TLS and H3 authentication |
| NaiveProxy | TCP | TLS H2 CONNECT or QUIC H3 CONNECT; Basic authentication |
| TrustTunnel base | TCP / UDP | Authenticated TLS HTTP/2 or HTTP/3; experimental |
| TUIC v5 | TCP / UDP | QUIC/TLS and UUID/password |
| VLESS flow-none | TCP / XUDP | Plain/TLS/REALITY; optional native VLESS Encryption |
| VLESS Vision | TCP only | Raw TLS 1.3, REALITY, or enabled VLESS Encryption. XHTTP H3 requires Encryption |
| AnyTLS v2/v1 | TCP / UoT2 | Mandatory TLS/password; TCP session reuse |
| Mieru | TCP / UDP | Embedded TCP/UDP library transport |
| Trojan standard | TCP / UDP | TLS/password |
| VMess AEAD | TCP / UDP | UUID; supported security profiles |
| Managed SOCKS5 | TCP CONNECT and opt-in UDP ASSOCIATE | Mandatory RFC 1929, loopback by default, protected Direct or Core Reject for UDP targets |
| Managed HTTP Proxy `http/1.1/base` | TCP CONNECT and absolute-form HTTP forwarding | Required Basic proxy authentication, loopback default, one forwarded exchange per connection |
| SOCKS5 / HTTP proxy nodes | SOCKS5 TCP and optional UDP, HTTP CONNECT TCP | Canonical node/auth settings |

Local entry includes SOCKS5 TCP/UDP, HTTP, Mixed and native TUN. Routing supports
DIRECT/REJECT and bounded selectors, URL-Test, fallback and load balance. DNS,
proxy providers, RuleSet providers, canonical imports and encrypted source
storage share the control plane.

[TrustTunnel](../protocol/TRUSTTUNNEL.md) provides native inbound/outbound
sessions and bounded static deep links. HTTP/3 and automatic mode require
`with_quic`; optional features and reference interoperability have documented limits.
[Local tunnel guards](../protocol/LOCAL_TUNNEL_GUARD.md) provide loopback TCP
entry for REALITY protected destinations, bounded visible TLS SNI inspection,
route-only admission, fixed configured targets and Core DNS resolution.
They do not terminate TLS or provide a general UDP firewall.

Raw TCP/TLS, WebSocket, HTTPUpgrade, gRPC, XHTTP H1/H2/H3, generic HTTP/H2/QUIC and modern mKCP streams are available to
VMess/VLESS/Trojan under their profile limits. Other protocols retain their own
transport and reject these stream wrappers. REALITY requires `with_utls`;
native TUN requires `with_gvisor`. The recommended distribution profile includes
`with_quic`; current QUIC adapters are present in both default and tagged builds.
See [transport details](SHARED_TRANSPORT.md), [XHTTP](XHTTP.md) and [mKCP](MKCP.md).

[NaiveProxy](NAIVE.md) provides H2/H3 CONNECT, TLS, Basic authentication,
multi-user operation, multiplexing and Naive padding. Payload is TCP only;
UDP forwarding, CONNECT-UDP and MASQUE are not implemented. Chromium fingerprint parity is not claimed.

[Hysteria transport](HYSTERIA_TRANSPORT.md) owns QUIC streams/datagrams,
HTTP/3 authentication, connection reuse, congestion selection and masquerade.
It supports native Reno, BBR, Brutal and force-brutal, with 404, string, rooted
file and HTTP/HTTPS proxy masquerade. BBR equivalence and performance are not certified.
Salamander, Gecko (experimental), and fixed or randomized UDP port hopping
are supported. Linux server UDP port ranges use nftables and require `nft`
and `CAP_NET_ADMIN`.
Hysteria v1 and arbitrary VLESS/VMess/Trojan over Hysteria are not supported.
Generic QUIC stream carriers and XHTTP HTTP/3 are separate transports and require
`with_quic`. AmneziaWG/Phase37 is intentionally retired.

VLESS Vision accepts raw TLS 1.3, REALITY, or enabled VLESS Encryption. Its
XHTTP H3 profile requires Encryption. [VLESS Encryption](../protocol/VLESS_ENCRYPTION.md)
VLESS raw TCP also admits a [FinalMask](FINALMASK.md) chain containing
header-custom, fragment or Sudoku. The first configured mask is innermost.
[Vision combinations](../protocol/VLESS.md) and [AnyTLS options](ANYTLS.md)
describe exact protocol restrictions. AnyTLS supports v2, bounded v1
compatibility, connected/nonconnected UoT2, multiplexing and dynamic padding.
No external Core runtime is required.
Mutation and quota/rate/session capabilities are protocol-specific; unsupported
strict policy fails closed. For example, VLESS user changes restart the affected
runtime generation. Read the live capability API rather than assuming uniform
hot mutation behavior.

Formal platform support covers Linux and Windows amd64. Native process tests
cover the local control API, VLESS, SOCKS5 and HTTP Proxy transfer, authentication
refusal, shutdown and persisted listener restoration. The direction audit identifies
the tested transport combinations and independent peers. [Direction audit](INBOUND_OUTBOUND_MATRIX.md)
Other protocol combinations, native Linux auto-route, real
Windows host networking and real hardware retain their existing qualification
limits. See [platform limits](../OPERATIONS.md).

ShadowQUIC restoration is ISOLATED_NOT_QUALIFIED and excluded from v0.6.1;
its formal v0.6.0 server-restart peer campaign failed. AWG remains retired.
