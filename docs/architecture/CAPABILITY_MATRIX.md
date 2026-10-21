# Protocol and feature capabilities

Protocol profiles are experimental. Native is the runtime engine; protocol
identity does not imply ownership of another Core process.

| Protocol/profile | Server and client payload | Security/transport |
| --- | --- | --- |
| Shadowsocks AEAD / SS2022 | TCP / UDP | Edition-specific symmetric credentials |
| Snell v5/v6 | TCP / UDP | PSK; v5 uses the v4 compatibility adapter |
| Hysteria2 | TCP / UDP | Specialized Hysteria transport; mandatory TLS and H3 authentication |
| NaiveProxy | TCP | TLS H2 CONNECT or QUIC H3 CONNECT; Basic authentication |
| TrustTunnel base | TCP / UDP | Authenticated TLS HTTP/2 or HTTP/3; experimental |
| TUIC v5 | TCP / UDP | QUIC/TLS and UUID/password |
| VLESS flow-none | TCP / XUDP | Plain/TLS; supported raw REALITY |
| VLESS Vision | TCP only | Raw TLS 1.3 or REALITY |
| AnyTLS v2/v1 | TCP / UoT2 | Mandatory TLS/password; TCP session reuse |
| Mieru | TCP / UDP | Embedded TCP/UDP library transport |
| Trojan standard | TCP / UDP | TLS/password |
| VMess AEAD | TCP / UDP | UUID; supported security profiles |
| SOCKS5 / HTTP proxy nodes | Profile-dependent | Canonical node/auth settings |

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

Raw TCP/TLS, WebSocket, HTTPUpgrade, gRPC, XHTTP and modern mKCP streams are available to
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
Hysteria v1, generic QUIC transport and arbitrary VLESS/VMess/Trojan over
Hysteria are not supported. XHTTP HTTP/3 is not implemented.

VLESS Vision requires raw TLS 1.3 or REALITY and rejects HTTP stream wrappers.
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

Platform support remains experimental and partially qualified. Linux arm64 is
build-only; native Linux auto-route and real Windows host networking are not
fully qualified. Real hardware is NOT YET QUALIFIED; product CLI/API end-to-end
qualification remains NOT QUALIFIED. See [platform limits](../OPERATIONS.md).
