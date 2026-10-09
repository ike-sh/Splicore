# Protocol and feature capabilities

Protocol profiles are experimental. Native is the runtime engine; protocol
identity does not imply ownership of another Core process.

| Protocol/profile | Server and client payload | Security/transport |
| --- | --- | --- |
| Shadowsocks AEAD / SS2022 | TCP / UDP | Edition-specific symmetric credentials |
| Snell v5/v6 | TCP / UDP | PSK; v5 uses the v4 compatibility adapter |
| Hysteria2 | TCP / UDP | QUIC/TLS and explicit trust |
| TUIC v5 | TCP / UDP | QUIC/TLS and UUID/password |
| VLESS flow-none | TCP / XUDP | Plain/TLS; supported raw REALITY |
| Mieru | TCP / UDP | Embedded TCP/UDP library transport |
| Trojan standard | TCP / UDP | TLS/password |
| VMess AEAD | TCP / UDP | UUID; supported security profiles |
| SOCKS5 / HTTP proxy nodes | Profile-dependent | Canonical node/auth settings |

Local entry includes SOCKS5 TCP/UDP, HTTP, Mixed and native TUN. Routing supports
DIRECT/REJECT and bounded selectors, URL-Test, fallback and load balance. DNS,
proxy providers, RuleSet providers, canonical imports and encrypted source
storage share the control plane.

Raw TCP/TLS, WebSocket, HTTPUpgrade and gRPC streams are available to
VMess/VLESS/Trojan under their profile limits. Other protocols retain their own
transport and reject these stream wrappers. REALITY requires `with_utls`;
native TUN requires `with_gvisor`. The recommended distribution profile includes
`with_quic`; current QUIC adapters are present in both default and tagged builds.
See [transport details](SHARED_TRANSPORT.md).

Vision and new REALITY/stream-wrapper combinations are unsupported.
FinalMask/Sudoku are outside runtime scope. No external Core runtime is required.
Mutation and quota/rate/session capabilities are protocol-specific; unsupported
strict policy fails closed. For example, VLESS user changes restart the affected
runtime generation. Read the live capability API rather than assuming uniform
hot mutation behavior.

Platform support remains experimental and partially qualified. Linux arm64 is
build-only; native Linux auto-route and real Windows host networking are not
fully qualified. See [platform limits](../OPERATIONS.md).
