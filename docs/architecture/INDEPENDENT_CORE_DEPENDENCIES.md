# Independent Core Dependencies

- Documentation status: Experimental
- Audience: Maintainers
- Last reviewed: 2026-10-06
- Owner: Splicore maintainers
- Responsibility: Independent dependency and ownership boundaries.
- Lifecycle: Update with dependency and runtime changes.

- Status: Phase 17 local development gates complete; READY FOR REVIEW
- Module: `github.com/ike-sh/Splicore`
- Minimum Go: 1.26.3; acceptance uses installed Go 1.26.6 and `GOTOOLCHAIN=local`
- Decision: [ADR 0038](../adr/0038-remove-sager-net-core-dependency-graph.md), Proposed

Splicore owns domain models, credentials, registries, application transactions,
DNS, routing, policy, underlay injection and runtime lifetimes. Production,
test and tool SagerNet imports are zero. Direct requirements, the full module
graph and active binary package paths contain no SagerNet modules. Historical
source attribution remains required.

## Minimal foundations

| Package | Consumers / reason | Contract and ownership |
| --- | --- | --- |
| `domain/access.Endpoint` / `engine/netaddr` | Protocols/routes need an endpoint independent of upstream metadata | Semantic host/port and standard net/netip conversion; wire tags stay separate |
| `protocol/address`, `protocol/socks` | SS and SOCKS share addresses; ingress needs CONNECT/UDP framing | Bounded codec; caller owns returned bytes; numeric domain literals are canonicalized |
| `engine/traffic` | Runtime/binding payload attribution | Atomic counters; wrapper owns close and immutable prefix snapshot |
| `engine/clientio` | All native outbound factories | Joins pending dials/sockets; handshake cancellation affects only its flow |
| `engine/clientconfig` | TLS trust and QUIC underlay | Immutable TLS snapshot; protected bootstrap DNS and lazy per-flow numeric UDP socket |
| `engine/packetio` | TUIC/VLESS packet delivery | Copies producer bytes; bounded queue; direction locks; data channel is never closed |
| `engine/relay` | Native target relays | Standard connections, half-close and joined directional workers |
| `engine/neterror` | Native error translation | Small standard error mapping |

Use context, sync, atomic, errors, io, bytes and net directly elsewhere.
Application logging remains owned. No upstream logger or generic service
locator survives. No buffer pool was introduced. Mutable record state belongs
to a connection and direction.

## Protocol boundaries

| Product | Owned integration | Independent substrate |
| --- | --- | --- |
| SS / SS2022 | internal/splicore/protocol/shadowsocks/wire + native server/client | Standard crypto, x/crypto, BLAKE3 primitive |
| Snell | protocol/snell/wire + native server/client | Standard crypto and x/crypto |
| Hysteria2 | protocol/hysteria2/wire + backend | Official AperNet QUIC fork / HTTP3 |
| TUIC | protocol/tuic/wire + backend | Independent quic-go |
| VLESS | protocol/vless/wire + backend | Standard TLS / MetaCubeX uTLS REALITY API |
| Mieru | protocol/mieru; SDK types confined to backend | Official enfein/mieru SDK; no wire rewrite |
| TUN | Owned device, NIC, sessions, routes and joined workers | Official gVisor, x/sys, independent netlink/Wintun |

SS retains aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305,
2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm and
2022-blake3-chacha20-poly1305. Snell server v5/v6 and client v4/v6 remain.
VLESS plain/TLS/REALITY remain; Vision remains deferred. DIRECT/REJECT and
owned local HTTP/SOCKS ingress remain.

QUIC receives an already protected packet socket; server ingress is separately
owned and admission gated. REALITY receives the protected target dialer and
cancellation owns both sockets. Client certificate verification parses supplied
DER without reflection or private unsafe pointers. Mieru SDK concrete types do
not enter domain/API/CLI/SQLite contracts.

HY2 currently uses the substrate's default CUBIC; the inherited runtime used
BBR. Managed settings expose neither bandwidth nor congestion selection.
Application interoperability is verified; identical congestion behavior is not
claimed. Official SDK reference UDP payloads use 4000 bytes because its 4096-byte
send buffer includes framing; owned 4096-byte regressions remain.

## Source and licensing

Dead inherited trees and their nonproduct tests were removed after Linux and
Windows production/test closure audits. Product tests remain, with owned
replacements for retired constructors. No SagerNet tree was cloned, mechanically
translated, vendored or patched in the module cache. Pinned external peers and
SDKs are acceptance oracles outside the repository. No external proxy core
handles production traffic.

Root GPL terms and attribution remain. See [third-party notices](../../THIRD_PARTY_NOTICES.md)
for exact module versions and preserved license texts.

## Acceptance boundary

See the [implementation report](../reports/PHASE17_SINGBOX_DECOUPLING_REPORT.md)
for failures, corpora and final gates. Review/Freeze/publication are not performed.
The frozen candidate b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c remains historically
PARTIALLY PASSED. Qualification is not rerun; this worktree is a development
candidate. Native Ubuntu host networking, destructive Windows qualification
and Linux arm64 runtime certification remain outside local acceptance.
