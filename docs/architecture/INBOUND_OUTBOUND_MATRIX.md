# Protocol direction and interoperability audit

This audit covers the `AMD64_ONLY` profiles in the source tree, including the
managed SOCKS5 addition. Inbound means a Server Core listener with managed
credentials. Outbound means a Client Core `RemoteNode` and native dialer.
The address columns describe the destination of the relayed payload. A test of
the proxy endpoint address alone is called out separately.

## Evidence and levels

1. Inspect the codec, backend and native adapter.
2. Match `Metadata().Roles`, `Capabilities()` and the outbound factory to
   [server composition](../../internal/splicore/registry/native_core.go) and
   [client composition](../../internal/splicore/app/app.go).
3. Check the inbound creation codec and the client `node` and `outbound`
   validators. The protected [CLI and API](../CLI.md#resource-transactions)
   persist these as separate resources.
4. Confirm a bound listener and a constructed dialer in the named runtime test.
5. Require authenticated writes and reads with a payload assertion for each
   claimed network and destination type.
6. Record observed closure, cancellation, restart or reconnect at the layer
   exercised. A compiler fixture can establish socket ownership. A complete
   daemon/SQLite restart requires process or application evidence.
7. Record independent client and server paths explicitly. Native self-interop
   and a parser or import test establish different levels of evidence.

`SUPPORTED_VERIFIED` applies to the exercised scope with independent evidence.
`SUPPORTED_WITH_LIMITATIONS` records exercised payload with a platform,
profile, lifecycle or independent-peer boundary. `REGISTERED_NOT_VERIFIED`
records admitted configurations without matching execution evidence.
`NOT_IMPLEMENTED` records a missing direction or payload. `NOT_QUALIFIED`
retains failed or excluded qualification. `NOT_EXECUTED` records an unexecuted
test or a verification that lacks an observable result.

The baseline is main `836c8858846391516a22ba33b4be297986b337c7`, tree
`16390ba5230d9ff5040249362181a81100551493`. Run `44787171785` Attempt 1
recorded `PASS`, command exit `0`, for default and full tests on Linux amd64
and Windows amd64. `commands/{default,full}-test.json` records the raw command
result and required passes. `.stdout` supplies available per-case Go events.
The baseline projection keeps a bounded tail. The current qualification supplies
`commands/*.test-identities.json` alongside the command result for a complete
lookup of permitted test identities. Consult the PR run for the exact current
tree and its SHA256 inventory. [Baseline run](https://github.com/ike-sh/Splicore/actions/runs/44787171785) · [Linux evidence](https://github.com/ike-sh/Splicore/actions/runs/44787171785/artifacts/14655313497) · [Windows evidence](https://github.com/ike-sh/Splicore/actions/runs/44787171785/artifacts/14654949331)

In the evidence below, **L** is Linux amd64 and **W** is Windows amd64. The
baseline independent-peer tests explicitly listed as L/W are required full-tag
passes in both target summaries. For other cases, the code link shows exactly
which payload and lifecycle the named case exercises. The current native
test indexes carry each individual result. Address entries marked `NOT_EXECUTED`
have no claimed matching payload proof for that row.

A supplementary full-tag run on the local WSL environment exited `1` with
UDP timeouts across several existing protocol families, including Hysteria2,
Shadowsocks, Snell and AnyTLS. This outcome belongs to that environment.
The hosted Linux evidence uses the repository's isolated network namespace.

## Managed listeners and remote nodes

| Protocol/version | Server Inbound | Client Outbound | TCP | UDP | IPv4 | IPv6 | Domain | Authentication | Observed exercise | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VLESS v0 plain, flow `none` | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | CONNECT | XUDP | TCP/UDP | TCP/UDP | TCP/UDP | UUID | Managed self-interop and reconnect, plain process smoke | [VLESS](#vless), [carriers](#shared-carriers-and-security) |
| VLESS TLS, flow `none` | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Stream | XUDP | TCP/UDP | `NOT_EXECUTED` for the raw TLS destination grid | `NOT_EXECUTED` for the raw TLS destination grid | UUID and TLS | Native TLS payload and shared-carrier close | [VLESS](#vless), [carriers](#shared-carriers-and-security) |
| VLESS REALITY, flow `none` | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Raw TCP and admitted XHTTP | Raw XUDP | TCP/UDP | `NOT_EXECUTED` for raw XUDP target | `NOT_EXECUTED` for the payload grid | UUID and REALITY keys | Raw loopback and separate XHTTP REALITY fixture | [VLESS](#vless) |
| VLESS Vision | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Raw TLS 1.3, REALITY or Encryption, plus encrypted XHTTP H3 | `NOT_IMPLEMENTED` | TCP | `NOT_EXECUTED` for the payload grid | `NOT_EXECUTED` for the payload grid | UUID, security profile | Bidirectional raw/H3 Xray cases and negative validation | [VLESS](#vless) |
| VLESS Encryption | `SUPPORTED_VERIFIED` | `SUPPORTED_VERIFIED` | X25519 / ML-KEM-768, native/xorpub/random, 1-RTT/0-RTT cases | XUDP on flow `none` | TCP/UDP | XHTTP H3 UDP target | XHTTP H3 UDP target | UUID plus encrypted handshake | Native TLS/REALITY/Vision, Xray both directions, encryption resumption and downloaded TCP smoke | [VLESS](#vless), [carriers](#shared-carriers-and-security) |
| VMess AEAD | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Raw plain/TLS and admitted carriers | Standard bound UDP | TCP/UDP | `NOT_EXECUTED` for native proxy payload on formal amd64 | TCP on the managed native path | UUID, AEAD with `alterId=0` | Self-interop, replay, close, pinned XHTTP H3 in both directions | [VMess and Trojan](#vmess-and-trojan) |
| Shadowsocks AEAD 2017 | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | AEAD streams | AEAD datagrams | TCP/UDP | UDP | UDP | Cipher-specific password-derived key | Per-cipher native TCP/UDP, shutdown, replay and destination isolation | [Shadowsocks](#shadowsocks) |
| Shadowsocks 2022 | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | SS2022 streams | SS2022 datagrams | TCP/UDP | UDP | UDP | Edition-specific key | Native matrix and replay boundaries, independent current amd64 campaign `NOT_EXECUTED` | [Shadowsocks](#shadowsocks) |
| Trojan standard | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | TLS and admitted TLS carriers | Trojan UDP frames | TCP/UDP | `NOT_EXECUTED` for native proxy payload on formal amd64 | TCP on the managed native path | Password plus TLS | Payload, wrong auth, half-close, lifecycle, pinned XHTTP H3 both ways | [VMess and Trojan](#vmess-and-trojan) |
| Snell v4 | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Native raw, bounded HTTP obfs and optional v4 reuse | UDP payload over TCP | TCP/UDP | `NOT_EXECUTED` across v4 modes | HTTP obfs authority and destination evidence are separate | PSK, one binding | Native TCP reuse, UDP port/destination change, pool shutdown | [Snell](#snell) |
| Snell v5 | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Raw TCP, tested v4-client subset | UDP over TCP and app QUIC Proxy with DRS | TCP/UDP and QUIC target | UDP and QUIC target | Outbound UDP resolves locally | PSK, one binding | Real QUIC payload, native and Linux official v5 upstream | [Snell](#snell) |
| Snell v6 | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Native stream | Bound UDP over TCP | TCP/UDP | TCP/UDP | TCP/UDP | PSK, one binding | Managed native creation/traffic/rotation/reconnect | [Snell](#snell) |
| Hysteria2 TLS/QUIC | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | QUIC streams | QUIC Datagram, fragmentation/reassembly | TCP/UDP | TCP/UDP | TCP/UDP | TLS plus H3 password auth | Native managed paths and multi-user UDP; optional reference cases `NOT_EXECUTED` | [Hysteria2](#hysteria2) |
| TUIC v5 | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | QUIC streams | Native QUIC Datagram | TCP/UDP | TCP/UDP | TCP/UDP | UUID/password over TLS/QUIC | Native managed dual-end traffic, cancellation and shutdown | [TUIC and Mieru](#tuic-and-mieru) |
| Mieru | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Embedded TCP/UDP underlay | Proxy packet sessions | TCP/UDP | TCP/UDP | TCP/UDP on TCP underlay | Username/password | Native managed dual-end payload and UDP-underlay cases | [TUIC and Mieru](#tuic-and-mieru) |
| AnyTLS v2 + UoT2 | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | TLS streams and session reuse | Connected and nonconnected UoT2 | TCP/UDP | TCP/UDP | UDP tested | Password plus TLS | Multi-user transfer, reuse and owned lifecycle | [AnyTLS](#anytls) |
| AnyTLS v1 compatibility | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | Bounded negotiation and stream reuse | Separate v1 UoT2 peer campaign `NOT_EXECUTED` | `NOT_EXECUTED` at managed Core level | `NOT_EXECUTED` | `NOT_EXECUTED` | Password plus TLS | Version negotiation and native session fixture | [AnyTLS](#anytls) |
| NaiveProxy H2 CONNECT | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | TLS HTTP/2 CONNECT | `NOT_IMPLEMENTED` | TCP | TCP | TCP | Basic over TLS | Native and unpadded HTTP/2 client, stream shutdown | [NaiveProxy](#naiveproxy) |
| NaiveProxy H3 CONNECT | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | TLS/QUIC HTTP/3 CONNECT | `NOT_IMPLEMENTED` | TCP | TCP | TCP | Basic over TLS | Full-tag multi-user/payload/half-close and H3 ownership | [NaiveProxy](#naiveproxy) |
| TrustTunnel H2/H3/auto | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | TLS CONNECT paths | Native tunneled datagrams | TCP/UDP | IPv6 proxy endpoint | Domain proxy endpoint, outbound UDP target resolved locally | Username/password plus TLS | Native TCP/UDP and ownership at H2/H3 and auto | [TrustTunnel](#trusttunnel) |
| SOCKS5 `5/base` | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | CONNECT | Managed inbound `NOT_IMPLEMENTED`, optional outbound relay to a capable peer | TCP | TCP | TCP | Required RFC 1929 inbound, outbound depends on node settings | Independent wire client, `curl`, two-Core TCP, management and process recovery | [SOCKS5 and HTTP](#socks5-and-http-proxy) |
| HTTP Proxy `1.1/base` | `SUPPORTED_WITH_LIMITATIONS` | `SUPPORTED_WITH_LIMITATIONS` | CONNECT in both directions, absolute-form HTTP forwarding inbound | `NOT_IMPLEMENTED` | TCP | IPv6 inbound target | Domain inbound target and outbound CONNECT | Required Basic inbound, optional Basic to upstream | Independent curl, two-Core TCP and managed recovery | [SOCKS5 and HTTP](#socks5-and-http-proxy) |
| Standard WireGuard userspace | `SUPPORTED_VERIFIED` (endpoint) | `SUPPORTED_VERIFIED` (endpoint) | Tunneled IP/TCP | Tunneled IP/UDP | TCP/UDP | TCP/UDP | Core DNS before endpoint selection | Peer keys and AllowedIPs | Native dual-end traffic, wireguard-go and Xray, close and malformed recovery | [WireGuard](#wireguard) |

### VLESS

The module registers plain, TLS and REALITY with the native compiler and one
`VLESSOutboundFactory`. Registry availability gates REALITY on `with_utls`.
`TestPhase11NativeSelfInteropMatrix/vless` exercises CLI/API-equivalent creation
through the application and all three destination types. The non-Vision
`TestVLESSNonVisionDefaultRaceTraffic` checks plain/TLS/REALITY live traffic in
full builds. The name retains its original test identity. VLESS Encryption
gate cases `TestVLESSEncryptionNativeSecurityVision`,
`TestVLESSEncryptionPinnedRuntimeInterop`, `TestPhase33PinnedEncryption`, and
`TestPhase33PinnedVision` passed baseline L/W with exit `0`. The independent
Xray cases exercise Splicore as both server and client. The full Linux
`TestPhase33EncryptionUDPDestinationsAndShutdown` leaves for `127.0.0.1`, `::1`,
and `localhost` passed with exit `0`. The four
`TestRuntimeBinaryTrafficShutdownAndRestart` smoke leaves cover plain and
encrypted profiles with and without Sudoku. VLESS Vision is TCP only. The
H3 exception requires VLESS Encryption. Android device interoperability is
`NOT_EXECUTED`. [Module and validators](../../internal/splicore/protocol/vless) · [Native traffic](../../internal/splicore/engine/native/vless_runtime_test.go) · [Pinned encryption](../../internal/splicore/engine/native/vless_encryption_test.go) · [Pinned H3](../../internal/splicore/engine/native/phase33_test.go)

### VMess and Trojan

The two native modules and outbound factories accept only AEAD VMess and
standard TLS Trojan. `TestVMessNativeModesTLSMultiUser` and
`TestTrojanNativeTLSMultiUserLifecycle` passed baseline default L/W, exit `0`,
with real TCP/UDP. Linux full `TestPhase19VMessManagedUsersAndRotation` and
`TestPhase18TrojanManagedUsersAndRotation` passed with exit `0`, including
TCP to a domain target. `TestVMessLifecycle25` and `TestTrojanLifecycle25`
cover generation release. `TestPhase33PinnedProtocols` independently verifies XHTTP
H3 TCP/UDP in both directions for both protocols in baseline full L/W, exit `0`.
The broader `TestVMessExternalInterop` campaign is `NOT_EXECUTED` in the native
release policy. VMess legacy, arbitrary mux and Trojan's optional fallback and
extensions have no qualification here. [VMess module](../../internal/splicore/protocol/vmess) · [Trojan module](../../internal/splicore/protocol/trojan) · [VMess tests](../../internal/splicore/engine/native/vmess_test.go) · [Trojan tests](../../internal/splicore/engine/native/trojan_test.go)

### Shadowsocks

The edition-specific modules share a native compiler and factory. The
`TestShadowsocksNativeTCPUDPMatrix` and `TestShadowsocksLifecycle25` cases pass
baseline default L/W, exit `0`. The matrix checks edition/cipher-specific
payload, including AEAD 2017 AES-GCM and ChaCha20-Poly1305 and the supported
SS2022 key/cipher profiles. `TestShadowsocksUDPMultipleDestinationsOneAssociation`
passed baseline default L/W, exit `0`, with IPv4, IPv6 and domain targets per
cipher. `TestShadowsocksAuthenticatedReplayAfterRestart`
checks the authenticated replay boundary. Independent peer qualification of
every cipher is `NOT_EXECUTED`. SIP options outside the registered profiles
have no direction claim. [Module](../../internal/splicore/protocol/shadowsocks) · [Native matrix](../../internal/splicore/engine/native/shadowsocks_test.go)

### Snell

One native compiler/factory covers all three registered wire versions. v4
HTTP obfs/reuse is a v4-specific option. `TestSnellV4HTTPNativeTCPReuseAndUDPPort`
and `TestSnellV4HTTPUDPDestinationChanges` passed baseline default L/W, exit
`0`. `TestSnellV5NativeAndOfficial` and
`TestSnellV5IPv6UnderlayAndUDP443/false` are full L/W required passes, exit `0`.
`TestSnellV5RealQUIC` exercises an independent QUIC application over native
Snell and, on Linux, the official Snell v5 upstream. The official executable
is Linux amd64 only. That upstream fixture establishes the native **client**
direction against the official server. Independent client against the native
server is `NOT_EXECUTED` in that fixture. DRS behavior is verified separately
by `TestSnellV5OfficialDRSTransitions` (full L/W, exit `0`). v6 has real TCP/UDP
and authentication/reconnect via `TestPhase11NativeSelfInteropMatrix/snell` and
`TestPhase11NativeEndpointsWrongAuthAndReconnect/snell`, with independent v6
peer qualification `NOT_EXECUTED`. [Options and capabilities](../../internal/splicore/protocol/snell) · [v5 traffic](../../internal/splicore/engine/native/snell_v5_test.go) · [v5 QUIC](../../internal/splicore/engine/native/snell_v5_quic_test.go) · [Managed matrix](../../internal/splicore/application/client_expansion_test.go)

### Hysteria2

The registered v2 module, compiler and factory use the specialized Hysteria
transport. `TestPhase11NativeSelfInteropMatrix/hysteria2` exercises managed
TCP/UDP over both destination families and domains. The native
`TestOwnedHysteria2ParallelAuthAttributionAndDomainTargets`,
`TestOwnedHysteria2DatagramsAndShutdown` and
`TestOwnedHysteria2HalfCloseAndIndependentCancellation` exercise native
QUIC traffic and lifecycle. The Linux `TestNativeHysteriaCompletenessNegativeMatrix`
checks incompatible obfuscation and downgrade refusal. The settings admit Salamander,
experimental Gecko, hopping, bounded masquerade and native congestion
profiles. The full cross-product, independent BBR equivalence and privileged
Linux nftables server ranges are `NOT_EXECUTED` in this audit. Hysteria v1
is `NOT_IMPLEMENTED`. The historic Windows ARM64 unqualified UDP failure
remains unresolved and outside amd64 coverage. [Module](../../internal/splicore/protocol/hysteria2) · [Native tests](../../internal/splicore/engine/native/hysteria2_owned_test.go) · [Transport profile](HYSTERIA_TRANSPORT.md) · [Original Windows ARM64 run](https://github.com/ike-sh/Splicore/actions/runs/44719508428)

### TUIC and Mieru

`TestPhase11NativeSelfInteropMatrix/tuic` and `/mieru` exercise managed native
inbound and outbound with TCP/UDP to all three destination types. The native
`TestOwnedTUICDatagramsAndShutdown` and
`TestOwnedTUICHalfCloseAndIndependentCancellation` passed baseline default
L/W, exit `0`. TUIC v5 advertises only admitted native relay settings, with
0-RTT disabled. Mieru uses the embedded in-process fork, with TCP/UDP server
endpoint families in `TestPhase11MieruUDPServerEndpointFamilies` and lifecycle
in `TestPhase11MieruClientLifecycle`. A separate independent protocol peer for
both directions is `NOT_EXECUTED` in the current release contract. [TUIC module](../../internal/splicore/protocol/tuic) · [Mieru module](../../internal/splicore/protocol/mieru) · [Managed tests](../../internal/splicore/application/client_expansion_test.go) · [Mieru lifecycle tests](../../internal/splicore/application/client_expansion_lifecycle_test.go)

### AnyTLS

The module and factory require TLS. `TestAnyTLSNativeTLSMultiUserTCPUDPReuse`,
`TestAnyTLSIPv6TCPUDPAndDomainUDP` and `TestAnyTLSOwnedLifecycle25` check
owned v2 payload, UoT2 and shutdown. `TestVersionNegotiationAndReuse` covers
bounded v1/v2 session negotiation. UDP uses ordered TCP and inherits
head-of-line blocking. The `TestAnyTLSOfficialCompatibility` campaign with
official AnyTLS and sing-box is `NOT_EXECUTED` in current native release gates.
Historical peer sizes and version boundaries remain in the AnyTLS record.
[Module](../../internal/splicore/protocol/anytls) · [Native traffic](../../internal/splicore/engine/native/anytls_test.go) · [AnyTLS profile](ANYTLS.md)

### NaiveProxy

The registered compiler and factory use HTTPS/H2 or H3 with `with_quic`.
The public server capability's `UDPTransport` describes the H3 underlay.
Server `UDPPayload` and client `UDP` are false. The
`TestNaiveCONNECTH2H3PayloadDestinationsAndPaddingNegotiation` payload case
passed baseline full L/W, exit `0`. `TestNaiveNativeManagedTCPAttributionAndOwnedLifecycle`
exercises the native adapters. `TestNaiveRegularH2ClientUsesUnpaddedTunnel`
checks a standard HTTP/2 client. Full L/W required H3 ownership tests include
`TestNaiveH3UploadEOFOwnership` and `TestNaiveH3ActiveAndTargetFailureCleanup`,
exit `0`. The historical Chromium/Caddy interoperability record has its own
scope. Fresh pinned Naive/Caddy both-way amd64 qualification is `NOT_EXECUTED`.
[Module](../../internal/splicore/protocol/naive) · [Payload fixture](../../protocol/naive/backend/connect_test.go) · [Naive limits](NAIVE.md)

### TrustTunnel

The compiler and factory support H2 and full-tag H3/auto. The native test
`TestTrustTunnelNativeOwnershipUDPAndMultiUser/http2` passed baseline default
L/W, exit `0`. H3 and auto have separate leaves in the full native suite.
That test cycles IPv4, IPv6 and domain **proxy** endpoints and relays real
TCP/UDP fixtures. `UDPDomainResolution` is local, so domain use depends on the
resolver path. The `TestOfficialClientToNativeServer` and related official
client/endpoint tests are opt-in and `NOT_EXECUTED` in current gates. No claim
is made for a full external TCP/UDP/address grid, per-app policy or ICMP.
[Module](../../internal/splicore/protocol/trusttunnel) · [Native payload fixture](../../internal/splicore/engine/native/trusttunnel_test.go) · [Profile limits](../protocol/TRUSTTUNNEL.md)

### SOCKS5 and HTTP Proxy

The managed SOCKS5 module and compiler share `socks5/5/base` with the existing
client factory. `TestManagedSOCKS5Processes` runs an independent RFC wire client
against the server for IPv4, IPv6 and domains, then runs the local SOCKS5 →
native SOCKS5 outbound → managed server chain. It checks actual bytes, user
attribution, rotation, disablement, stopped/running state across restarts,
half-close in both orders, abort, deletion, and redaction. The local Linux amd64
and native Windows amd64 focused suites both exited `0` with Go 1.26.3 and the
full tags. The Linux shell examples also executed against independent `curl`
and returned two HTTP response bodies, exit `0`. `TestManagedSOCKS5AuthenticationAndRouting`,
`TestManagedSOCKS5ConnectionBoundsAndCancellation` and
`TestManagedSOCKS5CommittedAdmission` cover negative auth, listener conflict,
protected dial/cancellation and committed SQLite admission. Explicit client
exports project TCP-only mode. The managed server returns `0x07` for BIND
and UDP ASSOCIATE. Native `TestPhase20SOCKSOutboundRemoteDNSRelayLifetime`
passed baseline default L/W, exit `0`, against a separate upstream fixture
with UDP relay. The upstream's capability determines whether UDP works.

HTTP uses one `http/1.1/base` profile for its managed module and existing
outbound factory. The local HTTP entry is a separate client listener.
`TestManagedHTTPProxyProcesses` exercises curl forwarding and HTTPS CONNECT,
IPv4/IPv6/domain targets, and the local SOCKS5 → HTTP outbound → managed HTTP
server chain using two Core processes. The HTTP native suites exercise streamed
requests and responses, safe trailers, target isolation after rejection,
bounds and cancellation. The existing outbound fixture still checks buffered
CONNECT data. The optional broader mature-upstream campaign
`TestPhase20MatureUpstreamInterop` is `NOT_EXECUTED`.

| Managed HTTP capability | Status |
| --- | --- |
| HTTP/1.1 managed server inbound and native HTTP outbound | Implemented |
| CONNECT and absolute-form forwarding | Implemented |
| Basic authentication, multiple bindings and SQLite recovery | Implemented |
| Keep-alive and pipelining for forwarded requests | `NOT_IMPLEMENTED`. The first response advertises `Connection: close`. |
| Server egress | Protected direct TCP and Core route rejection |
| HTTPS proxy listener, HTTP/2 server, HTTP Upgrade, CONNECT-UDP and MASQUE | `NOT_IMPLEMENTED` |

[Managed module](../../internal/splicore/protocol/proxy/managed_inbound.go) · [Native compiler](../../internal/splicore/engine/native/http.go) · [Outbound factories](../../internal/splicore/engine/native/proxy_outbound.go) · [HTTP process tests](../../cmd/splicore/http_runtime_test.go)

### WireGuard

The [endpoint manager](../../internal/splicore/wireguardendpoint) and client
network profile own standard WireGuard, with separate endpoint injection,
AllowedIPs and peer routing. `TestWireGuardDualStackBothDirections` uses real
TCP and UDP payload in both directions. `TestOfficialWireGuardInterop`,
`TestOfficialWireGuardDisallowedSource`, `TestXrayWireGuardInterop` and
`TestWireGuardLifecycleChurn100` passed baseline full L/W, exit `0`.
`TestWindowsWireGuardOversizedReceiveRecovery` passed baseline W, exit `0`.
NIC IPv6 and real host routing require their own evidence. Linux kernel backend
remains `NOT_QUALIFIED`, including its historical failed IPv6 concurrent churn.
An explicit kernel request returns `KERNEL_NOT_QUALIFIED`, and auto selects
userspace. The old Windows hotfix campaign retains its historical conclusion.
[Dual-end test](../../internal/splicore/wireguardendpoint/endpoint_test.go) · [Native peer test](../../internal/splicore/wireguardendpoint/interop_test.go) · [Historical feature inventory](../../distribution/historical-features.json)

## Shared carriers and security

| Applicability | Runtime evidence | Limits |
| --- | --- | --- |
| VLESS flow `none` / VMess AEAD / TLS Trojan, WebSocket, HTTPUpgrade and gRPC | `TestNativeSharedTransportMatrix` exercises actual native TCP and UDP in both directions, baseline default L/W exit `0` | Plain and TLS for VLESS/VMess. TLS required for Trojan. General `TestSharedTransportExternalInterop` is `NOT_EXECUTED` |
| VLESS, VMess and TLS Trojan XHTTP H1/H2 | `TestNativeXHTTPSharedProtocols` and separate `TestPhase32PinnedTransportInterop` VLESS Encryption cases | H1/H2 packet-up, stream-up, stream-one and auto have per-mode constraints. REALITY has a separate supported XHTTP test. Independent VMess/Trojan H1/H2 grid is `NOT_EXECUTED` |
| VLESS, VMess and TLS Trojan XHTTP H3 | `TestPhase33NativeProtocols`, `TestPhase33PinnedProtocols`, `TestPhase33PinnedEncryption`, `TestPhase33PinnedVision`, baseline full L/W exit `0` | `with_quic`. Vision requires Encryption for H3. Full reverse proxy/carrier cross-product and optional H3→H1/H2 translation campaigns are `NOT_EXECUTED` |
| Modern mKCP | Native `TestPhase32NativeTransportsRestartAndUDP/mkcp` and VLESS Encryption `TestPhase32PinnedTransportInterop/mkcp/*` | Admitted VLESS flow `none`, VMess and TLS Trojan profiles. General pinned Xray mKCP campaign `NOT_EXECUTED`. REALITY and Vision unavailable on mKCP |
| Generic HTTP/H2/QUIC stream carriers | `TestPhase32NativeTransportsRestartAndUDP/{http,h2,quic-stream}` checks encrypted VLESS payload and restart | QUIC requires `with_quic`. Complete VMess/Trojan independent carrier coverage is `REGISTERED_NOT_VERIFIED`. Hysteria2, NaiveProxy and TrustTunnel use their own transports |
| VLESS FinalMask and security combinations | `TestRuntimeBinaryTrafficShutdownAndRestart/{plain-native-sudoku,encrypted-native-sudoku}`, `TestVLESSEncryptionNativeSecurityVision`, `TestPhase33PinnedVision` | Raw TCP masks have explicit admission rules. Independent peers for the complete header-custom/fragment/Sudoku combination grid are `NOT_EXECUTED`. TLS/REALITY/Encryption are separate settings |

See the native [shared carrier fixture](../../internal/splicore/engine/native/shared_transport_test.go),
[XHTTP fixture](../../internal/splicore/engine/native/xhttp_test.go),
[encrypted transport fixture](../../internal/splicore/engine/native/phase32_test.go),
and the [profile validators](../../internal/splicore/domain/streamtransport).

## Local ingress, routing and target egress

| Capability | Status | Evidence and limits |
| --- | --- | --- |
| Local SOCKS5 | `SUPPORTED_VERIFIED` | `TestHTTPMixedLifecycleBufferedConnectPlainHTTPAndSOCKS`, `TestSOCKSUDPAssociationLifecycleAndIsolation`, `TestPhase20UDPAssociationChurn`, and the managed SOCKS5 process suite. TCP and local UDP use Client Core selection and their own local binding semantics. Application traffic passes to the selected outbound or route |
| Local HTTP | `SUPPORTED_WITH_LIMITATIONS` | `TestHTTPMixedLifecycleBufferedConnectPlainHTTPAndSOCKS`, `TestPhase20HTTPConnectHalfClose`, `TestPhase20HTTPTwoHopCredentialBoundary`. TCP CONNECT and HTTP forwarding with a separate local auth model. UDP `NOT_IMPLEMENTED`. Optional HTTP curl interoperability `NOT_EXECUTED` in current CI |
| Local Mixed | `SUPPORTED_WITH_LIMITATIONS` | `TestHTTPMixedLifecycleBufferedConnectPlainHTTPAndSOCKS` and `TestPhase20HTTPBodyCancellationAndMixedDetectionChurn`. HTTP/TCP and SOCKS5 TCP/UDP share local demultiplexing, with separate framing |
| Local TUN | `SUPPORTED_WITH_LIMITATIONS` | Full-tag `TestNativeTCPUDPIPv4IPv6PacketOwnership`, `TestNativeLifecycle25xGoroutineOwnership` and `TestTUNUDPQueryAcquiresCurrentDNSGeneration`. In-memory packet path and owned shutdown. Host auto-route, hardware and Windows Wintun deployment `NOT_EXECUTED` |
| DIRECT | `SUPPORTED_VERIFIED` | `TestClientDIRECTAddressesLifecycleAndStats` checks actual literal/domain traffic and state. Protected target underlay checked by `TestUnderlayActualNativeClientAndServerSocketPaths` |
| REJECT and outbound selection | `SUPPORTED_WITH_LIMITATIONS` | `TestPhase20PolicyFiltersHTTPUDP`, `TestSniffedDomainOrderedRoutes`, `TestCoreNetworkProtectedControlAndStoppedDesiredTUN`, and `TestPhase15OwnedNetworkLifecycle10x`. Traffic is selected by client routes and available capabilities. REJECT makes no outbound connection. DNS, rules, selector and failover belong to the client network graph |
| REALITY local tunnel guard | `SUPPORTED_WITH_LIMITATIONS` | `TestRealityVisionLocalTunnelGuard` and `TestRealityGuardSQLiteStartupOrder` cover the distinct fixed-target ingress with route-only admission, SNI inspection and startup ownership. Generic UDP ingress `NOT_IMPLEMENTED` |

Local source and fixtures are under [Client runtime](../../internal/splicore/clientruntime),
[native TUN](../../internal/splicore/nativetun), [routing/DNS](../../internal/splicore/networkruntime),
and [application lifecycle](../../internal/splicore/application).

Server target egress defaults to the protected `ServerTarget` dialer. SOCKS5,
VLESS, VMess and Trojan also call `ports.RoutedTargetDialer`. Only a route
scoped to the server inbound can select a Client Core proxy or endpoint for
that traffic. `TestPhase34WireGuardToProxyAndServerToEndpoint` exercises the
configured server→endpoint route and a separate endpoint→proxy path.
`TestManagedSOCKS5AuthenticationAndRouting` verifies the SOCKS5 compiler routing
hook and refusal of its own listener as an upstream peer. Full proxy chaining
qualification for every routed server protocol is `NOT_EXECUTED`. The
Hysteria2, TUIC, Snell, Mieru, Shadowsocks, AnyTLS, NaiveProxy and TrustTunnel
compilers use protected direct target paths. Their client factories do not
establish server-side chaining. [Routing boundary](../../internal/splicore/clientruntime/target.go) · [Chain fixture](../../internal/splicore/application/wireguard_test.go)

## Retired and unqualified paths

| Scope | Status | Evidence or boundary |
| --- | --- | --- |
| ShadowQUIC | `NOT_QUALIFIED` | Native reconnect with the independent peer failed in formal Linux v0.6.0 qualification. Source remains archived in `v0.6.0`, with no active registry entry |
| AmneziaWG / Phase37 | `NOT_IMPLEMENTED` | Retired. There is no active role or qualification identity. Standard WireGuard remains separately supported |
| External Xray runtime | `NOT_IMPLEMENTED` | Retired production engine. Pinned test-only Xray exercises independent interoperability |
| SOCKS4/SOCKS4a, Hysteria v1, TUIC versions below v5 | `NOT_IMPLEMENTED` | No formal server or factory for these wire profiles |
| Linux kernel WireGuard and old Windows WireGuard hotfix campaign | `NOT_QUALIFIED` | See the historical inventory and independent userspace evidence above |
| ARM64 | `NOT_QUALIFIED` | Outside formal support. Historical Windows Hysteria2 UDP failure and Linux Race failure remain independent. [Windows original](https://github.com/ike-sh/Splicore/actions/runs/44719508428) · [Linux original](https://github.com/ike-sh/Splicore/actions/runs/44727963972) |

The main outstanding direction gaps are authenticated independent peers for
both directions of unqualified protocol variants, an independent external
HTTP CONNECT upstream grid, and real host networking for TUN. Keep peer runs
bounded, record the original command and each exercised identity, and preserve
the frozen qualification of excluded profiles. [Qualification contract](../releases/QUALIFICATION.md) · [Project roadmap](../ROADMAP.md)
