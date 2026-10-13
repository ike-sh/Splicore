# Current capability matrix

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-11
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental native implementation; platform qualification remains separate

All runtime protocols are Experimental, under EngineID native. Protocol != Engine
is preserved; it does not authorize third-party runtime ownership.

| Protocol | Server TCP/UDP payload | Client TCP/UDP payload | Endpoint | Security |
| --- | --- | --- | --- | --- |
| Snell v4 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | Native PSK; none/HTTP obfs; serial reuse |
| Snell v5 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | Native PSK; qualified v4-compatible client scope |
| Snell v6 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | Native PSK; existing shaping |
| Hysteria2 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | QUIC/TLS, explicit trust |
| TUIC v5 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | QUIC/TLS, UUID/password |
| VLESS flow-none | Yes / XUDP | Yes / XUDP | IPv4/IPv6/domain | Plain/TLS/REALITY |
| Mieru | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | Official embedded TCP/UDP transport |
| AnyTLS v2/v1 | Yes / UoT2 | Yes / UoT2 | IPv4/IPv6/domain | Mandatory shared TLS, password |

Snell v4 has explicit native client/server configuration, TCP/UDP relay, reuse
and HTTP host/URI options. v5 client projections use v4-compatible semantics;
v5 QUIC Proxy Mode is not implemented. v6 retains its existing separate shaping.
See [Native Snell](../protocol/SNELL.md) for qualification and datagram limits.
REALITY requires `with_utls`. QUIC requires `with_quic`.
All-five native client adapters support bounded canonical validation and stats;
global SDK metrics never enter attributed accounting.

| Shared product feature | State |
| --- | --- |
| DIRECT / REJECT | Implemented builtins |
| SOCKS TCP/UDP, HTTP | Implemented local ingress |
| TUN, routing/DNS/policy | Implemented; platform qualification limits below |
| Selector / URL-Test / Fallback / Load-Balance | Implemented bounded profiles |
| Import/proxy provider/RuleSet provider | Experimental native implementation |
| Atomic previews, identity, encrypted sources, offline recovery | Retained |
| VLESS Vision | Experimental native TCP flow; raw TLS 1.3 / REALITY only |
| VLESS + TLS + Vision | Native inbound/outbound; real inner TLS direct transition tested |
| VLESS + REALITY + Vision | Native inbound/outbound; `with_utls` required |
| FinalMask TCP | Native reusable underlay; raw VLESS consumer |
| header-custom / fragment / sudoku | Implemented; [fields and peer limits](FINALMASK.md) |
| Xray engine/server/client/child/artifact | Absent |
| External runtime required | No |
| XHTTP | Native shared inbound/outbound for VLESS, VMess, Trojan; [configuration](XHTTP.md) |
| XHTTP modes | packet-up, stream-up, stream-one, auto |
| XHTTP HTTP/security | H1 packet-up/stream-up; H2 all modes; TLS; VLESS REALITY H2 |
| XHTTP H3 | Not implemented; h3 configuration rejected; generic QUIC/Mux.Cool not implied |

Native server binding counters are runtime-generation payload/session evidence,
not durable billing. Quota/rate/session enforcement is limited by the actual
capability API; strict unsupported policy fails closed. Hot mutation capabilities
are protocol-specific; VLESS user changes restart the affected native generation.

Production egress inventory covers DIRECT, DNS/bootstrap, health, five native
clients, native server targets and provider fetch, with Unknown=0 required. No
external-child egress surface remains. TUN generations retain shared leases and
host journal debt correctly.

Local evidence includes Linux default race/checkptr and disposable WSL kernel/service
tests. Native Ubuntu auto-route/real Windows system-network qualification remain
uncertified; Windows race is not executed, Linux arm64 build-only. Wintun
fixtures are contract evidence, not real host certification.

The current Xray boundary is described in
[ADR 0035](../adr/0035-xray-runtime-removed-from-core.md).

AnyTLS supports bounded stream multiplexing, newest-idle session reuse, padding
and dynamic scheme updates. Local anytls-go v0.0.13 and sing-box v1.14.2 TCP/UDP
interoperability and v1 compatibility are validated. See [Native AnyTLS](ANYTLS.md)
for peer payload limits, TLS, lifecycle and URI/export restrictions.
