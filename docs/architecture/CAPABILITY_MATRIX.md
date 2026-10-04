# Current capability matrix

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental; Phase 14 local freeze

All runtime protocols are Experimental, under EngineID native. Protocol != Engine
is preserved; it does not authorize third-party runtime ownership.

| Protocol | Server TCP/UDP payload | Client TCP/UDP payload | Endpoint | Security |
| --- | --- | --- | --- | --- |
| Snell v5/v6 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | PSK, inherited wire |
| Hysteria2 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | QUIC/TLS, explicit trust |
| TUIC v5 | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | QUIC/TLS, UUID/password |
| VLESS flow-none | Yes / XUDP | Yes / XUDP | IPv4/IPv6/domain | Plain/TLS/REALITY |
| Mieru | Yes / Yes | Yes / Yes | IPv4/IPv6/domain | Official embedded TCP/UDP transport |

Snell v5 canonical intent uses the inherited v4 compatibility adapter; v6 maps to
v6. No wire is rewritten. REALITY requires `with_utls`. QUIC requires `with_quic`.
All-five native client adapters support bounded canonical validation and stats;
global SDK metrics never enter attributed accounting.

| Shared product feature | State |
| --- | --- |
| DIRECT / REJECT | Implemented builtins |
| SOCKS TCP/UDP, HTTP | Implemented local ingress |
| TUN, routing/DNS/policy | Implemented; platform qualification limits below |
| Selector / URL-Test / Fallback / Load-Balance | Implemented bounded profiles |
| Import/proxy provider/RuleSet provider | Phase 14 implemented, unfrozen |
| Atomic previews, identity, encrypted sources, offline recovery | Retained |
| Vision | Deferred / Unsupported; explicit rejection |
| FinalMask / Sudoku | OUT OF SCOPE FOR SPLICORE; imports Unsupported |
| Xray engine/server/client/child/artifact | Absent |
| External runtime required | No |

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
uncertified; Windows race is not executed, Linux arm64 build-only. Wintun/WinINET
fixtures are contract evidence, not real host certification.

Historical reports remain unchanged and are superseded for current Xray support by
[ADR 0035](../adr/0035-xray-runtime-removed-from-core.md) and the
[correction report](../reports/ARCHITECTURE_CORRECTION_XRAY_BOUNDARY_REPORT.md).
