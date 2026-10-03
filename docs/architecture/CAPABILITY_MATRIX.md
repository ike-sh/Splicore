# Managed protocol capability matrix

- Documentation status: Canonical
- Audience: API, protocol and operations developers
- Last reviewed: 2026-10-03
- Owner: Protocol maintainers
- Responsibility: Current experimental managed capabilities and policy limits.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

| Protocol / engine | TCP payload | UDP payload | Multi-user | Attributed payload stats | Client qualification | Mutation |
|---|---|---|---|---|---|---|
| Snell v5/v6 / native | Yes | Yes | Single PSK | Inbound | Pinned Mihomo/sing-box; Surge contract only | Restart |
| Hysteria2 / native | Yes | Yes | Yes | Inbound/Binding | Mihomo 1.19.30, sing-box 1.14.1 | Binding restart |
| TUIC v5 / native | Yes | Yes | Yes | Inbound/Binding | Mihomo 1.19.30, sing-box 1.14.1 | Binding restart |
| VLESS flow-none / native | Yes | XUDP | Yes | Inbound/Binding | Pinned Mihomo/sing-box | Binding restart |
| VLESS flow-none / xray | Yes | Bounded profile | Yes | Unsupported | Pinned client/profile matrix | Child restart |
| VLESS FinalMask/Sudoku / xray | Bounded plain TCP | Unsupported feature profile | Yes | Unsupported | Xray 26.3.27 | Child restart |
| Mieru / native | Yes | Yes | Yes | Inbound/Binding | Mieru 3.38.0, Mihomo 1.19.30 | Binding restart |

All remain Experimental. Strict quota/speed/session enforcement and durable usage
are deferred. Mieru QuotaNative is **not exposed**, despite upstream rolling-MiB
admission support. No hot-user update/reload promise. Build, runtime availability
and measured qualification are separate. Exact profile/client boundaries:
[client compatibility](CLIENT_COMPATIBILITY.md), [interop](../testing/INTEROP_MATRIX.md),
[Mieru](../protocol/MIERU.md). Vision remains deferred/unsupported.

## Client Runtime Experimental capabilities

| Capability | State / scope |
| --- | --- |
| Local SOCKS5 TCP CONNECT | SUPPORTED; no-auth loopback IP only, configurable port, IPv4/IPv6. |
| Local SOCKS UDP ASSOCIATE | SUPPORTED; loopback relay, TCP peer IP/source-port ownership and bounded flows. |
| DIRECT | SUPPORTED; IPv4/IPv6/domain TCP and UDP. |
| Snell/native outbound | Experimental / TCP+UDP; server5→client4,6→6; UDP domains resolve locally. |
| Remote Snell outbound UDP | SUPPORTED through optional adapter port; separate from local SOCKS. |
| Minimal routing | Committed default outbound plus local selected override. |
| Health / stats | Passive configured/available/active/error; ephemeral payload/session dimensions. |
| HY2/native, TUIC v5/native | Experimental / TCP+UDP, TLS/QUIC, IPv4/IPv6/domain. |
| VLESS/native and VLESS/xray | Experimental / flow-none TCP+XUDP, plain/TLS/REALITY; Vision rejects. |
| Mieru/native | Experimental / official v3.38.0, TCP/UDP underlays and payloads; UDP domains resolve locally. |
| Client FinalMask/Sudoku | DEFERRED; server support does not imply client support. |
| Routing / DNS / policy | Experimental Phase 12; ordered domain/IP/port/network/local/RuleSet rules, System/UDP/TCP/DoT, typed groups and outbound HTTP probes. |
| TUN / subscriptions / providers / FakeIP / DoH / regex / Geo | DEFERRED. |

All implemented protocols and native/Xray engines declare both roles. Exact outbound
capabilities distinguish role, address families, domain, TLS/QUIC/REALITY and flows.
Server capabilities above remain Experimental within
their frozen feature scopes. No additional service/binary; no NoBrand migration.
See [client runtime](CLIENT_RUNTIME.md) and [routing](ROUTING_MODEL.md).
