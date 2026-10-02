# Managed protocol capability matrix

- Documentation status: Canonical
- Audience: API, protocol and operations developers
- Last reviewed: 2026-10-02
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
| Local SOCKS UDP ASSOCIATE | DEFERRED; explicit unsupported response. |
| DIRECT | SUPPORTED; IPv4/IPv6/domain TCP via the client runtime. |
| Snell/native outbound | Experimental / SUPPORTED TCP; server5→client4,6→6, no silent downgrade. |
| Remote Snell outbound UDP | SUPPORTED through optional adapter port; separate from local SOCKS. |
| Minimal routing | Committed default outbound plus local selected override. |
| Health / stats | Passive configured/available/active/error; ephemeral payload/session dimensions. |
| Other protocol outbounds | HY2/TUIC/VLESS native or Xray/Mieru DEFERRED. |
| Advanced routing / DNS / health probes | DEFERRED. |
| TUN / subscriptions / policy groups / providers | NOT IMPLEMENTED. |

Snell protocol and native engine have both roles. Other implemented protocols and
Xray have inbound role only. Server capabilities above remain Experimental within
their frozen feature scopes. No additional service/binary; no NoBrand migration.
See [client runtime](CLIENT_RUNTIME.md) and [routing](ROUTING_MODEL.md).
