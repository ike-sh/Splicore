# Phase 13 TUN and system integration source audit

- Documentation status: Canonical
- Audience: Maintainers and platform adapter implementers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Pinned source capabilities and ownership decisions before implementation.
- Lifecycle: Update when the supported adapter boundary changes.

## Evidence and baseline

Phase 12 `d09f5f10797aa63798419fa77ffd676257f1b609`, clean Phase 13 branch.
Audited local sing-box v1.14.1 source, its `go.mod`, and cached unmodified
`github.com/sagernet/sing-tun v0.9.3`. No dependency or upstream edits/downloads.
Source evidence is distinct from Splicore traffic acceptance.

| Capability | Actual source | Decision |
| --- | --- | --- |
| Linux TUN | sing-tun tun_linux.go: TUNSETIFF, addresses, device ownership | Reuse `tun.New`; refuse an existing interface name |
| Windows TUN | public pinned Wintun adapter/session API, winipcfg, SetupAPI | Separate owned creation/session and GUID recovery; operator supplies driver; aggregate activation still guarded |
| IPv4/IPv6 TCP/UDP | sing-tun stack.go, stack_system.go, UDP NAT | Reuse official gVisor stack on both platforms; qualify each family separately |
| Privileges | Linux device/netlink; Windows adapter/IP helper | Linux CAP_NET_ADMIN, Windows elevation for TUN/routes |
| Driver | cached Wintun Go wrapper `0fa3db229ce2`, dll.go | Loads `wintun.dll`; DLL is not embedded or downloaded |
| Driver version/license | wrapper LICENSE MIT, `wintun.Version` | Runtime DLL version is operator evidence; no approved DLL artifact yet |
| Auto-route | sing-tun tun_linux.go / tun_windows.go | Splicore owns an explicit platform plan and journal instead |
| DNS | upstream DNS native/hijack modes change host settings | Explicitly disable automatic upstream DNS mutation; intercept UDP/TCP53 in shared Phase 12 engine |
| Strict-route | Linux policy rules, Windows WFP filters | Full upstream strict-route is not the initial owned adapter surface |
| Interface monitoring | sing-tun `monitor_*`, network manager | Existing managed boxes use a static monitor; roaming needs separate ownership qualification |
| System proxy | sing-box `common/settings/proxy_*` | Existing Disable clears settings; exact restore needs a new owned adapter |

## Ownership plan

LocalInbound remains the client identity; typed TUN/HTTP settings use the same
runtime, graph, registry and counters as SOCKS. HostRouteManager/SystemProxyManager
are platform ports, with immutable mutation plans. SQLite stores desired intent;
a private durable journal stores only operational previous/desired states.
Persist intent before a host write, verify writes, compensate in reverse order.
Compare current state with both previous and installed states during recovery;
external changes cause a conflict, never a blind overwrite or routing-table flush.
The TUN adapter uses external configuration where supported so upstream cleanup
does not compete with this owner. Interface creation and route capture are distinct;
auto-route is opt-in. Endpoint/bootstrap bypass must be prepared before capture.
Default routes, VPN tables, user shell profiles and unrelated proxies are protected.

## Qualification environment

Maintainer explicitly chose existing local Windows/WSL only. No changes to the
Windows development host routes, DNS, registry proxy or drivers are authorized for
tests. Linux packet/route tests use disposable network/mount namespaces with
synthetic fixtures. WSL evidence never certifies native Ubuntu host networking.
Windows mocks/build/tests do not certify a real driver/elevated TUN/system proxy.
Native Linux auto-route and Windows host integration qualification remain pending.
macOS is not implemented/certified; FakeIP, DoH and full roaming remain deferred.

All Phase 0–12 historical reports and migrations are immutable. New evidence stays
in `D:/splicore-validation/phase13-20261003`; stage/commit/push/tag/release NONE.

## Completed stack ownership audit

The official system stack on Windows can mutate firewall state and has partial-start
cleanup assumptions; it is not used. Both platforms use gVisor. Pre-create its endpoint
before Start, then close the owned endpoint on failure; fixed NIC/protocol/buffer
options avoid user-controlled partial initialization. No recover or sanitizer switch.
Upstream `tun.New` loses its handle on partial session failure. Splicore now bypasses
that constructor using existing public Wintun adapter/session APIs, without editing
upstream. Exact GUID/service recovery and typed LAN WinINET API snapshots are
implemented with stateful failure fixtures. Unified runtime underlay wiring now
passes actual-adapter/fake Windows integration; real Windows TUN/proxy guards and
auto-route rejection remain before OS mutation pending platform qualification.
Ownership evidence: `D:/splicore-validation/phase13-windows-20261004`; current closure:
`D:/splicore-validation/phase13-underlay-20261004`. See the
[underlay report](../reports/PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md).
The lack of an isolated native qualification machine is a separate limitation.
See [Windows](../PLATFORM_WINDOWS.md).
