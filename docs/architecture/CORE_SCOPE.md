# Splicore Core scope

Splicore is an independent proxy core usable as Server Core and Client Core.

Core includes native proxy protocols and stream transports, TLS, local
SOCKS5/HTTP/Mixed/TUN entry, routing, DNS, policy, nodes/providers, API/CLI,
accounts, credentials, bindings, SQLite, backup/restore, stats, doctor, support
bundles and necessary native distribution/service lifecycle assets.

GUI, tray, desktop startup UX, desktop system proxy/PAC ownership and
Android/Apple/Desktop application shells are upper-layer products. Native OS
adapters are retained where required for Core networking; Windows TUN belongs
to Core, Windows desktop system proxy control does not. Container distribution
is outside the public Core source surface.

External Xray, sing-box and Mihomo runtime processes are not required or bundled.
VLESS supports native Vision over raw TLS 1.3 or REALITY. Its optional TCP
FinalMask chain supports header-custom, fragment and Sudoku. AnyTLS provides
native client/server TLS sessions with TCP, UoT2, reuse, multiplexing and padding.
See [capabilities](CAPABILITY_MATRIX.md), [VLESS](../protocol/VLESS.md),
[FinalMask](FINALMASK.md) and [AnyTLS](ANYTLS.md).

## Persistent compatibility

Embedded SQL migrations retain historical schema compatibility. The legacy
`client_host_profiles` table is inert: current Core does not read/write it as
desired state. Physical backups preserve it; current configuration exports omit
it. Obsolete desktop configuration fields are rejected. Legacy recovery journal
debt can be retained as opaque history and diagnosed without desktop OS writes.

Platform support is experimental and partially qualified. Linux arm64 is
build-only; Linux auto-route and real Windows host networking remain partly
unqualified. See [operations](../OPERATIONS.md).
