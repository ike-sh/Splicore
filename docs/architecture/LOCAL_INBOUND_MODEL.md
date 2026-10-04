# Local Inbound Model

- Documentation status: Canonical
- Audience: Core developers and operators
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Canonical SOCKS, HTTP, mixed and TUN ingress.
- Lifecycle: Update with the supported ownership and qualification boundary.

LocalInbound is a client identity, separate from the server Inbound. Kinds are
`socks5`, `http`, `mixed`, `tun`; all share the client generation and outbound graph.
SOCKS/HTTP/mixed require a literal loopback IP and port. Mixed examines the first byte
then dispatches to the existing SOCKS path or HTTP path. These listeners have no LAN
authentication surface and reject non-loopback binds.

TUN uses typed `tun` settings and omits `listen`. One TUN per runtime; addresses are
one IPv4 and/or IPv6 host prefix with a usable adjacent gateway. Interface names are
portable bounded labels; MTU is 1280–9000 (the acceptance fixture uses 1500).
`auto_route` defaults false; include/exclude prefixes require explicit capture.
The supported stack is `gvisor`; unsupported stack/platform/build rejects before
activation. Address overlap, interface name collision and occupied routing resources
reject. No transient platform index is persisted as canonical identity.

Active TUN settings edits require stop first. Ordinary routing/policy changes reuse
the device and preserve existing TCP/UDP generations. UDP has one destination/member
per upstream NAT flow, two-minute idle expiry, bounded 4096 sessions, owned direction
buffers and joined shutdown. DNS callback payload is copied before asynchronous use.

HTTP supports CONNECT with buffered payload and plain HTTP one request per socket.
Header parsing is bounded to 64 KiB; hop-by-hop and proxy credential fields are
removed, including duplicate Connection nominations. Shared DNS/policy selects the
outbound, with no environment proxy fallback or transparent HTTPS interception.

See [host integration](../SYSTEM_INTEGRATION.md) and [routing](ROUTING_MODEL.md).
