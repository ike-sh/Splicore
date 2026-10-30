# WireGuard kernel fast path

## Configuration

Existing `wireguard_endpoints` entries, API create/replace requests and CLI files
accept the same additional enum:

```yaml
backend: kernel # userspace | kernel | auto; omission means userspace
```

All other Phase34 fields keep their existing validation and limits. Unknown
backend values are rejected. `auto` remains the requested value; the selected
backend is derived runtime status. Endpoint configs remain bootstrap/service
state; client profiles persist only endpoint tag references. No database schema
change or migration is needed. CLI and HTTP continue through Application Service.

## Data plane and namespaces

```text
birth network namespace                 anonymous cleartext namespace
underlay network                        lo + owned WireGuard interface
encrypted kernel UDP sockets    <---->  kernel WireGuard crypto/network stack
                                        kernel TCP/UDP sockets
                                        Core routing and dispatch
```

The link is born in the caller's network namespace, before movement. Its encrypted
UDP socket uses that birth namespace even when the socket is initialized after
movement. Core's numeric cleartext socket operations execute inside the private
namespace, then return to the original thread namespace. Returned sockets retain
their namespace. No process-wide setns or persistent named namespace is used.

Namespace creation and all namespace-dependent socket/control operations use one
executor. Each callback runs in a fresh goroutine with LockOSThread. Before any
namespace change, a worker scheduled on m0 holds that unchanged thread while a
second worker executes elsewhere: Go parks m0 on locked exit instead of destroying
it. The non-main worker saves `/proc/thread-self/ns/net` and verifies restoration
before unlocking, including panic/error/cancellation paths. Restoration failure
is fatal `NAMESPACE_RESTORE_FAILURE`, preserves both operation and restore causes,
and never permits auto fallback. The still-locked non-main worker exits; the
caller waits for its OS thread to disappear before owned-resource rollback.
Cancellation joins the worker rather than abandoning its namespace operation.

Private rtnetlink and netfilter connections are opened without dependency-managed
namespace options inside this executor. Subsequent link/address/route operations
use namespace-bound sockets without changing the caller's namespace. Netfilter
uses an explicitly closed lasting socket with a deadline; unavailable socket
creation returns its causal error before any method can use an absent handle.

Core inbound preserves arbitrary original IP/port destinations using private
namespace nftables TPROXY and local-table routes selected by a private mark.
Conntrack **reply direction** bypasses interception for Core-originated sockets;
established inbound requests continue to their transparent sockets. TCP keeps
kernel half-close semantics. UDP uses transparent connected kernel sockets,
original-destination ancillary data, a 256-datagram bounded queue and mutable
read/write deadlines. A shared 4096-flow limit spans protocols and families.

This does not replace the Core's separate native TUN/gVisor ingress. That ingress
still selects a borrowed endpoint outbound through the existing routing/session
relay. Kernel WG mode creates no wireguard-go Device, memory TUN or WG gVisor stack.

## Routing, DNS and authenticated identity

Inner addresses and masked AllowedIPs routes exist only in the private namespace.
Both default AllowedIPs are supported there. Cryptokey AllowedIPs remain exact
kernel peer state, separate from Linux delivery routes and Core routing policy.
Phase34 rejects equal duplicate prefixes; overlapping prefixes use kernel LPM.
The immutable shared identity table mirrors authenticated receive-source checks.
Roaming changes endpoint addresses, never public-key identity.

Valid inner IPv6 link-local sockets pass the owned target-namespace WG ifindex
straight to `unix.SockaddrInet6.ZoneId`. Bind, TCP connect, UDP sends and connected
transparent ingress replies never resolve a zone string through Go's process-wide
interface-name cache. Ownership and the post-move index are verified through the
namespace-bound rtnetlink handle; scoped operations join before link/namespace
cleanup. Missing or replaced interfaces fail explicitly without runtime failover.

Scoped sockets are nonblocking and CLOEXEC. TCP connect waits in Go's poller,
checks SO_ERROR/getpeername and obeys cancellation and deadlines. FileConn and
FilePacketConn give the standard Go connection its own duplicated FD; the original
FD closes on handoff or failure. Readback zone names are presentation only. Core
peer identity, UDP sources and persisted config retain logical IPs without Linux
scope. IPv4 and global/ULA IPv6 keep their existing socket path. Multiple private
namespaces may reuse addresses and interface names. Outer transport endpoint
zones remain outside the existing public config schema.

All peer FQDNs resolve through existing Core bootstrap DNS before any backend
probe. Only numeric endpoints reach the kernel. Association/application names
continue through Core application DNS. No hidden system resolver or new endpoint
refresh scheduler is introduced. Managed DNS errors fail closed.

Kernel transport uses the existing Core underlay bypass fwmark `0x534c0001`.
When TUN is required, the underlay factory verifies the existing hostnetwork
protection contract. This backend installs no host policy rules. Host default
routes, DNS configuration and firewall are unchanged. The private namespace owns
its TPROXY table, mark rule and local routes; they disappear with the namespace.

## Control, dependencies and privileges

| Responsibility | Native API / exact dependency |
|---|---|
| Device create/delete/move, link up, IPs, routes/rules | rtnetlink; existing vishvananda/netlink v1.3.1 |
| Device/peer SET and multipart GET | WireGuard Generic Netlink; wgctrl-go v0.0.0-20241231184526-a9ab2273dd10 |
| Private transparent ingress | NETLINK_NETFILTER; google/nftables v0.3.0 |
| Namespace descriptors | x/sys unix; existing vishvananda/netns v0.0.5 |
| Userspace engine | unchanged official wireguard-go b3bc704ef0ee21a36298601a9e1e5ff90377ac52 |

wgctrl-go revision is a9ab2273dd1075ea74b88c76f8757f8b4003fcbf (MIT).
nftables revision is 6f574e7fd1b4d07006d1c598cdb9b22789e5e541 (Apache-2.0).
No new CGO requirement. No production wg/ip/wg-quick/shell command dependency.
No kernel installer, explicit module loader, DKMS or service manager integration.
The kernel may autoload its installed modules using normal netlink mechanisms.

| Operation | Required capability and owner namespace |
|---|---|
| Create anonymous network namespace | CAP_SYS_ADMIN in current user namespace |
| Enter/restore network namespace | CAP_SYS_ADMIN in user namespaces owning source/target |
| Create/delete birth link, set ownership alias | CAP_NET_ADMIN in birth network namespace owner |
| Move link | CAP_NET_ADMIN in source and destination network namespace owners |
| WireGuard Generic Netlink set/get | CAP_NET_ADMIN in target owner; birth owner where kernel requires socket reinit |
| Private link/IP/route/rule/netfilter changes | CAP_NET_ADMIN in private namespace owner |
| Transparent socket options | CAP_NET_ADMIN or CAP_NET_RAW in private owner |
| Kernel fwmark | configured through privileged WireGuard Generic Netlink |

UID zero alone does not establish support. Runtime operations detect namespaces,
rtnetlink, kernel WireGuard, Generic Netlink, TPROXY and conntrack availability.
No kernel version string is treated as a feature guarantee. Non-Linux kernel mode
returns UNSUPPORTED_PLATFORM. Linux failures preserve causal errno through
BackendError. Status exposes requested/selected backend, availability, interface
name/index, namespace identities, listen port, fwmark and peer count/counters;
private keys and PSKs never enter status/error formatting.

## Transaction and ownership

An instance gets a random 128-bit non-secret identity. Its interface name is a
deterministic 15-byte `spw` plus 12 hex digits of its identity hash; creation is
exclusive. A separate `splicore:<identity>` alias proves ownership. Linux clears
alias on movement, so it is set/read back in the exclusive target namespace.
Pre-existing links are never adopted or deleted. Any collision fails.

Prepare creates namespace/handles/link and moves the link. Start configures the
official kernel device, loopback, addresses, routes, link state and transparent
listeners. It reads back public key, actual port, mark, exact peer set,
AllowedIPs, PSK semantics, endpoint and keepalive. wgctrl handles fragmented SET
without repeating replace flags and coalesces multipart GET. Only new owned
links use ReplacePeers; partial setup never touches another endpoint's peers.

Close stops new traffic through endpoint cancellation, joins pending DNS/dials,
closes owned cleartext sockets/listeners, joins ingress workers, closes control,
deletes the verified owned interface, closes route clients, then closes the last
anonymous namespace descriptor. Close is idempotent, including partial startup.
Process death releases anonymous namespace handles and its device/socket state;
there is no persistent namespace mount. Unconfirmed cleanup is surfaced and
prevents auto fallback.

Auto fallback is limited to unsupported OS, unavailable kernel WG/netns/netlink/netfilter
facilities or insufficient privilege. It is never used for malformed config,
Core DNS failure, namespace restoration failure, route/config invariants,
cancellation or incomplete rollback. Fatal classes dominate joined errors and
runtime availability telemetry. Owned socket close errors join control/link/
namespace errors in the idempotent Close result.
After ACTIVE, failures remain failures of the selected backend.
