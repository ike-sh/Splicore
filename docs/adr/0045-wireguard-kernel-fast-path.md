# 0045: Linux WireGuard kernel backend

Status: Phase36 implementation; independent review required.

## Decision

Add `backend: userspace | kernel | auto` to the existing Core WireGuard endpoint
configuration. Omission means `userspace`. The frozen official wireguard-go pin
and Phase34 userspace qualification remain unchanged. Backend selection is runtime
state beneath Application Service, never a new Node, outbound protocol, route
policy or system VPN manager.

The Linux backend creates a native WireGuard link in its caller's birth network
namespace, then moves that link to an anonymous, exclusively owned namespace.
WireGuard's encrypted UDP sockets retain their birth namespace. Cleartext TCP/UDP
sockets use the Linux stack in the private namespace. A pinned thread executor
saves/restores the actual thread namespace and joins every operation. Only non-main
OS threads may enter the private namespace; m0 delegates while remaining unchanged.
A failed restore is fatal and prevents fallback. The locked worker exits, and the
caller confirms its OS thread disappeared before resource rollback.

Native rtnetlink owns links, movement, addresses and private routes. Official
wgctrl-go owns Generic Netlink device configuration/readback. Namespace-local
nftables TPROXY converts arbitrary decrypted destinations into Core ingress
without a gVisor or wireguard-go data plane. Conntrack reply direction preserves
the ordinary outbound socket return path. These private rules and local routes
are necessary to preserve Phase34's arbitrary-target inbound contract. No host
route, rule, firewall or DNS state is changed by the kernel backend.

Config validation, initial Core endpoint DNS, AllowedIPs credential identity,
association DNS/MTU enforcement, routing, service ownership and generation replace
remain shared. Explicit kernel failure is surfaced with classification and causal
errno. Auto can fall back only from classified environmental unavailability after
complete rollback, before activation. Cleanup errors, configuration errors, DNS
errors, cancellation and invariant failures cannot fall back. An active backend
never changes identity. Replace closes the old generation before starting the new
one, preserving the frozen model; there is no new live peer update or DNS timer.

Inner IPv6 link-local sockets pass the owned target-namespace WG interface index
directly as the native sockaddr scope ID. Go zone strings and its process-wide
interface cache are never scope authority. Logical Core addresses and persisted
config retain no interface zone.

See [implementation architecture](../architecture/WIREGUARD_KERNEL_FAST_PATH.md)
for the capability model, dependencies, config and resource ownership.
