# 0044: Native userspace WireGuard endpoint

Status: Proposed, Phase34 implementation; independent review required.

## Decision

A WireGuard endpoint is a symmetric L3 network endpoint, owned by Application
Service. One endpoint owns one unmodified official wireguard-go Device, one
protected UDP bind, a bounded memory TUN and one instance of the existing
`nativetun` gVisor stack. The stack handles both inbound flow conversion and
outbound TCP/UDP sockets. Production does not import upstream `tun/netstack`,
create system interfaces, invoke external programs, or require privileges.

Official module: `golang.zx2c4.com/wireguard` at
`v0.0.0-20261024220952-b3bc704ef0ee`, full revision
`b3bc704ef0ee21a36298601a9e1e5ff90377ac52`. Noise, crypto, handshake state,
replay checks, AllowedIPs source validation and authenticated roaming belong to
that engine. No fork, reflection, unsafe access or private-API hooks are used.

## Authenticated identity

The upstream exported TUN interface supplies decrypted IP packets without a
peer parameter. Its receive path authenticates and checks replay, then verifies
that the packet source's longest-prefix AllowedIPs owner is the authenticating
peer before delivering to TUN (`device/receive.go`, `RoutineSequentialReceiver`).
Splicore's private bridge is connected only to that Device. Its immutable
AllowedIPs table mirrors the engine's table for the entire Device lifetime;
source lookup at this trusted boundary therefore yields the authenticated public
key. The dispatcher adds endpoint tag and public key to Core context, routing
queries and safe session views. It rejects locally originated source addresses.
No outer UDP address or arbitrary application-supplied source identifies peers.
Equal prefixes assigned more than once are rejected; overlaps use longest-prefix
routing, independent of declaration order. Credential identity is separate from
server account/binding identity.

## Routing and DNS

Typed `kind: endpoint` outbounds borrow a Service-owned endpoint by tag. Local
endpoint inbound bindings enter the same TCP/UDP relay, policy, statistics and
session lifecycle as native TUN ingress, with no host listener. Endpoint configs
live in bootstrap `wireguard_endpoints` or the running Service registry; secrets
are not copied into persisted client profiles. Recreate runtime-created endpoints
before restoring profiles that reference them, or retain them in bootstrap.

Normal routes may match `endpoint_tags` and `peer_public_keys`. Native server
targets use a protocol-independent `ports.TargetRouter` boundary. Server routing
is explicitly enabled by a **top-level** route rule containing `server_inbounds`;
that rule may also reference rulesets. Server queries match only such explicitly
scoped rules and fall back to Direct. This avoids feeding a server's target back
into its own client proxy through an unrelated client final route. Existing
native server policy/account enforcement stays at its original boundary.

Peer endpoint names use Core bootstrap DNS; inner application names use Core
application DNS. Managed DNS errors fail closed, without ambient fallback.
Without managed DNS, existing explicit Core system-bootstrap policy applies.
Only numeric UDP endpoints are handed to the official engine.

## Ownership and limits

Endpoint states are CREATED, STARTING, ACTIVE, CLOSING, CLOSED. Service owns
endpoint generations; snapshots borrow dialers and own their flow sockets.
Closing cancels and joins pending resolutions/dials, closes the stack and its
sockets/workers, closes and waits for the Device, closes the exact UDP bind and
TUN, and drains both TUN queues. Each queue is bounded to 256 packets. Each
registry is bounded to 64 tags, each endpoint to 128 peers. Core ingress retains
its existing 4096-flow limit. UDP payloads beyond inner MTU are rejected. Default
MTU is 1420; supported bounds are 1280–9000.

Explicit `replace` closes and joins the complete old generation before starting
the replacement and resolving peer names again. Existing flows end. There is no
live mutation of the trusted identity table, periodic DNS worker, separate
keepalive layer or independent peer timer owner. Upstream Device owns peer
workers and standard keepalive timers. A failed replacement remains CLOSED and
inspectable; replacement is deliberately not a seamless transactional handoff.

## Control

`splicore wireguard keygen` explicitly outputs PrivateKey/PublicKey. Normal
formatting/config serialization and status never disclose private/PSK bytes.
API `/api/v1/wireguard/endpoints` supports list/create, `/validate`, `/{tag}`
status and `/{tag}/start`, `/close`, `/replace` POST operations. CLI
`wireguard validate|create|replace --file endpoint.json --config bootstrap.yaml`
and `wireguard list|status|start|close` use the same Application Service.

Standard reserved bytes only: nonzero values are rejected. Provider extensions,
outer obfuscation, privileged fast paths and automatic DNS refresh are out of
scope. Test/reference subprocesses and kernel interfaces are external validation
only. This implementation does not authorize publication or Freeze.
