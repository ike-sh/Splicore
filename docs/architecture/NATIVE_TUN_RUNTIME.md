# Splicore Native TUN Runtime

Status: Local Qualification Fix / Native TUN freeze; Platform Qualification not resumed.
ADR 0036 is Accepted for this local checkpoint. QF-003 resolved the inherited libbox profiler
blocker using public Go profiling APIs. Repository-wide default/native Go 1.26
race gates now pass. Native TUN source is unchanged; resource/stress evidence is
source-equivalent. See the implementation and QF-003 reports for gate scope,
and the [freeze report](../reports/QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md)
for the new candidate identity and qualification limits.

## Goals

Splicore owns device use, the actual network stack, NIC, link, packet workers,
flow admission, cancellation and complete teardown. The existing client Manager
owns generations, routing, policy, outbound leases and application sessions.
The host journal continues to own system mutations and device release.

## Non-Goals

No protocol wire changes, new backend selector, copied upstream implementation,
DNS architecture change, GSO expansion or Windows host qualification.

## Dependency Inventory

| Surface | Before | After / decision | Local evidence |
|---|---|---|---|
| A device creation | sing-tun Linux; owned Wintun | REPLACE Linux open; KEEP Wintun | hostnetwork/platform_linux.go, wintun.go |
| B netstack | hidden sing-tun old gVisor | REPLACE with owned official stack | clientruntime/tun_stack_gvisor.go |
| C packet I/O | NativeTun shared iovec; Wintun bridge | REPLACE with owned byte bridge | QF-001 tests, wintun_gvisor_windows.go |
| D TCP | sing-tun forwarder/lazy connection | REPLACE adapter; KEEP Manager relay | clientruntime/tun.go, runtime.go |
| E UDP | sing-tun NAT packet wrapper | REPLACE with connected tuple flow | clientruntime/tun.go |
| F DNS | Splicore DNS Engine | KEEP; WRAP flow handoff | networkruntime, tun.go |
| G routes/system | durable host journal/netlink | KEEP | hostnetwork/platform_linux.go, journal.go |
| H Wintun | owned adapter/session/GUID | KEEP; WRAP byte interrupt boundary | hostnetwork/wintun*.go |
| I Linux TUN | sing-tun NativeTun | REPLACE minimal standard FD adapter | platform_linux.go |
| J GSO | no product enablement/config | DEFERRED; plain packets retained | tun.go/options, domain/client/system.go |
| K checksum | old netstack | REPLACE with official stack checksums | backend link has no checksum offload |
| L MTU | domain 1280–9000, journal | KEEP | domain/client/system.go, hostnetwork |
| M buffers | old PacketBuffer/borrowed scratch | REPLACE explicit packet copies/refs | QF-001, tun.go DNS copy |
| N lifecycle | hidden Stack.Close | REPLACE owned stack Destroy and joins | QF-002 evidence |
| O cancellation | ingress context/Manager sessions | KEEP; add packet interruption | tun.go, runtime.go |
| P tests | QF-001/Phase13/15 | KEEP evidence; ADD native tests | application/*tun*test.go |
| Q build tags | with_gvisor | KEEP inclusion tag; own capability | hostnetwork/capabilities.go |

Inherited adapter/monitor/protocol utility uses of sing-tun and SagerNet gVisor
remain unchanged. They do not own Splicore's client TUN stack. Removing these
modules would cross unrelated inherited capabilities. No module cache patches,
forks, local replaces or copied sing-tun/sing-box netstack code are permitted.

## Ownership

See [resource ownership](TUN_RUNTIME_OWNERSHIP.md). Runtime borrows the device;
its interrupt stops packet I/O without releasing the journal's device handle.
Each successfully admitted flow runs until its synchronous dispatcher returns.
Manager generation references live for that same interval.

## Device Layer

The internal device boundary uses packet Read/Write, Start, Interrupt and Close.
Linux uses a nonblocking, close-on-exec TUN FD and Go's file poller; interruption
sets an expired I/O deadline. Wintun retains its owned session and quit event.
System route/address changes remain journal transactions.

## Netstack Layer

One backend: official `gvisor.dev/gvisor`
`v0.0.0-20261004063249-f57b8fc79db4`, commit
`f57b8fc79db4d392e8246d07e14c0c71e237afe8`, minimum Go 1.26.3.
The adapter holds the actual stack and an owned packet link. Its embedded channel
endpoint provides NIC/inbound delivery; an owned byte queue provides egress.
Backend types never enter
domain, application, routing, policy, persistence or CLI contracts. All protocol
handlers are installed before creating/attaching the NIC or starting ingress.
The channel link has no fdbased dispatcher/eventfd. Total FD equality remains a
hard gate. IPv4 and IPv6 protocols are both included; ICMP product policy is
audited against the previous JudgeFlow rejection contract.

## Packet Ownership

Ingress worker owns reusable read scratch and copies each IP packet into an
owned PacketBuffer. InjectInbound may retain a reference; the worker drops its
reference after injection. The link snapshots all egress bytes synchronously
before returning to the stack. Only immutable owned bytes cross the bounded
asynchronous queue; PacketBuffer/header references do not escape into the device
worker. The writer retains those bytes through synchronous Write return. No
pooling or shared iovec is used. A per-device writer enforces syscall ownership.
Stop rejects writes and joins the in-flight syscall before the journal can
close/reuse its FD. A Runtime has exclusive device use until Wait completes.

## TCP

Official TCP implements the wire stack. Splicore reserves a callback task before
calling the TCP forwarder, so even a callback that has not started is owned by
shutdown. Duplicate tuple admission is bounded. A lazy standard net.Conn
preserves route/policy/outbound rejection before local handshake acceptance.
The first link output after endpoint registration is a public cancellation
barrier: Close can find and Abort an unfinished exact-tuple handshake, then join
creation. Established flows use ordinary Close so queued replies and FIN remain
deliverable. Complete occurs exactly once. Manager owns route selection,
outbound dial and relay. Cancellation callbacks are joined before releasing
the generation that owns connection cleanup.

## UDP

Official connected UDP endpoints preserve the full source/destination tuple.
Splicore hands each flow to existing routing/policy/outbound integration. The
existing two-minute idle default remains. Every response uses that flow's
original destination. Session admission and completion are bounded and joined.
The adapter uses the public PMTUDiscoveryDont socket option on connected UDP
endpoints: this plain packet link supports ordinary stack fragmentation without
segmentation offload. In this exact candidate, the default Want mode can emit
IPv4 fragments with DF and ID zero, which mixes concurrent datagrams; explicit
fragmentation policy and concurrent IPv4/IPv6 4096-byte tests cover that boundary.

## DNS

TCP framing and UDP requests go to the existing DNS Engine. Each UDP query
acquires the current generation; an idle UDP endpoint does not pin an old DNS
profile. TCP retains its stream generation. The engine's
cache, bootstrap, System/UDP/TCP/verified DoT/proxy DNS rules remain authoritative.
DNS work is cancelled and joined with its flow. DoH/FakeIP remain deferred.

## Routing

All accepted flows enter Phase 12 route selection. Backend contains no DIRECT
or proxy choice. REJECT remains an upper-layer decision before TCP acceptance.

## Policy

Selector, URL-Test, Fallback, Load-Balance and affinity remain Manager/network
engine responsibilities. Backend knows only addresses and flow I/O.

## Underlay

Existing classified/protected outbound dialers and generation leases are used.
No direct outbound OS sockets are added to the backend. The host verifier and
daemon-UID bypass continue to prevent capture loops.

## Lifecycle

Prepared → Starting → Running → Draining → Stopping → Stopped; failures retain
a Failed terminal result after cleanup. Start is once-only. Stop before Start,
double/concurrent Close, cancellation and partial Start are defined and tested.
Wait means packet workers, admitted flows and backend workers have completed.
Terminal packet errors remain available after Wait/Close, including errors that
arrive during Start publication. Client status reports a failed TUN as degraded.
The host journal starts the borrowed device before Runtime.Start attaches the
stack; Runtime.Close interrupts use and leaves raw device release to the journal.

## Shutdown

Cancel context and stop flow admission, reject new device writes, interrupt
device I/O, and join the active write. Close tracked TCP/UDP flows, using the
public registration/Abort barrier for incomplete TCP handshakes. Join packet
workers and all reserved callbacks, then official Destroy joins and releases
the actual stack/NIC/link. Explicit link Close drains its owned egress queue.
Finally
the host journal restores owned system state and closes the borrowed device.
Any cleanup error remains visible as debt rather than a success claim.

## Crash Recovery

SIGKILL relies on OS FD/handle reclamation. Restart reconciles SQLite authority
and durable network journal identities; graceful Destroy is not a prerequisite
for recovery. Frozen Phase 15 history is unchanged.

## Platform Boundaries

Real tests run only in owned disposable Linux network namespaces. Their veth
underlay has explicit IPv6 global and link-local identities; suppressing address
generation without link-local addresses breaks later neighbor probes. WSL evidence
does not qualify a native Ubuntu deployment. Windows uses build, unit and safe
fake-driver integration only. Windows routes remain unmutated.

## Dependency Boundaries

Only the exact official stack and necessary transitive metadata may change.
Minimum Go/CI/build docs must agree. Legacy persisted `TUNSettings.Stack` remains
compatibility input; no new selector is introduced. Existing empty/gvisor intent
uses the single backend; historical unsupported system intent stays rejected.
Database migration: NONE. External daemon/binary dependencies: NONE.
