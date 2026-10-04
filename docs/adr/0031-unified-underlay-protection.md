# Unified Underlay Protection Contract

- Documentation status: Canonical
- Audience: Runtime and platform maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Socket protection and generation ownership across runtime adapters.
- Lifecycle: Preserve the accepted contract; update with qualified mechanisms.

## Status

Accepted for the Experimental Phase 13 local freeze. Real Windows activation remains guarded.

## Problem

After TUN routing selects DIRECT or a proxy, an ordinary runtime socket can re-enter
TUN. Both client proxy underlays and server final-target sockets need protection in
a shared daemon. DNS/bootstrap/health, QUIC, embedded Mieru and external Xray create
sockets through different APIs. First-start endpoint exclusions cannot protect fresh
DNS addresses, arbitrary targets, retained sockets or shared runtime references.

## Decision

One daemon-shared typed factory supplies purpose/runtime/generation capabilities.
Logical routing/DNS/policy selects before protection. TCP and packet constructors
use mature socket controls. Native adapters wrap official registries/NetworkManager
in isolated service contexts; explicit final DIRECT avoids implicit construction.
Official Mieru Dialer/PacketDialer/Resolver hooks retain socket ownership.
Constructors require an explicit provider even with TUN disabled. Missing required
capabilities reject construction.

External Xray uses an EngineUnderlayPlan bound to actual child generation/PID and a
verified inherited Linux UID/main-table strategy. Preflight occurs before launch;
sole process Wait and all socket workers complete before reference release. Required
Windows child bypass is unavailable and rejects. Official sockopt mark/interface
fields were audited but no renderer/artifact/source or wire change is needed.

## Lease and generation lifetime

Snapshot leases are distinct from TUN/interface journal and child generations.
Fresh bootstrap precedes reuse-key calculation; resolved address sets are immutable.
Provision/readback precede publication. Effective set is desired plus retained refs;
A/B/DNS sharing one address cannot cause early deletion. QUIC/UDP/DNS own refs for
runtime/association/socket lifetimes, not individual streams/packets/queries.
Reused TUN reconciles new leases without recreation. Resolution/provision failure
preserves old working runtime. Cleanup failure retains debt and degrades status.

## Platform and resolver boundary

Linux applies official socket RoutingMark and existing journaled UID/main-table
rules, including existing sockets and child processes. Host resource readback gates
publication and subsequent protected control. Windows composes official interface
binding, bounded infrastructure endpoint routes, transactional journal and readback.
Fake backend integration qualifies implementation; the real backend stays blocked.

System DNS cannot delegate to an unprotected stub/API/mDNS forwarder. Required
Windows System APIs and Linux loopback stubs reject. Native required System address
resolution uses the provider; no-TUN preserves official behavior. Xray child stubs
reject before required activation/launch. Explicit bootstrap-safe UDP/TCP/DoT
configuration preserves DNS semantics and original DoT SNI.

## Crash recovery and privacy

Recover recorded owned mutations against observed OS state before canonical desired
restoration. Never recreate references to dead sockets, delete borrowed resources or
overwrite unknown external changes. Journal failures retain exact debt. Diagnostics
contain strategy, generations/counts/error classes, never arbitrary destination
history or secrets. Narrow metadata/reconciliation locks do not serialize payload.

## Verification and limits

Actual adapters + stateful fake host spies, generation/shared/dynamic/reused fixtures,
default race/checkptr, ten repetitions and reviewed static socket inventory are
combined with isolated Linux kernel/service qualification. Real Windows TUN/
auto-route/WinINET, native Ubuntu and arm64 runtime remain NOT CERTIFIED.
No-TUN paths mutate no host or socket protection state and require no privilege.
See [system integration](../SYSTEM_INTEGRATION.md) and [testing](../TESTING.md).
