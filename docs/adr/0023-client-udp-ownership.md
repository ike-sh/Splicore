# ADR 0023: Client UDP and adapter ownership

- Documentation status: Canonical
- Audience: Core and runtime reviewers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: SOCKS UDP lifetime and shared adapter lease decisions.
- Lifecycle: Preserve the accepted ownership boundary; update through reviewed runtime changes.

## Status

Accepted for the Phase 11 Experimental local freeze. Runtime and platform
qualification remain bounded by the [freeze report](../reports/PHASE_11_FREEZE_REPORT.md).

## Context

Six outbound pairs share one daemon. Rebuilding every adapter on route mutation
would disrupt independent sessions. UDP needs explicit source and worker ownership.

## Decision

Retain the registry and immutable committed generations. Reference-count per-adapter
leases by effective canonical settings and credential ID. Reuse unchanged leases,
retain old generations for TCP streams, and release candidate refs on abort. Explicit
restart rebuilds. Per-lease health prevents retired traffic changing replacement health.

Each UDP control TCP connection owns a loopback relay. Validate peer IP and fixed/
first-valid source port; discard fragments and bound flows to 32. Buffers are private,
pool encoding copies before release. EOF/timeout/reconcile/shutdown closes sockets and
joins workers before generation release. Native constructors, official Mieru APIs and
the original Xray supervisor remain wire owners. No new engine/supervisor/switch/schema.

## Consequences and validation

UDP associations/packets and TCP sessions are distinct counters. Snell/Mieru UDP
targets resolve locally because frozen response APIs require IP headers; other proxy
UDP targets resolve remotely. Canonical domains persist. Advanced DNS/policy/TUN and
Vision remain deferred.

Default race/checkptr, shared races, ten lifecycle runs, source ownership, adapter
self interop and installed failure isolation are gates. Mieru exposes no client
event-loop join; owned raw close plus observed stack/socket cleanup qualifies exit.
See [Client Runtime](../architecture/CLIENT_RUNTIME.md).
