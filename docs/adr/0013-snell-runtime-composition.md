# ADR 0013: Owned Snell runtime composition

- Documentation status: Canonical
- Audience: Runtime maintainers and architecture reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Phase 2 listener ownership, Box isolation and network monitor choices.
- Lifecycle: Proposed for maintainer review; revise only with changed implementation evidence.

## Status

Proposed for maintainer review; implemented in the Phase 2 review worktree.

## Context

The stock Snell inbound's listener Close does not own all accepted handshake
sockets. Phase 2 needs pending admission blocking, deterministic shutdown and
rollback without changes to upstream data plane. Real Linux race testing also
found `route.NetworkManager.started` racing the default interface monitor's
startup callback (`route/network.go` post-start write and updateInterface read).

## Decision

Compose one private minimal Box per managed Inbound. Register a wrapper factory
that calls the stock Snell constructor, owns a TCP listener and forwards raw
connections into its existing NewConnection API. The wrapper never starts the
stock listener. It tracks sockets, bounds unauthenticated handshakes, and closes
them on shutdown. Payload/session counters use the standard authenticated router
tracker and sing counter wrappers. SQL commit precedes admission activation.

Use an explicit platform implementation with an inert default interface monitor.
The profile has fixed direct routing, OS-selected egress and no TUN, auto-detect,
WiFi or automatic reset policy. No asynchronous interface callback is needed.
This is normal runtime composition, applied equally with/without race detection;
no test exclusion or race-detector suppression is used. All platform features
outside this profile return unsupported. Upstream files remain unchanged.

## Consequences

Per-Inbound isolation simplifies cleanup and attribution at the cost of separate
Box resources. Phase 2 caps installations at 64 Inbounds; large scale capacity
qualification and a shared engine are deferred. Network changes affect future OS
dials naturally but do not trigger managed session resets. Introducing auto-detect,
TUN, hot route mutation or multi-user profiles requires a new runtime design and
requalification. This refines the existing engine composition direction without
altering protocol semantics or SQLite authority.
