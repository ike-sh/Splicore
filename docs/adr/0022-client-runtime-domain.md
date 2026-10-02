# ADR 0022: Client Runtime Domain and Node/Outbound Separation

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Rationale for the shared daemon and canonical client resources.
- Lifecycle: Preserve rationale; supersede with a new ADR when the decision changes.

## Status

Accepted for the Phase 10 Experimental local freeze. No stable or public release.

## Context

Server-only control state and exported third-party profiles cannot express owned
client listeners, remote resource identity, engine placement, health and routes.
The first real client slice must coexist with existing server protocols, without
duplicating wire code, credential storage or the daemon/service control plane.

## Decision

RemoteNode is the canonical remote resource; Outbound is an engine-specific use of
that resource. This permits independent lifecycle and future multiple placements
without name-based relations or engine JSON as authority. Server Account represents
an accessing user; RemoteNode represents a resource this machine connects to. They
have separate identity and ownership semantics. Remote credentials extend the
existing vault with a node owner rather than a protocol-specific Node secret field.

ClientProfile remains an export projection for third-party clients. Client ProfileState
owns committed intent and runtime outbounds remain ephemeral adapters. SQLite is
authority for both roles; one Application, API, CLI, binary and systemd service restore
both. This reuses transactional revision/security boundaries and enables server/client
coexistence and partial failure isolation.

Start with loopback-only no-auth SOCKS5 TCP, DIRECT and Snell/native. Reuse inherited
SOCKS codecs and Snell wire implementation behind ports. Publish immutable generations
after commit, retaining established session references during routing/credential changes.
Narrow synchronization protects ownership; payload copying has independent buffers.

## Alternatives and consequences

A second client service would duplicate management and recovery and complicate
coexistence. Storing runtime configuration as Node would tie identity to one engine.
Using Accounts as Nodes would conflate authorization with remote resources. Direct
ClientProfile-to-runtime conversion would omit runtime authority and lifecycle.

SOCKS-first creates a measurable TCP slice before introducing TUN, DNS interception
or policy complexity. Local SOCKS UDP is explicitly deferred although the remote
Snell adapter has UDP. Minimal route selection and passive health are bounded;
advanced routing/DNS/groups/probes and other proxy outbounds need later qualification.
Client stats are separate observational dimensions and cannot be summed for billing.

See [client runtime](../architecture/CLIENT_RUNTIME.md), [routing](../architecture/ROUTING_MODEL.md)
and [tests](../testing/TEST_STRATEGY.md).
