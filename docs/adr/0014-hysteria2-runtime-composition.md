# ADR 0014: Owned Hysteria2 service and UDP lifecycle

- Documentation status: Canonical
- Audience: Core maintainers and architecture reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Record the Phase 3 composition and its alternatives.
- Lifecycle: Review with native HY2 constructor, lifecycle or user-update changes.

## Status

Proposed for maintainer review; implemented experimentally in Phase 3.

Phase 3 freeze review permits the local Experimental slice. This does not promote
HY2 to Stable or blanket-accept the proposed ADR catalogue.

## Context

The pinned stock inbound owns its UDP listener privately and exposes no admission
gate or safe user replacement port. Its sing-quic v0.7.0 service replaces an
unsynchronized password map through UpdateUsers. Calling it during serving would
violate race and authorization guarantees. Phase 3 requires multi-user QUIC,
transactional activation, revocation, rollback and honest capabilities.

## Decision

Compose the exact library service used by the stock inbound with sing-box's TLS
server constructor, native Router, direct outbound and the existing static platform.
Own the UDP PacketConn and pass it to Service.Start. Drop reads before commit.
Do not copy wire, framing, QUIC, TLS or congestion code. Static TLS is validated
and snapshotted into inline options without a file watcher. The same Native Engine
dispatches Snell and Hysteria2 compilers; there is one shared lifecycle port.

Authenticated library identities are immutable Binding IDs. Router trackers meter
authenticated payload and routed sessions at Inbound/Binding scope. Counters reset
with runtime generation and do not imply durable quota enforcement.

Replace an affected Inbound to enable/disable a Binding. Construct a fresh user
map before serving; close existing sessions; journal/start/health/commit/admit the
candidate; reconstruct the committed prior intent on failure. Declare
HotUserUpdate=false and Users=Restart. Keep the UDP socket writable for a bounded
100 ms after cancellation, before closing the library listener/transport, to let
authenticated session callbacks emit QUIC close frames. Client reconnect is required.

## Alternatives and consequences

- Stock private listener cannot enforce precommit admission without an upstream patch.
- Live UpdateUsers cannot be used safely with this baseline.
- Duplicating the protocol or globally stopping Splicore would enlarge the scope.
- Library-level composition stays mergeable but must track the stock inbound's
  service/TLS dependencies during upgrades; it is an explicit realization deviation
  from using its outer NewInbound constructor.
- Session interruption and counter reset are visible limitations. Rollback is
  compensation, not atomicity between SQLite and a UDP socket.
- No upstream runtime source file is modified.

## Freeze review and follow-up

Classification: **NON-BLOCKING TECHNICAL DEBT**. Shared generic password,
multi-Binding/TLS/stats contracts were necessary to realize this second protocol.
Native compiler and exporter maps, committed SQLite authority, separate
Account/Binding/Credential and ClientProfile/runtime boundaries remain effective.
The shared create coordinator and per-Inbound replacement compensation avoid
duplicating the transactional control plane. Protocol modules have no HTTP/SQL
dependency; Engine options and private keys remain in the runtime adapter.

The present typed creation builders/public commands, SQLite display allowlist,
Phase2-to-Phase3 composition chain and placement of shared methods in protocol-named
files impose bounded extension work. Target: **Phase 4**, triggered by adding a
third creation command, its display mutation or runtime composition. Review and
introduce registered creation commands, move display availability into the service,
assemble direct registry entries and relocate shared methods before repeating
those patterns for TUIC. Preserve typed validation, API compatibility and existing
transaction/recovery tests. No Account/Binding schema redesign or second coordinator
is needed. The exact counts, affected files and triggers are maintained in the
[architecture disposition](../ARCHITECTURE.md#phase-3-extensibility-disposition).
This freeze performs documentation updates only; TUIC work has not started.

See [managed profile](../protocol/HYSTERIA2.md) and
[Phase 3 report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).
