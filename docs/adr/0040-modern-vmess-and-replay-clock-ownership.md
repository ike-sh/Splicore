# ADR 0040: Modern VMess and replay/clock ownership

- Status: Proposed
- Date: 2026-10-07
- Phase: 19 implementation; independent review pending

## Context

The independent native core needs current VMess TCP/UDP compatibility without
adding a second account system, external core or legacy transport stack. AEAD
authentication depends on serialized wall time and replay history. Listener
replacement occurs during generic managed transactions; putting replay state
inside a listener would permit captured authentication after replacement.

## Decision

Support modern AEAD, alterId0, raw TCP/shared verified TLS and standard
destination-bound command-2 UDP. Defer legacy authentication, Mux/XUDP and other
transports. Payload modes resolve to AES-GCM, ChaCha or none with exact peer wire
behavior. Reject optional authenticated-length until a canonical construction
meets the required nonce separation; do not invent incompatible encryption.

The native VMess compiler owns one bounded, generation-independent replay bank.
Atomic admission reserves AuthID and both directional session contexts. Capacity
fails closed rather than evicting admissible entries. Expiry follows inclusive
±120 seconds and timestamp+120; a wall-clock high-water mark guards rollback.
The wire accepts an explicit time value; internal relay timeouts remain shared
monotonic socket/timer lifecycles. The bank creates no periodic worker or FD.

Keep encrypted generic UUID credentials, Application Service transactions,
client flow registry, packet queue, relay, TLS, underlay and stats as the owners
of their existing concerns. No protocol-local DNS, routing, database or duplicated
destination registry is introduced.

## Consequences

Replay remains rejected across listener generations and user transactions.
Admission may reject all new connections while the bounded bank is full; sixteen
users and five-second/512-socket handshake limits bound unauthenticated work.
Replay history is in-process, expires lazily and is not persisted across restart.
Large clock rollback can temporarily deny otherwise clock-valid requests until
the high-water acceptance boundary is reached. These limits must remain explicit
in diagnostics/evidence rather than being presented as platform certification.

Management imports reject unsupported legacy, transport and security options
without coercing them. Explicit CA exports must remain faithful. Generic resource
and runtime tests remain mandatory alongside wire oracles and independent peers.

## References

- [Native VMess runtime](../architecture/VMESS_RUNTIME.md)
- [Phase 19 implementation report](../reports/PHASE19_NATIVE_VMESS_IMPLEMENTATION_REPORT.md)
- [VMess wire specification](https://www.v2fly.org/en_US/developer/protocols/vmess.html)
- External pinned source/vector provenance in the Phase 19 evidence directory.
