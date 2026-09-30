# Future native protocol guidelines

- Documentation status: Canonical
- Audience: Protocol and security developers
- Last reviewed: 2026-10-01
- Owner: Protocol maintainers
- Responsibility: Future wire specification, independent reference, security and qualification rules.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Source extension sequence: specification → state machine/packet diagrams → test
vectors → independent reference → native adapter/registration → fuzz/race/interop →
security review → experimental/beta/stable. No new protocol implemented in Phase 0.

Design may define framing, multiplexing, negotiation, sessions, padding and traffic
shaping. Use established cryptographic primitives and reviewed constructions for
encryption/hashing/key exchange/randomness; do not invent new algorithms or infer
security from obscurity. Cryptographic RNG, authenticated negotiation, nonce
uniqueness/rekey/replay behavior, failure handling and downgrade resistance must
be specified and reviewed.

Document bounded frame lengths/allocations, parser states, fragmentation/reassembly,
timeouts/idle limits, stream fairness/backpressure, cancellation, UDP behavior,
MTU overhead, IPv4/IPv6/domain encoding and resource exhaustion controls. Define
authenticated identity extraction and byte accounting points before implementation.
Apply expiry/quota/rate/session policy after authentication without bypass paths.

New wire behavior gets its own protocol/feature ID and version. Existing Snell,
Hysteria2, TUIC or VLESS profiles preserve standard wire semantics by default;
no unannounced private fields/handshakes. Interoperability claims name exact
client versions/features and an executable independent implementation.

ClientProfile and exporters must reject unsupported clients. Protocol registration
declares capabilities and schema/ABI requirements, uses protocol-specific settings
and credentials, and requires no Account/Usage/Subscription schema change.
Do not use a raw settings blob to expose arbitrary socket paths/process commands.

Before stable: invalid/truncated/oversized frames, auth failures, replay, concurrent
users, large/UDP/reconnect/restart tests, parser fuzzing, lifecycle leak/race tests,
failure injection and security review. Publish compatibility specification and
vectors with the future release; Phase 0 establishes requirements only.
