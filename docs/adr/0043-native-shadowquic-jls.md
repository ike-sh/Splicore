# ADR 0043: Native ShadowQUIC with isolated JLS libraries

- Documentation status: Draft
- Audience: Core and protocol maintainers
- Last reviewed: 2026-10-21
- Owner: Architecture maintainers
- Responsibility: ShadowQUIC protocol ownership and the JLS library boundary.
- Lifecycle: Revisit after independent implementation review or JLS API changes.

## Status

Proposed; implementation candidate. This document does not accept or freeze it.

## Context

[ShadowQUIC](https://github.com/spongebob888/shadowquic/tree/bb82cce54b61a4fc3112f664a71e07fd34775c13)
is a complete proxy protocol with an unversioned command/address grammar, QUIC
multiplexing and JLS v3 authentication of TLS Hello messages. Existing accepted
QUIC stacks expose ordinary Go TLS and cannot express the required JLS hooks.
A new auth stream or a global certificate override would change the protocol.

## Proposed decision

Keep the Splicore-owned command, UDP CID, identity and lifecycle code in a
private protocol package. Add independent `metacubex/jls-quic-go` at
`732f2fc9a34de12a58020a0ca75bf336095aed93` and `metacubex/jls-tls` at
`67adc0e2f79630fcf80f0b65278d4d1a094b812b` solely for this protocol. Neither
Mihomo Core nor a reference executable is a production dependency. Existing
QUIC consumers keep their stacks. JLS is an explicit client security kind.

Only authenticated JLS sessions may carry proxy commands. Disable resumption
and 0-RTT. Native credentials remain separately owned records. QUIC owns
congestion control and TLS cryptography; Splicore owns bounded command/packet
state, native runtime admission, protected sockets, cancellation and statistics.
The camouflage peer is explicit. When a Core DNS generation exists, resolve its
hostname through bootstrap DNS before constructing the server's protected
numeric packet-socket factory. Lookup failure is terminal; unauthenticated
traffic cannot trigger ambient DNS fallback. Server-only operation retains the
existing system-DNS policy when no client DNS generation is configured.

## Alternatives considered

- Existing standard/apernet QUIC stacks: lack the JLS TLS API.
- Original JLS QUIC fork: carries prohibited SagerNet module imports.
- Reference executable or another Core: violates native runtime ownership.
- SunnyQUIC authentication command: different authentication semantics.

## Consequences

The additional QUIC/TLS library increases binary size and adds a separate
upstream security/notice maintenance obligation. Pins and full license texts
must remain auditable. The native scope covers TCP and UDP DATAGRAM with
explicit limits; UDP stream mode and remote administration are unsupported.
Official v0.4.4 peers are qualification tools only. Configuration and bounds
are documented in [ShadowQUIC](../protocol/SHADOWQUIC.md).
