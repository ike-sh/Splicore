# Engine model

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental; Phase 14 local freeze

`Protocol != Engine`: ProtocolKey identifies wire/version/profile intent. EngineID
selects a compiled Splicore implementation. It is a domain abstraction and does
not grant Splicore ownership of third-party cores.

The current registry contains **native only**. VLESS maps to native, along with
Snell, Hysteria2, TUIC and Mieru. DIRECT/REJECT are builtins. Exact unsupported
outbound protocol/engine pairs return `UnsupportedEngineForProtocol`; no fallback
or implicit conversion occurs.

## Composition and ownership

[NativeCore](../../internal/splicore/registry/native_core.go) composes immutable
protocol, engine and exporter registries. Engine metadata retains independent
roles, ABI and protocol placement. EffectiveCapabilities intersects protocol and
engine support. EngineStatus reports compiled identity/availability only.

Native adapters own private Box/context or official embedded Mieru API instances.
Prepare validates and builds a candidate, Start checks admission/health, SQLite
commits, and Activate publishes it. Failure compensates the candidate and retains
the previous generation. A server generation owns bindings/stats and its underlay
scope. Client snapshots retain adapter leases until every old session releases.
Unchanged effective settings reuse adapters; name/metadata updates keep identity.

Mieru uses official v3.38.0 Go APIs, without a permanent external process. Its
injected socket owner cancels pending operations, closes raw/logical sockets and
joins operations. Global SDK metrics never become attributed Splicore counters.
See [client ownership](CLIENT_RUNTIME.md) and [Mieru](MIERU_INTEGRATION.md).

## VLESS boundary

Native VLESS plain/TLS/REALITY flow-none remains Experimental. TCP/XUDP,
IPv4/IPv6/domain, UUID and explicit trust retain their canonical contracts.
REALITY requires `with_utls`. Vision rejects as Deferred/Unsupported.

FinalMask/Sudoku are out of scope. Splicore has no external runtime supervisor,
Xray configuration renderer, artifact requirement, child socket protector or
engine-specific status/health surface. Ordinary VLESS ClientProfile export to an
external client's format is independent of engine ownership and may remain.

## Experimental upgrade

Generic persisted engine fields remain. Preflight rejects any retired Xray
inbound/outbound/provider or transport-mask intent, including disabled records,
before migration/replacement. Data and history remain intact. Remove those
records with the previous experimental build, then upgrade; never relabel them
native. A legacy bootstrap/receipt can be read only by the installer to remove
retired metadata after successful preflight. Normal `serve` remains strict.

[ADR 0035](../adr/0035-xray-runtime-removed-from-core.md) supersedes the Phase 6/7
runtime direction. Historical ADRs/reports are preserved. Independent future
Xray deployment belongs to [NoBrand orchestration](../integration/NOBRAND_MIGRATION.md).
