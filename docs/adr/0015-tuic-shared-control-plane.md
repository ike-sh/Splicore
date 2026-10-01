# ADR 0015: Registered creation and shared QUIC control plane

- Documentation status: Canonical
- Audience: Developers and acceptance reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Third-protocol extension cost and bounded shared infrastructure.
- Lifecycle: Update with reviewed implementation or qualification changes.

## Status

Proposed for maintainer review; implemented experimentally in Phase 4.
Follows [ADR 0014](0014-hysteria2-runtime-composition.md).

## Decision

Modules implement optional CreationCodec to validate neutral CreationDraft and generate
typed Credential payloads. ProtocolRegistry resolves this port by ID; draft selects an
exact registered wire/profile key. Application owns IDs, Account/Binding/Credential/
Policy construction, protocol-bound HMAC, pending journal, compile/start/health/commit/
admission and compensation. API/CLI dispatch IDs without new protocol branches.
Legacy Snell/HY2 methods/response shapes remain wrappers. Generic routes use uniform
plan/applied shapes, including Snell's one-element Binding list.

Phase4 composition directly registers modules, compilers and exporters; prior phase
fixtures remain. SQL display updates are generic; service checks compiled module and
owned resource. Shared application lifecycle/views/export/plan/Binding mutation move
to bounded files; no third resource builder/coordinator.

TLS trust/model/loading and password rules are shared support. One QUIC handle owns
Box/router/UDP/admission/health/cancellation/close grace and immutable Binding meters.
HY2/TUIC compilers validate intent then supply pinned protocol service factories.
User maps construct before Start; no live UpdateUsers. Snell retains different TCP
mechanics. No upstream wire/service/QUIC/crypto changes.

## Alternatives and limits

Copying HY2 would duplicate lifecycle/TLS/attribution. Stock private inbound cannot
expose commit admission. Adapter composes the same upstream Service/TLS/router.
Service factory interface is only Start(PacketConn)/Close and authenticated handler;
wire/options remain protocol-owned. General Account mutation/rotation/durable usage/
enforcement need separate reviewed contracts. Legacy wrappers retire only through
API review. Optional compiled ports are source ABI, not dynamic plugins.

A fourth TLS/QUIC protocol adds module/codec, small factory, exporter, composition,
fixtures/tests/docs without storage/domain/central runtime switches. Different
listener needs a bounded adapter. See
[architecture](../ARCHITECTURE.md#phase-4-third-protocol-realization).
