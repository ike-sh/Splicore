# ADR 0037: Native Shadowsocks editions and credential ownership

Status: Accepted

Date: 2026-10-06

## Context

Phase 16 adds standard AEAD Shadowsocks and SIP022/SIP023 to Splicore's own
managed server and client runtimes. Their shared cipher names do not erase the
different identity, framing, timestamp and replay contracts. Existing encrypted
Account/Binding/Credential and RemoteNode models can express both editions.

The cached library service implementations lack some required replay/resource
bounds and have mutable user maps. Patching upstream or copying an external core
would violate the project's ownership and dependency rules.

## Decision

- ProtocolID is `shadowsocks`; WireVersion is `2017` or `2022`; FeatureProfile is
  `base`. EngineID remains `native`. One compiler and outbound family dispatches
  on a validated method. No subprocess or inherited Shadowsocks inbound is used.
- Classic Account credentials use PasswordPayload. SS2022 Account credentials
  use exact-length canonical base64 PSKPayload. AES SIP023 identity credentials
  belong to the Inbound through the existing OwnerInboundID/vault mechanism.
- An explicitly authorized client export projects the inbound identity key and
  that binding's user key as a standard SIP023 chain. The opt-in projection
  interface leaves REALITY private credentials outside client export.
- RemoteNode credentials belong to immutable Node IDs. AES node credentials may
  contain a bounded SIP023 chain; inbound/account credentials may not.
- Runtime keys are immutable snapshots. Shared replay caches are bounded and
  retained across generations of one inbound. Stream/packet counters and buffers
  belong to their connection; shutdown closes sockets and joins owned workers.
- A routed UDP target association is keyed by authenticated user, client
  session/source, and destination. This preserves the existing router's DNS and
  address-family selection for every target. All associations/queues/replay
  windows have fixed caps. AES response sessions have independent random IDs and
  nonce counters. Authenticated SS2022 source migration updates the session's
  routed targets. No protocol resolver or target-rule engine is introduced.
- Reuse the existing protected server routing/DNS infrastructure and shared
  meters. Preserve optional half-close methods in SS wrappers. Use standard
  crypto and existing pinned crypto libraries; implement canonical framing glue
  locally where library lifecycle/bounds cannot satisfy the managed contract.
- Framework changes are limited to additional listener transports, opt-in server
  credential projection, optional TCP/UDP session counters and passive committed
  protocol validation in doctor. No database migration is required.

## Consequences

The same API/CLI/Application Service, SQLite authority, provider preview/apply,
backup, stable IDs, routing/policy/DNS and Native TUN govern SS nodes and accounts.
Passwords/keys are absent from settings and default diagnostics. Export rejects
features a target format cannot express without loss. In particular SIP002
cannot express a disabled UDP capability, plugins, or a complete multi-user server.

Resource caps are deliberate fail-closed admission limits; authenticated demand
above a cap can be rejected until retained state expires. Classic multi-user
password trials are limited to 16 bindings; SS2022 ChaCha remains single-user.
SIP022's one-read initial header requirement is preserved; later framing accepts
fragmentation. These constraints and actual acceptance evidence belong in the
[runtime architecture](../architecture/SHADOWSOCKS_RUNTIME.md).

Accepted after the Final Independent Re-Review PASSED, for the consolidated
Phase 16 + Phase 17 Independent Core Transition freeze. It does not change
the historical platform qualification verdict, historical ADRs, or public v0.1.0.

Acceptance evidence: [consolidated freeze report](../reports/PHASE17_INDEPENDENT_CORE_FREEZE_REPORT.md).
