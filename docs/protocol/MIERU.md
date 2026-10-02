# Mieru native support

- Documentation status: Canonical
- Audience: Protocol, operations and client developers
- Last reviewed: 2026-10-02
- Owner: Protocol maintainers
- Responsibility: Bounded Mieru canonical contract and qualified runtime/client behavior.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Phase 8 integrates Experimental `mieru / 2 / base` into the existing `native`
Engine. Official `github.com/enfein/mieru/v3 v3.38.0`, commit
`b961978c3be9dd26b94158487c760858e19d1db2`, implements authentication,
cryptography, sessions, multiplexing, framing and default traffic pattern.
No permanent mita child, fork, wire rewrite or copied source is used.
The bounded Experimental integration is locally frozen under the
[Phase 8 freeze report](../reports/PHASE_8_FREEZE_REPORT.md).

## Canonical import

[Synthetic input](../../tests/fixtures/nobrand/mieru.json) uses the common schema-1
name/listener/display_endpoint/users envelope. `settings.transport` is required
(`tcp` or `udp`, describing the underlay). Optional `mtu` defaults to 1500
(0 also means default; otherwise 1280–1500). Optional `multiplex` defaults to
`default`; choices are default/off/low/middle/high, projected to clients.
One IP listener, one independently mutable IPv4/IPv6/domain DisplayEndpoint.
Port remains in Endpoint; users remain Account/Binding/Credential resources.
Unknown/duplicate fields, explicit null and unrepresented TLS/pattern/log options reject.

Each of 1–16 users has a distinct account_name and username. Username is 1–64
UTF-8 bytes with no ASCII space/control characters; password is 12–64 UTF-8
bytes with no Unicode whitespace/control characters. Supply both username/password
or omit both for cryptographically safe generation. Existing encrypted generic
UsernamePassword credentials are used. Explicit disabled bindings are persisted
but excluded from runtime admission. At least one active binding is required.

`splicore inbound validate --protocol mieru --file <canonical.json>` is offline.
The existing generic plan/apply commands and `/api/v1/creation/{protocol}/...`
routes select `mieru`. Native is the default and sole supported engine. Full
deterministic private protobuf is reconstructed from SQLite committed resources;
no upstream apply/replace daemon merge or import-file authority exists.

## Capabilities and limits

| Capability | Phase 8 |
|---|---|
| TCP / UDP underlay; TCP / UDP payload | Supported, default traffic pattern |
| IPv4 / IPv6 / domain display endpoint | Qualified on Linux amd64 loopback |
| MultiUserNative / per-binding payload stats | Supported; authenticated username maps to immutable binding ID |
| QuotaNative / SpeedLimitNative / MaxSessions | Not exposed; strict policy rejects, metadata_only remains unenforced |
| HotUserUpdate / HotReload | False; binding changes restart the affected inbound |
| Multiple inbounds | Supported; users, credentials, meters and owned sockets isolated |
| Persistent usage | Deferred as for existing native adapters; generation counters reset on restart |

Splicore's one payload meter supplies inbound and binding counters. Account Usage
has no newly implemented persistent aggregate API. Upstream username-global
metrics are reference only and never added to billing. Session counts measure
routed sessions, excluding handshake/framing bytes. Live independent atomic
snapshots need not be transactional; exact sums are verified after joined Close.

Official quota combines upload/download in a rolling Days window, rounds down
to MiB, compares using `>` and checks at new-session admission. It does not stop
an admitted transfer at an exact-byte threshold. Metrics are global by username
and survive server replacement. The source/runtime reference test confirms next
Alice admission rejection with Bob unaffected; this is not Splicore policy acceptance.
These semantics cannot implement the unified lifetime exact-byte TrafficPolicy.

## Lifecycle ownership

Private config and username/binding maps are immutable after Compile. A fresh
official Server is created per generation, Store only precedes Start. Start and
Close serialize narrowly; resource registration uses a separate short mutex.
Raw sockets are owned before authentication; accepted and destination sessions
are tracked. Admission opens only after SQLite commit. Close cancels routing,
closes actual raw sockets, stops official Mux and joins all adapter workers.
This compensates for upstream packet Close using deadlines that an active Read
can replace. No sleeps, race/checkptr suppression or process-exit cleanup.

A forcibly exited UDP client may leave its peer session until upstream idle
expiry or owned inbound Close: UDP has no reliable transport EOF. Runtime Stop
still joins and clears all sessions; 10 lifecycle cycles return goroutines 2→2.
Upload EOF half-closes the destination write side and preserves its response.
Private runtime formatting and ordinary API/profile JSON redact credentials.
Upstream cipher caches retain templates after Stop; secret erasure is not claimed.

## Client exports

`format=mieru`, client_version `3.38.0`, returns `mieru-client-config`: profile core,
activeProfile, display endpoint, credentials, MTU and multiplexing; consumers add
local SOCKS/RPC ports. `format=mihomo`, client_version `1.19.30`, returns a proxies
fragment and requires MTU 1500. Both require explicit binding_id for multi-user
export. These are protected secret-returning exports. Ordinary diagnostics never
contain password or upstream private protobuf.

sing-box 1.14.1 has no Mieru outbound: UnsupportedExport. Surge, URI, Xray and
unknown versions also reject; no unsupported schema or URI is invented.

See [implementation ADR](../adr/0020-mieru-owned-native-embedding.md),
[qualification workflow](../development/PHASE_8_MIERU.md),
[capability matrix](../architecture/CAPABILITY_MATRIX.md) and
[Phase 8 report](../reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md).
