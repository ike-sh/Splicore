# Core Runtime Lifecycle

- Documentation status: Canonical
- Audience: Runtime and engine developers
- Last reviewed: 2026-10-09
- Owner: Core maintainers
- Responsibility: Core startup, admission, shutdown and owned resource recovery.
- Lifecycle: Update with runtime ownership or transaction changes.

## Composition and startup

One `splicore` process runs server and client Core roles. Native is the sole
runtime engine; Mieru is an embedded official SDK. Production never launches
Xray, sing-box or Mihomo. Historical external-engine proposals remain in ADRs
and reports, outside the current contract.

Startup validates bootstrap and persisted intent, acquires process ownership,
opens SQLite, checks frozen schema history and recovers Core journals before
activating traffic. Registries select exact owned protocol implementations.
Prepared generations keep admission closed until application transactions
commit and publish them. Listener health does not imply platform qualification.

The application preserves committed state if candidate construction, binding or
activation fails. Binding/account identities and authentication maps belong to
their generations. Protocol capabilities determine supported mutation behavior;
runtime cleanup does not add hot reload or user updates.

## Client generations

Client route/DNS/policy snapshots own adapter leases. Existing streams and UDP
associations retain their original generation; normal replacement retires it
after the last reference releases. Explicit stop/restart cancels sessions and
joins pending dials, relays and socket cleanup. Shared stream transports own
their workers and connection lifetime within these same boundaries.

See [client runtime](CLIENT_RUNTIME.md) and [shared transport](SHARED_TRANSPORT.md).

## TUN and recovery

Native TUN owns its device, interfaces, routes, sessions and resolver integration.
Packet readers stop before network restoration. Core journals enforce scope,
generation and exact-state ownership. Recovery preserves external mutations and
retains parent resources until child recovery debt is resolved.

Historical restored desktop records may remain as opaque journal data. Unfinished
legacy debt produces a typed unsupported diagnostic before store or OS writes.
Current plans cannot create desktop resource records. Frozen desktop desired
state is inert and has no current reader/writer or activation path.

See [recovery](../RECOVERY.md) and [Core scope](CORE_SCOPE.md).

## Shutdown and service deployment

Close admission, cancel/join sessions and workers, release native adapters and
restore only Core-owned network state before releasing storage/ownership.
Interrupted transactions and abrupt process death recover from durable Core
journals rather than relying on a final shutdown hook.

Core installers and `splicore.service` deploy this single native process.
Platform-specific socket, route, interface and service primitives are Core;
desktop preference management is outside this product.
