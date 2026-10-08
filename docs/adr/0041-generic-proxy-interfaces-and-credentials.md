# ADR 0041: Generic proxy interfaces and credential ownership

- Status: Proposed
- Date: 2026-10-08
- Phase: 20 reviewed implementation; Proposed decision status retained

## Context

The existing client runtime already owns SOCKS/HTTP/Mixed listeners, routing
generations, underlay and persistence. Generic Accounts and encrypted credentials
exist, while the SQL server binding table's inbound foreign key cannot reference
a local client listener. RemoteNode also requires an immutable credential reference
even for an upstream proxy that negotiates no authentication.

## Decision

Complete and consolidate existing local listeners. Keep Mixed a listener mode,
and expose native socks5/http node outbounds through the generic factory registry.
Canonical wire helpers own framing; shared routing/DNS/policy and lifecycle owners
remain authoritative. HTTP CONNECT is TCP-only, including policy selection.

Store typed generic local Bindings in existing LocalInbound JSON, referencing the
same generic Account and encrypted account-owned UsernamePassword Credential.
Validate references during prepare, commit and committed-state reads. There is no
shadow account database and no migration. Rotation uses a new credential ID,
joins affected sessions and removes obsolete exclusive local credentials.

For no-auth upstream nodes, use an explicit `auth=false` option and the exact
nonsecret `no_authentication` marker in the mandatory encrypted Password slot.
Validation rejects any other ignored credential. Never send this marker on wire.
This preserves the frozen generic schema and does not pretend there is a remote
authentication secret. An eventual optional-credential domain revision would be
a separate architecture change.

Treat SOCKS URI imports as proxy-node descriptions. Shared DNS policy decides
whether resolution is required; otherwise DOMAIN is forwarded unchanged.
Export SOCKS URIs as socks5h, documenting curl's distinct socks5 local-resolution
convention. Do not create protocol-owned DNS or silently export local-DNS semantics.

## Consequences

Existing encrypted backups preserve IDs/accounts/bindings/auth/nodes with schema 8.
Local-binding API/CLI writes share the generic transaction service and revision
checks. A maximum of 128 bindings per listener bounds comparisons and snapshots.
Authentication is cleartext on plaintext proxy transports; loopback is default,
LAN access is explicit and diagnosed. No-auth marker handling is deliberately
strict. Local and server binding placement differs while the typed resource and
secret owner model remains shared. This proposal is not an accepted Freeze ADR.

## References

- [Proxy interfaces architecture](../architecture/PROXY_INTERFACES.md)
- [Account / Binding / Credential](0004-account-binding-credential.md)
- [Client runtime domain](0022-client-runtime-domain.md)
- [Phase 20 implementation report](../reports/PHASE20_PROXY_INTERFACES_IMPLEMENTATION_REPORT.md)
