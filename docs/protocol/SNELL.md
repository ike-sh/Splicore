# Managed Snell support

- Documentation status: Canonical
- Audience: Protocol, runtime, client and integration developers
- Last reviewed: 2026-10-01
- Owner: Protocol maintainers
- Responsibility: Implemented Snell profile, credentials, capabilities and client contracts.
- Lifecycle: Update with implementation and independent client qualification evidence.

## Scope and provenance

Status: **experimental**. Phase 2 reuses sing-box v1.14.1's unchanged Snell
constructors and sing-snell `v0.0.0-20260829071736-20f2eaec77c3`.
Server versions are 5 and 6; version 4 is a compatible client for server 5,
not a separate server implementation. Managed v5 uses no obfs, v6 uses default
encrypted/shaped mode. Settings are exactly `{"version":5}` or `{"version":6}`.
Unknown/duplicate fields, obfs/mode/userkey/QUIC settings and v4 server requests
are rejected. No framing, crypto, authentication or version semantics are changed.

Native upstream supports top-level PSK plus userkey multi-user authentication.
Phase 2 deliberately uses one Account/Binding/PSK per Inbound, with one TCP
listener and one DisplayEndpoint. `multi_user_native=false` describes this
managed profile. Native userkey provisioning and shared multi-user listeners
are deferred. At most 64 managed Inbounds are allowed per installation.

## Capability

| Capability | Managed profile |
|---|---|
| TCP listener/payload | supported |
| UDP listener/underlay | unsupported |
| UDP payload | supported, tunneled over TCP |
| IPv4/IPv6/domain DisplayEndpoint | supported |
| Listener | IP address only, fixed after creation |
| Multi-user userkey | deferred; one Binding per Inbound |
| Payload attribution | Inbound and its sole Binding/Account |
| Counters | upload/download bytes, total/active routed TCP and UDP sessions |
| Counter lifetime | process lifetime; decimal strings over API |
| Quota, rate, max-session enforcement | unsupported |
| QUIC Proxy Mode | unsupported by upstream server |
| User/listener mutation, hot reload, credential rotation | deferred |
| DisplayEndpoint mutation | SQL-only; no socket/route/egress changes |
| URI / canonical JSON export | not implemented; no invented Snell URI |

UDP session count means authenticated routed packet connections, not number of
datagrams or native user identities. Failed handshakes do not count as routed
sessions. Counters exclude crypto/framing overhead and are not a billing ledger.
Attribution is valid because this profile has exactly one Binding. Durable usage,
quota enforcement, expiry/revocation during traffic and account aggregation across
multiple Inbounds are future work. Live account updates are rejected pending runtime
coordination; Account is never a protocol-secret container.

## Credential and secret boundary

PSK uses the existing typed Credential/secret.Value abstraction. Omitted PSK
generates 32 random bytes encoded as 43 base64url characters (256 bits entropy).
Supplied PSKs require 12..255 ASCII bytes from `A-Z a-z 0-9 _ + / = -`.
Explicit empty/null PSKs are rejected; only an omitted field requests generation.
This portable profile is narrower than native v5's nonempty-key requirement;
v6's native 12..255-byte constraint is preserved. Delimiters/control characters
are rejected without reflecting supplied values.

SQLite stores only AES-256-GCM ciphertext, nonce and key identity with owner-bound
associated data. Explicit Linux key-file provisioning uses exclusive creation,
32 random bytes, 0600 file and private directory checks. Loading checks regular
file, size, owner, permissions, symlinks and file identity. There is no missing-key
regeneration or plaintext fallback. Back up the key separately with the database;
losing it makes credentials unrecoverable. Windows remains a development build
target without production key provisioning/control transport.

Metadata, System, doctor, fixed errors and transaction records never contain PSKs.
Profile/credential/document formatting redacts secrets. Export is an explicit
secret-returning POST/CLI operation authorized by protected local control access;
it returns client content containing PSK. No ordinary GET reveals credentials.
Export files and inputs must remain private. Go strings are not guaranteed erased
from memory; runtime and authorized exports hold transient plaintext.

## Runtime and transaction

The native adapter compiles one private Box per Inbound with minimal registries,
Snell/direct/local DNS only. An owned TCP listener forwards sockets into the stock
Snell `NewConnection`; the stock listener is never started. Raw sockets have a
five-second unauthenticated deadline, cleared at authenticated routing. Shutdown
closes pending handshakes and established sessions, waits for owned handlers and
releases the port. No upstream runtime source is modified.

Sequence: strict validation → revision/HMAC plan check → compile without sockets
→ durable create journal → bind/start with closed admission → listener health
→ short SQL resource/revision/journal commit → open admission. Failure closes
the candidate and marks the journal failed. Listener health means accept-loop
readiness, not a complete authentication probe; real interop tests separately
qualify authentication and traffic. Pending resources cannot export/grant traffic.

Restart reads only committed SQLite resources and decrypted Credentials. Interrupted
create-only journals become failed; unknown Foundation pending journals stay fenced.
Startup cleanup closes all previously restored handles if one fails. A crash after
commit before admission is recovered from the committed generation. Generic update
recovery, durable candidate payloads/idempotency and hot reconcile remain deferred.
See [transaction model](../architecture/TRANSACTION_MODEL.md) and
[composition ADR](../adr/0013-snell-runtime-composition.md).

## Client contracts

| Server | Target contract | Client wire | Qualification |
|---|---|---|---|
| v5 | Mihomo 1.19.30 | v4 | real TCP/UDP PASS |
| v5 | sing-box 1.14.1 | v4 | real TCP/UDP PASS |
| v6 | sing-box 1.14.1 | v6 | real TCP/UDP PASS |
| v5/v6 | Surge Mac 6.7.0 / iOS 5.20.0 | v4/v6 | exporter contract only |
| v6 | Mihomo 1.19.30 | N/A | UnsupportedExport |

ClientProfile carries explicit UDPPayload=true; unsupported attempts to disable it
are rejected by this base-profile exporter. Each export envelope explicitly
reports server/client wire versions and compatibility.
v5→v4 is the documented TCP/UDP compatibility path; emitting Surge v5 would
enable its unsupported automatic QUIC Proxy Mode. Unknown target versions or
unexpressible features return `unsupported_export` (HTTP 422). Mihomo output is
a JSON node mapping accepted as YAML; sing-box is outbound JSON; Surge is one
comma-separated proxy declaration. Names are generated from canonical Binding IDs.
IPv6 literals remain raw in the separate server/host field and port field;
validated hosts and restricted PSKs prevent delimiter injection. Snell UDP is
automatic in Surge; no `udp-relay` flag is fabricated.

Contract sources: [pinned Mihomo source](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/adapter/outbound/snell.go),
[pinned sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.1/option/snell.go),
[Surge Snell manual](https://manual.nssurge.com/policies/snell.html).
Surge's host/port grammar supplies the contract for raw IPv6 formatting; this
is not a Surge parser/runtime test. Its exact licensed runtime remains unqualified.
See the [full matrix](../testing/INTEROP_MATRIX.md) and
[Phase 2 report](../reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md).
