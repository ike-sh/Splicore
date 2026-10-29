# Native ShadowQUIC

- Documentation status: Canonical
- Audience: Operators and client integrators
- Last reviewed: 2026-10-29
- Owner: Splicore maintainers
- Responsibility: Native ShadowQUIC configuration and supported wire behavior.
- Lifecycle: Update with protocol or configuration changes.

## Identity and scope

Protocol key: `shadowquic / unversioned / jls3`. The reference is
[ShadowQUIC v0.4.7](https://github.com/spongebob888/shadowquic/tree/3b8af96bf0c97d409e9a59dbb716280a7c5136bb),
whose proxy grammar has no version field. JLS v3 authenticates TLS Hello messages;
QUIC v1 carries bidirectional TCP command streams and UDP DATAGRAM associations.
Build with `with_quic`. Both native client and server roles are available.

TCP command 1 carries a SOCKS address followed directly by payload, without a
connect reply. FIN preserves half-close. UDP command 3 uses a reliable mapping
control stream and connection-wide 16-bit CID datagrams. Closing the control
stream retires the association. Initial binding must be an unspecified address
with port zero; the server owns ephemeral target sockets. UDP payload is limited
to 1200 bytes and may also be constrained by the peer's negotiated datagram size.
Domains remain semantic destinations, including replies. Queues may drop packets.
UDP command 4 carries payloads over QUIC unidirectional streams. Each stream
starts with a 16-bit big-endian CID, followed by repeated 16-bit big-endian length
and payload; control mappings are identical to command 3. Payload streams may
arrive before their mapping and wait within the handshake budget. Duplicate
active CID streams, wrong-mode payloads and oversized/truncated frames are
rejected without terminating unrelated sessions. SunnyQUIC and remote
administrative extensions remain unsupported. 0-RTT and resumption are disabled.

## Server creation

Submit through the existing `/api/v1` creation services or the shared CLI:
`splicore inbound plan --protocol shadowquic --file creation.json`, then the
existing apply flow. The document uses the native creation envelope:

```json
{
  "schema": 1,
  "name": "ShadowQUIC server",
  "listener": {"host": "0.0.0.0", "port": 443},
  "display_endpoint": {"host": "proxy.example", "port": 443},
  "settings": {
    "server_name": "cover.example",
    "camouflage_endpoint": {"host": "cover.example", "port": 443}
  },
  "users": [{
    "account_name": "Account display name",
    "username": "independent-auth-identifier",
    "password": "replace-with-a-strong-random-secret"
  }]
}
```

The listener is UDP. `display_endpoint` is client-facing metadata. The explicit
camouflage peer receives unauthenticated JLS traffic; it should offer QUIC/TLS
for the configured DNS SNI. It is not an authentication bypass or proxy target.
`account_name`, binding identity and authentication username remain distinct.
Missing username/password are generated during apply. Usernames must be unique,
nonempty, at most 255 bytes and contain no control characters. Passwords use the
Core credential validator. Optional user enable/account flags use the shared
creation service. Secrets are encrypted in SQLite. No new migration is needed.

## Settings and options

All tuning fields are optional integers. Zero means the default. Time units are
seconds. Unknown keys, duplicate keys, nulls and invalid combinations are rejected.

| Field | Default | Valid effective range | Applies to |
| --- | --- | --- | --- |
| `server_name` | none | explicit DNS SNI, 1–253 bytes; no URL, IP or wildcard | server settings; client security |
| `camouflage_endpoint` | none | required valid endpoint | server settings |
| `max_connections` | 32 | 1–128 authenticated connections | server settings |
| `max_streams` | 64 | 1–256 concurrent streams per connection | both |
| `max_udp_flows` | 32 | 1–128 active mappings per direction per connection; also bounds associations | both |
| `handshake_timeout` | 5 | 1–30; QUIC handshake, command admission, server target dial | both |
| `idle_timeout` | 60 | 10–600 | both |
| `keepalive` | 15 | 1 to less than `idle_timeout` | both |
| `udp_idle_timeout` | 60 | 2–600; association inactivity and server target inactivity | both |

Client `options` is `{"schema_version":1,"data":{}}` with the shared tuning
fields above and optional boolean `udp_over_stream` (default false). Set it true
to select CMD4; false retains CMD3 DATAGRAM. Both modes keep the 1200-byte payload
limit. Client options cannot contain server-only settings. These bounded JSON fields
are committed state, restored through existing SQLite restart/backup services.
Runtime sessions and generated camouflage certificate keys are derived state.

## Client security and lifecycle

A remote node uses transport `{"kind":"quic"}` and explicit security:

```json
{
  "kind": "jls",
  "tls": {
    "enabled": true,
    "server_name": "cover.example",
    "alpn": ["h3"],
    "trust": "jls"
  }
}
```

CA and REALITY material are rejected for JLS. JLS-authenticated Hello messages
supply trust, as required by the protocol; ordinary TLS fallback cannot authorize
proxy commands. The server uses an ephemeral certificate. There is no global
certificate-verification override. Native credentials are `username_password`.
Foreign Core configuration aliases and export/import formats are not added.

One lazy persistent QUIC connection belongs to each immutable node/credential
runtime generation. Streams share QUIC multiplexing. Dead connections are evicted
on the next request; there is no background reconnect loop. Closing a generation
cancels admissions and joins its sockets and workers. Native health and payload
statistics include binding attribution. Target errors terminate the affected
stream; the protocol defines no synthetic connect-success/error reply frame.

Client routing, policy groups and managed DNS remain in the existing Core
runtime. With managed DNS enabled, node bootstrap and target resolution use that
policy and fail without ambient fallback. Server targets use the existing
protected `ServerTarget` capability. With a Core DNS generation available, server
targets use its DNS rules and preserve the returned address preference; lookup
failure has no ambient retry. Camouflage uses an injected protected UDP
socket factory, with numeric socket destinations. Camouflage hostnames are resolved once at server compilation using the retained
Core bootstrap DNS generation, then pinned to numeric socket destinations.
NXDOMAIN fails compilation without ambient retry. Server-only operation retains
the existing Core system-resolution policy when managed DNS is not configured.
The JLS library does not own an ambient resolver/dialer path.

Receive windows are bounded at 1 MiB per stream and 4 MiB per connection.
Per-association payload queues and the connection's unknown-CID reorder queue
hold at most 32 packets each. Unknown mappings expire after one second when next
examined and cannot be delivered after expiry. Retired CIDs are not reused within
the same connection, preventing delayed packets reaching a new association.
EOF/reset, timeout and shutdown remove mappings and wake blocked packet I/O.

Phase35 tests pinned official v0.4.7 in both CMD3/CMD4 directions, plus TCP,
half-close, credentials, concurrency, IPv4/IPv6 targets and deterministic Close.
CMD4 has no dependency on resumption or 0-RTT; both remain disabled.
