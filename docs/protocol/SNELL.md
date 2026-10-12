# Native Snell

Splicore owns the Snell wire, client, server and socket lifecycle. No external
proxy core or Snell server executable is required. Versions are selected
explicitly; a missing version is rejected. Runtime engine: `native`.

## Supported profiles

| Version | Client / server | TCP / UDP relay | Connection reuse | Obfuscation |
| --- | --- | --- | --- | --- |
| 4 | Supported / supported | Supported / supported | Explicit client option; serial requests | None or HTTP |
| 5 | Supported in the qualified compatible scope | Supported / supported | Existing compatible request handling | None |
| 6 | Supported / supported | Supported / supported | Existing request handling | Existing encrypted traffic shaping |

The v5 client projection uses v4 TCP/UDP semantics. Official v5 servers accept
v4 clients. **Snell v5 QUIC Proxy Mode is not implemented.** v6 shaping and PSK
rules remain separate. v5/v6 canonical options remain exactly `{"version":5}`
and `{"version":6}`; additional mode, obfs or reuse fields are rejected there.
TLS obfs, ShadowTLS, Restls and JLS are outside this native profile.

## Configuration

See [inbound](../configuration/inbound/snell.md) and
[outbound](../configuration/outbound/snell.md) for canonical examples.
v4 inbound settings accept `version` and optional `obfs_mode` (`none` or `http`).
v4 outbound options additionally accept `reuse`, `udp`, `udp_port`, `obfs_host`
and `obfs_uri`. Unknown fields, duplicate keys, null values, invalid types,
invalid versions and unsupported combinations fail validation.

HTTP obfs wraps the initial submission in each direction, then carries the
ordinary authenticated Snell byte stream. It is camouflage, not HTTP proxying
or TLS security. Client host defaults intentionally to `localhost`, URI to `/`.
The host must be a valid IP or hostname; the URI must be a bounded ASCII
origin-form path with optional query, without spaces, controls or fragment.
Host and URI require HTTP mode. The server accepts compatible peer host/URI
values; it does not enforce a cover-host routing rule.

## TCP, UDP and reuse

TCP and UDP destinations support IPv4, IPv6 and domains. UDP relay runs over
TCP, with one record per datagram. Domain UDP flows in the managed outbound
resolve locally because Snell replies encode IP endpoints. The server association
and wire API can change destinations; the managed outbound retains its connected
flow target. `udp=false` disables outbound UDP. An optional `udp_port` selects
another TCP association port on the same server through the protected dialer;
it does not create an additional inbound listener. Zero or out-of-range ports
and a port combined with disabled UDP are rejected.

The preserved classic record codec has a traffic-dependent per-record budget,
initially approximately 1 KiB and growing to 16383 bytes including datagram
address framing. The command/reply consumes the first budget. A 1200-byte payload
is suitable for a fresh association; larger payloads may require prior traffic.
Oversized datagrams fail without splitting or merging boundaries. This profile
does not promise arbitrary 65535-byte UDP payloads.

For v4, `reuse=false` is the default and emits a non-reusable TCP request.
`reuse=true` maintains at most 64 physical transports, with at most eight idle
entries and a 30-second idle timeout. Each transport has one logical borrower;
it is not simultaneous multiplexing. A completed request must reach both logical
EOFs and join its read/write calls before reuse. Incomplete, failed or abandoned
requests close their physical transport. Half-close preserves the peer response.
Adapter shutdown closes active and idle sockets and cancels pending dials.
An idle connection closed by a peer can fail a subsequent request; payloads are
not automatically replayed. A later request creates a fresh transport.

## Accounts, credentials and statistics

The managed profile has one Account/Binding/PSK per inbound, one TCP listener
and one display endpoint. `multi_user_native=false`; userkey/multi-user extensions
are not qualified. Listener endpoints require an IP address. Display endpoints
may be IP or domain. The existing single-binding and transaction rules apply.

PSKs use typed Credentials and require 12..255 ASCII bytes from
`A-Z a-z 0-9 _ + / = -`. Omission during creation generates 32 random bytes as
43 base64url characters. Empty/null supplied keys are rejected. Encrypted SQLite
storage, protected control access and redacted ordinary output are retained.
Authorized exports contain the PSK and must be kept private.

Counters measure authenticated application payload and routed sessions for the
runtime generation, excluding framing and crypto overhead. They are not durable
billing. Quota/rate/session enforcement and live user/listener mutation are
unsupported. Snell does not add forward secrecy or dedicated replay protection.

## Import, export and interoperability

Canonical node JSON retains every supported v4 option. Existing sing-box JSON
and Mihomo JSON/YAML import support explicit v4, reuse, UDP selection and HTTP
mode/host. Their dialects do not expose Splicore's custom URI or alternate UDP
port; exports to these targets reject those non-default features. No Snell URI
scheme is invented. Surge declarations expose v4 reuse and HTTP host/URI and
alternate UDP port where their delimiter grammar is representable; this is a
configuration contract, not licensed Surge runtime qualification.

| Direction / reference | Qualified local scope |
| --- | --- |
| Splicore v4 client → official Snell 4.1.1 | TCP/UDP, reuse false/true, none/HTTP, IPv4/IPv6/domain |
| Splicore v4 client → official Snell 5.0.1 | Same v4 profiles, backward compatibility |
| sing-box 1.14.3 v4 client → Splicore v4 server | TCP/UDP, reuse false/true, none/HTTP |
| Mihomo 1.19.32 v4 client → Splicore v4 server | TCP/UDP, reuse false/true, none/HTTP |
| Surge mac-6.7.0 / ios-5.20.0 | Export contract only; runtime unavailable |

Custom URI behavior is validated locally and against official servers; the two
reference clients cannot configure a custom URI.
Mihomo closes the upstream on an early SOCKS upload EOF, including against the
official server; its qualification verifies the complete echo before application
close. Native, official-server and sing-box paths also verify half-close responses.
Previous v5 export targets
Mihomo 1.19.30 and sing-box 1.14.1 and v6 sing-box 1.14.1 remain supported.
Unknown export target versions are rejected. Qualification uses controlled
Linux amd64 references. Linux arm64 is build only. **Real hardware remains
NOT YET QUALIFIED.**

Behavioral references: [Surge policy](https://manual.nssurge.com/policies/snell.html),
[official server notes](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell),
[sing-box outbound documentation](https://sing-box.sagernet.org/configuration/outbound/snell/),
[Mihomo documentation](https://wiki.metacubex.one/en/config/proxies/snell/).
Reference programs serve only as interoperability oracles; their source is not
adapted into production.
