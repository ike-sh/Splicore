# Native HTTP/H2 and generic QUIC stream transports

Status: experimental native Core transport implementation, Phase31.
Protocol authentication and destination framing remain protocol owned.

## Config and supported bindings

Server protocol settings use `stream_transport`; native remote nodes use
`transport`. Existing TLS settings supply certificates, CA, SNI and verification.
Examples:

```json
{"kind":"http","path":"/stream","host":"transport.example"}
```

```json
{"kind":"h2","path":"/stream"}
```

```json
{"kind":"quic-stream"}
```

| Protocol/security | http | h2 | quic-stream |
| --- | --- | --- | --- |
| VLESS TLS, flow-none | Client/server | Client/server | Client/server |
| VMess AEAD TLS | Client/server | Client/server | Client/server |
| Trojan standard TLS | Client/server | Client/server | Client/server |
| Any other protocol/security/flow | Rejected | Rejected | Rejected |

Verification is enabled by default. Existing explicit insecure TLS opt-in remains
explicit. There is no cleartext HTTP or h2c mode. Unknown kinds, unsupported
fields, incompatible TLS/ALPN and unsupported bindings fail closed. `quic` retains
its previous protocol-specific meaning; it is not an alias for `quic-stream`.
The QUIC implementation requires `with_quic`; missing support fails startup.
Canonical native JSON preserves these configurations through existing application
services and SQLite. Foreign client formats and share URIs reject them. There is
no schema migration, new API namespace or transport credential model.

## HTTP wire contract

One POST to the exact configured origin-form path (default `/`), content type
`application/octet-stream`, and a 200 response with that content type carry
unmodified protocol bytes. Paths cannot contain escapes, dot segments, queries,
fragments or backslashes. Optional Host is independent of TLS SNI and physical
endpoint; custom client headers are cosmetic, bounded, and cannot override
framing, authentication, encoding or forwarded identity. Server custom headers
are rejected. Forwarded/X-Real-IP headers never confer identity or routing trust.

`http` is TLS HTTP/1.1 with streamed chunked bodies, required native full duplex,
explicit flushing and one dedicated physical connection per logical stream.
Keepalive/reuse is disabled. It is not HTTPUpgrade, CONNECT or a forward proxy.
A buffering reverse proxy does not satisfy this duplex contract.

`h2` is TLS HTTP/2 with ALPN `h2`. Each logical stream is one POST request;
a per-outbound client reuses one H2 connection. Standard HTTP/2 owns flow control,
RST_STREAM, GOAWAY and idle closure. Draining refuses new streams until current
streams close; failed requests are never replayed. H1 downgrade is rejected.

Wrong path yields 404, wrong method 405, mismatched transport metadata/framing
400, header over-budget 431 and resource saturation 503. Errors reveal no
protocol credentials or internal diagnostics. Standard Go HTTP parsing owns
Content-Length/Transfer-Encoding normalization. The H1 listener handles one
request per connection; it does not forward HTTP request framing upstream.

## Generic QUIC wire contract

ALPN: **splicore-stream/1**. QUIC v1 and TLS 1.3 only. Accepted independent stack:
`github.com/quic-go/quic-go` v0.63.0. One immutable outbound identity owns one
reusable connection, and each client-initiated bidirectional stream is one
protocol session. No preface, target, authentication or application envelope is
added. A stream becomes visible to the server when protocol bytes or FIN arrive.

Server-initiated/unidirectional streams, DATAGRAM, 0-RTT and TLS session
resumption are disabled. Stale sessions are evicted and redialed lazily; idle
session watchers close their UDP socket. CloseWrite sends FIN; full Close cancels
reads and finishes writes, preserving already written bytes. Explicit reset is
stream scoped. Connection failure propagates to all streams. Application close
code 0 means normal shutdown; stream cancel code 1 releases a closed reader.
No internal error or secret is exposed in close reasons.

An alternative already accepted QUIC stack is used as a raw standards peer in
tests. External reference implementation of this Splicore wire contract: N/A.
No ShadowQUIC, Hysteria or NaiveProxy peer compatibility is claimed.

## Lifecycle, half-close and resource bounds

Dial contexts govern admission; published streams belong to their protocol/runtime
owner, matching existing Core semantics. Runtime shutdown cancels admission,
closes listeners and children, and joins owned work. QUIC FIN preserves independent
read/write lifetimes. HTTP client CloseWrite ends the request body. Server
CloseWrite ends the response after request EOF because the handler owns the
request-body lifetime. H1 response EOF can end outstanding request writes in
the standard client. HTTP deadlines are terminal stream deadlines; partial writes
cannot safely be rolled back. They never change a sibling H2 stream's deadline.

| Resource | Limit |
| --- | --- |
| Admission / TLS / protocol handshake | 5 seconds |
| Physical idle HTTP/H2 or QUIC connection | 30 seconds; no QUIC keepalive |
| Client active + pending logical streams | 128 per outbound |
| H2 / QUIC incoming streams | 128 per connection |
| HTTP listener physical sockets | 512 |
| QUIC listener connections including handshakes | 128; address validation required |
| Listener pending stream queue | 64 |
| HTTP metadata | 16 KiB; config header values 8 KiB / 32 entries |
| QUIC receive windows | 256 KiB per stream, 2 MiB per connection maximum |
| H2 request receive windows | 256 KiB per stream, 2 MiB per connection |

Payloads stream through standard flow control without whole-session buffering.
Only injected approved underlay sockets are used. Managed physical endpoint DNS
uses the retained Core generation with no system fallback; SNI/Host are never
substituted for that endpoint. Existing protocol decode, auth, routing,
DIRECT/REJECT, counters and persistence remain in their established owners.

## Existing transport boundaries

[XHTTP](XHTTP.md) keeps its frozen modes, sessions and wire metadata; no code is
extracted or replaced. ShadowQUIC keeps its JLS/auth/commands/DATAGRAM framing.
Hysteria/Hysteria2 and NaiveProxy keep their own authenticated QUIC/H3 runtimes.
No shared QUIC implementation, crypto or DNS helper is refactored. Existing
WS/HTTPUpgrade/gRPC/mKCP behavior remains separately qualified.

Implementation evidence is external under
`D:/splicore-validation/phase31-http-h2-generic-quic-implementation-20261022`.
Linux arm64 qualification is build only. Independent review and freeze are
separate stages.

## Standard references

- [Go full duplex HTTP server API](https://pkg.go.dev/net/http#ResponseController.EnableFullDuplex)
- [Go HTTP/2 transport API](https://pkg.go.dev/golang.org/x/net/http2#Transport)
- [QUIC connection lifecycle](https://quic-go.net/docs/quic/connection/)
