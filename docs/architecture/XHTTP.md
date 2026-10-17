# Native XHTTP transport

XHTTP is a shared stream transport for VLESS, VMess and Trojan. It carries each
protocol's ordinary bytes; it adds no proxy authentication or protocol framing.

```text
proxy protocol → XHTTP → optional shared TLS / REALITY → approved network socket
```

## Modes and HTTP versions

| Mode | Upload | Download | HTTP support |
| --- | --- | --- | --- |
| `packet-up` | Numbered bounded requests | Separate streaming GET | H1, H2 |
| `stream-up` | Streaming request | Separate streaming GET | H1, H2 |
| `stream-one` | One streaming request | Its streaming response | H2 |
| `auto` | Selects one of the above | Follows the selected mode | H1, H2 |

Auto selects packet-up for plaintext and TLS. With REALITY it selects stream-one;
with REALITY and `downloadSettings` it selects stream-up. Explicit modes are
preserved. Plaintext uses H1. TLS defaults to H2; a single `http/1.1` ALPN selects
H1. REALITY uses H2 and requires `with_utls`. Vision remains a raw stream flow and
cannot be combined with XHTTP. Trojan requires TLS.

For H1 stream-up with the Xray 26.10.10 server, set its
`scStreamUpServerSecs` to `-1`: its response keepalive can compete with streaming
request-body reads. Native H1 stream-up supports its own response keepalive.

HTTP/3 is not implemented for this transport. An `h3` ALPN fails validation;
there is no fallback to H2. XHTTP support does not imply generic V2Ray QUIC,
Mux.Cool, or new XUDP features. FinalMask retains its raw VLESS boundary.

## Canonical configuration

An outbound node's `transport`, or an inbound's `settings.stream_transport`:

```json
{
  "kind": "xhttp",
  "path": "/stream?tenant=example",
  "host": "authority.example",
  "headers": { "X-Application": "example" },
  "xhttp": {
    "mode": "packet-up",
    "xPaddingBytes": "100-1000",
    "sessionIDPlacement": "path",
    "seqPlacement": "path",
    "uplinkDataPlacement": "body"
  }
}
```

The common `path`, `host`, and `headers` members are outside `xhttp`. Options
inside `xhttp` use the XHTTP names understood by Xray 26.10.10. There is one
transport implementation, named XHTTP; no separate SplitHTTP implementation or
legacy configuration alias is exposed.

An empty path becomes `/`; a missing leading slash is added. A trailing slash
is added when session or sequence placement uses the path. Query parameters are
retained. Dot segments and malformed paths are rejected. Client authority is
explicit `host`, then security server name, then endpoint host. Authority does
not replace TLS SNI or certificate identity. Server host checking is optional;
a configured host without a port accepts a matching host with an endpoint port.
Request headers are client headers; inbound headers are response headers.
Header names are case insensitive. Custom headers cannot use transport framing,
session/sequence metadata, padding, response state, or the numbered uplink data
namespace. Metadata keys cannot collide with one another or with that namespace.
Duplicate metadata fields, case variants, multiple values and ambiguous token
lists are rejected. Configure authority through `host`; a custom Host header is
rejected.

## Controls

Integer controls accept a JSON integer, a numeric string, or an inclusive range
string such as `"100-1000"`. Descending ranges and overflow are rejected.
Zero generally selects the documented default; XMUX zeros mean unlimited.

| Option | Meaning and default |
| --- | --- |
| `xPaddingBytes` | Padding range, `100-1000`; positive, maximum 16384 |
| `xPaddingObfsMode` | Enable configurable padding placement, default false |
| `xPaddingPlacement` | `queryInHeader`, `header`, `query`, or `cookie` |
| `xPaddingKey`, `xPaddingHeader` | Defaults `x_padding`, `X-Padding` |
| `xPaddingMethod` | `repeat-x` or `tokenish`; default `repeat-x` |
| `noGRPCHeader` | Client streaming requests omit the gRPC content type |
| `noSSEHeader` | Server download responses omit the SSE content type |
| `scMaxEachPostBytes` | Client packet size / server packet bound; default 1000000, maximum 8 MiB |
| `scMinPostsIntervalMs` | Client minimum request interval and coalescing window; default 30 ms, a nonpositive lower endpoint disables, maximum 20000 |
| `scMaxBufferedPosts` | Server pending packet count; default 30, maximum 1024 |
| `scStreamUpServerSecs` | Server upload response keepalive; default `20-80` seconds, `-1` disables, maximum 3600 |
| `serverMaxHeaderBytes` | HTTP header bound; default 8192, supported range 1024–1048576 |
| `sessionIDPlacement`, `seqPlacement` | `path`, `header`, `query`, or `cookie`; default `path` |
| `sessionIDKey`, `seqKey` | Header defaults `X-Session` / `X-Seq`; query/cookie defaults `x_session` / `x_seq` |
| `uplinkDataPlacement` | `auto`, `body`, `header`, or `cookie`; default `auto` |
| `uplinkDataKey` | Default `X-Data`, or `x_data` for cookies |
| `uplinkChunkSize` | Encoded header/cookie chunk range; default 3000–4000 for headers, 2048–3072 for cookies; minimum 64 |
| `uplinkHTTPMethod` | Default POST; GET requires explicit packet-up |
| `sessionIDTable`, `sessionIDLength` | Client custom randomized ASCII token table and bounded length; otherwise random UUID |

Header/cookie uplink data requires explicit packet-up. Header chunks use numbered
`key-N` headers; cookie chunks use `key_N` cookies. Auto on the server combines
header, cookie and body data; auto on the client sends a body. Metadata and
padding options must agree at both ends. Plain padding uses `x_padding` in the
Referer query and an `X-Padding` response header. Tokenish padding is measured
using HTTP's Huffman encoded length with a two byte tolerance.

Client-only controls are rejected in inbound configuration: downloadSettings,
XMUX, noGRPCHeader, packet interval, uplink chunk size, and custom session table
and length. POST, PUT, PATCH, DELETE and valid extension method tokens are
supported; OPTIONS is reserved for preflight. HEAD, CONNECT and TRACE are
rejected. Streaming GET, header/cookie data in streaming modes, unsafe metadata
keys and impossible security combinations fail validation.

Server-only controls are rejected in outbound configuration: noSSEHeader,
buffered post limits, stream-up server keepalive, and serverMaxHeaderBytes.
Packet controls require a packet mode; server keepalive requires stream-up or
auto. Custom padding keys/placement require xPaddingObfsMode. A separate
download configuration accepts downstream envelope and XMUX options and rejects
upload-only controls. H1 Xray export selects its standard TLS hello to preserve
the requested ALPN while keeping certificate verification enabled.

Session table presets are `ALPHABET`, `Alphabet`, `BASE36`, `Base62`, `HEX`,
`alphabet`, `base36`, `hex`, and `number`. A custom table uses URL-safe ASCII;
Tables cannot repeat characters; lengths are 1–256, and the shortest configured
length must independently provide at least 122 random bits, matching the default
UUIDv4. For example, decimal digits require at least 37 characters; Base62 requires
at least 21. Unsafe lengths/ranges are rejected without changing their values.
Session identities use cryptographic randomness and exact case-sensitive lookup.
Generated IDs are reserved while their session is active; a collision triggers
at most eight generation attempts, then fails safely. Inbound accepts compatible
IDs of varying valid lengths independently of the local generation policy.
Empty/zero padding settings
select the default; padding cannot be disabled.

## XMUX connection ownership

Client `xmux` controls HTTP connection reuse; it is not proxy payload mux.

| Option | Behavior |
| --- | --- |
| `maxConcurrency` | Concurrent logical sessions per reusable HTTP client |
| `maxConnections` | Reusable HTTP client pool size; exclusive with maxConcurrency |
| `cMaxReuseTimes` | Logical session reuse count before retirement |
| `hMaxRequestTimes` | HTTP request count before retirement |
| `hMaxReusableSecs` | Reusable lifetime before retirement |
| `hKeepAlivePeriod` | H2 idle ping period in seconds; zero uses 45, `-1` disables |

The default pool uses three HTTP clients, 600–900 requests and 1800–3000 seconds
of reusable lifetime. Retirement preserves existing download streams; later
packet uploads and new sessions move to eligible clients. Closing an outbound
closes its sessions and HTTP sockets. H2 isolates concurrent streams on a reused
connection. H1 needs separate upload/download connections for duplex modes.

## Separate download leg

Client `downloadSettings` contains an independent endpoint, transport and public
security configuration:

```json
{
  "endpoint": { "host": "download.example", "port": 443 },
  "transport": { "kind": "xhttp", "path": "/stream" },
  "security": "tls",
  "tls": {
    "enabled": true,
    "server_name": "download.example",
    "trust": "system"
  }
}
```

Both front doors must reach the same server session owner. Upload and download
can have independent targets, TLS identities, trust and supported security.
They carry one proxy session and use its same identity. Failure or close cancels
both legs. Recursive download configuration, non-XHTTP downloads and downloads
in stream-one are rejected.

## Bounds and interchange

Session association and first application data have a 30 second transport budget.
HTTP response headers may be sent first to unblock client startup; the native
proxy listener receives the logical stream only after its first application byte
is available. That byte is preserved for its first Read. Native authentication
uses an explicit transport admission scope: its five second processing budget
excludes blocking XHTTP reads/writes, each of which has a 30 second delivery
limit. A connection becomes an ordinary application stream only after the native
parser authenticates the complete request and finishes this scope. No proxy
header lengths or protocol parsing belong to XHTTP. Admission is bounded to
64 KiB, 1024 I/O steps and 30720 seconds total wall time; exhausted bounds,
no-data timeout, cancellation or close clean up the session. These are resource
limits, not a guarantee that every possible peer schedule completes. Ordinary
net.Conn deadlines remain absolute, including after admission. Missing packet
gaps also expire after 30 seconds.

`queryInHeader` padding carries one URL. Its path and unrelated query values may
contain commas; single-value and duplicate-header checks still apply. Validation
checks the decoded padding query value rather than treating the URL as a token
list. Duplicate padding keys and malformed URL/query syntax are rejected.

The first packet's configured delay is capped at 20 seconds, leaving two existing
5 second transport leg admission windows: downstream response startup and an
independent upload dial/security leg, including `downloadSettings`. Packet size
and chunk controls can end coalescing earlier; they add no delay. XMUX retirement
can open an upload connection within the same leg budget. Padding and server
keepalive do not delay upload application data. Application inactivity and network
failure remain subject to the bounded transport timeout.
Limits are 512 sessions, 32 MiB pending data per session, 128 MiB aggregate
pending packet data and 128 reusable HTTP clients per outbound. Requests larger
than the packet limit are rejected; duplicate sequence numbers never deliver
duplicate application bytes. Stream close is a full close; TCP half-close is
not exposed by XHTTP.

Canonical node import/persistence retains XHTTP controls. VLESS XHTTP export
targets Xray 26.10.10 and retains transport/security/download settings. Complex
XHTTP URI and other ecosystem exports are rejected rather than losing options.
Hardware deployment remains NOT YET QUALIFIED; Linux arm64 remains BUILD ONLY.
