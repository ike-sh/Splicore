# Modern mKCP shared transport

Splicore implements mKCP as a reusable inbound and outbound stream transport over
UDP. VLESS with no flow and modern VMess compose with plain or verified TLS;
standard Trojan composes with TLS. Protocol authentication, framing, target
routing, admission and payload accounting remain in their existing runtimes.
REALITY and Vision over mKCP are rejected.

## Configuration

Server protocol settings select the transport with `stream_transport`:

```json
{
  "security": "none",
  "flow": "none",
  "transport": "tcp",
  "packet_encoding": "xudp",
  "stream_transport": {"kind": "mkcp", "mkcp": {}}
}
```

This is a VLESS server settings example. The historical protocol `transport`
member retains its byte stream value; the shared transport selects the actual
UDP carrier. Managed creation sets the listener carrier to `udp`. VMess uses
its normal AEAD settings with the same `stream_transport`; Trojan uses its normal
TLS settings with the same member. Credentials are unchanged.

Remote nodes and client profiles select mKCP in their ordinary `transport`:

```json
{
  "kind": "mkcp",
  "mkcp": {
    "mtu": 1350,
    "tti": 50,
    "uplinkCapacity": 5,
    "downlinkCapacity": 20,
    "cwndMultiplier": 1,
    "maxSendingWindow": 2097152
  }
}
```

An omitted tuning object or omitted tuning fields select the defaults below.
Explicit null, duplicate or case folded fields, unknown fields and incompatible
HTTP/FinalMask members are rejected. Settings apply locally; they are not a
negotiated security or performance contract.

| Field | Default | Splicore range / meaning |
| --- | --- | --- |
| `mtu` | 1350 | 576–1460 bytes of UDP payload, including mKCP headers |
| `tti` | 50 | 10–100 milliseconds between transmission updates |
| `uplinkCapacity` | 5 | Local send capacity in binary MB/s: 1,048,576 bytes/s |
| `downlinkCapacity` | 20 | Local receive capacity in the same units |
| `cwndMultiplier` | 1 | 1–1024; multiplies the adaptive transmission budget |
| `maxSendingWindow` | 2097152 | MTU–16 MiB; bounds queued unacknowledged data |

Capacities accept 0–4095, subject to the receive storage bound below. Zero means
the minimum eight packet slots; it does not disable traffic. Capacity-derived
slots use `max(8, floor(floor(capacity * 1048576 / mtu) / floor(1000 / tti)))`.
Queue slots use `floor(maxSendingWindow / mtu)`. Calculations use 64 bit
intermediates. Local uplink controls local sends; local downlink controls the
advertised receive right edge. Supported local MTU, interval and capacities may
differ between peers.

The pinned Xray v26.10.10 parser accepts MTU ≥21 with no explicit upper bound,
TTI 10–1000, and wider unsigned capacity/window values. Splicore deliberately
uses the publicly recommended MTU/TTI scope and bounded storage. Acceptance of
a value by Xray does not imply its acceptance by Splicore.

## Wire and reliability

The modern wire carries big endian records directly in UDP. DATA has an 18 byte
header; ACK has `17 + 4 × N` bytes; PING and TERMINATE have 16 byte headers. ACK
lists are compressed into batches of at most 128 sequence numbers. This differs
from historical documentation describing a 16 byte ACK header.

Connections open with DATA or PING, without a separate transport handshake.
The listener keys sessions by listener, remote UDP address/port and a 16 bit
token. Each outbound session owns a private UDP socket and a random token.
Sequence comparisons handle wraparound. Retransmission, repeated ACKs and
selective/cumulative progress recover bounded packet loss. Reads expose ordered
bytes exactly once, without UDP datagram boundaries. Receiver window progress
follows application consumption; stopped readers and missing ACKs apply
backpressure to writers.

## Ownership and bounds

The listener owns its bound UDP socket. Outbound sockets use the existing
protected dialer, DNS and socket policy. There is no external runtime or relay.
Read/write deadlines can be changed or cleared while I/O is blocked. Admission
cancellation closes failed setup; published connections belong to their runtime
owner and outlive the dial context. Local Close wakes application I/O immediately
and drains pending writes for up to 15 seconds, then bounds termination exchange
to eight seconds. Keepalive checks occur every three seconds; a silent peer
expires after 30 seconds. Listener shutdown closes sessions and joins owners.

Receive/reorder payload reserves at most 16 MiB per connection, calculated using
the maximum supported peer MTU of 1460. ACK entries cannot exceed receive slots.
The listener admits at most 64 owned connections and reserves at most 128 MiB of
worst-case payload storage. That reservation includes the send queue, a transmit
snapshot, receive slots and a partial read. Map entries, timers and Go runtime
overhead are additional bounded resources; 128 MiB is not a process RSS claim.
Each UDP socket has one output worker with at most 128 queued datagrams and one
active write, each at most 1460 bytes of payload. This output storage is additional
to session reservations. Terminal session cleanup stably removes its queued
plans and clears their payload, flight and connection references before Done;
the fixed ring scan is at most 128 entries and never waits for UDP output.
Queue admission checks the same session lifetime mutex, so a prepared plan
cannot enqueue after terminal cleanup. A dequeued plan belongs separately to
the socket writer: it is rejected before preparation if stopped, or finishes an
already active bounded write and clears its references. Local Close retains
the existing graceful send-drain contract until terminal cleanup. Queue
admission never waits: a full queue leaves packets pending for a later tick.
Retry counts and RTO start only after successful UDP handoff. Writes have a two
second carrier deadline; session timers progress independently of output.
Retired tokens have a hard maximum of 4096 entries. Active sessions reserve
their eventual retired slot. Unexpired tokens are never evicted; late packets
are rejected for eight seconds. Expired entries are physically swept on valid
input, so an idle listener can retain expired entries until input resumes.

A completed transport leaves the active UDP session table promptly. Buffered
remote EOF data remains readable and retains its storage reservation until the
application reads or closes the connection. Listener shutdown also releases
these retained buffers. Per-session timers and private read loops have an
explicit joined completion barrier.

Normal remote EOF stops future receive input while preserving already accepted
ordered bytes, including a partial read. Transport teardown and expected socket
close errors preserve this tail; Read returns EOF after draining it. Local Close,
explicit Abort and live hard transport errors discard unread data. Receive bodies
are immutable owned copies and are not returned to a buffer pool.
The final EOF reply retries queue rejection until handoff or the bounded eight
second termination timeout; readable bytes outlive either transport outcome.

## Compatibility and limits

Local software compatibility uses exact Xray v26.10.10 commit
`701af60772cda123492f86e383e1fdba066614a9`. Configuration defaults, representative
tuning, local mismatches, large transfers and concurrent directions are tested.
Linux arm64 remains **BUILD ONLY**. Real hardware remains **NOT YET QUALIFIED**.

Canonical import/persistence retains all six tuning fields. VLESS Xray JSON
projection uses `network: "kcp"` and `kcpSettings`. Unqualified URI,
sing-box and Mihomo projections reject mKCP rather than drop settings or select
another transport; VMess/Trojan Xray export is not provided by their exporters.

Modern mKCP does not expose historical `header` or `seed`; these fields produce
a migration error. FinalMask `mkcp-legacy` is **NOT IMPLEMENTED / DEFERRED** and
its compatibility is not qualified. Existing TCP FinalMask does not compose
with this UDP transport.

mKCP supplies reliability, not encryption or authentication. The upper protocol
and optional TLS supply those properties. UDP is the carrier, without implying
a UDP proxy service. Generic KCP wire compatibility, generic QUIC, HTTP/3,
Hysteria transport, connection migration, STUN, ICE, hole punching and NAT
traversal are not claimed. Existing Hysteria2/TUIC/Naive H3 remain separate.

See [shared transports](SHARED_TRANSPORT.md) and
[the Xray mKCP documentation](https://xtls.github.io/en/config/transports/mkcp.html).
