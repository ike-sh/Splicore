# Native VLESS Encryption

Splicore implements the client and server wire protocol pinned to Xray-core
`v26.10.21` (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`). This experimental
implementation protects VLESS payloads before UUID authentication. It provides
neither TLS server identity nor HTTPS camouflage.

## Generate configuration

```sh
splicore vlessenc --auth mlkem768 --mode random --handshake 0rtt --ticket 600s
```

The explicit JSON output contains a private server `decryption` string and its
public client `encryption` string. Supported authentication methods are `x25519`
and `mlkem768`; modes are `native`, `xorpub`, `random`; client policy is `1rtt`
or `0rtt`. Every full handshake uses ephemeral ML-KEM-768 **and** X25519.

Enabled grammar:

```text
mlkem768x25519plus.MODE.POLICY.[PADDING.]KEY[.KEY...]
server POLICY: Ns or N-Ms (bare integer also accepted by the pinned reference)
client POLICY: 1rtt or 0rtt
PADDING: probability-min-max[.probability-min-max...]
```

Keys use canonical unpadded URL-safe base64. Server keys decode to an X25519
private scalar (32 bytes) or ML-KEM-768 seed (64 bytes). Client keys decode to a
32-byte X25519 public key or 1184-byte ML-KEM-768 public key. Ordered mixed chains
are supported; they are not alternative keys.

## Create an inbound

Use the existing VLESS creation API/Application Service. For example, pass this
creation document to the ordinary VLESS creation workflow, replacing the private
placeholder with generator output:

```json
{
  "schema": 1,
  "name": "encrypted-vless",
  "listener": {"host": "0.0.0.0", "port": 8443},
  "display_endpoint": {"host": "proxy.example", "port": 8443},
  "settings": {
    "security": "none",
    "flow": "none",
    "transport": "tcp",
    "packet_encoding": "xudp",
    "stream_transport": {"kind": "tcp"}
  },
  "server_secret": {"decryption": "<private server string>"},
  "users": [{"account_name": "Alice"}, {"account_name": "Bob"}]
}
```

The inbound owns one encryption credential shared by its UUID users. SQLite
stores it through the existing encrypted credential mechanism. Public settings,
profiles and ordinary API/diagnostic responses contain only the derived public
`encryption` string. REALITY's `server_secret.private_key` remains separate and
can coexist with `server_secret.decryption`. Normal UUID authentication remains
required after channel establishment.

Client nodes use `options.data.encryption` alongside the existing `security`,
`flow` and `packet_encoding`. Omitted historical fields retain `none`; explicit
empty strings, null, misspelled methods and unknown modes reject. No failure
falls back to plaintext. Foreign configuration export supports only the qualified
Xray `26.10.21` target; other formats/versions reject enabled encryption.

## Composition

Raw TCP has bidirectional pinned Xray runtime traffic tests for outer none,
TLS and REALITY, flow-none and Vision, and all three modes. The independent
client consumes the production Xray exporter output. WebSocket, HTTPUpgrade,
gRPC, XHTTP H1/H2 and mKCP compose through the existing shared transport; native
TCP and XUDP regression tests cover those carriers. Generic HTTP/H2/QUIC and
XHTTP H3 remain separate pending restorations and are not enabled here.

Outer security `none`, TLS and REALITY are supported. TLS trust/SNI checks and
REALITY local tunnel guards retain their existing owners. Vision is TCP only
and works with enabled encryption over outer none, TLS or REALITY. After Vision
command 2, verified inner TLS records replace the VLESS AEAD record layer;
`random` retains the continuous record-header XOR, while outer TLS/REALITY
remains in place. Existing XUDP is carried inside encrypted streams for flow
`none`; Vision packet sessions remain rejected.

## Resumption and bounds

`1rtt` always performs the full hybrid exchange. `0rtt` first acquires a ticket,
then uses protocol resumption on subsequent connections. It is not pooling.
Client state belongs to one outbound node/account instance. Restart, expiry,
replay detection or eviction can invalidate a ticket; a failed connection is
reported and a later connection performs a full handshake. Application data is
never automatically replayed.

Configuration is limited to eight keys, 31 padding tuples, ticket durations
0–65535 seconds, individual gaps at most 1000 ms and total padding at most
65553 bytes. Probabilities must be 0–100; the pinned comparison means probability
0 still selects one time in 100. The first length tuple must be probability 100
with minimum 35. Length/delay tuples alternate, with an optional trailing delay.
Negative/reversed ranges, extra tuple fields and noncanonical keys reject.
These explicit bounds harden unsafe permissive reference parsing; they do not
claim identical acceptance of malformed reference inputs.

The pinned reference runs Encryption before its VLESS request timeout. Splicore
keeps a bounded timing policy: five seconds for active processing/I/O, plus the
exact maximum local padding sleep, plus 15 seconds for independently configured
peer padding (at most 15 gaps of 1000 ms in the supported 31-tuple scope).
The absolute total is at most 35 seconds; elapsed intentional sleep consumes this
allowance. It is never extended by peer input or reset by network activity.
For a non-fixed range the upper endpoint is excluded; probability 99 or 100 is
mandatory, and lower probabilities can still select the maximum delay. Default
local padding contributes at most 110 ms. Both Encryption and native admission
through UUID validation use this calculation. Earlier caller cancellation and
transport-owned deadlines remain effective; admission does not overwrite them.
Resumed wire behavior and padding encoding are unchanged. A reference peer using
larger delays than this documented scope may time out.

The existing listener caps concurrent connections at 512. Each server holds at
most 1024 tickets and 4096 used NFS
secrets per ticket; reaching the replay bound invalidates the whole ticket.
Server expiry follows the reference minute-bucket grace. Records authenticate
before any plaintext is exposed and use bounded buffers. Encryption owns no
DNS resolver, route selector, socket dial or external proxy process.

## Restoration and qualification

This source restores the native implementation introduced in commit
`39c91b01355c0e43d47b2459c7af629fd0c1bb1a`, preserved by Frozen
`e42c6e995d000205ba7c1c316eda1a0e95ef8297`. It adapts to the current Core
interfaces and retains current permission, provider, underlay and shutdown fixes.
No module downgrade or schema migration is required. The protocol remains
experimental; implementation and local peer tests do not certify every client.
Android/v2rayNG device traffic and native ARM64 execution are NOT EXECUTED.
Cross-compilation is build evidence only.

CI fetches an official digest-pinned test peer through
`scripts/dev/fetch-vless-reference.py`; the product never invokes or links Xray.
`distribution/feature-gates.json` records required source and regression tests.
`scripts/dev/check-features.py` checks their presence before CI/release work; real
positive, negative and lifecycle tests remain the qualification gates.
