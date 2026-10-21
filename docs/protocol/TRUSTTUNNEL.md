# Native TrustTunnel

The experimental `trusttunnel/1/base` profile provides native inbound and
outbound TCP/UDP sessions over authenticated TLS HTTP/2 or HTTP/3. `auto` races
HTTP/3 against a delayed HTTP/2 attempt. HTTP/3 and `auto` require `with_quic`;
HTTP/2 is available without that tag. Other protocols do not acquire a generic
HTTP/3 or QUIC transport from this profile.

## Configuration

Use the existing managed inbound creation, account, Binding and credential
interfaces with protocol `trusttunnel`. A creation document can use:

```json
{
  "schema": 1,
  "name": "TrustTunnel service",
  "listener": {"host": "0.0.0.0", "port": 443},
  "display_endpoint": {"host": "vpn.example.com", "port": 443},
  "settings": {
    "mode": "http2",
    "tls": {
      "server_name": "vpn.example.com",
      "certificate_file": "/etc/splicore/server.pem",
      "private_key_file": "/etc/splicore/private/server.key",
      "ca_certificate": "<CA certificate PEM>"
    },
    "icmp": false
  },
  "users": [{"account_name": "Alice", "username": "alice"}]
}
```

Replace example names, endpoints and CA material with your deployment's values.
An omitted password uses the existing credential generator. TLS and Basic
authentication complete before a target is dialed. HTTP/2 owns TCP, HTTP/3 owns
UDP, and `auto` owns both on the configured port. Session, handler and flow
limits are bounded. Strict quota, rate and account session policy enforcement
are unsupported and reject through capability validation.

Outbound nodes use protocol `trusttunnel`, wire version `1`, feature profile
`base`, TLS security and a separate username/password Credential. Transport is
`tcp` for HTTP/2 or `auto`, and `udp` for HTTP/3. Options include `mode`, up to
16 `addresses`, `custom_sni`, `insecure_skip_verification`, `disable_ipv6`,
connection/health/idle timeouts, `fallback_delay`, `max_streams` and `max_flows`.
Certificate verification is enabled by default. Shared stream wrappers and
custom header maps are rejected.

Static `tt://` links support bounded import of documented versions 0–2 and
version 1 export. Auto mode and options that cannot be represented reject
export. Subscription runtime, anti-DPI and optional ClientRandom extensions
are not supported runnable profiles.

## Limits and qualification

Production uses native Go sessions and pinned independent TLS/HTTP/QUIC
libraries. No external proxy Core or official TrustTunnel executable is needed
at runtime. Tests against pinned reference peers cover supported TCP/UDP
profiles; they do not establish complete implementation or fingerprint parity.
Historical intermittent EOF behavior is not proven absent or fully explained.
Successful fixed-length reads alone do not establish EOF.

Reference peers have documented empty UDP and single-byte payload limitations;
native peers support those payloads. ICMP is off by default. Its optional
server path requires suitable raw-socket privileges and currently forwards
echo replies only; general ICMP and official client TUN interoperability are
not qualified. The generic Core TCP/UDP outbound interface exposes no ICMP method.

HTTP/1.1, browser/TLS fingerprint parity, anti-DPI parity, post-quantum
fingerprint parity, kill switch, subscription services and automatic certificate
management are not claimed. Linux arm64 remains BUILD ONLY.
