# Native local tunnel guard (Phase29.1)

Internal Core documentation. Scope: native local tunnel guard supporting TLS
SNI allow + fail-closed routing for REALITY protected-destination deployments.
This is an implementation candidate for independent review, not a qualification
claim covering all Xray security behavior.

## Owners and dependency direction

```text
native VLESS/Vision/REALITY inbound
  -> normal native target dial to 127.0.0.1:39000
  -> clientruntime local TCP tunnel listener
  -> engine/sniff TLS ClientHello inspection (metadata only)
  -> networkruntime ordered inbound + exact sniffed domain match
  -> existing native direct dial to configured target, or native reject
```

`domain/client.ProfileState` owns local ingress intent, including this tunnel.
The existing `domain/networkpolicy.Config` owns route intent. SQLite committed
documents remain authoritative; clientruntime snapshots are derived. Bootstrap
configuration remains process configuration, and exported ClientProfiles remain
client connection descriptions. There is no second runtime configuration format
and no Xray-shaped config compatibility layer. The tunnel imports no REALITY
internals and adds no production library dependency or subprocess.

## Native configuration and safe provisioning

The routing tag is the existing local inbound **ID** (a UUID). `name` is a display
label, not a routing identity. Existing plan/apply APIs and CLI accept the native
typed documents. A local tunnel mutation looks like:

```json
{
  "resource": "local-inbound",
  "action": "create",
  "local_inbound": {
    "id": "00000000-0000-4000-8000-000000000001",
    "name": "REALITY cover guard",
    "kind": "tunnel",
    "listen": {"host": "127.0.0.1", "port": 39000},
    "tunnel": {
      "target": {"host": "www.3verge.com", "port": 443},
      "network": "tcp"
    },
    "sniffing": {"enabled": true, "protocols": ["tls"], "route_only": true}
  }
}
```

The native network policy must place these two routes before any broader route
that could apply to this inbound:

```json
{
  "route": {
    "rules": [
      {
        "id": "00000000-0000-4000-8000-000000000002",
        "name": "approved visible SNI",
        "match": {
          "local_inbounds": ["00000000-0000-4000-8000-000000000001"],
          "sniffed_domains": ["www.3verge.com"]
        },
        "action": {"kind": "direct"}
      },
      {
        "id": "00000000-0000-4000-8000-000000000003",
        "name": "guard fail-closed fallback",
        "match": {"local_inbounds": ["00000000-0000-4000-8000-000000000001"]},
        "action": {"kind": "reject"}
      }
    ]
  }
}
```

This is `networkpolicy.Config`, used in the existing `resource: network`,
`action: replace`, `network: ...` mutation. Preserve other configured network
resources when replacing the aggregate. Alternatively replace the existing
route profile through its native mutation API. Plan then apply each mutation
through `/api/v1/client/plan` and `/api/v1/client/apply` with the returned digest
and revision. Provision the tunnel first (no applicable routes = deny), then
install the complete allow/fallback pair atomically, then create REALITY. A deny
rule alone is also valid. A direct allow without its following scoped reject
is rejected at validation. Rules that could bypass the guard before its scoped
fallback, including broad direct rules or policy groups, are rejected.

The existing VLESS server creation settings can then contain:

```json
{
  "security": "reality",
  "flow": "xtls-rprx-vision",
  "transport": "tcp",
  "packet_encoding": "xudp",
  "reality": {
    "server_name": "www.3verge.com",
    "short_ids": ["abcd"],
    "target": {"host": "127.0.0.1", "port": 39000}
  }
}
```

Use the existing server creation workflow for users and private key generation.
`server_name` remains the client export default. Optional `server_names` accepts
up to 16 distinct DNS names and must include that default. It controls REALITY
handshake policy only. Guard `sniffed_domains` is independently configured and
can contain multiple exact names. Authenticated proxy payloads do not acquire a
domain whitelist from either REALITY server names or the cover guard.

The process composition restores local listeners before server listeners using
`EnableRuntimeWithClient`; a persisted REALITY destination can therefore find
its local guard on restart. Embedded server-only users retain `EnableRuntime`;
combined deployments should use `EnableRuntimeWithClient`.

## Security semantics and limits

- Every tunnel in this phase is a protected local guard. Only explicit listener
  literals `127.0.0.1` and `::1` are accepted; `allow_lan` is prohibited. Wildcard,
  public, DNS-resolved and other listener forms are rejected. Missing listener
  host uses the existing local inbound default `127.0.0.1`.
- Network is exactly `tcp`. `udp`, `tcp,udp` and unknown values are rejected; no
  UDP socket is opened and no UDP tunnel forwarding is implemented.
- A valid visible TLS SNI plus the matching inbound identity can select direct;
  everything else is rejected. No explicit matching allow defaults to reject,
  even if the ordinary profile's final/default outbound is direct.
- `sniffed_domains` uses the existing DNS rule canonicalizer: ASCII DNS names,
  case insensitive, one trailing dot removed, exact host equality. No substring,
  implicit suffix, wildcard, empty, malformed or IP-literal match is admitted.
  The ordinary `domains` field describes target metadata and cannot authorize
  a guard. Configured target domains can never stand in for observed SNI.
- Sniffing has a **2 second absolute** read deadline; partial reads never extend
  it. Wire prefix <=64 KiB, ClientHello including handshake header <=32 KiB,
  record payload <=16 KiB, <=128 handshake records. At most 512 tunnel sessions
  are admitted per manager (within its existing 4096 total session bound).
- TLS 1.2/1.3 ClientHello framing, null compression, and exactly one usable SNI
  host_name are supported. TCP read fragmentation and handshake fragmentation
  across TLS records are supported within those bounds. Duplicate extensions,
  duplicate/unknown SNI name types, malformed vectors, excess lengths, non-TLS,
  missing SNI, truncation and timeout fail closed before upstream DNS/dial.
  Other extension bodies are opaque; this is not a complete TLS endpoint or a
  cryptographic handshake validator. The real destination validates TLS.
- No usable visible SNI (including ECH without a usable outer name) is rejected.
  Visible outer SNI is treated as visible metadata; there is no ECH decryption.
- Sniffing is strictly route-only: the configured target address/port remains
  the dial destination, including after a different allowed hostname is seen.
  No DNS lookup or dial is performed on the sniffed hostname. Any target DNS
  resolution uses the normal native direct underlay path after admission.
- Every consumed byte is replayed once, followed by unread bytes in order.
  Neither TLS termination nor MITM/certificate generation occurs in the guard.
- Exact self-targets (including IPv4-mapped spelling) and same-port localhost
  targets are rejected. DNS alias loops, cross-tunnel cycles and general network
  recursion detection are outside this bounded configuration check.

After allow, existing stream copying, half-close handling, accounting, dial
timeout and shutdown cancellation own the connection. Each session retains its
immutable configuration generation until cleanup; subsequent sessions use the
committed generation. Route updates follow existing session retention semantics.

## Observations and implementation references

`client/runtime` status exposes `tunnel_guards` counters: accepted, allowed
(policy decision, not upstream dial success), denied, sniff timeout, malformed
TLS, sniff limit, no visible SNI and truncated. Existing route hit/error/traffic
counters remain available. No ClientHello, application payload, UUID, credentials
or REALITY key material is logged by this feature.

Independently written parser references: [RFC 8446 ClientHello and record
framing](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2) and
[RFC 6066 SNI](https://www.rfc-editor.org/rfc/rfc6066.html#section-3). The existing
domain canonicalization intentionally also accepts one trailing dot. No Xray
implementation source was copied or inspected for this implementation. Optional
Xray differential oracle: NOT EXECUTED.
