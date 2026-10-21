# REALITY protected destinations and local tunnel guards

Native REALITY protected-destination support uses a local TCP tunnel guard,
bounded TLS SNI inspection, route-only matching, fixed configured destination
authority, Core DNS resolution and fail-closed routing. The guard is a native
local inbound and can be composed with the existing REALITY target setting.

## Native configuration

Create a local inbound through the existing client plan/apply interfaces:

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
      "target": {"host": "cover.example.com", "port": 443},
      "network": "tcp"
    },
    "sniffing": {"enabled": true, "protocols": ["tls"], "route_only": true}
  }
}
```

Example UUIDs are placeholders; use unique resource IDs. Replace
`cover.example.com` with an intended TLS destination. Listeners accept only
literal `127.0.0.1` or `::1`; LAN exposure and UDP are rejected.

The network route policy must scope admission to the local inbound ID and
exact approved visible SNI, followed immediately by its scoped reject fallback:

```json
{
  "route": {
    "rules": [
      {
        "id": "00000000-0000-4000-8000-000000000002",
        "name": "approved visible SNI",
        "match": {
          "local_inbounds": ["00000000-0000-4000-8000-000000000001"],
          "sniffed_domains": ["cover.example.com"]
        },
        "action": {"kind": "direct"}
      },
      {
        "id": "00000000-0000-4000-8000-000000000003",
        "name": "guard fallback",
        "match": {"local_inbounds": ["00000000-0000-4000-8000-000000000001"]},
        "action": {"kind": "reject"}
      }
    ]
  }
}
```

This is the network configuration inside a `resource: network`,
`action: replace`, `network: ...` mutation. Preserve the other network resources
when replacing the aggregate, or use the existing route profile mutation.
Use `/api/v1/client/plan` then `/api/v1/client/apply` with its returned revision
and digest. Create the tunnel first, install the complete route pair atomically,
then create REALITY. Until admission exists, the guard denies traffic. A direct
allow without its scoped reject, or a preceding rule that can bypass this
policy, is rejected by validation.

Set the managed REALITY inbound's `reality.target` to
`{"host":"127.0.0.1","port":39000}` using the existing VLESS creation workflow.
Its `server_name` and optional `server_names` control REALITY handshake policy
separately from guard admission. Server private keys remain server owned.
Authenticated proxy payloads do not acquire the cover guard's SNI allowlist.
See [VLESS configuration](VLESS.md) and the [local API](../api/README.md).

## Routing and DNS semantics

Sniffed SNI is routing metadata only. Even if another approved SNI is observed,
the configured destination host and port remain authoritative. The sniffed
hostname is never resolved or dialed. Destination resolution happens only after
admission, through the same Core DNS authority as ordinary native streams.
Errors from configured Core DNS do not trigger an implicit system DNS fallback.
An explicitly selected Core system resolver or DNS-disabled ordinary-stream
configuration retains its configured behavior.

The process restores local listeners before dependent server listeners.
Embedders combining server and client runtimes use `EnableRuntimeWithClient`.
Connections retain their immutable configuration generation until cleanup.

## Inspection bounds and limits

Inspection has an absolute two-second deadline, a 64 KiB consumed-prefix limit,
a 32 KiB ClientHello limit, a 16 KiB record limit and at most 128 records.
Malformed, truncated, over-limit, timed-out, non-TLS or unusable-SNI traffic
fails closed before upstream resolution or dialing. Consumed bytes are replayed
once in order through the normal native stream path.

The parser inspects visible ClientHello metadata. It does not terminate TLS,
generate certificates, decrypt ECH or validate the complete cryptographic
handshake. ECH without a usable visible outer name is rejected. There is no
arbitrary sniffed-SNI forwarding, generic firewall, UDP defender or full Xray
defender parity. Exact self-targets are rejected; general DNS alias loops and
cross-tunnel cycles remain outside this bounded configuration check.

`client/runtime` exposes `tunnel_guards` admission and parser outcome counters.
The allowed counter records a policy decision, not successful upstream dialing.
The feature does not log ClientHello bytes, application payloads or key material.
