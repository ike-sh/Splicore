# Snell inbound

Use the protected creation API/CLI with a canonical document:

```json
{
  "schema": 1,
  "account_name": "example",
  "name": "snell-v4",
  "listener": {"host": "0.0.0.0", "port": 24443},
  "display_endpoint": {"host": "proxy.example", "port": 24443},
  "settings": {"version": 4, "obfs_mode": "http"}
}
```

An omitted `psk` generates a secret. A supplied PSK must meet the portable
12..255-byte ASCII credential contract. Keep supplied credentials private.
The listener requires an IP address. One inbound has one account/binding/PSK.

`version` is required: 4, 5 or 6. For v4, `obfs_mode` may be omitted, `none`,
or `http`. Client-only host, URI, reuse and UDP-port options are rejected inbound.
v5/v6 settings contain only `version`; v6 retains its existing shaping.
Unknown fields, duplicate keys and null values are rejected.

The native server supports TCP and UDP relay over TCP, including IPv4/IPv6/domain
destinations and serial reusable v4 requests. HTTP obfs is an initial header
wrapper. v5 also owns UDP on the same listener address and port for authenticated
QUIC Initials and raw QUIC forwarding. Allow both TCP and UDP through the network.
UDP bind failure rolls back TCP; Close releases both. v5 retains v4 TCP/UDP
compatibility. TLS obfs and userkey multi-user extensions are not implemented. See [Native Snell](../../protocol/SNELL.md) for wire limits,
interoperability, statistics and qualification scope.
