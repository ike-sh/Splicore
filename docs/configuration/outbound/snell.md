# Snell outbound

A canonical remote node uses an owned PSK Credential, native proxy outbound,
TCP transport and no transport security wrapper:

```json
{
  "name": "snell-v4",
  "protocol": {"protocol": "snell", "wire_version": "4", "feature_profile": "base"},
  "endpoint": {"host": "proxy.example", "port": 24443},
  "transport": {"kind": "tcp"},
  "security": {"kind": "none"},
  "options": {
    "schema_version": 1,
    "data": {
      "version": 4,
      "reuse": true,
      "udp": true,
      "obfs_mode": "http",
      "obfs_host": "cover.example",
      "obfs_uri": "/resource?x=1"
    }
  },
  "metadata": {}
}
```

Create the node with the protected client plan/apply command and a PSK credential;
the control plane assigns identity and ownership. This is a node template, not
a complete canonical import document. An import document wraps the node and
test/private credential in `schema_version: 1` and `nodes`.

| v4 option | Default / rule |
| --- | --- |
| `version` | Required, exactly 4 for this profile |
| `reuse` | false; serial physical-connection reuse |
| `udp` | true when omitted; false disables packet flows |
| `udp_port` | Omitted uses endpoint port; otherwise 1..65535, UDP enabled |
| `obfs_mode` | Omitted or `none`; `http` enables native HTTP wrapper |
| `obfs_host` | HTTP only; intentionally defaults to `localhost` |
| `obfs_uri` | HTTP only; defaults to `/`; bounded ASCII origin-form path/query |

Host/header injection, invalid URI, unknown/duplicate/null fields, unsupported
mode and invalid port fail early. UDP domains resolve locally; each managed
packet flow remains connected to its destination. Alternate UDP port selects a
TCP association endpoint, not a UDP underlay. The preserved classic record
budget can reject large datagrams; see [Native Snell](../../protocol/SNELL.md).

v5 options remain `{"version":5}` and explicitly enable v5 dynamic records and
QUIC Proxy Mode. Valid QUIC v1/v2 Initials select UDP over UDP; ordinary UDP keeps
UDP over TCP, independently of destination port.
v6 options remain `{"version":6}` and use the separate existing v6 behavior.
Neither accepts the v4 optional fields. TLS obfs and userkey multi-user extensions
are not implemented. Surge private classifier verification remains unavailable;
see the precise qualification boundary in [Native Snell](../../protocol/SNELL.md).

Existing sing-box/Mihomo dialects support v4 reuse, UDP selection and HTTP host.
Custom URI/UDP-port export to those clients is rejected. Canonical JSON preserves
all supported options; no Snell URI scheme is defined.
