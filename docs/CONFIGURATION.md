# Configuration and state

Splicore separates process bootstrap from proxy and network intent. The bootstrap
is schema-1 YAML with strict field validation:

```yaml
schema: 1
state_directory: /var/lib/splicore
key_file: /var/lib/splicore/master.key
api:
  unix_socket: /run/splicore/splicore.sock
```

Paths must be absolute. For credential and encrypted provider storage, set
`key_file` to a private key provisioned with `splicore key init --file <path>`
as the Core account. The loader never creates a missing explicit key. Omitting
`key_file` leaves the credential vault unconfigured; it does not select or
create a default key. Unknown fields, duplicate keys, aliases and multiple YAML
documents are rejected. Bootstrap input is limited to 1 MiB.

```sh
splicore validate distribution/splicore.yaml
splicore run --config distribution/splicore.yaml
```

SQLite `state.db` in the state directory is the persistent authority for accounts,
inbounds, bindings, encrypted credentials, client nodes, routing, DNS, policy and
providers. The bootstrap does not contain a proxy profile or user list. Preserve
the database and its matching master key together; protect their filesystem
permissions. See [backups](UPGRADE.md).

Resource changes use typed Splicore JSON with validation, planning and application
through the [CLI](CLI.md) and [local API](api/README.md). Exported third-party client
formats are projections for those clients, not Splicore bootstrap documents.
Do not edit SQLite rows to bypass the application contract.

## Proxy resources

Create server listeners through protocol-specific managed documents, then plan
and apply them with revision guards. Client nodes use separate protocol,
transport, security, endpoint and credential fields. See [VLESS/Vision](protocol/VLESS.md),
[FinalMask](architecture/FINALMASK.md), [AnyTLS server](configuration/inbound/anytls.md)
and [AnyTLS client](configuration/outbound/anytls.md) for accepted settings.
See also [NaiveProxy](architecture/NAIVE.md), [mKCP](architecture/MKCP.md),
[XHTTP](architecture/XHTTP.md) and [Hysteria transport](architecture/HYSTERIA_TRANSPORT.md)
for their supported settings. Protocol settings belong in typed resources,
not in the bootstrap YAML.
