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

Paths must be absolute. `key_file` is optional; otherwise it is placed in the
state directory. Unknown fields, duplicate keys, aliases and multiple YAML
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
