# CLI usage

One `splicore` binary manages Server Core and Client Core. Linux commands use
the protected local socket selected by `--config`. On Windows the same bootstrap
field identifies a local named pipe scoped to the current user and normalized
path. The kernel rejects remote pipe clients. The pipe DACL allows the owner and
SYSTEM; clients verify the connected server's owner/DACL before sending API data.

```sh
splicore version --json
splicore help
splicore check --config distribution/splicore.yaml
splicore validate distribution/splicore.yaml
splicore status --config /etc/splicore/splicore.yaml
splicore capabilities --config /etc/splicore/splicore.yaml
splicore doctor --config /etc/splicore/splicore.yaml
splicore client status --config /etc/splicore/splicore.yaml
```

| Group | Purpose |
| --- | --- |
| `inbound`, `key` | Server resource creation, planning, application and explicit exports |
| `node`, `outbound`, `local-inbound`, `local-binding`, `route` | Typed client resources and route intent |
| `client` | Client status, validation, planning, application, start/stop/restart |
| `network`, `route-rule`, `rule-set`, `policy`, `dns`, `tun` | Network graph, selectors, DNS and local TUN intent |
| `provider`, `ruleset-provider`, `node import/import-uri/export/batch` | Imports, provider refresh and protected exports |
| `service`, `package`, `state`, `support-bundle` | Native operations, backups and diagnostics |

## Resource transactions

Client resource mutations are canonical Splicore JSON with `resource`, `action`
and the matching typed object. They are not sing-box or Mihomo configuration.
For a prepared, private node mutation:

```sh
splicore node validate --config /etc/splicore/splicore.yaml --file /private/node.json
splicore node plan --config /etc/splicore/splicore.yaml --file /private/node.json > /private/plan.json
splicore node apply --config /etc/splicore/splicore.yaml --file /private/node.json --plan /private/plan.json
```

Create owner-only files/directories before redirecting output. Plans bind normalized
intent and the global revision; stale plans are rejected. Stored credentials are
encrypted and ordinary reads do not reveal them. Imports accept private files or
stdin; credential-bearing URIs are not accepted as command-line arguments.
Secret export requires an explicit reveal option. Provider previews do not apply
changes; refresh/application is explicit.

`doctor` is passive; `dns lookup` deliberately sends a query. Client stop releases
local listeners and sessions while retaining configuration and server runtimes.
Desktop system proxy/PAC commands are absent. Linux service/control support does
not imply Windows service installation or host-network qualification. Windows
foreground core/control is implemented; service installation remains Linux-only.

See [API integration](api/README.md), [operations](OPERATIONS.md) and
[configuration](CONFIGURATION.md). The retained application/domain types define
the detailed JSON shapes for each resource.

## Key provisioning

For a new installation, run `splicore key init --file /var/lib/splicore/master.key`
as the account that will run the Core. Parent directories must be private and
owned by that account. The command refuses to overwrite an existing key. Set
the bootstrap `key_file` to that path; startup loads it without creating a key.
Preserve the original key with the database during backup or recovery.

## Offline checks and foreground lifecycle

`help`, `version`, `--help`, and `run --help` do not need configuration or a daemon.
Version includes product version, source commit, build time, Go, GOOS/GOARCH,
CGO state and build tags. Development builds report `devel`.

`check --config <bootstrap>` validates strict bootstrap structure, configured key
resources, control path and existing committed SQLite state through a read-only
connection. It checks server projections, credentials, referenced TLS material
and the stored client/network graph. It does not initialize a database, migrate,
recover pending transactions, start workers, bind ports or probe remote targets.
Pending recovery or unavailable encrypted resources are errors. A fresh install
may have no database yet. SQLite's existing read-only WAL reader semantics apply.

Add `--protocol <name> --file <canonical inbound.json>` to validate a new inbound
with the production codec, including port ranges, transport/security parameters
and TLS certificate/key identity/trust. A successful check cannot guarantee that
a port will still be available later. `validate <bootstrap>` retains its older,
bootstrap-only behavior. Do not substitute a third-party full-core JSON config.

`run --config <bootstrap>` stays in the foreground. `Splicore ready` is emitted
after database/key loading, registry construction, stored listener restoration
and management-worker startup. Process logs use stderr. Ctrl+C/SIGTERM or
`stop --config <bootstrap>` drains the local API, cancels/joins owned runtime
connections/workers and closes SQLite/installation ownership. `client stop`
only stops Client Core; `stop` requests shutdown of the entire daemon. Exit 0
means successful completion; errors exit 1 with redacted fixed diagnostics.
The protected local `POST /api/v1/runtime/shutdown` takes no body/query.

## Loopback VLESS example

After key provisioning and daemon startup, use the checked-in
`distribution/vless-loopback.json`. It listens only on 127.0.0.1:10810; the omitted
UUID is generated during application and encrypted in SQLite. This plain local
example is for local testing. Configure TLS/REALITY before remote deployment.

```sh
splicore check --config distribution/splicore.yaml --protocol vless --file distribution/vless-loopback.json
splicore inbound plan --config distribution/splicore.yaml --protocol vless --file distribution/vless-loopback.json > /private/plan.json
splicore inbound apply --config distribution/splicore.yaml --protocol vless --file distribution/vless-loopback.json --plan /private/plan.json
splicore inbound list --config distribution/splicore.yaml
```

Create a private plan directory first. Use the returned inbound/binding IDs and
the existing explicit inbound export command to obtain an authorized client
profile. Resource creation binds a real native listener; restarting the core
restores it from committed state. Windows uses the same commands with its
bootstrap and executable; PowerShell users should write redirected plan JSON
as UTF-8 without a BOM (PowerShell 7 does so by default).
