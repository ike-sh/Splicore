# CLI usage

One `splicore` binary manages Server Core and Client Core. On Linux, commands
use the protected local socket selected by `--config`.

```sh
splicore version --json
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
not imply Windows production local control or service integration.

See [API integration](api/README.md), [operations](OPERATIONS.md) and
[configuration](CONFIGURATION.md). The retained application/domain types define
the detailed JSON shapes for each resource.

## Key provisioning

For a new installation, run `splicore key init --file /var/lib/splicore/master.key`
as the account that will run the Core. Parent directories must be private and
owned by that account. The command refuses to overwrite an existing key. Set
the bootstrap `key_file` to that path; startup loads it without creating a key.
Preserve the original key with the database during backup or recovery.
