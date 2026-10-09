# Unified Splicore CLI

- Documentation status: Canonical
- Audience: Operators and integration developers
- Last reviewed: 2026-10-04
- Owner: Control-plane maintainers
- Responsibility: Client resource commands and shared daemon control.
- Lifecycle: Update with implemented CLI behavior.

## One binary, one daemon

The existing `splicore` binary manages both roles. On Linux, client commands use the
same protected UDS selected by `--config /etc/splicore/splicore.yaml`. `status` returns
structured `server_runtimes` and `client_runtime`. `doctor` reads passive client counts,
local listeners, route and health; it does not dial remote nodes.

| Command group | Implemented operations |
| --- | --- |
| `node`, `outbound`, `local-inbound` | `list`, `get --id ID`, `validate`, `plan`, `apply` |
| `route` | `get`, `validate`, `plan`, `apply` |
| `client` | `status`, `validate`, `plan`, `apply`, `start`, `stop`, `restart` |

Mutations use canonical ClientMutation JSON, not sing-box/Mihomo configuration.
Each document names `resource` and `action` and contains the corresponding typed
`node`, `outbound`, `local_inbound` or `route`. Update/delete/rotate identify the resource
by immutable `id`. Node creation and rotation accept a write-only `credential` object
with `kind` and `value`; keep those files private. Other reads never reveal stored
credential payloads. Plan files contain HMAC digest, global revision and command
identity; they do not copy the document or secret.

```sh
splicore client status --config /etc/splicore/splicore.yaml
splicore node list --config /etc/splicore/splicore.yaml
splicore node validate --config /etc/splicore/splicore.yaml --file /private/node.json
splicore node plan --config /etc/splicore/splicore.yaml --file /private/node.json > /private/plan.json
splicore node apply --config /etc/splicore/splicore.yaml --file /private/node.json --plan /private/plan.json
splicore client restart --config /etc/splicore/splicore.yaml
```

Create a private directory and files before using shell redirection. Use separate
node/outbound/local-listener transactions, then set the default route. Node references
are server resources, not server Accounts. A stale plan fails with the current global
revision; obtain a new plan after reviewing the latest state. Lifecycle commands plan
and apply one transaction. Stop releases local sockets and sessions; it preserves
client configuration and all server runtimes.

Linux installed service/API behavior is runtime qualified. Windows tests exercise
the native data path and in-process control transport; Linux UDS/systemd installation
is not a Windows-service claim. Existing server creation/export/service/key/backup/
support commands remain available. See [API](api/README.md), [operations](OPERATIONS.md)
and [client runtime](architecture/CLIENT_RUNTIME.md).

## Phase 11 options and observations

The same node/outbound/local-inbound/client commands handle every registered adapter.
Select `engine` on Outbound; VLESS nodes use native only; unsupported engine pairs reject. Generic
CredentialInput.kind also accepts `uuid_password` and `username_password`; value is
a private JSON string containing the canonical pair. Public TLS/REALITY trust fields
belong in Node.security.tls, never server private material. Unknown adapter options,
Vision and client masks reject before commit. Status reports UDP associations/packets
separately from TCP sessions; dimensions must not be summed. No protocol-specific
command group, service or configuration file is added.

## Phase 12 routing, policy and DNS

| Group | Operations |
| --- | --- |
| network | export/status; validate/plan/apply canonical Config or network-replace mutation |
| route | status; explain --file query.json (no network I/O); existing legacy default commands remain |
| route-rule / rule-set | list/export; validate/plan/apply typed ClientMutation |
| policy | list/status; validate/plan/apply; select --id UUID --file action.json |
| dns | list/status; validate/plan/apply; lookup --domain synthetic.local; flush |

All use the existing --config protected UDS or Application directly in tests.
Network export can be imported with network validate/plan/apply; plan digest binds the
normalized network-replace command and revision. Files are at most 2 MiB. Policy select
plans/applies atomically; existing sessions remain. DNS lookup performs a real query,
while explain reads supplied metadata only. No new service/binary or protocol command.

## Phase 13 host integration

`tun status|validate|plan|apply` uses local-inbound intent. Files for these aliases use the normal ClientMutation envelope. `network repair` uses Application plan/apply and only recorded owned resources after client stop. `service recover-network` is the stopped-service local recovery helper. Doctor is passive and lists stack/driver/privileges/owned routes/DNS mode/journal/exclusions. See [system integration](SYSTEM_INTEGRATION.md).

## Phase 14 imports, exports and providers

Use owner-only files or stdin for secret-bearing inputs. URI argv is rejected.
Provider create/update/delete commands return previews; apply is explicit. Manual
`refresh` performs a complete guarded transaction; `refresh-preview` is a dry run.

```sh
splicore node import-uri --config /etc/splicore/splicore.yaml --file /private/uris.txt --generate-outbounds > /private/plan.json
splicore node apply --config /etc/splicore/splicore.yaml --plan /private/plan.json
splicore node import --config /etc/splicore/splicore.yaml --format canonical --stdin
splicore provider create --config /etc/splicore/splicore.yaml --file /private/provider-command.json
splicore provider list --config /etc/splicore/splicore.yaml
splicore provider get --config /etc/splicore/splicore.yaml --id PROVIDER_UUID
splicore provider refresh-preview --config /etc/splicore/splicore.yaml --id PROVIDER_UUID
splicore provider refresh --config /etc/splicore/splicore.yaml --id PROVIDER_UUID
splicore node export --config /etc/splicore/splicore.yaml --provider-id PROVIDER_UUID --format canonical --reveal-secrets > /private/nodes.json
```

`provider` and `ruleset-provider` share create/update/delete/list/get/refresh-preview/
refresh/apply operations, enforcing their distinct resource kind. Create/update files
are ManagementRequest envelopes with provider/source; update sets --id and immutable
provider ID/kind/RuleSet ID but omits read-only diagnostics. Source omitted on update
retains encrypted settings. `node batch --file` takes operation=batch, action, IDs and
tags or metadata. Metadata replacement can move display folders without changing
ownership. Generic export uses one of --id, --provider-id or --all; secrets require
explicit reveal. External client-version gates apply; compatibility goes to stderr.
Existing `node apply --file mutation.json --plan client-plan.json` retains the prior
CRUD transaction; `node apply --plan management-preview.json` applies import tokens.
All operations reuse the existing protected control transport. Doctor is passive.
See [imports](architecture/IMPORT_MODEL.md) and [providers](architecture/PROVIDER_MODEL.md).
