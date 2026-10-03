# Unified Splicore CLI

- Documentation status: Canonical
- Audience: Operators and integration developers
- Last reviewed: 2026-10-03
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
Select `engine` on Outbound; VLESS nodes can be referenced by native and Xray. Generic
CredentialInput.kind also accepts `uuid_password` and `username_password`; value is
a private JSON string containing the canonical pair. Public TLS/REALITY trust fields
belong in Node.security.tls, never server private material. Unknown adapter options,
Vision and client masks reject before commit. Status reports UDP associations/packets
separately from TCP sessions; dimensions must not be summed. No protocol-specific
command group, service or configuration file is added.
