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
| `vlessenc` | Explicit offline VLESS Encryption private/public key generation |
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

`splicore vlessenc --auth mlkem768 --mode random --handshake 0rtt --ticket 600s`
explicitly outputs private server `decryption` and public client `encryption`
strings. Store this output privately. See [VLESS Encryption](protocol/VLESS_ENCRYPTION.md)
for the canonical inbound and client settings. It does not need a daemon.

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

## Managed SOCKS5 and a local client

The Linux shell examples use `jq`, `openssl` and `curl`. Set `SERVER_CONFIG`
and `CLIENT_CONFIG` to two bootstraps with separate private key, state and control
paths. Provision each key and run `splicore run --config <bootstrap>` in its own
terminal. Set `TARGET_URL` to a reachable HTTP test service, such as
`http://localhost:18080/` with an HTTP server listening on `127.0.0.1:18080`.
Use free loopback ports for `SERVER_PORT` and `LOCAL_PORT`, which default to
1080 and 1081. [Key provisioning](#key-provisioning)

### A. Create the server and test with curl

```sh
umask 077
scratch=$(mktemp -d)
SERVER_PORT=${SERVER_PORT:-1080}
LOCAL_PORT=${LOCAL_PORT:-1081}
openssl rand -hex 24 > "$scratch/password"
jq -n --argjson port "$SERVER_PORT" --rawfile password "$scratch/password" '
  {schema:1,name:"SOCKS5 demo",listener:{host:"127.0.0.1",port:$port},settings:{auth:true},
   users:[{account_name:"Demo",username:"demo",password:($password|rtrimstr("\n"))}]}' > "$scratch/server.json"
splicore check --config "$SERVER_CONFIG" --protocol socks5 --file "$scratch/server.json"
splicore inbound plan --config "$SERVER_CONFIG" --protocol socks5 --file "$scratch/server.json" > "$scratch/server.plan"
splicore inbound apply --config "$SERVER_CONFIG" --protocol socks5 --file "$scratch/server.json" --plan "$scratch/server.plan" > "$scratch/server-result.json"
inbound_id=$(jq -er .inbound_id "$scratch/server-result.json")
binding_id=$(jq -er '.bindings[0].binding_id' "$scratch/server-result.json")
splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id"
printf 'proxy-user = "demo:%s"\n' "$(cat "$scratch/password")" > "$scratch/curl.conf"
curl --fail --noproxy '' --config "$scratch/curl.conf" --proxy "socks5h://127.0.0.1:$SERVER_PORT" "$TARGET_URL"
```

`apply` starts the listener. `inbound get` shows health and per-binding payload
bytes and session counts for the current runtime generation. Explicit
`inbound export --id <inbound-id> --binding-id <binding-id> --format mihomo --client-version 1.19.32`
or `--format sing-box --client-version 1.14.2` returns a credential-bearing
TCP-only client profile. Redirect it to an owner-only file.

### B. Route a local application through the server

```sh
apply_client() {
  splicore "$1" plan --config "$CLIENT_CONFIG" --file "$scratch/$1.json" > "$scratch/$1.plan" &&
    splicore "$1" apply --config "$CLIENT_CONFIG" --file "$scratch/$1.json" --plan "$scratch/$1.plan"
}
jq -n --argjson port "$SERVER_PORT" --rawfile password "$scratch/password" '
  {resource:"node",action:"create",node:{name:"Demo upstream",
   protocol:{protocol:"socks5",wire_version:"5",feature_profile:"base"},
   endpoint:{host:"127.0.0.1",port:$port},transport:{kind:"tcp"},security:{kind:"none"},
   options:{schema_version:1,data:{auth:true,udp:false}}},
   credential:{kind:"username_password",value:({username:"demo",password:($password|rtrimstr("\n"))}|tojson)}}' > "$scratch/node.json"
apply_client node > "$scratch/node-result.json"
node_id=$(jq -er .id "$scratch/node-result.json")
jq -n --arg node "$node_id" '
  {resource:"outbound",action:"create",outbound:{name:"Demo SOCKS5",kind:"proxy",engine:"native",node_id:$node}}' > "$scratch/outbound.json"
apply_client outbound > "$scratch/outbound-result.json"
outbound_id=$(jq -er .id "$scratch/outbound-result.json")
jq -n --arg outbound "$outbound_id" --argjson port "$LOCAL_PORT" '
  {resource:"local-inbound",action:"create",local_inbound:{name:"Demo local SOCKS5",kind:"socks5",
   listen:{host:"127.0.0.1",port:$port},selected_outbound:$outbound}}' > "$scratch/local-inbound.json"
apply_client local-inbound
splicore client start --config "$CLIENT_CONFIG"
curl --fail --noproxy '' --proxy "socks5h://127.0.0.1:$LOCAL_PORT" "$TARGET_URL"
splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id"
```

### Disable a user and stop the server listener

```sh
snapshot_revision() {
  splicore inbound list --config "$SERVER_CONFIG" | jq -er .snapshot_revision
}
resource_revision() {
  splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id" | jq -er "$@"
}
binding_revision=$(resource_revision --arg id "$binding_id" '.bindings[]|select(.binding_id==$id)|.revision')
jq -n --arg revision "$(snapshot_revision)" --arg resource "$binding_revision" --arg binding "$binding_id" '
  {binding_id:$binding,enabled:false,revision:$revision,resource_revision:$resource}' > "$scratch/binding.json"
splicore inbound binding --config "$SERVER_CONFIG" --id "$inbound_id" --file "$scratch/binding.json"
lifecycle() {
  jq -n --arg action "$1" --arg revision "$(snapshot_revision)" --arg resource "$(resource_revision .inbound.revision)" '
    {action:$action,revision:$revision,resource_revision:$resource}' > "$scratch/lifecycle.json" &&
    splicore inbound lifecycle --config "$SERVER_CONFIG" --id "$inbound_id" --file "$scratch/lifecycle.json"
}
splicore client stop --config "$CLIENT_CONFIG"
lifecycle stop
splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id"
```

Use `enabled:true` with fresh revisions to enable the binding. The same
`inbound binding` command accepts `action:"rotate"` with a `credential` object
shaped like the node example, or `action:"delete"` to remove the user.
Use `lifecycle start` to start the listener again or `lifecycle delete` to
remove it and its owned users. An inbound named by a server route must be
removed from that route before deletion. The local API uses the same lifecycle
document at `POST /api/v1/inbounds/{id}/lifecycle` and binding document at
`POST /api/v1/inbounds/{id}/binding`. Dispose of the demo's private input files
after use. [SOCKS5 configuration](CONFIGURATION.md#managed-socks5)

### Enable SOCKS5 UDP

For a loopback server, use `"settings":{"auth":true,"udp":true}` in the
creation document above. Use `"auth":true,"udp":true` in the remote node's
`options.data`, or import the exported UDP-enabled binding. The local
application opens UDP ASSOCIATE on its SOCKS5 TCP connection, sends framed
datagrams to the returned address and port, and keeps the connection open
while using the relay. The remote relay also closes when its own control
connection closes.

A remote server can use settings such as the following alongside a
non-loopback TCP listener and an explicit TCP `display_endpoint`. Restrict
both ports and addresses to the intended client networks.

```json
{
  "auth": true,
  "allow_cleartext_remote": true,
  "udp": true,
  "udp_relay": {
    "listen": "0.0.0.0",
    "advertise": "proxy.example",
    "port_min": 22000,
    "port_max": 22063
  }
}
```

Allow inbound UDP 22000–22063 and forward these ports unchanged on any NAT.
Confirm delivery by sending a datagram to a known UDP target and checking the
response through the relay. [UDP configuration and source rules](CONFIGURATION.md#managed-socks5)

## Managed HTTP Proxy

Set `SERVER_CONFIG` and `CLIENT_CONFIG` to the bootstraps of two running Core
processes with independent keys, state directories and control endpoints.
Use free loopback proxy ports and set `TARGET_URL` and `HTTPS_TARGET_URL` to
reachable HTTP and HTTPS test URLs. Set `HTTPS_CA_FILE` if the HTTPS target
uses a private CA. The Linux example uses `jq`, `openssl` and `curl`.
[Key provisioning](#key-provisioning)

```sh
set -eu
umask 077
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
SERVER_PORT=${SERVER_PORT:-18081}
LOCAL_PORT=${LOCAL_PORT:-18082}
openssl rand -hex 24 > "$scratch/password"
jq -n --argjson port "$SERVER_PORT" --rawfile password "$scratch/password" '
  {schema:1,name:"Managed HTTP demo",listener:{port:$port},settings:{auth:true},
   users:[{account_name:"Demo",username:"demo",password:($password|rtrimstr("\n"))}]}' > "$scratch/http.json"
splicore check --config "$SERVER_CONFIG" --protocol http --file "$scratch/http.json"
splicore inbound plan --config "$SERVER_CONFIG" --protocol http --file "$scratch/http.json" > "$scratch/http.plan"
splicore inbound apply --config "$SERVER_CONFIG" --protocol http --file "$scratch/http.json" --plan "$scratch/http.plan" > "$scratch/http-result.json"
inbound_id=$(jq -er .inbound_id "$scratch/http-result.json")
binding_id=$(jq -er '.bindings[0].binding_id' "$scratch/http-result.json")
splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id"

printf 'proxy-user = "demo:%s"\n' "$(cat "$scratch/password")" > "$scratch/curl.conf"
server_proxy="http://127.0.0.1:$SERVER_PORT"
curl --fail --noproxy '' --proxy-basic --config "$scratch/curl.conf" --proxy "$server_proxy" "$TARGET_URL"
if [ -n "${HTTPS_CA_FILE:-}" ]; then
  set -- --cacert "$HTTPS_CA_FILE"
else
  set --
fi
curl --fail --noproxy '' --proxy-basic --config "$scratch/curl.conf" --proxy "$server_proxy" "$@" "$HTTPS_TARGET_URL"

apply_http_client() {
  splicore "$1" plan --config "$CLIENT_CONFIG" --file "$scratch/$1.json" > "$scratch/$1.plan"
  splicore "$1" apply --config "$CLIENT_CONFIG" --file "$scratch/$1.json" --plan "$scratch/$1.plan"
}
jq -n --argjson port "$SERVER_PORT" --rawfile password "$scratch/password" '
  {resource:"node",action:"create",node:{name:"HTTP demo upstream",
   protocol:{protocol:"http",wire_version:"1.1",feature_profile:"base"},
   endpoint:{host:"127.0.0.1",port:$port},transport:{kind:"tcp"},security:{kind:"none"},
   options:{schema_version:1,data:{auth:true}}},
   credential:{kind:"username_password",value:({username:"demo",password:($password|rtrimstr("\n"))}|tojson)}}' > "$scratch/node.json"
apply_http_client node > "$scratch/node-result.json"
node_id=$(jq -er .id "$scratch/node-result.json")
jq -n --arg node "$node_id" '
  {resource:"outbound",action:"create",outbound:{name:"HTTP CONNECT",kind:"proxy",engine:"native",node_id:$node}}' > "$scratch/outbound.json"
apply_http_client outbound > "$scratch/outbound-result.json"
outbound_id=$(jq -er .id "$scratch/outbound-result.json")
jq -n --arg outbound "$outbound_id" --argjson port "$LOCAL_PORT" '
  {resource:"local-inbound",action:"create",local_inbound:{name:"Local demo SOCKS5",kind:"socks5",
   listen:{host:"127.0.0.1",port:$port},selected_outbound:$outbound}}' > "$scratch/local-inbound.json"
apply_http_client local-inbound
splicore client start --config "$CLIENT_CONFIG"
curl --fail --noproxy '' --proxy "socks5h://127.0.0.1:$LOCAL_PORT" "$TARGET_URL"
splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id"

http_revision() {
  splicore inbound list --config "$SERVER_CONFIG" | jq -er .snapshot_revision
}
http_resource() {
  splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id" | jq -er "$@"
}
binding_revision=$(http_resource --arg id "$binding_id" '.bindings[]|select(.binding_id==$id)|.revision')
jq -n --arg revision "$(http_revision)" --arg resource "$binding_revision" --arg binding "$binding_id" '
  {binding_id:$binding,enabled:false,revision:$revision,resource_revision:$resource}' > "$scratch/binding.json"
splicore inbound binding --config "$SERVER_CONFIG" --id "$inbound_id" --file "$scratch/binding.json"
denied=$(curl --silent --noproxy '' --proxy-basic --config "$scratch/curl.conf" --proxy "$server_proxy" -o /dev/null -w '%{http_code}' "$TARGET_URL")
test "$denied" = 407
splicore client stop --config "$CLIENT_CONFIG"

jq -n --arg revision "$(http_revision)" --arg resource "$(http_resource .inbound.revision)" '
  {action:"stop",revision:$revision,resource_revision:$resource}' > "$scratch/lifecycle.json"
splicore inbound lifecycle --config "$SERVER_CONFIG" --id "$inbound_id" --file "$scratch/lifecycle.json"
splicore inbound get --config "$SERVER_CONFIG" --id "$inbound_id"
```

`inbound get` includes active connection IDs, modes and binding IDs when
connections are open, plus per-binding byte and session counters. Use
`action:"add"` with a `user` object in the same shape as the creation document,
the current inbound `resource_revision` and current snapshot `revision`.
For existing bindings, use their own `resource_revision` with `enabled:true`
or `enabled:false`, `action:"rotate"` and a replacement `credential` object,
`action:"revoke"`, or `action:"delete"`. The local API accepts those documents
at `POST /api/v1/inbounds/{id}/binding`. Use the lifecycle document at
`POST /api/v1/inbounds/{id}/lifecycle` with `start`, `stop` or `delete`.
The corresponding HTTP creation endpoints are
`POST /api/v1/creation/http/plan` and `POST /api/v1/creation/http/apply`.
[HTTP listener configuration](CONFIGURATION.md#managed-http-proxy)
