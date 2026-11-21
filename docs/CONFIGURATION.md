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

On Windows use [splicore-windows.yaml](../distribution/splicore-windows.yaml).
Its `api.unix_socket` absolute path identifies a user-scoped local named pipe;
it is not opened as a filesystem socket. New state/key directories receive a
private owner/SYSTEM DACL, and existing broad paths are rejected. `check --config`
validates configured key/control resources and existing committed state without
starting listeners. See [offline checks](CLI.md#offline-checks-and-foreground-lifecycle).

### Managed SOCKS5

Use `socks5/5/base` with `inbound plan/apply --protocol socks5`. Omit `listener.host`
to bind `127.0.0.1`. An IPv6 or IPv4 bind address must be an IP literal. A
non-loopback listener requires `settings.allow_cleartext_remote: true`. A
wildcard bind also requires an explicit, usable `display_endpoint`. SOCKS5
sends RFC 1929 credentials and relayed data without its own encryption. Keep
remote deployments on a trusted encrypted network. [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.html#section-3)

Set `settings.auth` to `true` and leave `settings.udp` omitted or `false`.
The server supports TCP CONNECT to IPv4, IPv6 and domains. BIND and UDP ASSOCIATE
return `0x07`. An unsupported address type returns `0x08`. [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html#section-6)

Each creation document can contain up to 16 users, with at least one enabled,
unexpired binding. Each user has an `account_name` and a unique, case-sensitive
`username` of 1 to 64 allowed ASCII characters (`A–Z`, `a–z`, `0–9`, `_`, `-`,
`.` and an initial alphanumeric character). Omit `password` for an automatically
generated value. Explicit passwords use 16 to 255 printable non-space ASCII
bytes, with at least eight distinct characters, and must differ from the username.
`enabled:false` disables the binding. Optional `expires_at` is a UTC RFC 3339
timestamp. New authentication checks the committed account, binding and credential
state. Binding changes replace the owning listener generation and close its
sessions. Stop, start or delete the listener using revision-guarded lifecycle
commands. Traffic statistics describe the running generation.

The target dial uses the protected `ServerTarget` underlay. An explicitly
scoped server inbound route can select a TCP-capable outbound, including a
proxy. With no scoped route, the server dials the target through the protected
default path. The local SOCKS5 listener and SOCKS5 remote nodes have their own
settings and support separate client-side UDP options. [CLI examples](CLI.md#managed-socks5-and-a-local-client)

### Managed HTTP Proxy

Create `http/1.1/base` with `inbound plan/apply --protocol http`. Set
`settings.auth: true`. The listener defaults to `127.0.0.1` and accepts explicit
IPv4 or IPv6 literals. Non-loopback binds require `allow_cleartext_remote: true`
in `settings`. Wildcard binds also need an explicit, usable `display_endpoint`.
HTTP Basic sends the proxy credential in cleartext encoding on the client-to-proxy
link. CONNECT carries an HTTPS session intact. Use an independently encrypted
network or secure tunnel for remote access. HTTPS proxy listeners, HTTP/2,
Upgrade and UDP tunneling are outside this profile.

Managed HTTP uses the same username, password, expiry and initial binding rules
as managed SOCKS5. Create up to 16 bindings with the initial document or enroll
more through the binding endpoint within that limit. Disable, rotate, revoke or
delete bindings with current revisions. Revocation disables the binding and
invalidates its credential. Committed account expiry and admission state are
checked on every new proxy connection. Binding changes replace the listener
generation and close its sessions. Natural expiry gates new auth at the
expiry timestamp, and established sessions run until close or timeout. Stats
count CONNECT payload and decoded HTTP body bytes in the running generation.

For ordinary HTTP, use an absolute `http://` request target and a matching
`Host`. The listener forwards one exchange per TCP connection and advertises
`Connection: close`. Reconnect for each exchange. CONNECT supports TCP
half-close. The listener permits up to 512 simultaneous sockets, 64 pending
handshakes and eight pending handshakes per source IP. Headers and target
dials have 10-second budgets. Established sockets have 60-second idle limits.
Over-limit sockets close at admission.

Targets use the protected `ServerTarget` underlay. For scoped Core routes,
direct TCP and rejection are supported. The outbound HTTP client factory is a
separate capability for local-client routing. [CLI examples](CLI.md#managed-http-proxy)
