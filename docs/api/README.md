# Local control API

API v1 invokes application queries and transactional commands. Linux production
control uses a protected Unix-domain socket selected by the bootstrap; it is not
a public HTTP listener. Access is bounded by local socket ownership/permissions.
Windows production local control transport is unavailable.

```sh
curl --unix-socket /run/splicore/splicore.sock http://localhost/api/v1/system
curl --unix-socket /run/splicore/splicore.sock http://localhost/api/v1/capabilities
```

`system` reports product/health, schemas, revision and runtime summaries. The
capability endpoint reports supported protocol/engine profiles and accepts
bounded pagination. Compatible client entries declare client versions; the optional public reference
field may be empty. This does not change the declared compatibility profile.
Protocol creation uses `POST /api/v1/creation/<protocol>/validate`, `/plan` and
`/apply`. Validate/plan consume the creation document. Apply consumes an object
containing `document`, `digest` and `revision` from its saved plan.


Reads and errors are JSON; errors carry a typed code, safe
message, request ID and, when relevant, the current revision. Responses disable
caching. A system response exposes the revision as an ETag.

Server resources, client resources, network/routing/DNS and providers have typed
operations. Changes validate and plan normalized intent before application;
revision and identity guards reject stale/conflicting mutations. Plans and
management previews are distinct resource-specific contracts, not generic SQL
transactions. Ordinary reads do not reveal credentials.

The retained `internal/splicore/api`, application command/request types and domain
types define implemented routes and JSON shapes. Start with the [CLI](../CLI.md)
for operational examples. Do not treat upstream sing-box configuration or an
external client export as an API mutation. See [state authority](../CONFIGURATION.md)
and [architecture](../ARCHITECTURE.md).
