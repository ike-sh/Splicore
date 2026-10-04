# Remote Node Management

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Immutable client identity, ownership, state and batch mutation.
- Lifecycle: Update with implemented contracts and qualified evidence.

## Implemented Phase 14 scope

Experimental RemoteNode is a canonical client resource. It is separate from server
Account, imported candidate, provider and runtime Outbound. Its random UUID v4 is
assigned once and persisted. References use IDs, never display names, source URLs
or feed order. Builtin DIRECT/REJECT names cannot overwrite ID references.

| Field | Meaning |
| --- | --- |
| id / credential_id | Immutable node identity / replaceable encrypted credential reference. |
| provenance.origin | Empty legacy/manual, manual, uri, import or provider. |
| provenance.provider_id | Immutable provider ownership, independent of provider name/source URL. |
| provenance.key | Provider-scoped hashed native key or normalized non-secret fingerprint. |
| tags / metadata | Bounded display annotations; tags are not an authorization boundary. |
| disabled | New connections fail closed; established generations retain their leases. |
| state | active, stale, invalid, unavailable; legacy empty means usable. |

Names may collide, including names matching builtins. Tags are unique UTF-8 labels:
at most 32 per node, 64 bytes per label. Metadata follows existing non-secret
key/value limits. Node limits remain 128; outbounds remain 129 including DIRECT.

## Stable provider matching

Provider native keys must be public, bounded hints; persisted matching keys are
domain-separated SHA256 hashes. Without a native key, normalize protocol, endpoint,
transport, public security and options. Exclude credential ID/value, ID, name,
tags, annotations, lifecycle state and source order. Fingerprints are matching
hints, never generated resource IDs. Provider scope is independent of the hash.

Rename/reorder/credential rotation keep Node and generated Outbound IDs. A native
key can retain identity while its endpoint changes. Without that hint a changed
endpoint becomes a new node. A key changing protocol rejects as explicit Conflict;
the source must supply a new key and resolve old references. Changing credential
payload always uses a validated replacement reference, never an incompatible write
to an existing credential kind.

Within one feed, the same matching key and credential is an exact duplicate.
Different credentials for that key reject as ambiguous identity. Different keys
can describe intentionally separate provider nodes on one endpoint. Separate manual
and provider ownership is preserved and an overlap appears in preview. Manual import
dedup uses normalized settings plus actual credential equality; a distinct credential
can create a separate manual node. Canonical export/reimport detects an existing
manual exact duplicate. Manual reimport is not a provider credential rotation API.

## Removal and operator annotations

Generated outbounds record provider_id and retain their UUID across refresh. Manual
outbounds may reference provider-owned nodes. A missing node with any group, route,
DNS, local listener, manual outbound or fetch dependency is retained **stale**.
Current explicit policy permits new sessions on stale nodes using the last committed
credential; no DIRECT fallback occurs. Disable the node to refuse new sessions.
Unreferenced missing nodes and their owned outbounds are removed in one transaction.
Provider deletion requires a reference-safe preview; no destructive cascade.

Provider refresh preserves operator tags, disabled status and metadata. Manual CRUD
cannot change a provider node's endpoint/credential/protocol/provenance. Batch enable,
disable, delete, tag replacement and metadata replacement are generic preview/apply
operations. Provider-owned delete rejects. Moving a node between display folders
uses metadata such as `{"folder":"work"}`; moving provider ownership is unsupported.

Node/outbound counter identity stays keyed by immutable IDs. Unchanged adapters
retain passive health; new credentials intentionally start unproven adapter health.
Counters and automatic health remain ephemeral, as in Phase 12; restart resets them.
See [providers](PROVIDER_MODEL.md), [imports](IMPORT_MODEL.md), [runtime](CLIENT_RUNTIME.md).
