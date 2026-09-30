# Domain model

- Documentation status: Canonical
- Audience: Domain and application developers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Entity meaning, authorization relationships and identity/secret separation.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Design invariants; no repositories or runtime structs implemented in Phase 0.
Opaque stable IDs are random UUIDs generated with a cryptographic random source;
names/IPs/hostnames are mutable labels. UTC timestamps; byte counts are integers,
rates are bits per second. Resource revisions monotonically increase at commit.

| Entity | Fields and meaning |
|---|---|
| Node | id, name, instance_id, created_at; runtime identity projection supplies product/version/schema/ABI. Node ID survives restart/upgrade; instance_id changes per process incarnation. Cloned installations require explicit new identity. |
| Account | id, name, status(active/suspended/closed), enabled, created_at, updated_at, expires_at, bounded metadata, revision. No Linux identity, admin token or protocol password. |
| Operator | independent id/control principal, authentication reference, state. Actor type can be local OS principal now; full RBAC deferred. |
| Inbound | id, node_id, name, protocol+wire_version, internal engine assignment, listener set, display_endpoint set, typed versioned settings, enabled, tags, revision. Shared server keys refer to secret records. |
| Listener | id, inbound_id, transport(tcp/udp), bind address/port/interface/namespace. A logical Inbound can expand into multiple listeners/instances. |
| DisplayEndpoint | id, inbound_id, public host/port, family hints and priority. NAT/reverse mapping is explicit; never copied from SNI/egress/REALITY target. |
| Binding | id, account_id, inbound_id, credential_id, enabled, policy_override, created_at, revision. Grants usage on exactly one logical Inbound. |
| Credential | id, owner_account_id (nullable only for inbound server material), kind, schema_version, encrypted protocol data reference, state, valid_from/until, revision. PSK/UUID/UUID+password/username+password are tagged data. |
| TrafficPolicy | id, quota_bytes, upload_bps, download_bps, reset_policy/timezone, max_sessions, expiry constraints; optional device limits reserved. Null means no limit; zero denies usage. |
| PlanTemplate | id, name, immutable version, policy defaults, expiry default, resource selector; technical reusable template, no prices/payments/orders. |
| Entitlement | id, account_id, source_template_id/version optional, effective policy snapshot, resource selector, valid_from/until, revision. Actual authorization, valid even without Panel. |
| Subscription | id, account_id, name, allowed formats, resource selector, enabled, expires_at, last_used_at, revision. Independent revocable export access. |
| SubscriptionToken | id, subscription_id, verifier digest, issued_at, expires_at, revoked_at, generation. Random token is returned at issue, never Account ID. |
| Usage | binding/node/protocol/generation/period dimensions, upload_bytes, download_bytes, connections, source cursor and measurement quality. Account/inbound sums are projections, not separate sources to add. |
| Tag / ResourceGroup | normalized labels on Inbounds; versioned selector groups (all/any/none, node filters), cycle-free bounded expressions. |

## Relationships and validity

Account `1 → 0..N` Bindings and `1 → 0..N` Subscriptions. Binding belongs to
one Account, one Inbound, and one credential owned by that Account and compatible
with that protocol. Prefer one active credential per Binding; reuse across
bindings requires explicit ownership and compatibility validation. Rotation
retains old/new credential references during a declared overlap window, then
revokes the old generation. No permanent extra protocol columns on Account.

Authorization is the intersection of Account state, Entitlement access/validity,
Binding enabled state, Inbound state and credential validity. Subscription selectors
can only narrow authorized bindings; selecting a tag does not create credentials
or bypass a Binding. Newly matching Inbounds require application reconciliation
to create real authorized bindings in a revisioned transaction.

One effective Entitlement is active per Account in Phase 1. Future overlapping
grants require explicit composition semantics; do not silently sum quotas or
raise rate limits. Binding overrides can only restrict account ceilings.
Soft disable/revocation preserves historic usage dimensions. Hard deletion is
blocked while live bindings/transactions reference a resource, and history is
retained with tombstones according to retention policy.

## Required scenarios

| Case | Walkthrough and check |
|---|---|
| A | Alice has four Binding rows for Tokyo Snell, Tokyo VLESS, HK TUIC and future SG Mieru. Each has protocol-compatible credentials; stable Account ID joins all usage. Future Mieru is not enabled now. |
| B | Premium 500G template selects tag premium. Entitlement snapshots limits and selector; assignment reconciles matching Inbounds into Bindings transactionally. New tag match is planned, not an implicit authentication side effect. |
| C | 500 GB means 500,000,000,000 upload+download payload bytes across Alice's bindings in one period. GiB is a different explicit unit. |
| D | 200 Mbps account ceiling maps to one shared limiter per direction across VLESS/TUIC/Mieru streams. Per-session native congestion settings cannot substitute for that ceiling. |
| E | Single-credential protocol expands into internal listener/instance per Binding with an explicit display endpoint/port allocation, or rejects multi-user deployment. No account separation is promised for shared unauthenticated PSK. |

See [policy semantics](POLICY_USAGE.md), [ERD](DATABASE_ERD.md),
[protocol contract](PROTOCOL_SDK.md).
