# Policy, quota and accounting authority

- Documentation status: Canonical
- Audience: Domain and policy developers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Unified payload accounting, quota/rate, reset and crash uncertainty semantics.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Splicore owns unified Usage and TrafficPolicy. Native counters are possible
sources and diagnostics, never independent quota authorities. Enforce only a
capability with a measured and tested implementation; reject unsupported strict
policies in Validate/Plan with field-level errors.

## Accounting contract

Phase 3 HY2 exposes authenticated payload bytes and routed TCP/UDP sessions per
Inbound/Binding. Immutable native user identity is Binding ID. Counters reset on
runtime replacement/recovery; shared Account aggregation and durable billing remain
deferred. Distinct policies persist per Binding with explicit `policy_mode:metadata_only`
and `policy_enforced:false`. Native HY2 bandwidth hints are not user speed enforcement;
the profile ignores client hints and uses BBR. No policy values enter runtime/export.
See [HY2 contract](../protocol/HYSTERIA2.md).

Billable unit is successfully forwarded proxy payload byte, excluding protocol
encryption/framing/padding/handshakes/retransmits. Upload is client → destination;
download is destination → client. Count TCP payload after authentication and
protocol decoding; UDP payload at the equivalent datagram boundary. Each logical
stream/datagram traverses one billable meter. Do not count UOT/mux frames twice.
Protocol-native statistics with different units are labeled separately, not
converted by undocumented guesses.

Every sample has `(node_id, instance_id, source_id, binding_id, generation,
period_id, sequence)` plus monotonic counters/cursor and quality. Ingestion commits
sample and watermark together, rejects duplicates, treats counter decrease as a
new source epoch, and never subtracts prior usage. Immutable generation mappings
keep old sessions associated with their authenticated Binding after rotation.
Account, Inbound, Protocol, Node and time-window reports sum the same leaf rows.
Cross-node views are future federation; a single installation cannot claim a
distributed globally exact quota.

## Quota correctness and crash bounds

One Account budget is shared across all bindings and native protocol handlers.
Admission rejects expired/suspended/exhausted users and closes existing sessions
according to the declared policy. Strict mode reserves durable budget **before**
forwarding. Bounded prepaid byte leases amortize writes; reservations consume
available quota, actual forwarding settles them. Uncertain leases after crash
remain charged/reserved until safely reconciled; do not refund unknown traffic.
Expose measured bytes and uncertain reserved bytes separately. Exact traffic
delivery across process/power failure cannot be inferred from an atomic DB commit.

A relaxed batch mode may lose the unflushed sample window; it must expose a
documented bound/quality and cannot be advertised as strict quota. No per-packet
SQL writes. Flush on timer/threshold and shutdown. Read-only/disk-full DB makes
strict admission fail closed. Usage never rolls back with a configuration change.

## Rates and sessions

Shared Account upload/download token buckets use monotonic time, bounded bursts
and fair waiting; Binding limiters compose with account limits as the lower
ceiling. `200 Mbps = 200,000,000 bits/s`; byte admission converts units explicitly.
UDP must declare queue/burst/drop behavior; max_sessions counts authenticated
logical proxy sessions, with exact definition for mux and UDP associations.
Handshake flood controls and transport bandwidth settings are separate controls.

Native Hysteria congestion/bandwidth settings are connection/server settings,
not a cross-protocol rate budget. Strict policies require measured authenticated
enforcement; do not silently weaken a Plan. Independent external core policy
ownership is outside Splicore.

## Reset and entitlement

Reset policies: `never`, `calendar(day|week|month, timezone, anchor)` and
`rolling(duration)`. Phase 1 recommends never/calendar only; rolling is reserved
until event/bucket retention can compute an actual sliding window. IANA timezone
required; specify week start, month-anchor clamp to last day, DST skipped/repeated
boundary handling (first valid instant, once per period ID), and UTC storage.
Advance periods idempotently; retain prior periods rather than zeroing all history.
Time rollback never reopens a settled period. Sessions crossing reset boundaries
are metered into each period by forwarding time.

PlanTemplate is versioned reusable intent; Entitlement snapshots actual limits,
selector and validity. Editing a template does not mutate users silently.
Explicit reassignment produces a new Entitlement/revision; mid-period quota changes
keep consumed usage and calculate remaining budget from the new ceiling. Binding
policy cannot raise Account quota/speed/access. Expiry is the earliest applicable
Account/Entitlement/Binding credential limit. No commerce fields are introduced.
