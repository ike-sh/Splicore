# Policy Group Model

- Documentation status: Canonical
- Audience: Runtime and control-plane developers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Selection, health, affinity and scheduler ownership.
- Lifecycle: Update with typed strategies and qualification.

## Canonical strategies

Immutable group UUID, mutable name; members are typed Outbound/Group or explicit
DIRECT/REJECT. Exactly one typed strategy:

| Type | Selection/failure |
| --- | --- |
| selector | Persist selected member; unknown allowed, known unhealthy fails; no alternate. |
| url_test | Completed healthy HTTP measurement; minimum latency, ordered ties; tolerance retains previous healthy choice. |
| fallback | First healthy member in order; all unavailable fails; primary recovery affects new selections. |
| load_balance | Atomic round_robin only; unprobed unknown eligible, unhealthy excluded. |

64 groups, 129 members, eight nesting edges. Missing references/cycles reject.
REJECT is unavailable to probes/automatic strategies; DIRECT is explicit.
Selector updates use the common transaction. No established session migration.

## Health

Unknown/healthy/unhealthy, last probe, latency milliseconds and bounded error class
are observations. Samples/counters/automatic selection are not SQLite authority.
HTTP GET runs through the terminal adapter, includes HTTPS TLS, measures through
bounded response reading and requires configured status. HTTP/HTTPS only; no userinfo,
redirects/public default URL; body cap 4097 bytes; no credentials sent to target.
Active groups require completed active samples; passive success is not a measurement.
Newer passive failure overrides older active healthy; later active success restores
that group. Unprobed groups use passive availability and their unknown policy.
Passive failures cover failed dials and sessions without a usable response; closing
an established session after successful payload does not poison selection.
An unprobed failed selector may require operator diagnosis or successful traffic.

## Scheduler and lifetime

Four workers, queue 16, 256 probed memberships; one coordinator, one-second tick,
immediate initial round, intervals 1..86400 seconds, timeout 1..10 seconds.
Lifecycle lock orders Start/Add and Stop/Wait. Cancel closes requests and joins jobs.
No unbounded per-node scheduler or implicit DIRECT fallback.
Narrow group locks protect samples/selection; RR/counts are atomic, payload I/O unlocked.
Health inherits only for identical effective graphs and every unchanged reachable
adapter; replacement discards stale samples. Stats are bounded by configured IDs.
TCP binds once. UDP association owns a private group→terminal affinity map, including
new flows after updates. Health changes affect new selections without killing sessions.
See [routing](ROUTING_MODEL.md), [DNS](DNS_MODEL.md), [ADR 0025](../adr/0025-policy-selection-health.md)
and the [report](../reports/PHASE_12_ROUTING_DNS_POLICY_REPORT.md).
