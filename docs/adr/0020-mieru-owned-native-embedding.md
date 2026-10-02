# ADR 0020 — Mieru owned native embedding

- Documentation status: Canonical
- Audience: Runtime developers and reviewers
- Last reviewed: 2026-10-02
- Owner: Engine maintainers
- Responsibility: Phase 8 embedding decision, source boundary and ownership tradeoffs.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Status

Accepted for the Phase 8 Experimental local freeze; no Stable release.
[Freeze report](../reports/PHASE_8_FREEZE_REPORT.md).
Refines [ADR 0010](0010-mieru-integration-strategy.md) after its three staged gates.

## Alternatives evaluated against v3.38.0

| Concern | A: external mita | B: delegate official server API | C: owned adapter around official API/primitives |
|---|---|---|---|
| Code volume | Supervisor/rendering glue plus child management | Small translation/start/accept glue | Bounded module/codec/runtime/exporter and lifecycle ownership |
| Upstream maintenance | Binary/config pin and process compatibility | Module/API pin; no wire merge | Same module pin; listener/Accept/close behavior must be re-audited |
| Globals | Process isolated | Logger, replay/cipher caches, username metrics shared | Globals audited; accounting excluded, user registry per Mux |
| Configuration | Daemon apply/replace/persistence risks | Private protobuf Store | Immutable deterministic private protobuf, fresh server per generation |
| Users/stats | Requires control API/polling | UserContext exists; global metrics collide | Immutable username→Binding map; single attributed payload meter |
| Shutdown | Owned process exit can reclaim resources | Stop alone is insufficient | Own raw sockets and sessions; Stop plus joined workers |
| Testability | Pinned oracle process tests | Embedding prototype | Transactions, recovery, isolated inbounds, default race and managed clients |
| License/wire | Stock oracle license retained | Official GPL library/wire | Same official GPL library, no fork/copy/framing/crypto rewrite |

## Decision

Choose B→C: import official apis/server inside MieruCompiler in existing Native
Engine, while Splicore owns lifecycle, listener factories, authenticated egress,
domain resources and stats. Protocol=mieru, Engine=native. Native routing for this
bounded adapter uses standard direct TCP/UDP sockets and local DNS; current
RuntimeIntent has no configurable egress policy. It does not silently claim support
for richer sing-box routing rules. All other protocols retain their existing routers.

The embedding does not invoke the CLI loader, install signals or register/parse
daemon flags. pkg/log includes a test log adapter that imports standard testing/flag,
but Splicore does not call SetOutputToTest, testing.Init or flag.Parse through it.
pkg/log has fatal helpers but the embedding path calls none. NewServer uses its locked global
NilFormatter; the adapter never enables metrics logging or changes it back.
No import-created logger goroutine. Each server owns a Mux/user registry. Global
RNG, replay caches and synchronized cipher cache remain upstream implementation
details; immutable templates are cloned for mutable usage. No secret-erasure claim.

Store's documented after-Start error is not enforced by actual implementation;
the adapter must enforce Store-before-Start itself. Stop is not a complete socket/
session cleanup contract. Own raw sockets and close them before Stop, preventing
an in-flight UDP Read from replacing a deadline-only Close. Track accepted and
destination sessions, reject precommit admission and join workers on Close.
The official Accept parser retains malformed/timeout sessions inside Mux until
its lifecycle cleanup; owned raw sockets guarantee bounded shutdown, but this
does not establish a hardened hostile-peer resource policy. No upstream patch is carried.

## Policy/accounting consequence

Do not consume username-global upstream metrics as Splicore usage: they collide
across inbounds. Count authenticated payload exactly once at relay boundary;
update inbound and binding from each event. Per-generation atomics are safe;
live snapshots are independent. Account aggregates and persistent usage remain
deferred. Native quota uses a rolling MiB admission policy with global counters,
not exact-byte lifetime enforcement, so QuotaNative is not exposed. No native
rate limit exists. Strict policies reject; metadata-only is explicit.

## Qualification and review triggers

Official/Mihomo managed clients, two users/inbounds, TCP/UDP, all endpoint kinds,
16 concurrency, 4 MiB hashes, restart, rollback and ten joined lifecycle cycles.
Linux default race/checkptr and Windows units/build; Linux arm64 compile only.
Review API lifecycle/global-state/license/dependency behavior at every module pin
change. Wire/traffic-pattern additions and general routing/persistent usage need
separate scoped work. [Contract](../protocol/MIERU.md), [report](../reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md).
