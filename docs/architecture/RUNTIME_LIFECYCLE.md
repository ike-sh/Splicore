# Runtime and process lifecycle

- Documentation status: Canonical
- Audience: Runtime and engine developers
- Last reviewed: 2026-10-01
- Owner: Core / Engine maintainers
- Responsibility: Startup, admission, shutdown, recovery and future child ownership.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current Phase 2 implementation

Snell has Start/Health/Activate/Close, closed pending admission, raw socket tracking, idempotent shutdown and SQLite-only restart. Health is listener readiness. See [composition ADR](../adr/0013-snell-runtime-composition.md). Broader reconcile/hot reload/child contracts below remain proposed.

Target Linux deployment: one systemd unit `splicore.service`, one native process,
many logical Inbounds and internal listeners. Systemd restarts the main process;
Splicore reconciles committed state and supervises optional children.

Startup: load bootstrap → establish process identity/ownership lock → open/check DB
and schema → migration if explicitly permitted → recover pending journal → compile
committed domain generation → construct native registries/Box → staged start →
protocol/identity/policy health → activate admissions → serve local control API.
Diagnostics can report startup/recovery state while the data plane is unavailable.

Native adapters remain inside one process even when a single-user protocol expands
into per-binding instances/listeners. Port allocation/conflicts and display endpoints
must be included in the plan; no per-protocol systemd units. A separate external
engine failure can degrade its own bindings while native bindings continue.

## Child supervision (future)

Pin executable digest/version and config schema; render protected per-generation
config, validate, launch without shell under limited identity, drain logs with
bounded buffers/redaction, monitor exit/readiness/auth health and enforce a restart
budget. Persist generation and child ownership metadata. A PID alone is insufficient:
verify incarnation/start time/executable/cgroup before cleanup; never kill an unrelated
reused PID. Clear privileged environment and use private management endpoints.
Main-process death must terminate children using process groups/parent-death signals
and systemd KillMode=cgroup, with platform equivalents for Windows.

Restart after child crash reconstructs the committed child generation, registers a
new stats epoch, and blocks unqualified policy enforcement rather than forgetting
quota. Config rollback uses last committed child snapshot. Cross-native/child
operations are a compensated multi-engine plan, not a distributed ACID transaction.

## Shutdown/reload

Stop accepting new mutations, finish or journal current operation, block new data
admission, drain sessions with deadlines, settle/flush usage, stop/reap children,
close native inbounds/managers, close DB and logs. Abrupt death must be recoverable
without a final shutdown hook. Files/signals cannot bypass application transactions.
Bootstrap changes may require restart; domain updates use validate/plan/apply.

Default Phase 1 user/listener changes are classified restart/rebuild. Fine-grained
hot updates are enabled only after protocol-specific concurrency, revocation,
same-port replacement and compensation tests. SIGHUP in upstream is not evidence
of transactional reload. Rollback means restoring configuration availability;
closed sessions remain closed and clients reconnect.
