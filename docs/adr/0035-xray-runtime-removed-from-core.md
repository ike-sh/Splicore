# ADR 0035 — Xray Runtime Removed From Splicore Core Boundary

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental; correction accepted in Phase 14 local freeze

Status: Accepted by explicit maintainer architecture correction, 2026-10-04.

## Context

An architecture misunderstanding led Phase 6/7 to add an owned Xray Compatibility
Engine, FinalMask/Sudoku, child lifecycle and artifact distribution. Those phases
were implemented and frozen; their reports and ADRs remain historical facts.
The maintainer's original intended boundary is an independent Splicore core,
usable for both Server and Client, with orchestration in future NoBrand-OneClick.

## Decision

Remove Xray runtime integration from active Splicore. Register only native while
preserving the generic Protocol != Engine abstraction. Delete unused supervisor,
renderer, artifact management, health/PID status and child-underlay infrastructure.
Retain native VLESS plain/TLS/REALITY flow-none. Vision is Deferred/Unsupported.
FinalMask/Sudoku are out of scope; future NoBrand can deploy independent Xray.
No hidden runtime, native mask implementation or silent downgrade is permitted.

Keep all Phase 14 management/provider features and native host ownership. Generic
engine storage remains; explicit preflight rejects retired records without mutation
or conversion, including disabled records. Native-only old builds upgrade normally.
Installer-only legacy metadata decoding supports safe bootstrap/receipt cleanup
after preflight. Normal serve remains strict. Historical migrations are unchanged.
Imports show Unsupported for retired modes and never produce stripped runnable nodes.
Ordinary engine-neutral client format exports may remain without a runtime dependency.

## Consequences

Single Splicore core binary, embedded Mieru, no external runtime requirement,
simpler distribution and less process/lifecycle complexity. APIs/doctor/support
describe Splicore only. NoBrand owns independent artifact verification, deployment
choice and lifecycle in the future; its real repository is untouched here.

Phase 6/7 runtime direction is **superseded**, while frozen history/reports remain
unchanged. This correction does not freeze Phase 14 or modify Git history. Exact
regressions and qualification limits are recorded in the
[correction report](../reports/ARCHITECTURE_CORRECTION_XRAY_BOUNDARY_REPORT.md).
