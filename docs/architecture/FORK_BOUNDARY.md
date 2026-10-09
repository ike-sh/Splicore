# Core Source and Product Boundary

- Documentation status: Canonical
- Audience: Core developers and provenance reviewers
- Last reviewed: 2026-10-09
- Owner: Core maintainers
- Responsibility: Current module, source ownership and command boundary.
- Lifecycle: Update with ownership, dependency or distribution changes.

The module is `github.com/ike-sh/Splicore`. The production command is
`cmd/splicore`; one native process supplies server and client Core roles.
Domain/application/ports/storage/API packages expose owned contracts rather than
upstream configuration objects. See [Core scope](CORE_SCOPE.md).

## Implementation and dependencies

Splicore owns runtime generations, routing/DNS/policy, credentials, underlay
injection and protocol integration. Independent substrates provide QUIC,
uTLS/REALITY, gVisor, network primitives and SQLite; Mieru uses its official
embedded SDK. No inherited Box, SagerNet module or external Core child process
belongs to production. Historical Foundation and Phase 2–5 compositions are
test fixtures excluded from the command closure.

See [independent dependencies](INDEPENDENT_CORE_DEPENDENCIES.md),
[engine ownership](ENGINE_MODEL.md) and [lifecycle](RUNTIME_LIFECYCLE.md).

## History and attribution

The fork originated from sing-box v1.14.1. GPL terms, source copyrights and
required attribution remain. Removing orphan assets does not erase retained
derivative provenance. Baseline observations and earlier architectural choices
remain in [upstream history](UPSTREAM_BASELINE.md), ADRs and frozen reports.
The exact pre-purge working tree is externally archived.

Current installers, service assets and native binaries package Splicore Core.
Mobile/desktop client shells and inactive inherited build targets are removed.
Splicore distribution does not publish itself as an official upstream product.

## Private Go runtime boundary

Owned production source must use exported Go APIs; private runtime hooks require
a separate justified architecture exception. Dependency-owned hooks are audited
separately and are not copied or patched into Splicore adapters.
The historical libbox OOM profiler, mobile FFI and QF-003 resolution remain
historical evidence; see the [QF-003 report](../reports/QF_003_PRIVATE_RUNTIME_LINKNAME_RESOLUTION_REPORT.md).
