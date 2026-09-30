# Development Context

- Documentation status: Canonical
- Audience: Developers, maintainers and returning coding agents
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Current project constraints and the minimum recovery context.
- Lifecycle: Replace obsolete constraints when reviewed scope changes; never append a diary.

## Goal and current phase

Splicore is an independent modular server proxy core project derived from sing-box.
The target is unified protocol access, multi-user policy/accounting and qualified
third-party interoperability with sustainable upstream maintenance.

**Current state: Phase 1 Foundation frozen; Phase 2 implementation not started.**
The explicit freeze request authorizes one Foundation commit, fast-forward of
`main` and creation of `codex/phase-2-snell-vertical-slice`. Own binary,
domain values, registries, SQLite, transaction journal, shared application reads,
API v1 and CLI now exist. Upstream runtime source changes: **NONE**. No stable
Splicore proxy runtime, actual traffic adapters, Mieru, Xray supervisor, new wire
protocol or Panel has been implemented. Proposed ADRs retain maintainer review status.

## Reproducible baseline

- Upstream: SagerNet/sing-box **v1.14.1**.
- Full upstream baseline: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Phase 0 freeze branch: `codex/phase-0-architecture`; its documentation commit `687425bdbfff6c76f900035068c23a03c4547062` is the first owned Splicore commit, directly after the upstream baseline.
- Phase 1 freeze branch: `codex/phase-1-foundation`; its single Foundation commit has the Phase 0 freeze as sole parent.
- Local `main` advances only by fast-forward to the Phase 1 freeze and matches `codex/phase-1-foundation`.
- Working branch: `codex/phase-2-snell-vertical-slice`, created from frozen `main`; HEAD remains the Phase 1 freeze and the working tree is clean. Phase 2 code has not started.
- Only remote: `upstream`, `https://github.com/SagerNet/sing-box.git`.
- Full upstream history retained; module path remains `github.com/sagernet/sing-box`.
- Freeze identities: resolve `git rev-parse codex/phase-0-architecture` and `git rev-parse codex/phase-1-foundation`; neither is a product tag.
- Phase 0 message: `docs: establish Splicore architecture baseline`; Phase 1 message: `feat: establish Splicore foundation`.
- No `origin`, push, new tag or release; upstream history and existing tags remain intact.

Verify actual Git state when resuming. The freeze instruction supersedes the
earlier implementation-only ban on staging/commit. Stop after preparing the
Phase 2 branch; further implementation needs a new scope instruction. No push,
origin creation, tag or release is authorized. Historical reports/evidence remain
frozen; tools, binaries and fresh logs stay outside the repository. This document
does not authorize publication.

## Architecture constraints

- Protocol and Engine are separate contracts; engine placement is internal.
- Account, Binding and Credential have separate identity/authorization/secret responsibilities; Operator is a control principal.
- Node, Inbound, Listener and DisplayEndpoint are separate; public endpoint, SNI, REALITY target and egress are not interchangeable.
- SQLite **committed generation** is the sole domain authority; bootstrap owns process settings and imports are validate/plan/apply commands.
- Runtime configuration and ClientProfile are separate projections; exporters own target format/version mappings.
- Domain/ports do not depend on HTTP, SQL drivers, upstream options or engine schemas.
- Protocol registration is explicit and compiled; no dynamic Go plugins.
- DB, sockets and children cannot commit atomically; journal, generation fences and reconstructible compensation are required.
- Strict quota/rate needs proven authenticated payload hooks; polling counters cannot establish shared enforcement.
- Wire compatibility is a release gate with exact third-party client/profile evidence.
- Target deployment uses one future `splicore.service`, native adapters and optional trusted supervised children.

## Where authority lives

Start at the [docs index](README.md) and [architecture overview](ARCHITECTURE.md),
then use the [specification map](architecture/README.md) and relevant
[ADRs](adr/README.md). OpenAPI owns the proposed API surface; the ERD owns logical
entities/relationships. Historical reports record past outcomes, not current
specification authority. [Documentation policy](DOCUMENTATION_POLICY.md)
defines when to update each source.

## Implemented Foundation and deferred scope

The runnable command serves only System/Capabilities reads over protected Linux
UDS. Windows uses httptest; no public TCP bind exists. Account application commands
use repository ports; creation of other Foundation entities exists in the writer.
Protocol/engine/exporter placeholders fail with NotImplemented. Schema 1 migration
is checksummed and transactional; pending crash journals block further mutation.
Credential encryption requires an injected key; the command provisions no key.

Entitlements, usage, imports, runtime apply/compensation, key deployment/recovery,
third-party interop, all live protocol adapters and broader management surfaces
remain deferred. This supersedes Phase 0's recommended reference-protocol and
broader ERD Phase 1 staging. See [Foundation workflow](development/FOUNDATION.md)
and the completed [Phase 1 report](reports/PHASE_1_FOUNDATION_REPORT.md).

Before implementation, maintainers still need to settle public repository/module
ownership, secret-key provisioning/recovery, and exact future FinalMask/Sudoku
fork/spec/license references. These do not block documentation review.

## Forbidden shortcuts

Do not turn Splicore into a raw runtime JSON wrapper, let installers edit SQLite,
add protocol columns to Account, weaken unsupported policy silently, treat exporter
rendering as interoperability, or call an upstream build a qualified Splicore release.
Do not globally rename upstream packages/branding or move large package trees
without a reviewed decision. Preserve LICENSE, copyright and non-affiliation.
Do not implement Panel or broaden Foundation into live proxy traffic.

## Validation context

Historical upstream results include successful builds and qualified Linux root CI,
Windows integration failures, additional vet findings and unrun optional suites.
Read the [baseline ledger](architecture/UPSTREAM_BASELINE.md) for exact scope.
Foundation requires own package tests, Linux race/fuzz, both binaries on Windows
and Linux, arm64 compilation, repeated upstream regression and docs/OpenAPI/
inclusive whitespace/secret audits. Known upstream/environment failures stay
classified; source is not patched to silence them. Archived Phase 0 evidence
remains part of the freeze; fresh outputs remain external.
See the [development index](development/README.md).
