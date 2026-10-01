# Development Context

- Documentation status: Canonical
- Audience: Developers, maintainers and returning coding agents
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Current project constraints and the minimum recovery context.
- Lifecycle: Replace obsolete constraints when reviewed scope changes; never append a diary.

## Goal and current phase

Splicore is an independent modular server proxy core derived from sing-box.
Phase 0, Phase 1 and Phase 2 are frozen. **Current scope: the local Phase 2 freeze
and preparation of the Phase 3 branch; implementation is not started.** Snell
remains experimental. Only Snell is implemented. HY2, TUIC,
VLESS/REALITY, Mieru, Xray, Panel and NoBrand production integration remain deferred.
See [Snell support](protocol/SNELL.md), [workflow](development/PHASE_2_SNELL.md)
and [report](reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md).

## Reproducible baseline and authorization

- Upstream v1.14.1: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Phase 0 freeze: `687425bdbfff6c76f900035068c23a03c4547062`.
- Phase 1 freeze / Phase 2 parent: `a2ca59e6dbf1a239feae5e471ec1914cae0f1eac`.
- Phase 2 freeze: the shared tip of `main` and `codex/phase-2-snell-vertical-slice`;
  resolve its full SHA with `git rev-parse main` and inspect the freeze delivery report.
- Prepared branch: `codex/phase-3-hysteria2-vertical-slice`, based on the Phase 2
  freeze with a clean working tree. Phase 3 implementation is not authorized here.
- Sole remote: upstream at `https://github.com/SagerNet/sing-box.git`; no origin.
- Module remains `github.com/sagernet/sing-box`; upstream runtime changes: 0.
- The Phase 2 freeze request supersedes the implementation-only staging/commit
  restriction: one freeze commit and a fast-forward of main are authorized,
  followed by creation of the Phase 3 branch and an immediate stop.
- Push, origin creation, tag, release and edits to NoBrand-OneClick remain prohibited.
- Historical Phase 0/1 reports/evidence remain unchanged. Tools/binaries/logs and
  test state are external. No publication is authorized.

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

## Implemented and deferred scope

Schema 2 SQLite committed state is authority. Snell creation has strict
validate/plan/pending/start/listener-health/commit/admission semantics. Plans bind
compact JSON and global revision using a daemon-local HMAC; restart requires
replanning. One Inbound creates one Account, Binding and encrypted PSK. Explicit
Linux key-file provisioning has no lost-key or plaintext fallback.

The protected Linux UDS API exposes metadata, creation, display mutation and
explicit secret-returning client export. Windows remains a development target.
Each Inbound owns a private Box, TCP listener and authenticated routing counters.
Static platform composition avoids an inherited monitor startup race; see
[ADR 0013](adr/0013-snell-runtime-composition.md).

Quota/rate, userkey multi-user, account mutation/revocation, credential rotation,
hot reload/delete, durable usage and generic imports remain deferred. Surge live
testing is unqualified. Public module ownership and future FinalMask/Sudoku
provenance remain future decisions.

## Forbidden shortcuts

Do not turn Splicore into a raw runtime JSON wrapper, let installers edit SQLite,
add protocol columns to Account, weaken unsupported policy silently, treat exporter
rendering as interoperability, or call an upstream build a qualified Splicore release.
Do not globally rename upstream packages/branding or move large package trees
without a reviewed decision. Preserve LICENSE, copyright and non-affiliation.
Do not implement Panel or broaden Phase 2 beyond managed Snell.

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
