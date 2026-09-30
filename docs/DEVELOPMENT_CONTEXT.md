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

**Current scope: Phase 0 Freeze.** Architecture and documentation have completed
review for a local freeze; individual proposed ADRs retain their recorded status.
The freeze creates one documentation commit, fast-forwards `main` and prepares
`codex/phase-1-foundation` at that commit. Branch preparation does not start
Phase 1 implementation. Runtime Changes: **NONE**. No stable Splicore
runtime, own binary, SQLite repository, API server, Mieru integration, Xray
supervisor, new wire protocol or Panel has been implemented.

## Reproducible baseline

- Upstream: SagerNet/sing-box **v1.14.1**.
- Full upstream baseline: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Freeze branch: `codex/phase-0-architecture`; its documentation commit is the first owned Splicore commit, directly after the upstream baseline.
- Local `main` advances only by fast-forward to that freeze commit.
- Prepared working branch: `codex/phase-1-foundation`, created at the freeze commit with no implementation changes.
- Only remote: `upstream`, `https://github.com/SagerNet/sing-box.git`.
- Full upstream history retained; module path remains `github.com/sagernet/sing-box`.
- Freeze identity: resolve `git rev-parse codex/phase-0-architecture`; this commit is the architecture freeze point, without a product tag.
- Freeze commit message: `docs: establish Splicore architecture baseline`.
- No `origin`, push, new tag or release; upstream history and existing tags remain intact.

Verify actual Git state when resuming. The freeze authorization covers local
staging/commit, fast-forward `main` and branch preparation only. Stop after the
prepared branch is verified clean; implementation requires a separate prompt.
This document does not authorize future commits or publication.

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

## Next planned phase

Phase 1 is a **recommendation requiring a later explicit scope**, not work started
here: review proposals, establish independent composition/command and domain ports,
qualify storage/key handling and recovery, then local API/CLI and one native
reference protocol with policy and real client tests. Broad protocol expansion,
Mieru, special Xray features and management interfaces remain later work.

Before implementation, maintainers still need to settle public repository/module
ownership, secret-key provisioning/recovery, and exact future FinalMask/Sudoku
fork/spec/license references. These do not block documentation review.

## Forbidden shortcuts

Do not turn Splicore into a raw runtime JSON wrapper, let installers edit SQLite,
add protocol columns to Account, weaken unsupported policy silently, treat exporter
rendering as interoperability, or call an upstream build a qualified Splicore release.
Do not globally rename upstream packages/branding or move large package trees
without a reviewed decision. Preserve LICENSE, copyright and non-affiliation.
Do not implement Panel or start Phase 1 during this phase.

## Validation context

Historical upstream results include successful builds and qualified Linux root CI,
Windows integration failures, additional vet findings and unrun optional suites.
Read the [baseline ledger](architecture/UPSTREAM_BASELINE.md) for exact scope.
Freeze requires a normal upstream build, docs/link checks, OpenAPI validation,
inclusive and staged `git diff --check`, runtime scope audit and ancestry checks.
Known Windows driver integrations are not rerun; source is not patched to silence
baseline failures. Archived Phase 0 validation evidence is part of the reviewed
freeze; temporary tools, fresh logs, binaries and caches remain outside the repo.
See the [development index](development/README.md).
