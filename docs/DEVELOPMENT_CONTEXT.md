# Development Context

- Documentation status: Canonical
- Audience: Developers, maintainers and returning coding agents
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Current project constraints and the minimum recovery context.
- Lifecycle: Replace obsolete constraints when reviewed scope changes; never append a diary.

## Goal and current phase

Splicore is an independent modular server proxy core derived from sing-box.
Phases 0–3 are locally frozen. **Current scope: Phase 4 branch reserved;
TUIC implementation NOT STARTED.** Phase 3 passed independent WSL2 acceptance and
the final freeze review. Snell and HY2
remain Experimental. TUIC, VLESS/REALITY, Mieru, Xray, Panel and NoBrand production
integration remain deferred. See [HY2 support](protocol/HYSTERIA2.md),
[workflow](development/PHASE_3_HYSTERIA2.md) and
[report](reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).

## Reproducible baseline and authorization

- Upstream v1.14.1: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Phase 0 freeze: `687425bdbfff6c76f900035068c23a03c4547062`.
- Phase 1 freeze / Phase 2 parent: `a2ca59e6dbf1a239feae5e471ec1914cae0f1eac`.
- Phase 2 freeze / Phase 3 parent: `5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`.
- Phase 3 is the single commit `feat(protocol): add experimental Hysteria2 vertical slice`
  containing this freeze record. Its full SHA and Git transition evidence are recorded
  externally in `D:\splicore-validation\phase3-freeze-20261001` and the final freeze response.
- `main` is fast-forwarded to Phase 3; current branch is
  `codex/phase-4-tuic-vertical-slice`, based on that commit with a clean worktree.
- Sole remote: upstream at `https://github.com/SagerNet/sing-box.git`; no origin.
- Module remains `github.com/sagernet/sing-box`; upstream runtime changes: 0.
- The final Phase 3 authorization permits explicit staging, one freeze commit,
  fast-forward of main and creation of the Phase 4 branch. Stop after that branch
  creation. TUIC implementation, push, origin creation, tag, release and real
  NoBrand access/edits are not authorized by this freeze.
- Historical Phase 0/1/2 reports/evidence and migrations 0001/0002 remain unchanged. Tools/binaries/logs and
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

Schema 3 SQLite committed state is authority. Snell/HY2 creation shares strict
validate/plan/pending/build/start/listener-health/commit/admission semantics. Plans bind
compact JSON and global revision using a daemon-local HMAC; restart requires
replanning. Snell creates one Account/Binding/PSK; HY2 creates 1–16 distinct
Account/Binding/password records with optional metadata-only TrafficPolicy. Explicit
Linux key-file provisioning has no lost-key or plaintext fallback.

The protected Linux UDS API exposes metadata, creation, display mutation and
explicit secret-returning client export. Windows remains a development target.
Each Inbound owns a private Box, TCP (Snell) or UDP/QUIC (HY2) listener and
authenticated routing counters. HY2 adds per-Binding stats, static TLS and
independent listener/public endpoint/SNI/certificate semantics.
Static platform composition avoids an inherited monitor startup race; see
[ADR 0013](adr/0013-snell-runtime-composition.md).

HY2 Binding enable/disable safely reconstructs only its Inbound; HotUserUpdate
is false. Existing sessions close and counters reset. [ADR 0014](adr/0014-hysteria2-runtime-composition.md)
records owned socket/service composition and the 100 ms close grace.

Architecture concern: **NON-BLOCKING TECHNICAL DEBT**, extension cost **MEDIUM**.
Protocol/Engine registries, committed-state authority and separate domain/runtime/
client models remain effective. Phase 4 must address registered creation commands,
service-owned display availability, direct composition and relocation of shared
methods when adding the third protocol. The exact current behavior, affected files,
counts, justification and triggers are in the
[architecture disposition](ARCHITECTURE.md#phase-3-extensibility-disposition) and
[ADR 0014](adr/0014-hysteria2-runtime-composition.md#freeze-review-and-follow-up).
This records future constraints and does not start that work.

Quota/rate enforcement, Snell userkey multi-user, general Account mutation,
credential rotation, hot reload/delete, durable usage and generic imports remain deferred. Surge live
testing is unqualified. Public module ownership and future FinalMask/Sudoku
provenance remain future decisions.

## Forbidden shortcuts

Do not turn Splicore into a raw runtime JSON wrapper, let installers edit SQLite,
add protocol columns to Account, weaken unsupported policy silently, treat exporter
rendering as interoperability, or call an upstream build a qualified Splicore release.
Do not globally rename upstream packages/branding or move large package trees
without a reviewed decision. Preserve LICENSE, copyright and non-affiliation.
Do not implement Panel or start TUIC under the Phase 3 freeze authorization.

## Validation context

Independent Ubuntu-24.04 WSL2 acceptance passed native builds, unit/race, six fuzz
smokes, HY2's 12 real client/user/endpoint cells, Snell's nine regression cells,
fresh HTTP/export-envelope schemas and CLI/API equality. Native runtime state,
private TLS fixtures and temporary clients were removed. Full upstream root CI
passed; two extra inherited unsafe.Pointer vet findings remain visible.
Docker/Redis were not queried or changed in this acceptance round. Their recovery
and old residue cleanup are DEFERRED EXTERNAL ENVIRONMENT WORK, not a code blocker
under the latest authorization. Docker Desktop recovery, Redis ownership
(unconfirmed, likely TeleLedger) and old test residue remain DEFERRED EXTERNAL
ENVIRONMENT CLEANUP. Do not query/restart Docker or touch Redis/TeleLedger.
Architecture debt and Experimental limits remain in the report. Publication is not authorized.

Freeze checks repeat Windows unit/both builds/own vet and native WSL unit/critical
HY2 and Snell smoke/own vet. All 103 owned functional source/test/script/fixture
files match the independent acceptance manifest. The auxiliary post-run file-list
FAIL remains historical; its narrowly cache-excluding external helper passes a
fresh snapshot/test/cache reproduction and is NON-GATING, acceptance impact NONE.
The two extra unsafe.Pointer vet sites are byte-identical to pristine upstream
v1.14.1 and Phase 2; no new Splicore findings. See the
[freeze audit](reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md#phase-3-freeze-disposition-and-validation).

Historical upstream results include successful builds and qualified Linux root CI,
Windows integration failures, additional vet findings and unrun optional suites.
Read the [baseline ledger](architecture/UPSTREAM_BASELINE.md) for exact scope.
Foundation requires own package tests, Linux race/fuzz, both binaries on Windows
and Linux, arm64 compilation, repeated upstream regression and docs/OpenAPI/
inclusive whitespace/secret audits. Known upstream/environment failures stay
classified; source is not patched to silence them. Archived Phase 0 evidence
remains part of the freeze; fresh outputs remain external.
See the [development index](development/README.md).
