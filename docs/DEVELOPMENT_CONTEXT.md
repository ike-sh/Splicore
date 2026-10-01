# Development Context

- Documentation status: Canonical
- Audience: Developers, maintainers and returning coding agents
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Current project constraints and the minimum recovery context.
- Lifecycle: Replace obsolete constraints when reviewed scope changes; never append a diary.

## Goal and current phase

Splicore is an independent modular server proxy core derived from sing-box.
Phases 0–4 are locally frozen. Phase 4 implements Experimental TUIC v5 and shared
creation/TLS/QUIC infrastructure. Phase 5 has a reserved branch only;
VLESS/REALITY implementation is NOT STARTED. Snell/HY2 remain Experimental; no Stable
release. See [TUIC](protocol/TUIC.md), [workflow](development/PHASE_4_TUIC.md) and
[report](reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md).

## Reproducible baseline and authorization

- Upstream v1.14.1: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Phase 0 freeze: `687425bdbfff6c76f900035068c23a03c4547062`.
- Phase 1 freeze: `a2ca59e6dbf1a239feae5e471ec1914cae0f1eac`.
- Phase 2 freeze: `5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`.
- Phase 3 freeze / Phase 4 sole parent: `94555d9608ebcc36c5a396bc06a5743cce4e0788`.
- Phase 4 freeze: the commit containing this record, with message
  `feat(protocol): add experimental TUIC vertical slice`; main and
  `codex/phase-4-tuic-vertical-slice` point to it. Exact SHA and Git evidence live in
  `D:\splicore-validation\phase4-freeze-20261001`.
- Reserved branch: `codex/phase-5-vless-reality-vertical-slice`, based on frozen main;
  working tree CLEAN. Branch creation does not authorize VLESS implementation.
- Sole remote upstream: https://github.com/SagerNet/sing-box.git; no origin.
- Phase 4 Freeze authorizes one reviewed commit, main fast-forward with `--ff-only`,
  and the reserved Phase 5 branch. Stop after branch creation. Push/tag/release NONE;
  no publication or real NoBrand access/changes.
- Historical Phase 0/1/2/3 reports/evidence and all migrations unchanged. Fresh
  outputs/tools/binaries/state external. Module path unchanged; upstream edits 0.

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

Schema 3 SQLite committed state is authority; no TUIC migration. All implemented
modules expose registered CreationCodec; shared Application resource builder owns
Account/Binding/Credential/policies and protocol-bound HMAC plan/pending/start/health/
commit/admission. Direct Phase4 composition has one native compiler map. Service owns
display availability/ownership; SQL is generic. Protected Linux UDS API/CLI share
commands; explicit scoped export returns secrets, ordinary metadata/doctor stays safe.

HY2/TUIC share TLS model/load/snapshot, minimal Box/router, UDP ownership/admission/
health/close grace, immutable Binding identity and payload/session meters. TUIC v5
UUID/password uses cubic/native/h3/no-0RTT. Both have HotUserUpdate=false and Binding
restart closes sessions/resets counters. Keys external; Linux mode/owner enforced;
Windows development only. See [ADR 0015](adr/0015-tuic-shared-control-plane.md) and
[extension audit](ARCHITECTURE.md#phase-4-third-protocol-realization).

Phase 3 extension debt is resolved at its four triggers. General Account mutation,
credential rotation, quota/rate, durable Account aggregates, delete/hot reload,
dynamic TLS, Snell userkey multi-user, generic imports and Stable remain deferred.
VLESS/REALITY, Mieru, Xray, Panel, self-designed protocols and real NoBrand canary
remain outside current implementation authorization.

## Forbidden shortcuts

Do not turn Splicore into a raw runtime JSON wrapper, let installers edit SQLite,
add protocol columns to Account, weaken unsupported policy silently, treat exporter
rendering as interoperability, or call an upstream build a qualified Splicore release.
Do not globally rename upstream packages/branding or move large package trees
without a reviewed decision. Preserve LICENSE, copyright and non-affiliation.
Do not implement deferred protocols or Panel under the Phase 4 authorization.

## Validation context

Native Ubuntu-24.04 WSL2 state/TLS/socket and race-built actual traffic are required.
Clients stay Mihomo1.19.30 and sing-box1.14.1 with archive/binary SHA256. Report owns
actual unit/race/platform/fuzz/root-CI/doc/live-schema and TUIC/HY2/Snell results.
Never qualify exporter rendering alone. Snapshot native source and verify functional
file hashes; logs/tools/binaries outside repository. Phase 4 freeze verifies 131
functional files against final acceptance, repeats critical TUIC/HY2/Snell smoke,
Windows/Linux units and builds, own vet and docs/OpenAPI/live schemas. Freeze-only
changes are report/canonical docs; historical full unit/race/fuzz/33-cell evidence
remains immutable. New runtime changes require corresponding acceptance again.

Docker Desktop issue and old residue are DEFERRED EXTERNAL ENVIRONMENT CLEANUP.
Redis/TeleLedger UNTOUCHED: do not query/restart Docker or operate Redis. Existing
WSL user shell permissions and unrelated `/` repository remain unchanged. Toolchains,
caches/clients stay on D; runtime/private fixture state native ext4. Two extra inherited
unsafe.Pointer vet sites are byte-identical upstream and recorded in the
[baseline ledger](architecture/UPSTREAM_BASELINE.md); do not patch them to silence vet.
Historical reports/evidence remain intact; [development index](development/README.md).
