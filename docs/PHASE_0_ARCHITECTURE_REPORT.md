# Splicore Phase 0 Architecture Report

- Documentation status: Historical
- Audience: Maintainers and historical reviewers
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Original Phase 0 acceptance snapshot, including its original file count and validation scope.
- Lifecycle: Frozen snapshot; only typo, broken-link or factual corrections.

Review date: 2026-10-01 (Asia/Shanghai). This is an architecture and upstream
baseline phase, not a product implementation or release qualification.

## Repository

* Path: `D:\code\Splicore`
* Branch: `codex/phase-0-architecture`
* HEAD: `1ac1a339cb1223e9c70eae14c44411c75033c02d`
* main: same full SHA; created directly from v1.14.1.
* Upstream remote: only `upstream`, `https://github.com/SagerNet/sing-box.git`.
* Complete upstream history/tags retained; shallow=false; baseline ancestry 2,723 commits.
* Directory was empty before clone; no unknown user files overwritten.

## Upstream Baseline

* Project: SagerNet/sing-box.
* Tag: v1.14.1, official published stable (not draft/prerelease).
* Full commit: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
* Date: committed 2026-09-15 01:21:37 +08:00; published 2026-09-15 00:06:50 UTC.
* Go version: module minimum 1.25.5, no explicit toolchain directive; root test CI
  ~1.25/~1.26; standard release build workflow 1.26.8. Observed Windows Go1.26.2
  and isolated Linux Go1.26.6. No module dependency added or changed.
* License: GPL-3.0-or-later and preserved upstream derivative naming/association text.
* Build: PASS, Windows minimal/CI/official tags and Linux CI tags.
* Tests: Linux complete root CI PASS in a suitable isolated environment;
  Windows complete root CI FAIL for WinDivert/TLS spoof host integration.
  Windows supplementary ordinary tests PASS with explicit integration exclusion.
* Additional vet FAIL (three existing unsafe.Pointer findings); configured lint
  and read-only formatting PASS. The baseline is **not globally all green**.

See [exact commands, platform limits and evidence](architecture/UPSTREAM_BASELINE.md).

## Product Identity

* Name: Splicore, independent server core; no IDC brand or NoBrand product rename.
* Binary target: `splicore`; Phase 0 leaves original command/build scripts intact.
* Service target: `splicore.service`.
* Config target: bootstrap `/etc/splicore/splicore.yaml`; public declarative schema.
* State target: `/var/lib/splicore/state.db`; local API `/run/splicore/splicore.sock`.
* No product binary/tag/version/repository is published by this phase.

## License / Attribution

* GPL: original LICENSE unchanged; derivative distribution must preserve notices
  and supply required corresponding source/build material.
* Upstream copyright: preserved, including individual Go/gRPC/other file headers.
* Splicore naming: own future package/binary/service/CLI identity; no official sing-box claim.
* Non-affiliation: NOTICE and docs/UPSTREAM explicitly disclaim SagerNet affiliation/endorsement.
* Future Mieru boundary: official embedding API research, GPL header/license
  and transitive dependency review before linkage; no imported code.
* Future Xray boundary: official MPL-2.0 reference; separate trusted executable,
  provenance/licenses for any special-feature fork still need identification.

See [license review](architecture/LICENSE_BOUNDARIES.md); Phase 0 does not alter licensing.

## Upstream Architecture Findings

* Startup: Cobra preRun composes contextual registries before config decoding;
  run/read/merge → box.New → managers/factories → staged Box.Start → inbound bind.
* Inbound: adapter.Inbound is Lifecycle + Type/Tag; optional injectable handler interfaces.
* Protocol registration: explicit maps with generic typed factories;
  include/build tags compose available implementations.
* Listener: shared TCP/UDP listener infrastructure; QUIC services consume UDP PacketConn.
* User model: per-protocol indexed users and auth context → metadata.User;
  no persistent unified Account/Binding/Credential. Snell v5/v6 has optional userkey mode.
* Stats: route ConnectionTracker, trafficcontrol per-connection/total observations,
  optional V2Ray selected inbound/outbound/user counters and SSM protocol management.
* API: Clash compatibility and newer daemon/API-service gRPC/status/platform tools;
  these expose upstream models, not the required public domain API.
* State: option structs/files are runtime inputs; bbolt caches mode/selection/rule/DNS/fake-IP.
* Hot reload: SIGHUP checks then closes/recreates Box; no durable transaction or
  automatic last-known-good recovery. Manager replacement can clash on the same port.
* Lifecycle: Initialize/Start/PostStart/Started; coordinated shutdown and task monitors.

[Actual source paths/calls and A–J answers](architecture/UPSTREAM_ARCHITECTURE_MAP.md).

## Recommended Fork Boundary

* Keep upstream unchanged: listener/TLS/REALITY/QUIC/route/DNS/transport/platform foundation.
* Extend: own composition root/registries, typed protocol compilers, authenticated
  router wrappers and bounded application/domain/storage/API/client modules.
* Wrap: Box lifecycle with generation/journal/recovery; expose stable domain operations.
* Avoid modifying: global option schema, Box order, private auth services and route fast paths
  before a demonstrated missing hook; no wholesale branding/module import changes.
* Recommendation: gradual namespace; retain module path in Phase 0; add own binary
  in Phase 1 before any derivative distribution, not immediate global rename.

[Conflict tiers and module/binary alternatives](architecture/FORK_BOUNDARY.md).

## Domain Model

* Node: random stable installation ID; runtime instance identity is separate.
* Operator: control principal, separate from proxy Account.
* Account: logical user/status/expiry/metadata/revision, without credentials.
* Inbound: logical protocol/version/settings with private resolved engine placement.
* Binding: Account↔Inbound authorization + compatible Credential reference.
* Credential: typed encrypted material and validity/rotation, protocol-specific schema.
* TrafficPolicy: unified quota/rates/reset/timezone/session/expiry ceilings.
* PlanTemplate: versioned technical defaults/selectors, no price/payment.
* Entitlement: materialized actual authorization snapshot and validity.
* Subscription: independently scoped/revocable export access; many per Account.
* Usage: durable leaf accounting by Binding/Node/Protocol/period with source epoch/cursor.
* Tag/Group: resource selection vocabulary; selectors do not bypass Binding authorization.
* Listener/DisplayEndpoint: actual bind vs advertised endpoint; neither equals SNI,
  egress or REALITY target.

[Fields, relationships and cases A–E](architecture/DOMAIN_MODEL.md).

## Account / Multi-user Model

* One account / many protocols: many owned Binding/Credential rows, one shared Account policy.
* Multi-user native: use qualified per-user auth, stable Binding-ID labels, generation mappings.
* Non-multi-user protocol: explicit per-binding internal instances/listeners/endpoints,
  or reject unsupported deployment; never fabricate attribution from a shared key.
* Quota: Splicore authority; upload+download decoded forwarded payload across bindings.
* Speed: shared per-Account per-direction limiter; native connection bandwidth settings
  cannot implement the aggregate 200 Mbps contract by themselves.
* Expiry: effective earliest authorization/credential boundary, checked at admission and
  active-session cutoff according to policy.
* Usage aggregation: one leaf source per payload, idempotent source ingestion, no double counting.
* Reset: never/calendar initially, explicit timezone/anchor/DST; rolling window reserved.

[Strict reservations, crash uncertainty and external-engine limits](architecture/POLICY_USAGE.md).

## Protocol Registry

* Interface: metadata/capabilities, validate/normalize inbound, create/validate
  credentials, neutral runtime intent, ClientProfile and health probe plan.
* Capabilities: protocol/version/feature × engine × platform/build intersection,
  plus independently qualified client/export combinations.
* Registration: compile-time explicit composition, duplicate and ABI checks; no .so plugin.
* New protocol workflow: spec/schema → contract implementation → native compiler/adapter
  → capabilities/registration → interop/fuzz/race/security gates. Account/Subscription
  storage does not gain protocol-specific columns.

[Contract notation and extension points](architecture/PROTOCOL_SDK.md).

## Engine Registry

* Native: private upstream option translation and many in-process inbounds.
* Xray: reserved private compatibility child with pinned executable/config/lifecycle/stats.
* Future external: implement reviewed engine ports, not arbitrary command execution.
* Account/Subscription/Exporter remain engine-independent. Strict external policy
  combinations reject unless identity-preserving enforcement is proven.

## Mieru Strategy

* Stage 1: pinned official external reference runtime/client interop.
* Stage 2: official apis/server embedded prototype with listener/user/UDP/policy/lifecycle gates.
* Stage 3: native Splicore inbound, profiles/exporters, accounting, recovery and field beta.
* Research v3.38.0 SHA: `b961978c3be9dd26b94158487c760858e19d1db2`.
* Store-after-Start is forbidden; Stop does not terminate established sessions;
  prototype must own fresh instances and session cleanup. No implementation in Phase 0.

[Source-backed research and roadmap](architecture/MIERU_INTEGRATION.md).

## Client Compatibility

* Canonical ClientProfile: authorized public endpoint + typed credentials/security/
  transport/options/metadata; no runtime/private engine structs or server private key.
* Mihomo/sing-box/Surge: separate target/version-aware exporters.
* URI/JSON/bundle: protocol grammar or canonical schema plus independent assembly.
* Interop gate: actual third-party traffic/auth/user isolation/reconnect/restart and
  claimed TCP/UDP/family/domain capabilities; unsupported features reject/exclude explicitly.
* Snell userkey and v6 support need exact tested clients; unavailable Surge live
  testing remains unqualified. No Splicore interop is claimed in Phase 0.

## State Authority

* Bootstrap config: process settings and trusted storage/API/logging/engine paths.
* Declarative import: scoped idempotent validate/plan/apply command, pinned normalized input.
* SQLite: only committed domain authority; pending journal is intent, not published state.
* Runtime state: observed derived generation, reconstructible from committed DB.
* Single authority: no bidirectional YAML/DB watcher or raw private-engine mutation path.

## Storage

* SQLite recommendation: WAL, local disk, durable commits, one bounded writer/read pool.
* Driver recommendation: modernc.org/sqlite, provisional until static Linux amd64/arm64,
  performance/lock/crash/backup tests; mattn CGO alternative if those gates fail.
* WAL: short SQL transactions and checkpoint monitoring; no runtime health calls inside SQL locks.
* Migration: forward-only numbered/checksummed migrations with compatibility checks.
* Backup: coherent SQLite online backup/snapshot + protected key material, not db-only WAL copy.
* Recovery: detect corruption/fail closed, preserve originals, restore checked checkpoint
  and reconcile generation/usage. No automatic empty DB replacement.

[Driver comparison](architecture/STORAGE_MODEL.md), [staged ERD](architecture/DATABASE_ERD.md).

## API

* Application Service: resource queries/commands and mutation coordinator; no handler SQL writes.
* Unix Socket: Phase 1 Linux default with protected permissions/server-derived peer identity.
* REST v1: system/capability/resource/usage/subscription queries and validate/plan/apply;
  operation observation added to make async success concrete.
* Future Panel: same application contracts over authenticated transport.
* Subscription API: separate public access credential/listener; never admin token.
* Security boundary: redacted reads, revision/If-Match/idempotency, 202 durable operation,
  409 stale precondition and 428 missing precondition; typed bounded input.

[API design](api/API_V1_DESIGN.md), [OpenAPI skeleton](api/openapi-skeleton.yaml).

## Runtime Process Model

* splicore.service: one main process/service owns native protocols and optional children.
* Native protocols: internal instances/listeners share managers, no per-protocol units.
* Xray child: trusted absolute binary/no shell, protected config, health/backoff,
  private management, generation identity/stats epoch and orphan prevention.
* Crash recovery: lock/DB/schema/journal → reconstruct committed generation → health
  → admit. Candidate observations cannot promote uncommitted state.

## Transactions

* Validation/Plan: explicit capability/ownership/listener checks and redacted impacts.
* Apply: revision fence and durable pending intent; runtime side effects outside SQL transaction.
* Health: protocol/auth/listener/policy probes with candidate admission blocked.
* Commit: resource updates + generation pointer + success audit in one SQLite transaction,
  then activate admission; post-commit faults reconcile to the committed generation.
* Rollback: compensate/reconstruct previous committed generation; failure is recovery_required,
  not false success. Closed connections/transferred traffic cannot be undone.
* Revision: per-resource and global generation, monotonic and surfaced as decimal strings.
* Audit: actor/action/resource/old-new revision/time/result/request/operation, secrets excluded.

[Crash table, concurrency and idempotency](architecture/TRANSACTION_MODEL.md).

## Versioning

Separate Splicore SemVer/full Git commit/build time/Go/platform, upstream tag/SHA,
Config Schema, DB Schema, Protocol ABI and API v1. Stable/beta/nightly qualification
is distinct from latest upstream. Phase 0 does not assign a product release/tag.

## Diagnostics

doctor/status/version/validate/diagnose report typed checks and committed/applied
generations. Support bundle is a local bounded redacted archive with manifest;
no automatic upload. PSK/UUID secrets/passwords/admin/subscription tokens/private
keys/client credentials excluded. Raw memory dumps are not default bundle content.

## NoBrand Integration

Download: qualified stable manifest → platform artifact → verify digest.
Version pin: explicit product/schema/capability qualification, never arbitrary HEAD.
Config import: public declarative document → validate → plan → apply → operation → health.
Migration: A Snell, B Hysteria2/TUIC independently, C VLESS/REALITY, D future Mieru;
special Xray compatibility after separate gates. Per-protocol feature flags default
off until qualification, one actual listener owner, preserve rollback checkpoint.
Field testing: actual old-state fixtures later, opt-in beta, manual redacted bundles;
no NoBrand code/installation changes now.

## Upstream Sync Strategy

Baseline pinned full SHA. Fetch official stable → identify/compare/review protocol/network/
toolchain/license changes → merge or traced selective port → build/unit/interop/
migration/failure tests → field beta → qualified stable. Hotspots are global options,
Box/auth/router/stats/listener/TLS/QUIC. Own modules/composition, patch inventory,
upstream hook proposals and differential references limit long-term drift.

## Answers to required questions 1–38

| # | Explicit answer |
|---|---|
| 1 | v1.14.1 SHA is 1ac1a339cb1223e9c70eae14c44411c75033c02d. |
| 2 | Builds PASS; suitable Linux full root CI PASS; Windows full root CI FAIL, supplementary tests PASS. |
| 3 | Module requires Go1.25.5; CI ~1.25/~1.26; standard release build1.26.8; actual tested1.26.2/1.26.6. |
| 4 | Do not immediately rename module; gradual namespace recommended, public module reassessed when ownership/library scope fixed. |
| 5 | Do not mass-rename now; add own cmd/binary/package/service assets in Phase1 before derivative distribution. |
| 6 | Preserve listener, route, DNS, TLS/REALITY, QUIC, transport and platform foundation. |
| 7 | Own composition/registries, typed constructors/router decorators and private translators are preferred insertion points. |
| 8 | Account identity; Binding authorization edge; Credential typed owned secret material. |
| 9 | Multiple Binding/Credential rows join one Account and effective policy. |
| 10 | Per-binding internal listener/instance with planned endpoint, or reject unsupported sharing. |
| 11 | Splicore durable policy/accounting service; native counters are sources only. |
| 12 | Shared account limiters at authenticated payload boundary; external strict coverage must be proven. |
| 13 | Never/calendar with timezone/anchor/DST and durable period IDs; rolling deferred. |
| 14 | PlanTemplate reusable versioned defaults; Entitlement actual authorization snapshot. |
| 15 | Subscription independently scopes/revokes exports, many per Account; proxy credential lifetime is separate. |
| 16 | New random token generation + verifier, explicit old-token revoke/overlap/expiry; no admin token reuse. |
| 17 | Subscription selects authorized profiles; registry exporters render target format/version independently. |
| 18 | Metadata/caps/validation/credentials/runtime intent/client profile/health-plan source contract, not upstream interface replacement. |
| 19 | Spec/schema + Protocol + Engine compiler/inbound + registry/capabilities + qualification/export mappings. |
| 20 | Effective protocol-version/feature × engine × platform/build capabilities and client qualification. |
| 21 | Engine metadata/supports/compile/prepare and handle apply/health/usage/drain/close ports. |
| 22 | Trusted private supervised child with rendered config/lifecycle/health/logs/stats; no public Xray model. |
| 23 | Runtime is private engine projection; ClientProfile is client endpoint/auth/security/transport/options only. |
| 24 | One target/version-aware exporter module each for Mihomo/sing-box/Surge plus URI/JSON/bundle. |
| 25 | Pin client/profile versions and execute actual auth/traffic/reconnect/UDP/families/failure interop gates. |
| 26 | SQLite WAL recommended for single installation with bounded writer and local disk. |
| 27 | modernc preferred provisionally; mattn CGO alternative after measured qualification. |
| 28 | SQLite committed domain generation; bootstrap owns process settings; import files are commands. |
| 29 | Scoped public import with stable keys, validate/plan revision/digest/expiry and idempotent apply. |
| 30 | Transport outside application services/domain/ports; handlers do not directly mutate DB. |
| 31 | Yes; local daemon CLI via UDS, offline path still uses same application/journal ownership rules. |
| 32 | Yes for Linux Phase1 with permissions/peer identity; Windows adapter and future TLS separate. |
| 33 | One systemd process owning native instances/listeners and optional engine children. |
| 34 | Pinned executable/config, process ownership/cgroup, health/restart budget/logs/stats epochs/reaping. |
| 35 | Durable intent + generation fences + compensated reconstruction; not SQL/kernel atomicity. |
| 36 | Stable fetch/identify/compare/review/merge-or-traced-port/build/tests/interop/migration/beta/stable. |
| 37 | Global options, Box construction, protocol auth, route/stats fast paths and listener/TLS/QUIC. |
| 38 | Small adapter patch inventory, stable comparisons, upstream hook proposals and differential/client gates. |

## Documents Added

The complete list includes architecture/API/testing/integration documents, all
twelve ADRs, NOTICE and captured baseline/post-document evidence. No runtime
package skeleton was needed.

<!-- PHASE0_FILES_START -->
* [NOTICE.md](../NOTICE.md)
* [docs/ARCHITECTURE.md](ARCHITECTURE.md)
* [docs/PHASE_0_ARCHITECTURE_REPORT.md](PHASE_0_ARCHITECTURE_REPORT.md)
* [docs/PHASE_0_REQUIREMENTS.md](PHASE_0_REQUIREMENTS.md)
* [docs/UPSTREAM.md](UPSTREAM.md)
* [docs/adr/0001-upstream-baseline.md](adr/0001-upstream-baseline.md)
* [docs/adr/0002-product-identity.md](adr/0002-product-identity.md)
* [docs/adr/0003-domain-state-authority.md](adr/0003-domain-state-authority.md)
* [docs/adr/0004-account-binding-credential.md](adr/0004-account-binding-credential.md)
* [docs/adr/0005-protocol-engine-separation.md](adr/0005-protocol-engine-separation.md)
* [docs/adr/0006-client-profile-exporter.md](adr/0006-client-profile-exporter.md)
* [docs/adr/0007-storage-strategy.md](adr/0007-storage-strategy.md)
* [docs/adr/0008-api-boundary.md](adr/0008-api-boundary.md)
* [docs/adr/0009-xray-compatibility-engine.md](adr/0009-xray-compatibility-engine.md)
* [docs/adr/0010-mieru-integration-strategy.md](adr/0010-mieru-integration-strategy.md)
* [docs/adr/0011-upstream-sync-strategy.md](adr/0011-upstream-sync-strategy.md)
* [docs/adr/0012-versioning-model.md](adr/0012-versioning-model.md)
* [docs/adr/README.md](adr/README.md)
* [docs/api/API_V1_DESIGN.md](api/API_V1_DESIGN.md)
* [docs/api/openapi-skeleton.yaml](api/openapi-skeleton.yaml)
* [docs/architecture/CLIENT_COMPATIBILITY.md](architecture/CLIENT_COMPATIBILITY.md)
* [docs/architecture/CONFIG_STATE_AUTHORITY.md](architecture/CONFIG_STATE_AUTHORITY.md)
* [docs/architecture/DATABASE_ERD.md](architecture/DATABASE_ERD.md)
* [docs/architecture/DIAGNOSTICS.md](architecture/DIAGNOSTICS.md)
* [docs/architecture/DOMAIN_MODEL.md](architecture/DOMAIN_MODEL.md)
* [docs/architecture/ENGINE_MODEL.md](architecture/ENGINE_MODEL.md)
* [docs/architecture/FORK_BOUNDARY.md](architecture/FORK_BOUNDARY.md)
* [docs/architecture/LICENSE_BOUNDARIES.md](architecture/LICENSE_BOUNDARIES.md)
* [docs/architecture/MIERU_INTEGRATION.md](architecture/MIERU_INTEGRATION.md)
* [docs/architecture/NATIVE_PROTOCOL_GUIDELINES.md](architecture/NATIVE_PROTOCOL_GUIDELINES.md)
* [docs/architecture/POLICY_USAGE.md](architecture/POLICY_USAGE.md)
* [docs/architecture/PROTOCOL_SDK.md](architecture/PROTOCOL_SDK.md)
* [docs/architecture/RUNTIME_LIFECYCLE.md](architecture/RUNTIME_LIFECYCLE.md)
* [docs/architecture/SECURITY_BOUNDARIES.md](architecture/SECURITY_BOUNDARIES.md)
* [docs/architecture/STORAGE_MODEL.md](architecture/STORAGE_MODEL.md)
* [docs/architecture/SUBSCRIPTION_MODEL.md](architecture/SUBSCRIPTION_MODEL.md)
* [docs/architecture/TRANSACTION_MODEL.md](architecture/TRANSACTION_MODEL.md)
* [docs/architecture/UPSTREAM_ARCHITECTURE_MAP.md](architecture/UPSTREAM_ARCHITECTURE_MAP.md)
* [docs/architecture/UPSTREAM_BASELINE.md](architecture/UPSTREAM_BASELINE.md)
* [docs/architecture/UPSTREAM_SYNC.md](architecture/UPSTREAM_SYNC.md)
* [docs/architecture/VERSION_MODEL.md](architecture/VERSION_MODEL.md)
* [docs/architecture/evidence/README.md](architecture/evidence/README.md)
* [docs/architecture/evidence/SHA256SUMS.json](architecture/evidence/SHA256SUMS.json)
* [docs/architecture/evidence/baseline-build-ci.log.gz](architecture/evidence/baseline-build-ci.log.gz)
* [docs/architecture/evidence/baseline-build-minimal.log.gz](architecture/evidence/baseline-build-minimal.log.gz)
* [docs/architecture/evidence/baseline-build-windows.log.gz](architecture/evidence/baseline-build-windows.log.gz)
* [docs/architecture/evidence/baseline-format.log.gz](architecture/evidence/baseline-format.log.gz)
* [docs/architecture/evidence/baseline-lint.log.gz](architecture/evidence/baseline-lint.log.gz)
* [docs/architecture/evidence/baseline-linux-build.log.gz](architecture/evidence/baseline-linux-build.log.gz)
* [docs/architecture/evidence/baseline-linux-qualified-env-test.log.gz](architecture/evidence/baseline-linux-qualified-env-test.log.gz)
* [docs/architecture/evidence/baseline-linux-test.log.gz](architecture/evidence/baseline-linux-test.log.gz)
* [docs/architecture/evidence/baseline-test-ci.log.gz](architecture/evidence/baseline-test-ci.log.gz)
* [docs/architecture/evidence/baseline-test-without-integration.log.gz](architecture/evidence/baseline-test-without-integration.log.gz)
* [docs/architecture/evidence/baseline-vet.log.gz](architecture/evidence/baseline-vet.log.gz)
* [docs/architecture/evidence/diff-check.txt](architecture/evidence/diff-check.txt)
* [docs/architecture/evidence/diff-stat.txt](architecture/evidence/diff-stat.txt)
* [docs/architecture/evidence/document-check.log](architecture/evidence/document-check.log)
* [docs/architecture/evidence/git-verification.json](architecture/evidence/git-verification.json)
* [docs/architecture/evidence/go-env.json](architecture/evidence/go-env.json)
* [docs/architecture/evidence/go-version.txt](architecture/evidence/go-version.txt)
* [docs/architecture/evidence/linux-go-env.json](architecture/evidence/linux-go-env.json)
* [docs/architecture/evidence/linux-go-version.txt](architecture/evidence/linux-go-version.txt)
* [docs/architecture/evidence/linux-image.txt](architecture/evidence/linux-image.txt)
* [docs/architecture/evidence/linux-qualified-env-results.txt](architecture/evidence/linux-qualified-env-results.txt)
* [docs/architecture/evidence/linux-results.txt](architecture/evidence/linux-results.txt)
* [docs/architecture/evidence/post-doc-build-ci.log.gz](architecture/evidence/post-doc-build-ci.log.gz)
* [docs/architecture/evidence/post-doc-build-minimal.log.gz](architecture/evidence/post-doc-build-minimal.log.gz)
* [docs/architecture/evidence/post-doc-build-windows.log.gz](architecture/evidence/post-doc-build-windows.log.gz)
* [docs/architecture/evidence/post-doc-format.log.gz](architecture/evidence/post-doc-format.log.gz)
* [docs/architecture/evidence/post-doc-lint.log.gz](architecture/evidence/post-doc-lint.log.gz)
* [docs/architecture/evidence/post-doc-linux-build.log.gz](architecture/evidence/post-doc-linux-build.log.gz)
* [docs/architecture/evidence/post-doc-linux-results.txt](architecture/evidence/post-doc-linux-results.txt)
* [docs/architecture/evidence/post-doc-linux-test.log.gz](architecture/evidence/post-doc-linux-test.log.gz)
* [docs/architecture/evidence/post-doc-test-ci.log.gz](architecture/evidence/post-doc-test-ci.log.gz)
* [docs/architecture/evidence/post-doc-test-without-integration.log.gz](architecture/evidence/post-doc-test-without-integration.log.gz)
* [docs/architecture/evidence/post-doc-vet.log.gz](architecture/evidence/post-doc-vet.log.gz)
* [docs/architecture/evidence/results.jsonl](architecture/evidence/results.jsonl)
* [docs/integration/NOBRAND_MIGRATION.md](integration/NOBRAND_MIGRATION.md)
* [docs/testing/INTEROP_MATRIX.md](testing/INTEROP_MATRIX.md)
* [docs/testing/TEST_STRATEGY.md](testing/TEST_STRATEGY.md)
<!-- PHASE0_FILES_END -->

## Runtime Changes

**NONE**. No production source, protocol wire behavior, original README/LICENSE,
module dependency, workflow, package path or build/service artifact changed.

## Validation

The post-document repeat reproduced the scoped baseline outcomes. Tracked source
and the real index are unchanged; a temporary index additionally checks every
new document and evidence file.

<!-- PHASE0_VALIDATION_START -->
| Gate | Initial | Post-doc |
|---|---|---|
| Windows minimal/CI/official-tag builds | PASS | PASS |
| Linux CI-tag build | PASS | PASS |
| Linux complete root CI, suitable isolated environment | PASS | PASS |
| Windows complete root CI | FAIL (host/driver integration) | FAIL (same packages/limitations) |
| Windows ordinary tests, explicit TestIntegration exclusion | PASS | PASS |
| Additional Windows vet | FAIL (3 upstream diagnostics) | FAIL (same 3) |
| Configured Windows lint | PASS (0 issues) | PASS (0 issues) |
| Read-only format check | PASS (no diff) | PASS (no diff) |
| OpenAPI 3.1 standard validation | design gate | PASS |
| Mandatory files / 12 ADRs / links / answers 1–38 | design gate | PASS |
| Tracked source equality with HEAD | clean | clean |
| git diff --check, including untracked docs via temporary index | n/a | PASS |

Full logs/tool identities/Git metadata: [evidence](architecture/evidence/README.md).
Normal git diff --stat omits untracked additions; [document-inclusive stat](architecture/evidence/diff-stat.txt)
uses a copied temporary index, with the real index left unchanged.
<!-- PHASE0_VALIDATION_END -->

## Git

Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
No new remote/repository. Worktree intentionally contains uncommitted Phase 0
documents on codex/phase-0-architecture; main remains the pinned upstream commit.

## Open Architecture Questions

Only decisions requiring future maintainer input:

1. Public repository/module owner and whether to publish a Go library (affects later
   module migration; no owner or remote invented now).
2. Supported Phase1 secret-key provisioning/recovery mode (local protected key vs
   operator-supplied key/keystore); choose before implementing recoverable secrets.
3. Exact FinalMask/Sudoku Xray fork/protocol reference, license/provenance and
   supported client versions before that future engine stage.

None prevents reviewing the Phase0 architecture. Missing enforcement hooks,
client evidence or old NoBrand fixtures are future engineering gates, not hidden
completed features or requests for permission to implement them now.

## Recommended Phase 1

1. Maintainer reviews ADRs/contracts and validation limitations.
2. Add own Splicore composition/identity/command with inward domain/application ports.
3. Qualify chosen SQLite driver/key handling, minimal generation/revision storage,
   forward migration and crash-safe coordinator before broad protocol mutation.
4. Add local UDS API/CLI workflow and one native reference protocol with Account/
   Binding/Credential mapping, policy hooks and actual client interoperability.
5. Establish contract/race/failure/migration/diagnostic gates, then expand protocol
   coverage and controlled NoBrand field beta. Mieru/Xray/Panel remain later stages.

**Recommendations only; Phase1 not executed.**

## Final Result

**ARCHITECTURE READY FOR REVIEW** — source-grounded specification and contracts,
with explicitly scoped validation; not a claim that every baseline/platform gate passes.

## Blockers

None for architecture review. Full Windows integration qualification remains
blocked by observed host/driver errors; additional vet findings require upstream
review before treating that supplementary gate as passed. Mobile/macOS/full lint
matrix, separate Docker interop suite and all Splicore protocol qualification
remain NOT RUN/planned as specified above.
