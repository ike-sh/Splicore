# Splicore Phase 0 Documentation Finalization Report

- Documentation status: Historical
- Audience: Maintainers, reviewers and future developers
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Documentation audit, authority boundaries and scoped finalization acceptance evidence.
- Lifecycle: Frozen completion snapshot; only typo, broken-link or factual corrections.

Review scope: Phase 0 Documentation Finalization at baseline
`1ac1a339cb1223e9c70eae14c44411c75033c02d`. This is not Phase 1,
a runtime implementation or release qualification.

## README

- Previous role: unchanged upstream sing-box homepage, packaging badge, upstream site and license excerpt (31 lines).
- New role: concise Splicore project homepage and entry into owned documentation.
- Line count: **90**, including source-only documentation metadata; within the requested 80–180 guidance.
- Sections: Status, Goals, Architecture, Protocol Direction, Compatibility, Documentation, Upstream, License.
- Runtime claims reviewed: early development/architecture; no stable Splicore runtime; all protocol rows explicitly planned/unqualified.
- Native direction: Snell, Hysteria2, TUIC, VLESS/REALITY; planned native Mieru; future Xray compatibility for FinalMask/Sudoku.
- Interoperability is an exact-client/profile release gate, not a claim from exporter output.
- Independent derivative/non-affiliation, copyright preservation and unchanged LICENSE are explicit.
- No fake installation/release/badges, Panel promise, endpoint/SQL reference, phase report, test-failure details or TODO list.
- NoBrand does not define homepage identity; its future integration path is in the docs index.

Review the actual [homepage](../../README.md). The original copyright/license
text remains in the unchanged LICENSE and original upstream history.

## Documentation Structure

The tree below shows owned documents; inherited upstream docs remain in place.

```text
README.md
NOTICE.md
docs/
├── README.md
├── ARCHITECTURE.md
├── DOCUMENTATION_POLICY.md
├── DEVELOPMENT_CONTEXT.md
├── UPSTREAM.md
├── PHASE_0_ARCHITECTURE_REPORT.md       Historical, established path
├── PHASE_0_REQUIREMENTS.md             Historical, original brief traceability
├── adr/
│   ├── README.md
│   └── 0001–0012-*.md                  12 actual ADRs, all retained
├── architecture/
│   ├── README.md
│   ├── CLIENT_COMPATIBILITY.md
│   ├── CONFIG_STATE_AUTHORITY.md
│   ├── DATABASE_ERD.md
│   ├── DIAGNOSTICS.md
│   ├── DOMAIN_MODEL.md
│   ├── ENGINE_MODEL.md
│   ├── FORK_BOUNDARY.md
│   ├── LICENSE_BOUNDARIES.md
│   ├── MIERU_INTEGRATION.md
│   ├── NATIVE_PROTOCOL_GUIDELINES.md
│   ├── POLICY_USAGE.md
│   ├── PROTOCOL_SDK.md
│   ├── RUNTIME_LIFECYCLE.md
│   ├── SECURITY_BOUNDARIES.md
│   ├── STORAGE_MODEL.md
│   ├── SUBSCRIPTION_MODEL.md
│   ├── TRANSACTION_MODEL.md
│   ├── UPSTREAM_ARCHITECTURE_MAP.md     Historical, pinned source observations
│   ├── UPSTREAM_BASELINE.md             Historical, pinned validation ledger
│   ├── UPSTREAM_SYNC.md
│   ├── VERSION_MODEL.md
│   └── evidence/                       36 original files, frozen
├── api/
│   ├── README.md
│   ├── API_V1_DESIGN.md
│   └── openapi-skeleton.yaml
├── protocol/
│   └── README.md                       index to existing specs, no relocation
├── development/
│   └── README.md                       actual workflow, no placeholder
├── testing/
│   ├── TEST_STRATEGY.md
│   └── INTEROP_MATRIX.md
├── integration/
│   └── NOBRAND_MIGRATION.md
└── reports/
    └── PHASE_0_DOCUMENTATION_FINALIZATION_REPORT.md
```

Navigation: root README → docs index → architecture overview → bounded
specifications and relevant ADRs. API, protocol and development indexes provide
focused routes. The inherited site configuration, client/configuration/installation
pages and changelog are not repurposed as Splicore documentation.

## Canonical Documents

**48 canonical artifacts: 47 Markdown documents and one OpenAPI contract.**
Canonical means maintained authority for a topic, not functionality implemented.
The runtime design remains proposed; proven upstream observations are labeled
as historical research. Owners are maintainer roles, not assigned individuals.
All canonical documents declare audience, owner, responsibility, lifecycle and
last review date. The homepage stores this metadata in a source comment;
OpenAPI uses `x-documentation`.

| Document | Owner | Responsibility |
| --- | --- | --- |
| [NOTICE.md](../../NOTICE.md) | Project maintainers | Independent derivative identity, attribution and non-affiliation. |
| [README.md](../../README.md) | Project maintainers | Project identity, development status and documentation entry point. |
| [docs/ARCHITECTURE.md](../ARCHITECTURE.md) | Core maintainers | Overall boundaries, dependency direction, invariants and implementation gates. |
| [docs/DEVELOPMENT_CONTEXT.md](../DEVELOPMENT_CONTEXT.md) | Project maintainers | Current project constraints and the minimum recovery context. |
| [docs/DOCUMENTATION_POLICY.md](../DOCUMENTATION_POLICY.md) | Documentation maintainers | Documentation classification, ownership and change review rules. |
| [docs/README.md](../README.md) | Documentation maintainers | Complete navigation to Splicore specifications, decisions and history. |
| [docs/UPSTREAM.md](../UPSTREAM.md) | Upstream maintainers | Current baseline provenance, history policy and independent project identity. |
| [docs/adr/0001-upstream-baseline.md](../adr/0001-upstream-baseline.md) | Core maintainers | ADR 0001 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0002-product-identity.md](../adr/0002-product-identity.md) | Core maintainers | ADR 0002 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0003-domain-state-authority.md](../adr/0003-domain-state-authority.md) | Core maintainers | ADR 0003 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0004-account-binding-credential.md](../adr/0004-account-binding-credential.md) | Core maintainers | ADR 0004 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0005-protocol-engine-separation.md](../adr/0005-protocol-engine-separation.md) | Core maintainers | ADR 0005 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0006-client-profile-exporter.md](../adr/0006-client-profile-exporter.md) | Core maintainers | ADR 0006 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0007-storage-strategy.md](../adr/0007-storage-strategy.md) | Core maintainers | ADR 0007 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0008-api-boundary.md](../adr/0008-api-boundary.md) | Core maintainers | ADR 0008 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0009-xray-compatibility-engine.md](../adr/0009-xray-compatibility-engine.md) | Core maintainers | ADR 0009 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0010-mieru-integration-strategy.md](../adr/0010-mieru-integration-strategy.md) | Core maintainers | ADR 0010 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0011-upstream-sync-strategy.md](../adr/0011-upstream-sync-strategy.md) | Core maintainers | ADR 0011 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/0012-versioning-model.md](../adr/0012-versioning-model.md) | Core maintainers | ADR 0012 rationale, alternatives, consequences and decision review triggers. |
| [docs/adr/README.md](../adr/README.md) | Core maintainers | Decision navigation, individual decision status and review lifecycle. |
| [docs/api/API_V1_DESIGN.md](../api/API_V1_DESIGN.md) | API maintainers | Transport, security and operation semantics; OpenAPI owns endpoint surface. |
| [docs/api/README.md](../api/README.md) | API maintainers | Contract authority, semantic references and API change workflow. |
| [docs/api/openapi-skeleton.yaml](../api/openapi-skeleton.yaml) | API maintainers | Machine authority for proposed API paths, methods, parameters, schemas and responses. |
| [docs/architecture/CLIENT_COMPATIBILITY.md](../architecture/CLIENT_COMPATIBILITY.md) | Client maintainers | ClientProfile projection, exporter responsibility and client/version checks. |
| [docs/architecture/CONFIG_STATE_AUTHORITY.md](../architecture/CONFIG_STATE_AUTHORITY.md) | Core maintainers | Bootstrap, import-command and committed-domain authority boundaries. |
| [docs/architecture/DATABASE_ERD.md](../architecture/DATABASE_ERD.md) | Storage / Core maintainers | Logical entities, relationships, ownership and constraints; not schema migration history. |
| [docs/architecture/DIAGNOSTICS.md](../architecture/DIAGNOSTICS.md) | Core maintainers | Proposed diagnostic command semantics and bounded redacted local bundles. |
| [docs/architecture/DOMAIN_MODEL.md](../architecture/DOMAIN_MODEL.md) | Core maintainers | Entity meaning, authorization relationships and identity/secret separation. |
| [docs/architecture/ENGINE_MODEL.md](../architecture/ENGINE_MODEL.md) | Engine maintainers | Private native/compatibility execution contracts and enforcement limits. |
| [docs/architecture/FORK_BOUNDARY.md](../architecture/FORK_BOUNDARY.md) | Core maintainers | Namespace, composition, adapters and product command transition strategy. |
| [docs/architecture/LICENSE_BOUNDARIES.md](../architecture/LICENSE_BOUNDARIES.md) | Project maintainers | Attribution, third-party provenance and future distribution review boundaries. |
| [docs/architecture/MIERU_INTEGRATION.md](../architecture/MIERU_INTEGRATION.md) | Protocol maintainers | Pinned Mieru API research and staged native integration qualification. |
| [docs/architecture/NATIVE_PROTOCOL_GUIDELINES.md](../architecture/NATIVE_PROTOCOL_GUIDELINES.md) | Protocol maintainers | Future wire specification, independent reference, security and qualification rules. |
| [docs/architecture/POLICY_USAGE.md](../architecture/POLICY_USAGE.md) | Core maintainers | Unified payload accounting, quota/rate, reset and crash uncertainty semantics. |
| [docs/architecture/PROTOCOL_SDK.md](../architecture/PROTOCOL_SDK.md) | Protocol maintainers | Proposed protocol ports, compiled registry and effective capabilities. |
| [docs/architecture/README.md](../architecture/README.md) | Core maintainers | Route architectural changes to the bounded specification that owns them. |
| [docs/architecture/RUNTIME_LIFECYCLE.md](../architecture/RUNTIME_LIFECYCLE.md) | Core / Engine maintainers | Startup, admission, shutdown, recovery and future child ownership. |
| [docs/architecture/SECURITY_BOUNDARIES.md](../architecture/SECURITY_BOUNDARIES.md) | Security maintainers | Secret handling, transport authorization, imports, files and executable trust. |
| [docs/architecture/STORAGE_MODEL.md](../architecture/STORAGE_MODEL.md) | Storage maintainers | Driver qualification, durability, migration mechanics, backup and corruption recovery. |
| [docs/architecture/SUBSCRIPTION_MODEL.md](../architecture/SUBSCRIPTION_MODEL.md) | Client / Core maintainers | Export-access scope, token lifecycle and authorized profile selection. |
| [docs/architecture/TRANSACTION_MODEL.md](../architecture/TRANSACTION_MODEL.md) | Core maintainers | Journal, generation fences, runtime compensation, idempotency and audit. |
| [docs/architecture/UPSTREAM_SYNC.md](../architecture/UPSTREAM_SYNC.md) | Upstream maintainers | Stable candidate review, merge/selective port, drift control and qualification. |
| [docs/architecture/VERSION_MODEL.md](../architecture/VERSION_MODEL.md) | Core maintainers | Independent product, build, schema, API and client-qualification identities. |
| [docs/development/README.md](../development/README.md) | Project maintainers | Recovery reading order, change workflow and scoped validation. |
| [docs/integration/NOBRAND_MIGRATION.md](../integration/NOBRAND_MIGRATION.md) | Integration maintainers | Future NoBrand import, rollout, field-test and rollback boundaries. |
| [docs/protocol/README.md](../protocol/README.md) | Protocol maintainers | Protocol extension navigation and qualification boundaries. |
| [docs/testing/INTEROP_MATRIX.md](../testing/INTEROP_MATRIX.md) | Test maintainers | Planned third-party protocol/client qualification cells and evidence rules. |
| [docs/testing/TEST_STRATEGY.md](../testing/TEST_STRATEGY.md) | Test maintainers | Meaningful implementation/interop/failure gates and reporting scope. |

## Historical Documents

Six Markdown snapshots:

- [docs/PHASE_0_ARCHITECTURE_REPORT.md](../PHASE_0_ARCHITECTURE_REPORT.md): Original Phase 0 acceptance snapshot, including its original file count and validation scope.
- [docs/PHASE_0_REQUIREMENTS.md](../PHASE_0_REQUIREMENTS.md): Traceability to the original Phase 0 brief; not a live backlog.
- [docs/architecture/UPSTREAM_ARCHITECTURE_MAP.md](../architecture/UPSTREAM_ARCHITECTURE_MAP.md): Source observations pinned to sing-box v1.14.1 and its full commit.
- [docs/architecture/UPSTREAM_BASELINE.md](../architecture/UPSTREAM_BASELINE.md): Phase 0 baseline commands, toolchains and observed scoped results.
- [docs/architecture/evidence/README.md](../architecture/evidence/README.md): Interpretation and provenance of frozen Phase 0 generated captures.
- [docs/reports/PHASE_0_DOCUMENTATION_FINALIZATION_REPORT.md](PHASE_0_DOCUMENTATION_FINALIZATION_REPORT.md): Documentation audit and finalization acceptance snapshot.

The original architecture report remains at its path. There were five Markdown
links to it across the overview, itself, evidence index and baseline ledger,
plus a textual traceability reference. Moving it would also rebase its many
relative links and original 80-file inventory. Classification/navigation solves
the ambiguity without migration churn; future completed reports use `docs/reports/`.

The original report, requirement traceability, baseline ledger and source map
bodies are unchanged after removing the new metadata block. Their statements
about README/source preservation and 80 files remain true for their original
acceptance point, not a statement of the later finalization state.

Evidence README received metadata plus an explicitly labeled factual correction
about empty captures. All **35 generated evidence files are byte-for-byte unchanged**.
Generated ownership/lifecycle is declared in that README and each audit row below.

## ADR

- Count: **12**, unchanged; no new decision or runtime behavior was introduced.
- Index: [docs/adr/README.md](../adr/README.md).
- Status: 0001 accepted for Phase 0; 0002–0012 proposed for maintainer review.
- Each has Status, Context, Decision, Alternatives, Consequences and Future Review.
- Numbered ADR bodies and decision status are unchanged apart from metadata.
- Canonical classification does not accept a proposal or qualify implementation.
- Durable replacement gets a new ADR and supersession link; minor docs edits need no ADR.

## Documentation Governance

Policy: [docs/DOCUMENTATION_POLICY.md](../DOCUMENTATION_POLICY.md).

- Significant architecture/domain/protocol/engine/API/storage/transaction/security
  changes include the owning canonical docs in the same review as code.
- ADRs record durable decisions with meaningful alternatives; avoid one ADR per edit.
- Historical reports freeze on completion; only typo, broken-link and factual corrections.
- OpenAPI owns proposed and future implemented API surface; Markdown owns
  transport, security, design, semantics and future scope, not duplicate endpoint tables.
- ERD owns logical entities/relationships/ownership; storage owns operations;
  future migrations own actual schema history. No copied full SQL schema.
- Keep inherited upstream docs and history distinct; no global naming replacement.
- Update indexes with ownership changes; no empty phase/package/report placeholders.

## Development Context

File: [docs/DEVELOPMENT_CONTEXT.md](../DEVELOPMENT_CONTEXT.md).
Purpose: recover current constraints without old chats or an expanding diary.

It records goal, stable tag/full SHA, branch/remotes, current phase, canonical
authorities, next phase as a recommendation, and prohibited shortcuts. It preserves
Account/Binding/Credential and Protocol/Engine distinctions, separate runtime/client
projections, committed SQLite authority, compiled registration, generation recovery,
proven strict policy hooks, third-party interop and independent project identity.
No Phase 1 or Panel work is authorized by this context. Obsolete context is replaced,
not appended as dated session history.

## File Audit

- Original Phase 0 added files: **80**, exact Git untracked inventory captured before edits.
- Final Phase 0 added files: **88**; tracked changed files: **1** (`README.md`).
- Final combined added/changed scope relative to HEAD: **89 files**.
- This finalization changes 45 existing Phase 0 files (44 Markdown metadata/edits
  and OpenAPI metadata), adds 8 documents and changes the tracked README: **54 touched files**.
- The remaining 35 original generated evidence files are unchanged.
- Original roles: Canonical 40 / Historical 5 / Generated 35 / Draft 0.
- Final roles: Canonical 48 / Historical 6 / Generated 35 / Draft 0.
- Keep: **79**; Merge: **1**; Rename: **0**; Remove: **0**.

`Merge` here means consolidating duplicate endpoint reference content into its
existing OpenAPI authority while keeping the API semantics document. It does not
delete a file. No valuable evidence was removed merely to lower the count.

Eight actual new documents:

- [docs/DEVELOPMENT_CONTEXT.md](../DEVELOPMENT_CONTEXT.md)
- [docs/DOCUMENTATION_POLICY.md](../DOCUMENTATION_POLICY.md)
- [docs/README.md](../README.md)
- [docs/api/README.md](../api/README.md)
- [docs/architecture/README.md](../architecture/README.md)
- [docs/development/README.md](../development/README.md)
- [docs/protocol/README.md](../protocol/README.md)
- [docs/reports/PHASE_0_DOCUMENTATION_FINALIZATION_REPORT.md](PHASE_0_DOCUMENTATION_FINALIZATION_REPORT.md)

Individual audit of every original file follows. Canonical lifecycle follows
owned design/code changes; Historical freezes; Generated remains the immutable
identified capture. Current validation outputs and tools stay outside the repo.

| # | Original file | Action | Role | Owner | Lifecycle | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | [NOTICE.md](../../NOTICE.md) | Keep | Canonical | Project maintainers | Update with owned design/code | Independent derivative identity, attribution and non-affiliation. |
| 2 | [docs/ARCHITECTURE.md](../ARCHITECTURE.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Overall boundaries, dependency direction, invariants and implementation gates. |
| 3 | [docs/PHASE_0_ARCHITECTURE_REPORT.md](../PHASE_0_ARCHITECTURE_REPORT.md) | Keep | Historical | Project maintainers | Frozen; corrections only | Original Phase 0 acceptance snapshot, including its original file count and validation scope. Retain original body as a frozen source/acceptance snapshot. |
| 4 | [docs/PHASE_0_REQUIREMENTS.md](../PHASE_0_REQUIREMENTS.md) | Keep | Historical | Project maintainers | Frozen; corrections only | Traceability to the original Phase 0 brief; not a live backlog. Retain original body as a frozen source/acceptance snapshot. |
| 5 | [docs/UPSTREAM.md](../UPSTREAM.md) | Keep | Canonical | Upstream maintainers | Update with owned design/code | Current baseline provenance, history policy and independent project identity. |
| 6 | [docs/adr/0001-upstream-baseline.md](../adr/0001-upstream-baseline.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Upstream stable baseline: distinct durable decision and alternatives; do not merge into specification prose. |
| 7 | [docs/adr/0002-product-identity.md](../adr/0002-product-identity.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Independent product and gradual namespace: distinct durable decision and alternatives; do not merge into specification prose. |
| 8 | [docs/adr/0003-domain-state-authority.md](../adr/0003-domain-state-authority.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Single domain state authority: distinct durable decision and alternatives; do not merge into specification prose. |
| 9 | [docs/adr/0004-account-binding-credential.md](../adr/0004-account-binding-credential.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Account, Binding and Credential separation: distinct durable decision and alternatives; do not merge into specification prose. |
| 10 | [docs/adr/0005-protocol-engine-separation.md](../adr/0005-protocol-engine-separation.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Protocol and Engine separation: distinct durable decision and alternatives; do not merge into specification prose. |
| 11 | [docs/adr/0006-client-profile-exporter.md](../adr/0006-client-profile-exporter.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Canonical ClientProfile and exporters: distinct durable decision and alternatives; do not merge into specification prose. |
| 12 | [docs/adr/0007-storage-strategy.md](../adr/0007-storage-strategy.md) | Keep | Canonical | Core maintainers | Decision events / supersession | SQLite WAL and driver qualification: distinct durable decision and alternatives; do not merge into specification prose. |
| 13 | [docs/adr/0008-api-boundary.md](../adr/0008-api-boundary.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Application services and local API boundary: distinct durable decision and alternatives; do not merge into specification prose. |
| 14 | [docs/adr/0009-xray-compatibility-engine.md](../adr/0009-xray-compatibility-engine.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Internal Xray compatibility engine: distinct durable decision and alternatives; do not merge into specification prose. |
| 15 | [docs/adr/0010-mieru-integration-strategy.md](../adr/0010-mieru-integration-strategy.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Mieru reference to native embedding: distinct durable decision and alternatives; do not merge into specification prose. |
| 16 | [docs/adr/0011-upstream-sync-strategy.md](../adr/0011-upstream-sync-strategy.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Stable mergeability and drift control: distinct durable decision and alternatives; do not merge into specification prose. |
| 17 | [docs/adr/0012-versioning-model.md](../adr/0012-versioning-model.md) | Keep | Canonical | Core maintainers | Decision events / supersession | Independent product/schema/API identities: distinct durable decision and alternatives; do not merge into specification prose. |
| 18 | [docs/adr/README.md](../adr/README.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Decision navigation, individual decision status and review lifecycle. |
| 19 | [docs/api/API_V1_DESIGN.md](../api/API_V1_DESIGN.md) | Merge | Canonical | API maintainers | Update with owned design/code | Remove duplicate manual endpoint table; surface authority remains OpenAPI. Retain transport/security/read/mutation semantics; no route changed. |
| 20 | [docs/api/openapi-skeleton.yaml](../api/openapi-skeleton.yaml) | Keep | Canonical | API maintainers | Update with API surface | Substantive proposed machine contract, 13 operations and schemas; keep skeleton name and add metadata without changing surface. |
| 21 | [docs/architecture/CLIENT_COMPATIBILITY.md](../architecture/CLIENT_COMPATIBILITY.md) | Keep | Canonical | Client maintainers | Update with owned design/code | ClientProfile projection, exporter responsibility and client/version checks. |
| 22 | [docs/architecture/CONFIG_STATE_AUTHORITY.md](../architecture/CONFIG_STATE_AUTHORITY.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Bootstrap, import-command and committed-domain authority boundaries. |
| 23 | [docs/architecture/DATABASE_ERD.md](../architecture/DATABASE_ERD.md) | Keep | Canonical | Storage / Core maintainers | Update with owned design/code | Logical entities, relationships, ownership and constraints; not schema migration history. |
| 24 | [docs/architecture/DIAGNOSTICS.md](../architecture/DIAGNOSTICS.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Proposed diagnostic command semantics and bounded redacted local bundles. |
| 25 | [docs/architecture/DOMAIN_MODEL.md](../architecture/DOMAIN_MODEL.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Entity meaning, authorization relationships and identity/secret separation. |
| 26 | [docs/architecture/ENGINE_MODEL.md](../architecture/ENGINE_MODEL.md) | Keep | Canonical | Engine maintainers | Update with owned design/code | Private native/compatibility execution contracts and enforcement limits. |
| 27 | [docs/architecture/FORK_BOUNDARY.md](../architecture/FORK_BOUNDARY.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Namespace, composition, adapters and product command transition strategy. |
| 28 | [docs/architecture/LICENSE_BOUNDARIES.md](../architecture/LICENSE_BOUNDARIES.md) | Keep | Canonical | Project maintainers | Update with owned design/code | Attribution, third-party provenance and future distribution review boundaries. |
| 29 | [docs/architecture/MIERU_INTEGRATION.md](../architecture/MIERU_INTEGRATION.md) | Keep | Canonical | Protocol maintainers | Update with owned design/code | Pinned Mieru API research and staged native integration qualification. |
| 30 | [docs/architecture/NATIVE_PROTOCOL_GUIDELINES.md](../architecture/NATIVE_PROTOCOL_GUIDELINES.md) | Keep | Canonical | Protocol maintainers | Update with owned design/code | Future wire specification, independent reference, security and qualification rules. |
| 31 | [docs/architecture/POLICY_USAGE.md](../architecture/POLICY_USAGE.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Unified payload accounting, quota/rate, reset and crash uncertainty semantics. |
| 32 | [docs/architecture/PROTOCOL_SDK.md](../architecture/PROTOCOL_SDK.md) | Keep | Canonical | Protocol maintainers | Update with owned design/code | Proposed protocol ports, compiled registry and effective capabilities. |
| 33 | [docs/architecture/RUNTIME_LIFECYCLE.md](../architecture/RUNTIME_LIFECYCLE.md) | Keep | Canonical | Core / Engine maintainers | Update with owned design/code | Startup, admission, shutdown, recovery and future child ownership. |
| 34 | [docs/architecture/SECURITY_BOUNDARIES.md](../architecture/SECURITY_BOUNDARIES.md) | Keep | Canonical | Security maintainers | Update with owned design/code | Secret handling, transport authorization, imports, files and executable trust. |
| 35 | [docs/architecture/STORAGE_MODEL.md](../architecture/STORAGE_MODEL.md) | Keep | Canonical | Storage maintainers | Update with owned design/code | Driver qualification, durability, migration mechanics, backup and corruption recovery. |
| 36 | [docs/architecture/SUBSCRIPTION_MODEL.md](../architecture/SUBSCRIPTION_MODEL.md) | Keep | Canonical | Client / Core maintainers | Update with owned design/code | Export-access scope, token lifecycle and authorized profile selection. |
| 37 | [docs/architecture/TRANSACTION_MODEL.md](../architecture/TRANSACTION_MODEL.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Journal, generation fences, runtime compensation, idempotency and audit. |
| 38 | [docs/architecture/UPSTREAM_ARCHITECTURE_MAP.md](../architecture/UPSTREAM_ARCHITECTURE_MAP.md) | Keep | Historical | Upstream maintainers | Frozen; corrections only | Source observations pinned to sing-box v1.14.1 and its full commit. Retain original body as a frozen source/acceptance snapshot. |
| 39 | [docs/architecture/UPSTREAM_BASELINE.md](../architecture/UPSTREAM_BASELINE.md) | Keep | Historical | Upstream maintainers | Frozen; corrections only | Phase 0 baseline commands, toolchains and observed scoped results. Retain original body as a frozen source/acceptance snapshot. |
| 40 | [docs/architecture/UPSTREAM_SYNC.md](../architecture/UPSTREAM_SYNC.md) | Keep | Canonical | Upstream maintainers | Update with owned design/code | Stable candidate review, merge/selective port, drift control and qualification. |
| 41 | [docs/architecture/VERSION_MODEL.md](../architecture/VERSION_MODEL.md) | Keep | Canonical | Core maintainers | Update with owned design/code | Independent product, build, schema, API and client-qualification identities. |
| 42 | [docs/architecture/evidence/README.md](../architecture/evidence/README.md) | Keep | Historical | Validation maintainers | Frozen; corrections only | Historical capture provenance and limitations; add only metadata and factual clarification of 6 empty outputs, preserving bytes/names. |
| 43 | [docs/architecture/evidence/SHA256SUMS.json](../architecture/evidence/SHA256SUMS.json) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Integrity of 21 original log artifacts, including 6 zero-byte captures; never replace with current hashes. |
| 44 | [docs/architecture/evidence/baseline-build-ci.log.gz](../architecture/evidence/baseline-build-ci.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original upstream build transcript at this named attempt/platform/tag set; retained for provenance. |
| 45 | [docs/architecture/evidence/baseline-build-minimal.log.gz](../architecture/evidence/baseline-build-minimal.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original upstream build transcript at this named attempt/platform/tag set; retained for provenance. |
| 46 | [docs/architecture/evidence/baseline-build-windows.log.gz](../architecture/evidence/baseline-build-windows.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original upstream build transcript at this named attempt/platform/tag set; retained for provenance. |
| 47 | [docs/architecture/evidence/baseline-format.log.gz](../architecture/evidence/baseline-format.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Zero-byte command-output capture, not a valid gzip stream or design placeholder; retain with exit ledger and checksum. |
| 48 | [docs/architecture/evidence/baseline-lint.log.gz](../architecture/evidence/baseline-lint.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Configured lint output; byte-identical attempts corroborated by separate exit labels, not redundant specifications. |
| 49 | [docs/architecture/evidence/baseline-linux-build.log.gz](../architecture/evidence/baseline-linux-build.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original upstream build transcript at this named attempt/platform/tag set; retained for provenance. |
| 50 | [docs/architecture/evidence/baseline-linux-qualified-env-test.log.gz](../architecture/evidence/baseline-linux-qualified-env-test.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Successful complete Linux CI retry in qualified environment; preserve separately from failed constrained attempt. |
| 51 | [docs/architecture/evidence/baseline-linux-test.log.gz](../architecture/evidence/baseline-linux-test.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Failed initial constrained Linux CI transcript; preserves environment/tool failures before retry. |
| 52 | [docs/architecture/evidence/baseline-test-ci.log.gz](../architecture/evidence/baseline-test-ci.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Windows complete root CI transcript with integration failures; initial/post-doc attempts retain chronology. |
| 53 | [docs/architecture/evidence/baseline-test-without-integration.log.gz](../architecture/evidence/baseline-test-without-integration.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Windows supplementary test transcript with explicit TestIntegration exclusion; distinct evidence, not full CI success. |
| 54 | [docs/architecture/evidence/baseline-vet.log.gz](../architecture/evidence/baseline-vet.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Supplementary vet findings; byte-identical before/after outputs corroborate unchanged baseline limitations. |
| 55 | [docs/architecture/evidence/diff-check.txt](../architecture/evidence/diff-check.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original inclusive whitespace gate outcome, not a current finalization check. |
| 56 | [docs/architecture/evidence/diff-stat.txt](../architecture/evidence/diff-stat.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original 80-file / 4,590-insertion review snapshot; preserve historic count. |
| 57 | [docs/architecture/evidence/document-check.log](../architecture/evidence/document-check.log) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original docs/OpenAPI/167-link/38-answer gate result; not current CI status. |
| 58 | [docs/architecture/evidence/git-verification.json](../architecture/evidence/git-verification.json) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original branch, source, remotes and unstaged-state evidence. |
| 59 | [docs/architecture/evidence/go-env.json](../architecture/evidence/go-env.json) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original Windows environment/build context; non-secret paths explain observed scope. |
| 60 | [docs/architecture/evidence/go-version.txt](../architecture/evidence/go-version.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original Windows compiler identity, used with the environment ledger. |
| 61 | [docs/architecture/evidence/linux-go-env.json](../architecture/evidence/linux-go-env.json) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original isolated Linux compiler/environment context. |
| 62 | [docs/architecture/evidence/linux-go-version.txt](../architecture/evidence/linux-go-version.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Original isolated Linux compiler identity. |
| 63 | [docs/architecture/evidence/linux-image.txt](../architecture/evidence/linux-image.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Exact Linux image digest; distinct from compiler identity. |
| 64 | [docs/architecture/evidence/linux-qualified-env-results.txt](../architecture/evidence/linux-qualified-env-results.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Exit ledger of successful complete Linux root CI retry. |
| 65 | [docs/architecture/evidence/linux-results.txt](../architecture/evidence/linux-results.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Initial restricted Linux build/test exits, including failure; not overwritten by retry. |
| 66 | [docs/architecture/evidence/post-doc-build-ci.log.gz](../architecture/evidence/post-doc-build-ci.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Zero-byte command-output capture, not a valid gzip stream or design placeholder; retain with exit ledger and checksum. |
| 67 | [docs/architecture/evidence/post-doc-build-minimal.log.gz](../architecture/evidence/post-doc-build-minimal.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Zero-byte command-output capture, not a valid gzip stream or design placeholder; retain with exit ledger and checksum. |
| 68 | [docs/architecture/evidence/post-doc-build-windows.log.gz](../architecture/evidence/post-doc-build-windows.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Zero-byte command-output capture, not a valid gzip stream or design placeholder; retain with exit ledger and checksum. |
| 69 | [docs/architecture/evidence/post-doc-format.log.gz](../architecture/evidence/post-doc-format.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Zero-byte command-output capture, not a valid gzip stream or design placeholder; retain with exit ledger and checksum. |
| 70 | [docs/architecture/evidence/post-doc-lint.log.gz](../architecture/evidence/post-doc-lint.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Configured lint output; byte-identical attempts corroborated by separate exit labels, not redundant specifications. |
| 71 | [docs/architecture/evidence/post-doc-linux-build.log.gz](../architecture/evidence/post-doc-linux-build.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Zero-byte command-output capture, not a valid gzip stream or design placeholder; retain with exit ledger and checksum. |
| 72 | [docs/architecture/evidence/post-doc-linux-results.txt](../architecture/evidence/post-doc-linux-results.txt) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Post-document Linux exit ledger; supports the empty build capture. |
| 73 | [docs/architecture/evidence/post-doc-linux-test.log.gz](../architecture/evidence/post-doc-linux-test.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Post-document complete Linux root CI transcript; distinct successful verification attempt. |
| 74 | [docs/architecture/evidence/post-doc-test-ci.log.gz](../architecture/evidence/post-doc-test-ci.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Windows complete root CI transcript with integration failures; initial/post-doc attempts retain chronology. |
| 75 | [docs/architecture/evidence/post-doc-test-without-integration.log.gz](../architecture/evidence/post-doc-test-without-integration.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Windows supplementary test transcript with explicit TestIntegration exclusion; distinct evidence, not full CI success. |
| 76 | [docs/architecture/evidence/post-doc-vet.log.gz](../architecture/evidence/post-doc-vet.log.gz) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Supplementary vet findings; byte-identical before/after outputs corroborate unchanged baseline limitations. |
| 77 | [docs/architecture/evidence/results.jsonl](../architecture/evidence/results.jsonl) | Keep | Generated | Validation maintainers | Immutable Phase 0 capture | Windows invocations, attempt labels, exit codes and tool identity; supports empty output captures. |
| 78 | [docs/integration/NOBRAND_MIGRATION.md](../integration/NOBRAND_MIGRATION.md) | Keep | Canonical | Integration maintainers | Update with owned design/code | Future NoBrand import, rollout, field-test and rollback boundaries. |
| 79 | [docs/testing/INTEROP_MATRIX.md](../testing/INTEROP_MATRIX.md) | Keep | Canonical | Test maintainers | Update with owned design/code | Planned third-party protocol/client qualification cells and evidence rules. |
| 80 | [docs/testing/TEST_STRATEGY.md](../testing/TEST_STRATEGY.md) | Keep | Canonical | Test maintainers | Update with owned design/code | Meaningful implementation/interop/failure gates and reporting scope. |

## Duplicate Content Audit

| Coverage examined | Resolution / intentional overlap |
| --- | --- |
| API endpoint table vs OpenAPI | Removed the manual table; linked OpenAPI. Paths/methods/parameters/schemas/responses are unchanged; semantics remain Markdown. |
| Overview reading guide vs master navigation | Replaced exhaustive overview link list with focused indexes. Docs index owns complete navigation; architecture map routes changes by owner. |
| Domain vs ERD | Domain owns meaning/authorization; ERD owns logical persistence relationships/constraints. No full SQL duplication. |
| Storage vs ERD vs transaction | Clarified scope in both storage/ERD. Storage owns durability/backup/migration mechanics; coordinator owns runtime effects/recovery. |
| Protocol vs Engine vs client specs | Distinct source contracts; repeated short invariants prevent boundary leakage, not three copies of an interface. |
| Mieru research vs ADR 0010 | Roadmap owns pinned API details/stages; ADR owns why staged native embedding is preferred. |
| Policy vs API/security/runtime | Policy owns accounting/enforcement semantics; other documents state relevant guarantees and limits at their own boundary. |
| Reports vs current specs | Intentional frozen acceptance overlap; reports are labeled Historical and do not become the live architecture authority. |
| Requirement traceability | Frozen original brief mapping, not a competing current specification or backlog. |
| Evidence before/after logs | Separate attempt/provenance records. Identical lint/vet payloads corroborate stable results; they are not duplicate canonical prose. |
| Empty captures | Six zero-byte outputs retain original names/bytes/checksums and separate exit ledgers; not design skeletons or valid gzip streams. |
| OpenAPI skeleton | Substantive 13-operation design with schemas/ref validation; filename does not make it an empty placeholder. |
| Architecture/API/protocol/development indexes | Different navigation responsibilities, each points to real maintained content; no duplicate specification bodies. |
| NOTICE vs homepage/provenance | Short attribution repeated at relevant entry/distribution boundaries; preserved license text lives in LICENSE. |

No empty owned Markdown specs or runtime package skeletons were found.
Existing upstream skeletons/templates were not part of the owned-document audit.

## Links

PASS — 462 local links across 53 Markdown documents; README 15, docs index 44, ADR documents/index 26.

- Root README, docs index, focused indexes, ADRs, source citations and historical
  report inventories are included. Relative targets and supplied fragments are checked.
- Every one of the 89 owned added/changed artifacts is reachable from root README.
- OpenAPI 3.1 references resolve; all 13 operation IDs are unique.
- Local links only: external sites are preserved source citations, not a live URL availability audit.
- Inherited upstream documentation links/site build are outside this owned-document gate.

## Runtime

**Runtime Changes: NONE.** No Go/protocol/option/network/route/transport source,
go.mod/go.sum, workflow, build behavior, package path, LICENSE or service asset
changed. The only tracked modification is the explicitly requested root README.
All 88 additions are Splicore documentation/NOTICE. No new feature was implemented.

## Validation

| Gate | Outcome and scope |
| --- | --- |
| Upstream normal build | **PASS**, exit 0; go version go1.26.2 windows/amd64, CGO=0, GOTOOLCHAIN=local. Makefile build-equivalent default tags/linker flags and pinned v1.14.1; output in temporary storage. |
| Documentation metadata and classification | 53 Markdown docs; 47 Canonical / 6 Historical; one Canonical machine contract; all have owner/audience/responsibility/lifecycle/review date. |
| README claim review | Early architecture status, planned table, non-affiliation and GPL wording checked; no fake install/release or feature support claims. |
| Local Markdown / links / navigation | PASS — 462 local links across 53 Markdown documents; README 15, docs index 44, ADR documents/index 26. |
| OpenAPI | Standard OpenAPI 3.1 validator **0.7.2**; 13 operations, unique IDs, refs and Account read redaction checked. Surface structurally identical to original; only vendor documentation metadata added. |
| ADRs / original traceability | 12 unchanged decision bodies and statuses; original report answers 1–38 intact. |
| Frozen evidence integrity | 35 generated files unchanged; all 21 manifest hashes verified; 15 valid gzip captures decoded, 6 zero-byte output captures identified. |
| Historical text integrity | Four snapshot bodies unchanged after metadata removal; evidence README correction explicitly labeled. |
| Protected tracked source / Git scope | PASS — real index hash and all refs/remotes unchanged; protected tracked source equals HEAD. |
| git diff --check | PASS: tracked HEAD diff exit 0; 88 additions checked against an empty directory with no-index diff (exit 1 means expected file differences), no whitespace diagnostics; no index mutation. |
| Expensive root integration / optional suites | Not rerun for documentation changes; prior scoped PASS/FAIL/NOT RUN results remain unchanged and visible. |

Build translation (actual tags/linker content is read from unchanged upstream files):

```powershell
$env:CGO_ENABLED = '0'
$env:GOTOOLCHAIN = 'local'
$buildTags = (Get-Content release/DEFAULT_BUILD_TAGS_OTHERS -Raw).Trim()
$buildFlags = (Get-Content release/LDFLAGS -Raw).Trim() + ' -X github.com/sagernet/sing-box/constant.Version=1.14.1 -s -w -buildid='
go build -trimpath -tags $buildTags -ldflags $buildFlags -o <temporary-upstream-normal.exe> ./cmd/sing-box
```

Validation ran in a disposable `python:3.12-slim` container with read-only source
mount; `openapi-spec-validator==0.7.2` and `markdown-it-py==4.0.0` supplied standard
schema checking and CommonMark link parsing. No repository dependency changes.
Temporary scripts, original inventory/hashes, final audit data and command results
are under `C:/Users/admin/AppData/Local/Temp/splicore-doc-finalization-20261001`.
They are session verification aids; this completed report is the retained result.
Future contributors can repeat the documented checks in the development index;
there is no dedicated committed Splicore docs CI gate yet.

## Git

- Branch: `codex/phase-0-architecture`.
- HEAD / main / v1.14.1: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Sole remote: `upstream` → `https://github.com/SagerNet/sing-box.git`.
- Full history retained; shallow=false; no new origin/repository.
- Worktree: tracked README modified; 88 untracked additions; actual index unstaged.
- Commit: **NONE**. Push: **NONE**. New tag: **NONE**. Release: **NONE**.
- Ref/tag/remote state unchanged; inclusive validation uses tracked HEAD diff plus
  untracked no-index comparison against an empty directory. Real index is unchanged;
  no staging or temporary index modification was needed.

## Recommended Reading Order

1. [Project homepage](../../README.md).
2. [Technical navigation](../README.md).
3. [Current development constraints](../DEVELOPMENT_CONTEXT.md).
4. [Architecture overview](../ARCHITECTURE.md).
5. [Bounded specification map](../architecture/README.md) and relevant topic specs.
6. [Relevant decisions and alternatives](../adr/README.md).
7. [Documentation policy](../DOCUMENTATION_POLICY.md) and [development workflow](../development/README.md).
8. [Historical Phase 0 report](../PHASE_0_ARCHITECTURE_REPORT.md) and evidence when reviewing original acceptance scope.

## Remaining Documentation Problems

No blocking documentation problem for review. Explicit limits and future inputs:

- Eleven architecture ADRs remain proposed; organization has not accepted them.
- Runtime contracts, API and protocol qualification are designs, not implementations.
- Public repository/module ownership, secret-key provisioning and exact future
  FinalMask/Sudoku fork/spec/license provenance require later maintainer decisions.
- Empty historical `.log.gz` names remain misleading if read alone; their index
  and audit now identify all six accurately, with exit ledgers and unchanged hashes.
- No committed docs CI gate/site integration yet; local link/schema validation
  covers owned docs only. Upstream site config and remote URL availability were not audited.
- Historical Windows integration failures, supplementary vet findings and unrun
  optional/platform/interop suites remain qualification limits, not finalization failures.

These items do not require starting Phase 1 or changing runtime to finish this review.

## Final Result

**DOCUMENTATION READY FOR REVIEW**

README is a concise project entry; detailed designs, current context, durable
decisions and frozen history have explicit navigation, ownership and lifecycle.
Runtime Changes: **NONE**. Phase 1: **NOT STARTED**.
