# Documentation Policy

- Documentation status: Canonical
- Audience: All contributors and reviewers
- Last reviewed: 2026-10-01
- Owner: Documentation maintainers
- Responsibility: Documentation classification, ownership and change review rules.
- Lifecycle: Update when the documentation workflow or authority boundaries change.

## Classification and maturity

Every Splicore document declares documentation status, audience, review date,
owner, responsibility and lifecycle. Owners are maintainer roles, not invented
individual assignments. Use simple headers; machine contracts can use vendor
metadata and the project homepage can use a source comment.

| Documentation status | Meaning and lifecycle |
| --- | --- |
| Canonical | Current maintained specification or navigation for its bounded topic; changes with the design/code it owns. |
| Historical | Frozen phase, release or source-research snapshot; only typo, broken-link or factual corrections. |
| Draft | Incomplete candidate document; no authority until reviewed and explicitly promoted. |
| Generated | Captured or generated evidence; retain provenance and regenerate only as a new identified capture. |

Record design maturity separately: proposed, accepted, implemented and qualified
are different states. A **Canonical proposed design** does not certify a feature.
An ADR's `Status` section is decision status; its documentation metadata is
independent. Do not mark an ADR accepted solely because its document was organized.

Metadata added in this finalization labels old snapshots without changing their
recorded outcomes. A historical correction must explain the correction; new
architecture or test results belong in current specifications or a new report.

## Change rule

A significant change to architecture, domain, protocol interfaces, capabilities,
engines, API, storage, transaction semantics or security must include the relevant
canonical documentation update in the same review. Runtime changes also include
meaningful applicable verification. Update the overview if its boundaries or
invariants change; place details in the owning specification.

Use the [architecture map](architecture/README.md), [API index](api/README.md) and
[protocol index](protocol/README.md) to find the owner. Review cross-topic
consequences with affected maintainers. Changed documents must pass relative
link and whitespace checks; changed OpenAPI must pass schema/ref validation.

## ADR rule

Create an ADR for a durable decision with meaningful alternatives and rationale
future maintainers will need. Small wording changes, routine fixes, navigation
and metadata do not each require an ADR. Keep context, decision, alternatives,
consequences and review triggers. Maintainers explicitly accept or reject proposals.

When replacing an accepted decision, create a new numbered ADR, link it from the
old record and mark the old decision superseded. Preserve the old rationale;
keep the [ADR index](adr/README.md) synchronized. Specifications own detailed
contracts; ADRs own why a durable choice was made.

## Authority boundaries

| Topic | Maintained authority | Other documents |
| --- | --- | --- |
| Project introduction | Root [README](../README.md) | Concise status, goals and links only. |
| Navigation | [docs index](README.md) | Focused indexes route readers; no copied specifications. |
| Architecture | [overview](ARCHITECTURE.md) and bounded specifications | Overview states dependency rules; topic documents own details. |
| API surface | [OpenAPI](api/openapi-skeleton.yaml) | Owns paths/methods/schemas/parameters/responses; Markdown owns transport, security, semantics and future scope. |
| Database structure | [ERD](architecture/DATABASE_ERD.md) | Owns entities/relationships/ownership; storage owns durability/operations; future migrations own actual schema history. |
| Protocol contracts | [Protocol SDK](architecture/PROTOCOL_SDK.md) | Engines own execution; client docs own profiles/exporters; interop matrix owns qualification coverage. |
| Current constraints | [development context](DEVELOPMENT_CONTEXT.md) | Replace obsolete context; never append a session diary. |
| Acceptance history | Completed reports and captured evidence | Frozen results, explicitly scoped to capture time and source. |

OpenAPI is already the machine authority for the **proposed** API surface. Future
implementation must maintain it as the implementation contract. Do not maintain
a second manual endpoint reference or add endpoints only in Markdown.
Examples explain semantics and do not create additional routes.

Avoid copying full SQL/schema/interface definitions across README, overview,
storage, ERD and reports. Short invariant summaries, ADR rationale and frozen
historical snapshots may intentionally overlap; link to maintained details.

## Files and navigation

Keep bounded existing specifications in `architecture/`. The `protocol/` index
can point there; move files only when ownership/navigation benefits justify
updating every link. No empty package, phase, report or protocol placeholders.
New completed reports use `reports/`. Keep useful evidence with source, toolchain,
invocation and outcome; do not replace old output with a new run.

Preserve inherited sing-box documentation, source names, licensing and headers.
Splicore documents do not redefine upstream product documentation. Update root
and docs links whenever navigation changes.

## Review checklist

- The claim's design/implementation/qualification state is clear.
- The owning specification changed; overlapping summaries still agree.
- An ADR is included when a durable choice warrants one.
- OpenAPI or ERD/migrations changed when their owned contract changed.
- Metadata, local links and inclusive whitespace checks pass.
- Historical results and upstream docs retain their original scope.

See the [development workflow](development/README.md) for current boundaries
and validation instructions.

## Phase 21 Core scope normalization

[Core scope](architecture/CORE_SCOPE.md) is authoritative. Inherited sing-box
manuals/translations outside the owned Splicore documentation catalog are historical
reference documents, not current Splicore product contracts. They are excluded from
the current navigation. Frozen reports and ADR rationale remain byte-preserved.
