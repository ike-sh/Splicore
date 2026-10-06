# ADR 0038 — Remove sing-box / SagerNet Core Dependency Graph

- Status: Accepted
- Date: 2026-10-06
- Scope: Phase 17 Independent Core Decoupling

## Context

The user superseded the Phase 16 Freeze prerequisite and authorized migration
of the preserved, unstaged Phase 16 worktree. The existing managed protocol
capabilities and internal regression suite must survive. The inherited module
identity, runtime constructors and SagerNet network/protocol dependencies do
not satisfy the required independent-core architecture.

## Decision

Use module `github.com/ike-sh/Splicore`, with zero SagerNet imports or graph
nodes in production, tests or tooling. Prefer standard network/concurrency
types and narrow owned contracts. Own protocol framing/integration, credentials,
registries, underlay injection and resource lifetimes. Reuse independent mature
libraries for crypto, QUIC and the official gVisor TCP/IP stack; retain the
official Mieru SDK and make its owned integration visible in `protocol/mieru`.

Preserve existing protocols, wire semantics, Windows compilation and all
race/checkptr/security gates. Keep attribution. Do not copy the dependency tree,
rename its API, vendor a disguised fork, patch the module cache or use an
external core process. Keep minimum Go 1.26.3.

## Migration and evidence

Preserve Phase 16 before edits. Move module identity, then remove proven unused
inherited surfaces and migrate dependency families in the user-prescribed
sequence. Each step requires compilation and relevant tests before proceeding.
The final full audit must include transitive and separate test-module imports.

The module identity step is implemented. Unused App Store/mobile build tooling
and its asc-go/gomobile dependencies are removed. Unused CCM/OCM AI services,
AnyTLS, Cloudflared and Tor source/registrations/options and their five parent
requirements are also removed, without deleting tests. Remaining runtime dependency
migrations are incomplete. Audited OpenSnell v1.0.4 rejects v6; its public code
cannot substitute for the existing Snell v6 profile. An owned v6 implementation
requires a verified wire behavior contract and interoperability evidence before
removing sing-snell. The pinned sing-snell v6 source is readable as an authorized
reference and preliminary behavior notes have been recorded. The candidate
failure does not establish that an original owned rewrite is impossible.
This unresolved migration blocks readiness.

### Round 2 implementation update

The preceding paragraph records the initial candidate finding. Round 2 now has
owned Snell v5/v6 server and v4/v6 client wire, with pinned differential and
both-role reference evidence. SS/SS2022, HY2, TUIC, VLESS and Mieru use owned
integration and independent foundations. Dead inherited source was removed
after Linux/Windows production/test closure audits. SagerNet source imports,
direct requirements and full graph nodes are zero. Final lifecycle/stress gates
are recorded in the implementation report. At the Round 2 checkpoint this ADR
remained Proposed because Review/Freeze had not yet been authorized. The final
acceptance metadata below supersedes that historical status.

## Consequences

API/CLI/domain/storage behavior is preserved; no database migration is justified
by a module path change. Real external interoperability and resource/stress
gates must be rerun after runtime migration. No residual dependency may be
accepted through this ADR. Implementation and Final Independent Re-Review have
completed with no unresolved architecture blocker. The separately authorized
consolidated freeze permits one local forward commit. Publication is outside
that authorization.

## Evidence

- [Dependency architecture](../architecture/INDEPENDENT_CORE_DEPENDENCIES.md)
- [Phase 17 report](../reports/PHASE17_SINGBOX_DECOUPLING_REPORT.md)
- Preserved worktree: `D:/splicore-validation/phase16-pre-decoupling-20261006`
- Current audit: `D:/splicore-validation/phase17-core-decoupling-20261006`


## Acceptance — consolidated freeze

Accepted on 2026-10-07 (Asia/Shanghai) following Final Independent Re-Review PASS.
All seven findings are CLOSED, SagerNet imports/direct/graph/binary are 0/0/0/0,
and `protocol/mieru` is the owned integration boundary. The accepted migration
and review fixes are consolidated with Phase 16 in one local freeze commit.
Historical migration paragraphs above remain checkpoint records. Qualification
is NOT RE-RUN; the new freeze remains NOT REQUALIFIED. See the
[canonical freeze report](../reports/PHASE17_INDEPENDENT_CORE_FREEZE_REPORT.md).
