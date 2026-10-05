# Development Documentation

- Documentation status: Canonical
- Audience: Contributors, reviewers and returning coding agents
- Last reviewed: 2026-10-02
- Owner: Project maintainers
- Responsibility: Recovery reading order, change workflow and scoped validation.
- Lifecycle: Update when development scope or required validation gates change.

## Recover context

1. [Project README](../../README.md): identity and maturity.
2. [Documentation index](../README.md): where each topic lives.
3. [Development context](../DEVELOPMENT_CONTEXT.md): baseline and constraints.
4. [Architecture overview](../ARCHITECTURE.md) and [specification map](../architecture/README.md).
5. Relevant [ADRs](../adr/README.md) and bounded specification.

Use completed reports to inspect historical decisions/evidence. The original
[Phase 0 report](../PHASE_0_ARCHITECTURE_REPORT.md) and
[finalization report](../reports/PHASE_0_DOCUMENTATION_FINALIZATION_REPORT.md)
are frozen acceptance snapshots, not growing development logs.

## Current scope

Current work is Phase 9 Distribution & Service Foundation on
`codex/phase-9-distribution-service-foundation`, at Phase 8 freeze
`bd141f98e28d9499a88fe610ba3fc49aca48bf14`. See [distribution](../DISTRIBUTION.md)
and [operations](../OPERATIONS.md). No stage/commit/push/tag/release. Historical
Phase 0–8 reports and migrations are immutable. Docker is not queried or touched;
NoBrand remains read-only. The entries below preserve earlier scoped workflows.

Phase 1 is frozen at `a2ca59e6dbf1a239feae5e471ec1914cae0f1eac`.
Phase 2 froze experimental Snell at `5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`.
Read [workflow](PHASE_2_SNELL.md) and [report](../reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md).

Phase 3 froze experimental HY2 at `94555d9608ebcc36c5a396bc06a5743cce4e0788`. Read
[HY2 workflow](PHASE_3_HYSTERIA2.md) and [report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).
Phase 4 is locally frozen at `2a9c0f3e14de29050c1228ce013b2f1ad4556946`; main and
HEAD remain there. `codex/phase-5-vless-reality-vertical-slice` has an unstaged
native VLESS/REALITY candidate. Vision is deferred/unsupported; flow-none acceptance is separate.
No stage/commit/push/tag/release. Upstream runtime sources and historical Phase
0–4 reports remain unchanged; tools/binaries/logs/state stay external.
Foundation composition remains for independent placeholder contract tests.

## Change workflow

Find the owning document through the indexes; update its canonical specification,
cross-topic consequences and navigation. Use [documentation policy](../DOCUMENTATION_POLICY.md)
to decide whether an ADR is warranted. Preserve history and upstream documents.
Keep proposals, implementation facts and client evidence distinct. Significant
future code changes require their canonical docs in the same review.

## Validation for documentation changes

- Inspect `git status`, branch/HEAD/remotes and staged changes before and after.
- Check every owned Markdown relative link, including fragments, and metadata.
- Validate OpenAPI 3.1 with pinned `openapi-spec-validator==0.7.2`; check refs,
  operation IDs and redacted read schemas. No root dependency change is needed.
- Build the retained upstream command with its actual default tags/linker flags.
- Run `git diff HEAD --check` for tracked edits and `git diff --no-index --check`
  against an empty directory for a temporary snapshot of untracked additions.
  The latter returns 1 for differing files; require no whitespace diagnostics.
  Verify the real index hash is unchanged. No staging is needed.
- Verify source changes are confined to new Splicore code/scripts, dependencies
  and canonical docs. Compare protected upstream runtime and historical files to HEAD.

The completed Phase 0 freeze included approved archived evidence and has the
pinned upstream commit as its sole parent. Phase 1 preserves those bytes and
keeps fresh logs/binaries/tools outside the repository. The Phase 1 freeze
instruction supersedes the implementation-only staging/commit restriction.
The Phase 2 freeze request supersedes its implementation-only staging/commit
restriction. Phase 3 and Phase 4 freeze requests supersede their respective
implementation-only staging/commit restrictions. Phase 4 allows one reviewed
commit, main fast-forward and a reserved Phase 5 branch, then requires stopping.

For Windows, the normal build's PowerShell translation is:

```powershell
$env:GOTOOLCHAIN = 'local'
$env:CGO_ENABLED = '0'
$buildTags = (Get-Content release/DEFAULT_BUILD_TAGS_OTHERS -Raw).Trim()
$buildFlags = (Get-Content release/LDFLAGS -Raw).Trim() + ' -X github.com/sagernet/sing-box/constant.Version=1.14.1 -s -w -buildid='
go build -trimpath -tags $buildTags -ldflags $buildFlags -o "$env:TEMP/splicore-upstream-review.exe" ./cmd/sing-box
```

This pins the verified baseline instead of invoking Makefile's mutable version
helper. It preserves build behavior and writes the upstream executable outside
the repository; it is not a Splicore install or release command.

Python and the validator can run in a disposable container with a read-only
source mount. Tools, binaries and fresh raw outputs belong outside the repository;
put scoped acceptance results in a completed report. The original
[evidence](../architecture/evidence/README.md) contains prior Phase 0 results only.

Do not rerun expensive root integrations solely for doc edits. Prior Windows
integration failures and additional vet findings stay visible in the
[baseline ledger](../architecture/UPSTREAM_BASELINE.md). Broader implementation
gates belong to the [test strategy](../testing/TEST_STRATEGY.md).

## Phase 4

[TUIC workflow](PHASE_4_TUIC.md) defines native/shared campaign and local freeze
gates. Fresh freeze evidence is external at `D:\splicore-validation\phase4-freeze-20261001`.
The frozen profile remains Experimental; further implementation requires new scope.

## Current Phase 5

[Workflow](PHASE_5_VLESS.md), [support](../protocol/VLESS.md) and [report](../reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md)
own the frozen native flow-none VLESS/REALITY scope and Vision rejection gates.
Subsequent checkpoints follow their explicit freeze authorization; push/tag/release remain NONE.

- [Phase 7 Xray extensions](PHASE_7_XRAY_EXTENSIONS.md): managed FinalMask/Sudoku contract, acceptance and limits.
- [Phase 7 freeze](../reports/PHASE_7_FREEZE_REPORT.md): local checkpoint and clean Phase 8 baseline; current Mieru work follows the Phase 8 workflow.

## Phase 8 qualification

[Mieru workflow](PHASE_8_MIERU.md) covers source/license audit, default race, native ten cycles, managed clients and protected evidence.

[Phase 8 freeze](../reports/PHASE_8_FREEZE_REPORT.md) is the current local checkpoint.
Phase 9 distribution and service is locally frozen under the
[freeze report](../reports/PHASE_9_FREEZE_REPORT.md).
See the [distribution gate](../DISTRIBUTION.md) and
[acceptance report](../reports/PHASE_9_DISTRIBUTION_SERVICE_FOUNDATION_REPORT.md).
The clean `codex/phase-10-client-runtime-foundation` branch starts there;
client implementation is not started. NoBrand migration remains deferred until
the unified client/server core is complete.

## Current architecture correction

Native is the sole runtime engine. Historical Phase 6/7 direction is superseded; FinalMask/Sudoku are out of scope.

- [Decision](../adr/0035-xray-runtime-removed-from-core.md)
- [Correction report](../reports/ARCHITECTURE_CORRECTION_XRAY_BOUNDARY_REPORT.md)

## Phase 15 unified core hardening

[Hardening inventory](PHASE_15_HARDENING_INVENTORY.md) records resource ownership,
lock ordering, lifecycle fixes and crash/recovery validation. The
[Phase 15 freeze report](../reports/PHASE_15_FREEZE_REPORT.md) records the local
checkpoint; real platform qualification requires later scope.

## Qualification Fix / Native TUN freeze

The [Qualification Fix freeze report](../reports/QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md)
records the forward candidate after maintainer review. QF-001/QF-002/QF-003 and
the owned Native TUN runtime are included. Requalification must use the new
frozen commit; this workflow does not resume it or start a new feature phase.
