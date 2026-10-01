# Development Documentation

- Documentation status: Canonical
- Audience: Contributors, reviewers and returning coding agents
- Last reviewed: 2026-10-01
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

Phase 1 is frozen at `a2ca59e6dbf1a239feae5e471ec1914cae0f1eac`.
Phase 2 freezes experimental Snell on `codex/phase-2-snell-vertical-slice` and main.
Read [workflow](PHASE_2_SNELL.md) and [report](../reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md).

Phase 3 implements experimental HY2 on `codex/phase-3-hysteria2-vertical-slice`,
parent/main `5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`. Read
[HY2 workflow](PHASE_3_HYSTERIA2.md) and [report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).
No stage, commit, push, origin, tag or release. Upstream runtime sources and
historical reports remain unchanged; tools/binaries/logs/state stay external.
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
restriction. Phase 3 has its own implementation-only authorization; all changes
remain unstaged and unpublished until review.

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
