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

Phase 0 Freeze permits final documentation audit, explicit staging, one local
documentation commit, fast-forward of `main`, and creation of
`codex/phase-1-foundation` at that freeze commit. Stop after the new branch is
verified clean. Phase 1 implementation requires a separate prompt.

No runtime, protocol, option, network, route, transport, module, workflow or
build/service changes; no push, `origin`, new tag or release. The inherited
build verifies upstream source, not a Splicore binary. Individual proposed ADRs
remain proposed; freezing does not claim implemented or qualified functionality.

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
- Verify tracked changes are confined to README; additions belong to Splicore
  documentation/NOTICE. Compare protected tracked source to HEAD.

For the authorized freeze, explicitly stage the audited README/NOTICE/docs scope,
including approved archived Phase 0 evidence. Fresh logs, binaries, temporary
outputs, IDE state, secrets and caches are excluded. Check staged name/status,
stat, whitespace and content before the fixed-message commit. Confirm its single
parent is the pinned upstream baseline, fast-forward `main` without rewriting
history, then create the foundation branch and verify the clean tree. Existing
historical reports retain their original pre-commit state and evidence scope.

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
