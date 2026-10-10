# Splicore Codex Instructions

Before any release, publication, version tag, GitHub Release, release asset or
lean public export task:

1. Read `docs/internal/RELEASE_PROCESS.md` in full before taking any release
   action. Do not proceed if it is unavailable.
2. Treat it as the release-process source of truth. Clear, deliberate instructions
   in the current maintainer request override its defaults.
3. Never infer official release targets from successful build or test coverage.
4. For public exports, classify `AGENTS.md` and `docs/internal/**` as
   `INTERNAL_MAINTENANCE` and `EXCLUDE`. A future file under `docs/internal/`
   may be included only after explicit reclassification; the release runbook
   and this instruction file remain excluded.
