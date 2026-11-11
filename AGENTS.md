# Development policy

- The only development baseline is the latest `origin/main`. Use one short-lived
  `codex/` feature branch directly from it. Never stack restoration branches or
  establish another integration/release mainline.
- Frozen tags are read-only references for comparison and minimal, attributable
  ports. Never merge the historical branch wholesale, rewrite published history,
  move release tags, reset main, or force-push.
- Only one feature restoration PR may await integration at a time. After its
  authorized merge, update main before starting the next restoration branch.
- Do not merge PRs or change repository protection without explicit authorization.
  Local hooks supplement, and cannot replace, GitHub branch protection.
- Use the maintainer-designated canonical checkout and auxiliary workspace. Do
  not clone another project checkout or create worktrees. Preserve historical
  branches, user changes, and existing worktree registrations.
- Run `scripts/dev/preflight.sh` (WSL/Git Bash) or
  `scripts/dev/preflight.ps1` (Windows) before development. Install the versioned
  hooks as described in `docs/DEVELOPMENT.md`. Inspect and preserve existing
  changes before explicitly using `--allow-dirty`.
- Keep private reports, credentials, logs, caches, binaries, and temporary output
  outside the source tree. Never commit local machine paths or private evidence.
- Preserve the single native binary, CGO-free builds, encrypted SQLite state,
  CLI, lifecycle/error semantics, and protected network underlays. Xray is an
  optional independent test peer, never a production dependency.
- Each restoration must cite its historical source and pass matching native
  Linux/Windows, lifecycle, negative security, and independent interoperability
  gates. Cross-compilation is build evidence only. Report unavailable tests as
  NOT EXECUTED; do not weaken assertions or permissions to obtain a pass.
- Keep Phase37, WAL candidate work, and unqualified Windows WireGuard hotfixes
  out of feature restoration PRs. WireGuard hotfix qualification remains
  NOT QUALIFIED until independently accepted.
