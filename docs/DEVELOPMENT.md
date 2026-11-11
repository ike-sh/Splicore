# Development from main

Use the maintainer's canonical checkout. Install local guards once from that
checkout (Python 3.9+ and Git are required):

```sh
git config --local splicore.canonicalRoot "$(pwd -P)"
git config --local core.hooksPath .githooks
git fetch origin
git switch -c codex/restore-feature origin/main
scripts/dev/preflight.sh
```

On Windows PowerShell, use `(Get-Location).Path` for `splicore.canonicalRoot` and
run `scripts/dev/preflight.ps1`. The path is local Git configuration, never a
public machine-specific policy. Windows drive paths and their WSL mount paths
refer to the same checkout; path case is ignored for Windows volumes.
The PowerShell entry can use WSL Python when native Python is unavailable.
Git for Windows hooks can also use WSL Python when native Python is absent;
the outgoing-ref input is preserved. WSL Git uses WSL Python directly.

Preflight verifies the repository identity, origin, branch ancestry, immutable
release commits, worktree inventory, pending restoration PRs, and clean status.
After integration, `scripts/dev/preflight.sh --verify-main` (PowerShell:
`-VerifyMain`) checks clean main against exact origin/main without authorizing
development, commit or push operations on main.
It requires an authenticated `gh` or `gh.exe`; network/authentication failures
stop the check. Inspect and preserve existing changes before using
`--allow-dirty` (`-AllowDirty` in PowerShell). This option acknowledges dirty
state only; it does not bypass path, ancestry, PR, or content checks. A stale
registration for a nonexistent worktree is reported without deleting it.

The pre-commit hook checks staged paths and content. Pre-push checks the actual
destination and every outgoing ref and commit, including files added and later
removed. Push only the current `codex/` branch to `origin`, then open a PR with
base `main`. Direct main/release/tag pushes, other remotes, stacked or outdated
branches, private reports, build artifacts, and recognizable secrets reject.
Only one main integration PR may be open; finish integration before the next branch.

Formal development starts from main and returns to main after integration.
Review the complete historical feature inventory before every release; publishing
a version does not close an unresolved feature gap. Delete completed temporary
branches safely after integration. Valuable unadmitted historical work requires
a verified Git bundle, SHA256, original ref/commit, and a recorded qualification
blocker before retiring its active branch. Never move a published release tag.
AmneziaWG / Phase37 is retired; standard WireGuard is a separate endpoint.
WAL/P1-B candidates remain excluded. Windows WireGuard receive changes require
fresh native and independent-peer qualification; historical targeted Hotfix
reports alone cannot admit them.

Hooks are reversible local assistance. If a guard needs repair, inspect the
failure and fix it; an explicitly authorized exceptional operation can use Git's
standard `--no-verify`, or restore the previous local `core.hooksPath`. Neither
is permission to push main, alter tags, or skip qualification. No global Git
configuration is changed. Configure GitHub required PR review and required CI
checks separately with maintainer authorization.

The restoration CI runs native Linux/Windows builds and tests, CLI process
traffic/restart, credential/storage and lifecycle regressions, and Linux race
tests. Optional reference peers must be pinned and used only in test code.
Run `python3 -m unittest discover -s scripts/dev -p 'test_*.py'` to verify guard
rejection cases without creating another source checkout.
