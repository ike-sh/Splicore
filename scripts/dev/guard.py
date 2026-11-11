#!/usr/bin/env python3
"""Read-only local Git guards. No configuration, refs, or files are mutated."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPOSITORY = 'ike-sh/Splicore'
PINNED = {'v0.3.0': 'e42c6e995d000205ba7c1c316eda1a0e95ef8297',
          'v0.4.0': 'cbac3fd1fcfdc76166513cdaa2d4f113497682cb',
          'v0.5.0': '70b09da7d2758e19ba03df9ff9b9e541a669fa29'}
ZERO = '0' * 40


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=45, check=False)
    require(result.returncode == 0, 'Command failed: ' + ' '.join(args[:3]) +
            ' (check local tools, authentication, and connectivity)')
    return result.stdout.decode('utf-8', errors='strict').strip()


def git(*args):
    return run('git', *args)


def path_identity(path):
    path = path.replace('\\', '/').rstrip('/')
    # wslpath also handles non-default automount roots.
    if path.startswith('/') and shutil.which('wslpath'):
        result = subprocess.run(['wslpath', '-w', path], capture_output=True, text=True)
        if result.returncode == 0:
            path = result.stdout.strip().replace('\\', '/')
    match = re.fullmatch(r'/(?:mnt/)?([a-zA-Z])/(.*)', path)
    if match:
        path = match[1] + ':/' + match[2]
    if re.match(r'^[a-zA-Z]:/', path):
        return path.casefold()
    return str(Path(path).resolve())


def expected_remote(url):
    return bool(re.fullmatch(r'(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)'
                            r'ike-sh/Splicore(?:\.git)?/?', url, re.IGNORECASE))


def feature_branch(branch):
    return bool(re.fullmatch(r'codex/[a-zA-Z0-9][a-zA-Z0-9._/-]*', branch))


def worktrees(text, root):
    stale = []
    for record in text.split('\n\n'):
        lines = record.splitlines()
        if not lines:
            continue
        path = lines[0].removeprefix('worktree ')
        if path_identity(path) == path_identity(root):
            continue
        if any(line.startswith('prunable ') for line in lines) and not os.path.lexists(path):
            stale.append(path)
        else:
            raise RuntimeError('Additional worktree requires review: ' + path)
    return stale


def pending_prs(branch):
    gh = shutil.which('gh') or shutil.which('gh.exe')
    require(gh, 'GitHub CLI (gh/gh.exe) is required to verify pending PRs')
    prs = json.loads(run(gh, 'pr', 'list', '--repo', REPOSITORY, '--state', 'open',
                        '--limit', '100', '--json', 'number,headRefName,baseRefName,title'))
    for pr in prs:
        require(not (pr['baseRefName'] == 'main' and pr['headRefName'] != branch),
                'Another main integration PR is pending: #' + str(pr['number']))
    require(len(prs) < 100, 'PR inventory is truncated; review it before development')


def check_state(allow_dirty=False, verify_main=False):
    root = git('rev-parse', '--show-toplevel')
    canonical = git('config', '--local', '--get', 'splicore.canonicalRoot')
    require(canonical and path_identity(root) == path_identity(canonical),
            'Wrong source directory; use the configured canonical checkout')
    require(git('rev-parse', '--is-inside-work-tree') == 'true', 'Expected a Git working tree')
    require((Path(root) / 'go.mod').read_text(encoding='utf-8').startswith(
        'module github.com/ike-sh/Splicore\n'), 'Unexpected repository module')
    for direction in ([], ['--push']):
        urls = git('remote', 'get-url', *direction, '--all', 'origin').splitlines()
        require(len(urls) == 1 and expected_remote(urls[0]), 'Unexpected origin URL')
    branch = git('symbolic-ref', '--quiet', '--short', 'HEAD')
    require(branch == 'main' if verify_main else feature_branch(branch),
            'Use a short-lived codex/ branch from origin/main; --verify-main is read-only main verification')
    remote_main = git('ls-remote', '--heads', 'origin', 'refs/heads/main').split()
    require(len(remote_main) == 2 and remote_main[0] == git('rev-parse', 'origin/main'),
            'origin/main is stale; fetch origin before development')
    require(git('merge-base', 'HEAD', 'origin/main') == git('rev-parse', 'origin/main'),
            'Branch must contain current origin/main; do not stack historical branches')
    if verify_main:
        require(git('rev-parse', 'HEAD') == git('rev-parse', 'origin/main'), 'main must exactly match origin/main')
    # Reject grafting/merging an alternate history into the feature range.
    require(not git('rev-list', '--merges', 'origin/main..HEAD'),
            'Feature history contains a merge; use a direct main-based feature branch')
    for tag, commit in PINNED.items():
        require(git('rev-parse', tag + '^{commit}') == commit, 'Frozen/release tag changed: ' + tag)
    for marker in ('MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'rebase-merge', 'rebase-apply'):
        require(not Path(git('rev-parse', '--git-path', marker)).exists(),
                'Finish or review the in-progress Git operation: ' + marker)
    stale = worktrees(git('worktree', 'list', '--porcelain'), root)
    for path in stale:
        print('NOTICE: preserved stale worktree registration: ' + path)
    changes = git('status', '--porcelain', '--untracked-files=all')
    require(allow_dirty or not changes, 'Unresolved worktree changes; inspect/preserve them before --allow-dirty')
    if changes:
        print('NOTICE: dirty state explicitly acknowledged; content checks still apply')
    pending_prs(branch)
    return branch


def check_blob(path, data):
    parts = path.casefold().split('/')
    name = parts[-1]
    blocked = {'reports', 'recovery', 'cleanup-audit', 'build', 'builds', 'dist', 'bin',
               'logs', 'temporary', '.venv', '__pycache__'}
    require(not any(p in blocked for p in parts), 'Private/generated directory cannot be committed: ' + path)
    require(not re.search(r'\.(?:exe|dll|a|o|test|db|sqlite|sqlite3|log|zip|tar|gz|pprof|prof|pyc)$', name),
            'Build/state artifact cannot be committed: ' + path)
    require(not (name == '.env' or name.startswith('.env.') and not name.endswith(('.example', '.template'))),
            'Environment credentials cannot be committed: ' + path)
    require(name not in {'convergence_master_tracker.md', 'frozen_main_feature_matrix.csv',
                        'local_development_guardrails.md', 'current_feature_implementation.md',
                        'pr_delivery_report.md', 'final_feature_matrix.csv',
                        'final_branch_cleanup.md', 'final_delivery_report.md'},
            'Private convergence report: ' + path)
    require(len(data) <= 10 * 1024 * 1024, 'Unexpected large file: ' + path)
    fixture = '/testdata/' in '/' + path or name.endswith(('_test.go', '_test.py')) or name.startswith('test_')
    if not fixture:
        require(not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', data),
                'Private key material: ' + path)
    require(not re.search(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16})', data),
            'Recognizable access token: ' + path)


def scan_index():
    paths = git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z').split('\0')
    for path in filter(None, paths):
        data = subprocess.check_output(['git', 'show', ':' + path])
        check_blob(path, data)


def check_push(remote, url, lines, branch):
    require(remote == 'origin' and expected_remote(url), 'Push destination must be expected origin')
    # Git can invoke pre-push for an up-to-date push with no updates.
    for line in lines:
        fields = line.split()
        require(len(fields) == 4, 'Invalid pre-push ref input')
        local_ref, local_sha, remote_ref, remote_sha = fields
        require(remote_ref == 'refs/heads/' + branch and local_ref == remote_ref,
                'Push only the current codex/ branch; main, release, tags and deletions are protected')
        require(local_sha != ZERO and local_sha == git('rev-parse', 'HEAD'), 'Push must use the current HEAD')
        if remote_sha != ZERO:
            require(git('merge-base', remote_sha, local_sha) == remote_sha, 'Non-fast-forward push rejected')
        for commit in git('rev-list', 'origin/main..' + local_sha).splitlines():
            for path in filter(None, git('diff-tree', '--root', '--no-commit-id', '-r', '--name-only',
                                         '--diff-filter=ACMR', '-z', commit).split('\0')):
                data = subprocess.check_output(['git', 'show', commit + ':' + path])
                check_blob(path, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('start', 'commit', 'push'))
    parser.add_argument('remote', nargs='?')
    parser.add_argument('url', nargs='?')
    parser.add_argument('--allow-dirty', action='store_true')
    parser.add_argument('--verify-main', action='store_true')
    args = parser.parse_args()
    require(not args.verify_main or args.mode == 'start', '--verify-main cannot authorize commit or push hooks')
    # Capture the hook protocol before any child process (especially Windows
    # interop/gh) can consume its pipe. Read-only probes also receive DEVNULL.
    push_lines = sys.stdin.read().splitlines() if args.mode == 'push' else []
    branch = check_state(args.allow_dirty, verify_main=True) if args.verify_main else check_state(args.allow_dirty)
    if args.mode == 'commit':
        scan_index()
    if args.mode == 'push':
        check_push(args.remote, args.url, push_lines, branch)
    print('SPLICORE_PREFLIGHT_PASS: ' + branch)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('SPLICORE_PREFLIGHT_STOP: ' + str(error), file=sys.stderr)
        sys.exit(1)
