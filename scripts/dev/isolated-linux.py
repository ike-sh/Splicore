#!/usr/bin/env python3
"""Run a qualification command in an owned Linux network namespace."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or sys.platform != 'linux':
        raise RuntimeError('A Linux qualification command is required')
    if args.inside:
        for cmd in (['ip', 'link', 'set', 'lo', 'up'], ['ip', 'link', 'set', 'lo', 'mtu', '1500'],
                    ['ip', 'address', 'add', '192.0.2.29/32', 'dev', 'lo'],
                    ['ip', '-6', 'address', 'add', '2001:db8::29/128', 'dev', 'lo', 'nodad']):
            subprocess.run(cmd, check=True)
        env = os.environ.copy()
        count = int(env.get('GIT_CONFIG_COUNT', '0'))
        env.update(SPLICORE_PRIVATE_NETNS='1', SPLICORE_PHASE36_KERNEL='1',
                   GIT_CONFIG_COUNT=str(count + 1), **{f'GIT_CONFIG_KEY_{count}': 'safe.directory', f'GIT_CONFIG_VALUE_{count}': str(ROOT)})
        return subprocess.run(command, cwd=ROOT, env=env).returncode
    if os.geteuid() != 0:
        # Pass only qualification inputs. No credential or global configuration is
        # needed for the namespace or its test-only peers.
        names = {'PATH', 'GITHUB_ACTIONS', 'GITHUB_WORKSPACE', 'CI', 'GOCACHE', 'GOMODCACHE', 'GOPATH',
                 'GOENV', 'GOTOOLCHAIN', 'GOTELEMETRY', 'GOFLAGS', 'GOMAXPROCS', 'PYTHONDONTWRITEBYTECODE'}
        env = {k: v for k, v in os.environ.items() if k in names or k.startswith('SPLICORE_')}
        # sudo changes HOME. Keep the caller's populated module/cache paths so
        # the offline namespace does not try to populate /root/go instead.
        go = json_go_env()
        for key in ('GOCACHE', 'GOMODCACHE', 'GOPATH'):
            env.setdefault(key, go[key])
        values = [k + '=' + v for k, v in env.items()]
        return subprocess.run(['sudo', '-n', '--', 'env', *values, sys.executable, str(Path(__file__).resolve()), '--', *command], cwd=ROOT).returncode
    try:
        return subprocess.run(['unshare', '--net', sys.executable, str(Path(__file__).resolve()), '--inside', '--', *command], cwd=ROOT).returncode
    finally:
        # Hosted artifact collection runs as the original runner. Only this
        # checkout's generated build tree changes ownership; links are not followed.
        if os.environ.get('GITHUB_ACTIONS') and os.environ.get('SUDO_UID'):
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            for base, dirs, files in os.walk(ROOT / 'build', followlinks=False):
                for path in [Path(base), *[Path(base) / name for name in dirs + files]]:
                    if not path.is_symlink():
                        os.chown(path, uid, gid, follow_symlinks=False)


def json_go_env():
    import json
    return json.loads(subprocess.check_output(['go', 'env', '-json', 'GOCACHE', 'GOMODCACHE', 'GOPATH'], cwd=ROOT, text=True))


if __name__ == '__main__':
    raise SystemExit(main())
