#!/usr/bin/env python3
"""Run the required native Windows amd64 Race qualification."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT/'scripts'))
import release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = 'windows-amd64'
    release.require(release.native_target() == target, 'Windows Race requires native Windows amd64')
    go = json.loads(release.command(['go', 'env', '-json', 'GOOS', 'GOARCH']))
    release.require(go == {'GOOS': 'windows', 'GOARCH': 'amd64'}, 'native host/toolchain mismatch')

    out = args.output.resolve()
    release.require(out != ROOT and ROOT not in out.parents, 'output must be outside source')
    out.mkdir(parents=True, exist_ok=True)
    release.require(not any(out.iterdir()), 'use a fresh output directory')
    release.save(out/'identity.json', dict(host_os=platform.platform(), host_arch='amd64', go=go,
                                          source=release.identity(), command=sys.argv))
    temp_parent = out/'runtime'
    temp_parent.mkdir()
    env = release.goenv(target, cgo='1')
    summary = {'classification': 'NOT_EXECUTED', 'target': target, 'power_loss': 'NOT EXECUTED'}
    try:
        with tempfile.TemporaryDirectory(prefix='sq-', dir=temp_parent) as tmp:
            env.update(TEMP=tmp, TMP=tmp, GOTMPDIR=tmp)
            evidence = out/'persistence'
            evidence.mkdir()
            env['SPLICORE_PERSISTENCE_EVIDENCE'] = str(evidence)

            # The Race test process uses CGO. Its lifecycle fixture runs a
            # separately built CGO-free release core.
            release.build(out, target, out)
            env['SPLICORE_RUNTIME_BINARY'] = str(out/target/'splicore.exe')
            compiler = env.get('CC', 'gcc')
            library = subprocess.check_output([compiler, '-print-file-name=libsynchronization.a'], text=True).strip()
            release.require(Path(library).is_file(), 'mingw-w64 v8+ runtime synchronization library required')
            release.save(out/'race-toolchain.json', dict(compiler=compiler, synchronization_library=library))

            stage = 'race-test'
            command = ['go', 'test', '-mod=readonly', '-race', '-tags='+release.TAGS,
                       '-json', '-count=1', '-timeout=1200s', '-p=1', './...']
            result = release.run_logged(command, env, out, stage)
            summary[stage] = result
            release.check_behavior(result, out, stage, target, 'race', process_leaves=True)
            summary.update(classification='QUALIFIED_WITH_LIMITATIONS', native_startup='PASS', native_traffic='PASS',
                           native_full_qualification='NOT EXECUTED')
    except Exception as exc:
        summary.update(classification='NOT_QUALIFIED', error=str(exc))
        raise
    finally:
        release.save(out/'summary.json', summary)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except release.LoggedFailure as error:
        print(error, file=sys.stderr)
        sys.exit(error.exit_code)
