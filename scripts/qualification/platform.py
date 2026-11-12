#!/usr/bin/env python3
"""Native ARM64 and Windows Race gates, separate from release qualification."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('splicore_release', ROOT/'scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def host_architecture():
    if os.name == 'nt':
        class SystemInfo(ctypes.Structure):
            _fields_ = [('architecture', ctypes.c_ushort), ('reserved', ctypes.c_ushort), ('tail', ctypes.c_byte*44)]
        info = SystemInfo()
        ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(info))
        return {12: 'arm64', 9: 'amd64'}.get(info.architecture, 'unknown')
    return {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(platform.machine().casefold(), 'unknown')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=['arm64', 'windows-race'], required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    release.require(out != ROOT and ROOT not in out.parents, 'output must be outside source')
    out.mkdir(parents=True, exist_ok=True)
    release.require(not any(out.iterdir()), 'use a fresh output directory')
    system = 'windows' if os.name == 'nt' else 'linux'
    host = host_architecture()
    go = json.loads(subprocess.check_output(['go', 'env', '-json', 'GOOS', 'GOARCH'], cwd=ROOT, text=True))
    target = system+'-'+host
    identity = dict(host_os=platform.platform(), host_arch=host, go=go, source=release.identity(), command=sys.argv)
    release.save(out/'identity.json', identity)
    release.require(go == {'GOOS': system, 'GOARCH': host}, 'native host/toolchain mismatch; cross compilation is BUILD ONLY')
    release.require((args.mode == 'arm64' and host == 'arm64') or (args.mode == 'windows-race' and target == 'windows-amd64'), 'requested native platform unavailable')
    if system == 'linux':
        release.require(os.environ.get('SPLICORE_PRIVATE_NETNS') == '1', 'use scripts/dev/isolated-linux.py')
    env = release.goenv(target)
    temp_parent = out/'runtime'
    temp_parent.mkdir()
    summary = {'classification': 'NOT_EXECUTED', 'target': target, 'power_loss': 'NOT EXECUTED'}
    try:
        with tempfile.TemporaryDirectory(prefix='sq-', dir=temp_parent if system=='windows' else None) as tmp:
            if system == 'linux':
                os.chmod(tmp, 0o700)
                release.require(Path(tmp).stat().st_mode & 0o077 == 0, 'private POSIX temporary filesystem required')
                env.update(TMPDIR=tmp, GOTMPDIR=tmp)
            else:
                env.update(TEMP=tmp, TMP=tmp, GOTMPDIR=tmp)
            evidence = out/'persistence'
            evidence.mkdir()
            env['SPLICORE_PERSISTENCE_EVIDENCE'] = str(evidence)
            profiles = [('race', ['-race', '-tags='+release.TAGS])] if args.mode=='windows-race' else [('default', []), ('full', ['-tags='+release.TAGS])]
            if args.mode == 'arm64' and system == 'linux':
                profiles.append(('race', ['-race', '-tags='+release.TAGS]))
            for profile, tags in profiles:
                if profile == 'race':
                    env['CGO_ENABLED'] = '1'
                    if system == 'windows':
                        compiler = env.get('CC', 'gcc')
                        library = subprocess.check_output([compiler, '-print-file-name=libsynchronization.a'], text=True).strip()
                        release.require(Path(library).is_file(), 'mingw-w64 v8+ runtime synchronization library required')
                        release.save(out/'race-toolchain.json', dict(compiler=compiler, synchronization_library=library))
                    actions = ['test']
                else:
                    actions = ['build', 'vet', 'test']
                for action in actions:
                    command = ['go', action, '-mod=readonly'] + tags
                    if action == 'test':
                        command += ['-json', '-count=1', '-timeout=1200s']
                        if system == 'windows':
                            command += ['-p=1']
                    result = release.run_logged(command+['./...'], env, out, profile+'-'+action)
                    summary[profile+'-'+action] = result
                    if action == 'test':
                        behavior = importlib.util.spec_from_file_location('policy', ROOT/'scripts/dev/qualification_policy.py')
                        policy = importlib.util.module_from_spec(behavior); behavior.loader.exec_module(policy)
                        result['behavior_policy'] = policy.validate(ROOT, result, target, profile)
                        release.require(result['tests'].get('github.com/ike-sh/Splicore/cmd/splicore/TestRuntimeBinaryTrafficShutdownAndRestart') == 'pass', 'native CLI process traffic/restart must execute')
                        release.save(out/(profile+'-test.json'), result)
                    release.save(out/'summary.json', summary)
            summary['classification'] = 'QUALIFIED_WITH_LIMITATIONS'
            summary['native_startup'] = 'PASS'
            summary['native_traffic'] = 'PASS'
            summary['native_full_qualification'] = 'NOT EXECUTED' if args.mode=='windows-race' else 'QUALIFIED_WITH_LIMITATIONS'
            summary['limitations'] = 'Independent oracle and platform skip identities are enumerated by behavior_policy. Physical TUN/Wintun, 24/72h soak, OS crash and power loss are not certified.'
    except Exception as exc:
        summary.update(classification='NOT_QUALIFIED', error=str(exc))
        raise
    finally:
        release.save(out/'summary.json', summary)
    return 0


if __name__ == '__main__':
    sys.exit(main())
