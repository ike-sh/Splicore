#!/usr/bin/env python3
"""Bounded, read-only source overlays for the two P3.6 integration incidents.

Results are diagnostic evidence, never a substitute for the ordinary CI gates.
No checkout, branch, test assertion, network timeout, or retry policy is changed.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PROXY = 'internal/splicore/application/proxy_interfaces_test.go'

STACK_HELPER = r'''

// Only the bounded diagnostic overlay calls this observer. Stack collection
// and filesystem writes may affect scheduling; ordinary tests are unchanged.
var p36Snapshot struct { sync.Mutex; number int }
func p36Capture(stage string, counted int) {
    root := os.Getenv("SPLICORE_P36_STACK_DIR")
    if root == "" { return }
    p36Snapshot.Lock()
    defer p36Snapshot.Unlock()
    p36Snapshot.number++
    before := runtime.NumGoroutine()
    stack := make([]byte, 1<<20)
    n := runtime.Stack(stack, true)
    if n == len(stack) { panic("diagnostic stack buffer truncated") }
    base := filepath.Join(root, fmt.Sprintf("%03d-%s", p36Snapshot.number, stage))
    if err := os.MkdirAll(root, 0700); err != nil { panic(err) }
    if err := os.WriteFile(base+".stack", stack[:n], 0600); err != nil { panic(err) }
    raw, err := json.Marshal(map[string]any{"stage":stage,"counted":counted,"before":before,"after":runtime.NumGoroutine(),"at":time.Now().UTC()})
    if err != nil { panic(err) }
    if err := os.WriteFile(base+".json", raw, 0600); err != nil { panic(err) }
}
'''


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)


def stack_source(source):
    needle = 'r := phase20Resources{Goroutines: runtime.NumGoroutine()}'
    assert source.count(needle) == 1
    source = source.replace(needle, needle + '\n\tp36Capture("sample-entry", r.Goroutines)')
    needle = '\t\tend := phase20Sample(s)\n'
    assert source.count(needle) == 1
    source = source.replace(needle, needle + '\t\tp36Capture(fmt.Sprintf("after-stop-%02d", cycle), end.Goroutines)\n')
    needle = '\n\tend := phase20Sample(s)\n'
    assert source.count(needle) == 1
    source = source.replace(needle, '\n\tp36Capture("before-final", runtime.NumGoroutine())' + needle + '\tp36Capture("after-final", end.Goroutines)\n')
    return source + STACK_HELPER


def overlay(base, directory, stacks=False):
    source_dir = directory / 'sources'
    source_dir.mkdir()
    changes = git('diff', '--name-only', base, 'HEAD').decode().splitlines()
    changes = [p for p in changes if p.endswith('.go') or p in ('go.mod', 'go.sum')]
    if stacks and PROXY not in changes:
        changes.append(PROXY)
    replacements = {}
    blobs = []
    for number, path in enumerate(changes):
        result = subprocess.run(['git', 'show', base + ':' + path], cwd=ROOT, capture_output=True)
        if result.returncode:
            replacements[str(ROOT / path)] = ''
            blobs.append({'path': path, 'absent_in_fixed_version': True})
            continue
        data = result.stdout
        blobs.append({'path': path, 'original_sha256': hashlib.sha256(data).hexdigest()})
        if stacks and path == PROXY:
            data = stack_source(data.decode()).encode()
        target = source_dir / (str(number) + '-' + Path(path).name)
        target.write_bytes(data)
        replacements[str(ROOT / path)] = str(target)
    path = directory / 'overlay.json'
    save(path, {'Replace': replacements})
    save(directory / 'fixed-source-blobs.json', blobs)
    return path


def run_case(args, version, commit, number):
    case = args.output / f'{number:02d}-{version}'
    case.mkdir()
    mapping = overlay(commit, case, stacks=args.mode == 'lifecycle')
    env = dict(os.environ, GOMAXPROCS='4', GOTOOLCHAIN='local', GOTELEMETRY='off', GOFLAGS='-mod=readonly')
    command = ['go', 'test', '-overlay=' + str(mapping), '-json', '-count=1', '-timeout=1200s']
    if args.mode == 'routing':
        env['CGO_ENABLED'] = '1'
        command += ['-race', '-tags=with_quic,with_utls,with_gvisor', '-run', '^TestPhase12RoutingDNSPolicyAcceptance$']
    else:
        env['CGO_ENABLED'] = '0'
        env['SPLICORE_P36_STACK_DIR'] = str(case / 'stacks')
        if number < 3:
            command += ['-run', '^TestPhase20ProxyLifetimeAuthRotation25$']
    command += ['./internal/splicore/application']
    identity = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'version': version, 'fixed_commit': commit,
                'fixed_tree': git('rev-parse', commit + '^{tree}').decode().strip(), 'command': command,
                'kernel': platform.release(), 'machine': platform.machine(), 'go': subprocess.check_output(['go', 'version'], text=True).strip(),
                'go_environment': json.loads(subprocess.check_output(['go', 'env', '-json', 'GOARCH', 'GOOS', 'GOVERSION'], env=env)),
                'GOMAXPROCS': env['GOMAXPROCS'], 'CGO_ENABLED': env['CGO_ENABLED'],
                'observer': 'All original assertions retained. Stack capture can change scheduling; not pristine qualification.'}
    for name in ['/etc/os-release', '/proc/meminfo', '/sys/fs/cgroup/cpu.max', '/sys/fs/cgroup/memory.max']:
        path = Path(name)
        if path.exists():
            identity[name] = path.read_text()
    save(case / 'identity.json', identity)
    with (case / 'test.stdout').open('xb') as stdout, (case / 'test.stderr').open('xb') as stderr:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, timeout=1500)
    events = []
    for line in (case / 'test.stdout').read_text(errors='replace').splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get('Action') in ('pass', 'fail', 'skip') and event.get('Test'):
            events.append({'test': event['Test'], 'action': event['Action']})
    row = {'version': version, 'round': number, 'exit_code': result.returncode, 'events': events}
    save(case / 'result.json', row)
    print(json.dumps({'version': version, 'round': number, 'exit_code': result.returncode}), flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['lifecycle', 'routing'], required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    assert args.mode == 'lifecycle', 'Routing is run by the separately bounded isolated local controller'
    fixed = {'A': git('rev-parse', args.baseline + '^{commit}').decode().strip(),
             'B': git('rev-parse', args.candidate + '^{commit}').decode().strip()}
    assert platform.machine() in ('aarch64', 'x86_64'), 'Native Linux diagnostic host required'
    records = []
    for number in range(1, 4):
        for version in (['A', 'B'] if number % 2 else ['B', 'A']):
            records.append(run_case(args, version, fixed[version], number))
    save(args.output / 'summary.json', {'fixed': fixed, 'records': records,
                                      'qualification': 'NOT_QUALIFIED', 'scope': 'Bounded diagnostic, not integration admission'})
    return int(any(x['exit_code'] for x in records))


if __name__ == '__main__':
    sys.exit(main())
