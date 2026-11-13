#!/usr/bin/env python3
"""Preregistered, bounded historical lifecycle forensics; never admission by replay."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
TARGET = 'TestPhase20ProxyLifetimeAuthRotation25'
PROXY = 'internal/splicore/application/proxy_interfaces_test.go'
VERSIONS = {
    'M': '497f5509e1e66f28c480189b486e8fa3cbe4ba06',
    'H': 'fe0c01ab7862029b331eae6a0483dc452e67bbf6',
    'F': '78c3ebe451ff0b55d9765cf51722de764c0adc7d',
}

HELPER = r'''

// Diagnostic overlay only: reuse the original sample's stack and defer disk
// writes until cleanup. This observer still changes allocation and scheduling.
type p37Record struct {
    Stage, Kind string
    At time.Time
    Resource phase20Resources
    Stack string
}
var p37Enabled bool
var p37Stage string
var p37Records []p37Record
func p37Keep(kind string, r phase20Resources, stack []byte) {
    if !p37Enabled { return }
    p37Records = append(p37Records, p37Record{p37Stage, kind, time.Now().UTC(), r, string(stack)})
}
func p37Entry(r phase20Resources) {
    if !p37Enabled || r.Goroutines <= 10 { return }
    b := make([]byte, 1<<20)
    n := runtime.Stack(b, true)
    // Only the count is measured here; the remaining resource fields are not
    // sampled yet. The following original sample records all original fields.
    p37Keep("high-count-entry-only", r, b[:n])
}
func p37Take(stage string, s *application.Service) {
    p37Stage = stage
    r := phase20Resources{Goroutines:runtime.NumGoroutine()}
    fd, err := os.ReadDir("/proc/self/fd")
    if err == nil { r.FDs = len(fd) }
    status, err := s.ClientStatus(context.Background())
    if err == nil {
        r.Sessions = len(status.Sessions)
        if status.Health == "healthy" { r.Listeners = len(status.LocalStats) }
    }
    b := make([]byte, 1<<20)
    n := runtime.Stack(b, true)
    r.UDPWorkers = bytes.Count(b[:n], []byte("proxy_outbound.go")) + bytes.Count(b[:n], []byte("clientruntime.(*Manager).serveUDP.func"))
    p37Keep("boundary",r,b[:n])
}
func p37Failed(t *testing.T, s *application.Service) {
    // The original predicate has already failed. Its original end value and
    // Fatal remain unchanged regardless of what these observations show.
    base := time.Now()
    for _, offset := range []time.Duration{0,10*time.Millisecond,100*time.Millisecond,time.Second,3*time.Second} {
        if deadline, ok := t.Deadline(); ok && !base.Add(offset).Before(deadline) { break }
        if remaining := time.Until(base.Add(offset)); remaining > 0 {
            timer := time.NewTimer(remaining)
            <-timer.C
        }
        p37Take(fmt.Sprintf("failed-predicate-followup-%s",offset),s)
    }
}
func p37Start(t *testing.T) {
    p37Enabled = true
    p37Stage = "initial-stopped"
    p37Records = nil
    t.Cleanup(func() {
        p37Enabled = false
        root := os.Getenv("SPLICORE_P37_STACK_DIR")
        if root == "" { t.Error("missing forensic output directory"); return }
        if err := os.MkdirAll(root,0700); err != nil { t.Error(err); return }
        for i, record := range p37Records {
            base := filepath.Join(root,fmt.Sprintf("%03d",i))
            b, err := json.Marshal(record)
            if err == nil { err = os.WriteFile(base+".json",b,0600) }
            if err != nil { t.Error(err) }
        }
    })
}
'''


def save(path, data):
    with path.open('x') as f:
        json.dump(data, f, indent=2)


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def instrument(source):
    edits = [
        ('r := phase20Resources{Goroutines: runtime.NumGoroutine()}',
         'r := phase20Resources{Goroutines: runtime.NumGoroutine()}\n\tp37Entry(r)'),
        ('\treturn r\n}\nfunc '+TARGET,
         '\tp37Keep("original-sample-stack", r, stack[:n])\n\treturn r\n}\nfunc '+TARGET),
        ('func '+TARGET+'(t *testing.T) {', 'func '+TARGET+'(t *testing.T) {\n\tp37Start(t)'),
        ('\t\tcurrent := phase20Sample(s)', '\t\tp37Stage = fmt.Sprintf("cycle-%02d-before-stop",cycle)\n\t\tcurrent := phase20Sample(s)'),
        ('\t\tend := phase20Sample(s)', '\t\tp37Stage = fmt.Sprintf("cycle-%02d-after-wait",cycle)\n\t\tend := phase20Sample(s)'),
        ('\n\tend := phase20Sample(s)\n', '\n\tp37Take("before-final",s)\n\tp37Stage = "final-original-sample"\n\tend := phase20Sample(s)\n\tp37Take("after-final",s)\n'),
        ('\t\tt.Fatalf("goroutine residue start=%+v end=%+v", start, end)',
         '\t\tp37Failed(t,s)\n\t\tt.Fatalf("goroutine residue start=%+v end=%+v", start, end)'),
    ]
    original = source
    for old, new in edits:
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    # Reversibility proves that no original assertion or loop was edited.
    restored = source
    for old, new in reversed(edits):
        restored = restored.replace(new, old)
    assert restored == original
    return source + HELPER


def make_overlay(commit, out, mode):
    spec = importlib.util.spec_from_file_location('p36', ROOT/'scripts/qualification/integration-diagnostics.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    mapping = module.overlay(commit, out)
    replacements = json.loads(mapping.read_text())['Replace']
    source = git('show', commit+':'+PROXY)
    if mode == 'buffered':
        observed = instrument(source.decode()).encode()
        target = out/'buffered-proxy_interfaces_test.go'
        target.write_bytes(observed)
        replacements[str(ROOT/PROXY)] = str(target)
    save(out/'observer-source-proof.json', {
        'mode': mode, 'fixed_test_sha256': hashlib.sha256(source).hexdigest(),
        'all_original_bytes_recoverable_by_removing_observer': True,
        'observed_test_sha256': hashlib.sha256(observed).hexdigest() if mode == 'buffered' else None,
    })
    mapping.write_text(json.dumps({'Replace': replacements}, indent=2))
    return mapping


def run(command, env, out, name):
    with (out/(name+'.stdout')).open('xb') as stdout, (out/(name+'.stderr')).open('xb') as stderr:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, timeout=1500)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['pristine','buffered'], required=True)
    parser.add_argument('--profile', choices=['default','race'], required=True)
    parser.add_argument('--scope', choices=['whole','target'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    arch = {'aarch64':'arm64','x86_64':'amd64'}.get(platform.machine())
    assert arch and sys.platform == 'linux', 'Real native Linux host required'
    assert os.environ.get('SPLICORE_PRIVATE_NETNS') == '1'
    assert (arch == 'arm64' and args.scope == 'whole') or (arch == 'amd64' and args.scope == 'target' and args.profile == 'default')
    rounds = 2 if arch == 'arm64' and args.profile == 'default' else 1
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    host = {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'machine':platform.machine(),
            'kernel':platform.platform(), 'go':subprocess.check_output(['go','version'],text=True).strip(),
            'go_environment':json.loads(subprocess.check_output(['go','env','-json','GOOS','GOARCH','GOVERSION'])),
            'cpu_affinity':sorted(os.sched_getaffinity(0)), 'GOMAXPROCS':'4', 'mode':args.mode,
            'profile':args.profile,'scope':args.scope,'rounds':rounds,'versions':VERSIONS,
            'runner':{k:os.environ.get(k) for k in ['ImageOS','ImageVersion','RUNNER_ARCH','RUNNER_OS','RUNNER_NAME','GITHUB_RUN_ID','GITHUB_SHA']}}
    for name in ['/etc/os-release','/proc/meminfo','/proc/self/cgroup','/sys/fs/cgroup/cpu.max','/sys/fs/cgroup/memory.max']:
        if Path(name).exists(): host[name]=Path(name).read_text()
    assert host['go_environment']['GOARCH'] == arch and host['go_environment']['GOVERSION'] == 'go1.26.3'
    save(out/'host.json',host)
    rows=[]
    for number in range(1,rounds+1):
        for version in (['M','H','F'] if number%2 else ['F','H','M']):
            case=out/f'{number:02d}-{version}';case.mkdir()
            commit=VERSIONS[version];mapping=make_overlay(commit,case,args.mode)
            runtime=case/'runtime';runtime.mkdir(mode=0o700)
            env=dict(os.environ,CGO_ENABLED='0',GOTOOLCHAIN='local',GOTELEMETRY='off',GOFLAGS='-mod=readonly',GOMAXPROCS='4',
                     TMPDIR=str(runtime),GOTMPDIR=str(runtime))
            env.pop('SPLICORE_PERSISTENCE_EVIDENCE',None)
            env.pop('SPLICORE_P36_STACK_DIR',None)
            if args.mode=='buffered': env['SPLICORE_P37_STACK_DIR']=str(case/'stacks')
            binary=case/'splicore'
            build=['go','build','-mod=readonly','-overlay='+str(mapping),'-tags=with_quic,with_utls,with_gvisor','-o',str(binary),'./cmd/splicore']
            build_code=run(build,env,case,'build')
            if build_code: raise RuntimeError('Forensic binary preparation failed; preserve evidence, do not retry tests')
            env['SPLICORE_RUNTIME_BINARY']=str(binary)
            command=['go','test','-mod=readonly','-overlay='+str(mapping),'-json','-count=1','-timeout=1200s']
            if args.profile=='race':
                env['CGO_ENABLED']='1';command+=['-race','-tags=with_quic,with_utls,with_gvisor']
            if args.scope=='target':command+=['-run','^'+TARGET+'$']
            command+=['./...' if args.scope=='whole' else './internal/splicore/application']
            save(case/'identity.json',{'fixed_commit':commit,'fixed_tree':git('rev-parse',commit+'^{tree}').decode().strip(),
                                     'command':command,'build_command':build,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                                     'CGO_ENABLED':env['CGO_ENABLED'],'mode':args.mode,'round':number,
                                     'context':'Full historical package concurrency/order retained in whole mode; buffered observer is not pristine.'})
            started=time.monotonic();code=run(command,env,case,'test')
            target=[];failed=[]
            for line in (case/'test.stdout').read_text(errors='replace').splitlines():
                try:e=json.loads(line)
                except ValueError:continue
                if e.get('Test')==TARGET:target.append(e)
                if e.get('Action')=='fail':failed.append({'package':e.get('Package'),'test':e.get('Test')})
            row={'version':version,'round':number,'exit_code':code,'elapsed':time.monotonic()-started,
                 'target_events':target,'all_failed_tests':failed}
            save(case/'result.json',row);rows.append(row)
            print(json.dumps({'case':case.name,'exit_code':code,'target_failed':any(e.get('Action')=='fail' for e in target)}),flush=True)
    save(out/'summary.json',{'host':host,'cases':rows,'qualification':'NOT_QUALIFIED',
                             'root_cause':'ROOT_CAUSE_UNRESOLVED until extra goroutines map to owners; green runs are not repair evidence'})
    return int(any(r['exit_code'] for r in rows))


if __name__=='__main__':
    sys.exit(main())
