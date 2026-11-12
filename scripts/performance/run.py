#!/usr/bin/env python3
"""Reproducible native socket measurements; results are BASELINE, never an SLO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
TAGS = 'with_quic,with_utls,with_gvisor'


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def capture(args, env=None):
    result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True)
    return dict(command=args, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)


def source_identity():
    names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(set(names)) if name and (ROOT/name).is_file()}


def quantiles(values):
    values = sorted(values)
    if not values:
        return None
    return {key: values[min(len(values)-1, max(0, int(len(values)*fraction+.999999)-1))]
            for key, fraction in [('p50', .5), ('p95', .95), ('p99', .99)]}


def summarize(raw):
    groups = {}
    for line in raw.read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        name = row.get('scenario', row.get('label'))
        if not name:
            continue
        groups.setdefault(name, []).append(row)
    result = {}
    for name, rows in groups.items():
        connections = [r for r in rows if r['kind'] == 'connection']
        samples = [r for r in rows if r['kind'] == 'resources']
        tcp = [r for r in connections if r['network'] == 'tcp' and r['status'] != 'FAIL']
        udp = [r for r in connections if r['network'] == 'udp']
        elapsed = next((r['elapsed_ns'] for r in rows if r['kind'] == 'group'), 0)
        completed = any(r['kind']=='outcome' and r['passed'] for r in rows)
        bytes_tcp = sum(r['bytes_per_direction'] * (2 if r['mode'] == 'duplex' else 1) for r in tcp)
        sent = sum(r.get('sent_packets', 0) for r in udp)
        received = sum(r.get('received_packets', 0) for r in udp)
        cpu = []
        for a, b in zip(samples, samples[1:]):
            dt = b['time_ns'] - a['time_ns']
            if dt > 0:
                cpu.append(100*(b['cpu_ns']-a['cpu_ns'])/dt)
        result[name] = dict(
            status='BASELINE' if completed and connections and not any(r['status']=='FAIL' for r in connections) else 'FAIL',
            connections=len(connections), errors=[r.get('error') for r in connections if r['status'] == 'FAIL'],
            tcp_goodput_mbps=bytes_tcp*8000/elapsed if elapsed else None,
            tcp_connection_mbps=[r['bytes_per_direction']*(2 if r['mode']=='duplex' else 1)*8000/r['transfer_ns'] if r['transfer_ns']>0 else None for r in tcp],
            timing_not_executed={'transfer_below_timer_resolution':sum(r['transfer_ns']==0 for r in tcp),
                                 'note':'Zero-duration raw samples are retained; their per-connection throughput is unavailable, never inferred from an invented duration.'},
            udp_sent=sent, udp_received=received,
            udp_loss_percent=100*(sent-received)/sent if sent else None,
            udp_goodput_mbps=sum(r.get('received_packets',0)*r.get('packet_bytes',0) for r in udp)*8000/elapsed if elapsed else None,
            rtt_ns={n:quantiles([r['ns'] for r in rows if r['kind']=='rtt' and r['network']==n]) for n in ['tcp','udp']},
            dial_ns=quantiles([r['dial_ns'] for r in connections if 'dial_ns' in r]),
            ready_ns=quantiles([r['ready_ns'] for r in connections if 'ready_ns' in r]),
            close_ns=quantiles([r['close_ns'] for r in connections if 'close_ns' in r]),
            peak_rss_bytes=max((r['rss_bytes'] for r in samples), default=None),
            peak_goroutines=max((r['goroutines'] for r in samples), default=None),
            peak_os_resources=max((r['os_resources'] for r in samples), default=None),
            cpu_percent=quantiles(cpu), resource_errors=[r['error'] for r in samples if r['error']],
            resource_before=samples[0] if samples else None, resource_after=samples[-1] if samples else None)
    return result


def scenarios(profile, suite):
    config = json.loads((ROOT/'scripts/performance/profiles.json').read_text())
    common = config['defaults']
    rows = config['profiles'][profile]
    if suite=='wireguard':
        rows = [dict(row,protocol='wireguard',name='wireguard'+row['name'][len('vless-tcp'):]) for row in rows if row['protocol']=='vless-tcp']
    return [dict(common, **row) for row in rows]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--profile', choices=['ci', 'baseline', 'matrix', 'soak'], default='ci')
    p.add_argument('--repeat', type=int, default=1)
    p.add_argument('--suite', choices=['native','wireguard'], default='native')
    p.add_argument('--conditions', default='clean', help='comma-separated names from conditions.json, or all')
    p.add_argument('--soak-hours', type=int, choices=[24,72])
    p.add_argument('--isolate', action='store_true', help='owned Linux user/mount/network namespaces only')
    p.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--parent-netns', type=int, default=0, help=argparse.SUPPRESS)
    args = p.parse_args()
    out = args.output.resolve()
    if out == ROOT or ROOT in out.parents or args.repeat < 1:
        p.error('output must be outside the source tree; repeat must be positive')
    out.mkdir(parents=True, exist_ok=True)
    if not args.inside and any(out.iterdir()):
        p.error('use a fresh output directory; existing evidence is preserved')
    binary = out/(args.suite+'-perf'+('.exe' if os.name=='nt' else ''))
    env = os.environ.copy()
    env.update(CGO_ENABLED='0', GOFLAGS='-mod=readonly', GOTOOLCHAIN='local', GOTELEMETRY='off')
    if not args.inside:
        info = dict(commit=capture(['git','rev-parse','HEAD']), diff_sha256=hashlib.sha256(subprocess.check_output(['git','diff','HEAD'],cwd=ROOT)).hexdigest(),
                    platform=platform.platform(), machine=platform.machine(), processor=platform.processor(), logical_cpus=os.cpu_count(),
                    go=capture(['go','version']), goenv=capture(['go','env','-json']), profile=args.profile,
                    command=sys.argv, classification='BASELINE', slo='NONE; no performance qualification asserted')
        save(out/'source-sha256.json',source_identity())
        if sys.platform=='linux':
            info.update(cpuinfo=Path('/proc/cpuinfo').read_text(), meminfo=Path('/proc/meminfo').read_text())
        save(out/'environment.json', info)
        package = './internal/splicore/engine/native' if args.suite=='native' else './internal/splicore/wireguardendpoint'
        build = capture(['go','test','-c','-mod=readonly','-tags='+TAGS,'-o',str(binary),package], env)
        save(out/'build.json', build)
        if build['exit_code']:
            return build['exit_code']
        if args.isolate:
            if sys.platform!='linux':
                p.error('--isolate requires Linux')
            command=[sys.executable,str(Path(__file__).resolve()),*sys.argv[1:], '--inside','--parent-netns',str(os.stat('/proc/self/ns/net').st_ino)]
            return subprocess.run(['unshare','--user','--map-root-user','--mount','--net',*command], cwd=ROOT, env=env).returncode
    conditions=json.loads((ROOT/'scripts/performance/conditions.json').read_text())
    names=list(conditions) if args.conditions=='all' else args.conditions.split(',')
    if any(name not in conditions for name in names):
        p.error('unknown condition')
    if (args.conditions!='clean' or args.inside) and not args.inside:
        p.error('netem conditions require --isolate')
    if args.inside:
        if not args.parent_netns or os.stat('/proc/self/ns/net').st_ino==args.parent_netns:
            raise RuntimeError('refusing network changes without a newly owned namespace')
        subprocess.run(['ip','link','set','lo','up'],check=True)
        runtime_tmp=out/'runtime'
        runtime_tmp.mkdir(exist_ok=True)
        subprocess.run(['mount','-t','tmpfs','-o','mode=700,size=3G','tmpfs',str(runtime_tmp)],check=True)
        env.update(TMPDIR=str(runtime_tmp),GOTMPDIR=str(runtime_tmp))
    deadline=time.monotonic()+args.soak_hours*3600 if args.soak_hours else None
    failed=0;iteration=0;summary={}
    while True:
        for name in names:
            condition=conditions[name]
            stem=f'{iteration:05d}-{name}'
            if args.inside:
                subprocess.run(['ip','link','set','lo','mtu',str(condition['mtu'])],check=True)
                tc=['tc','qdisc','replace','dev','lo','root','netem','limit','10000']
                if condition['rtt_ms']:
                    tc+=['delay',str(condition['rtt_ms']/2)+'ms']
                    if condition['jitter_ms']:
                        tc+=[str(condition['jitter_ms'])+'ms','distribution','normal']
                tc+=['loss','random',str(condition['loss_percent'])+'%']
                subprocess.run(tc,check=True)
                save(out/(stem+'-netem-before.json'),dict(condition=condition,command=tc,qdisc=capture(['tc','-s','-j','qdisc','show','dev','lo']),
                     loopback=capture(['ip','-j','address','show','dev','lo']),note='delay is one way per loopback traversal; proxy application RTT traverses two local connections'))
            config=out/(stem+'-config.json');save(config,scenarios(args.profile,args.suite))
            raw=out/(stem+'-raw.jsonl')
            env.update(SPLICORE_PERF_CONFIG=str(config),SPLICORE_PERF_RAW=str(raw))
            test='TestP2NetworkBaseline' if args.suite=='native' else 'TestP2WireGuardBaseline'
            command=[str(binary),'-test.v','-test.run=^'+test+'$','-test.timeout=30m']
            stamp=time.monotonic()
            with (out/(stem+'-test.log')).open('w',encoding='utf-8') as log:
                result=subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
            row=dict(exit_code=result.returncode,command=command,elapsed_seconds=time.monotonic()-stamp,results=summarize(raw) if raw.exists() else {})
            save(out/(stem+'-summary.json'),row);summary[stem]=row
            failed+=bool(result.returncode)
            print(f'{stem}: exit={result.returncode}, {len(row["results"])} measured scenarios',flush=True)
            if args.inside:
                save(out/(stem+'-netem-after.json'),capture(['tc','-s','-j','qdisc','show','dev','lo']))
        iteration+=1
        save(out/'summary.json',dict(classification='BASELINE' if not failed else 'FAIL',iterations=iteration,failed_runs=failed,soak_requested_hours=args.soak_hours,
                                   soak_status='EXECUTED' if deadline and time.monotonic()>=deadline else 'NOT EXECUTED',runs=summary))
        if failed or (deadline is None and iteration>=args.repeat) or (deadline is not None and time.monotonic()>=deadline):
            break
    return int(bool(failed))


if __name__=='__main__':
    sys.exit(main())
