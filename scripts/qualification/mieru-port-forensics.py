#!/usr/bin/env python3
"""Bounded real-socket controls, separate from the ordinary qualification gates."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = {'M': '497f5509e1e66f28c480189b486e8fa3cbe4ba06',
            'P6': '78c3ebe451ff0b55d9765cf51722de764c0adc7d',
            'P7': '4b77bbcdc9078be69815c937467a9e865d24f8de'}
FIXTURE = 'internal/splicore/engine/testfixture/fixtures.go'
BACKEND = 'protocol/mieru/backend/mieru.go'
PROBE = r'''
package backend
import (
 "context"
 "encoding/json"
 "fmt"
 "net"
 "os"
 "reflect"
 "strings"
 "testing"
 "time"
)
func p38Event(stage string, h *mieruHandle, network, address string, err error) {
 record := map[string]any{"stage":stage,"at":time.Now().UTC(),"network":network,"address":address,"error":fmt.Sprint(err)}
 if h != nil { record["handle"] = fmt.Sprintf("%x",reflect.ValueOf(h).Pointer()) }
 if err != nil {
  for _, name := range []string{"tcp","tcp6","udp","udp6"} {
   b,_ := os.ReadFile("/proc/net/"+name); record[name] = string(b)
  }
 }
 entries,_:=os.ReadDir("/proc/self/fd")
 sockets:=map[string]string{}
 for _, e:=range entries { s,_:=os.Readlink("/proc/self/fd/"+e.Name());if strings.HasPrefix(s,"socket:"){sockets[e.Name()]=s} }
 record["socket_fds"]=sockets
 b,_:=json.Marshal(record);fmt.Fprintf(os.Stderr,"P38_SOCKET %s\n",b)
}
func TestP38EphemeralOwnership(t *testing.T) {
 rangeText,err:=os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
 if err!=nil || strings.Join(strings.Fields(string(rangeText))," ")!="42000 42000" {t.Fatal("requires isolated controlled ephemeral range",err)}
 transport:=os.Getenv("SPLICORE_P38_TRANSPORT")
 if transport!="tcp" && transport!="udp" {t.Fatal("invalid controlled transport")}
 // The target uses the unchanged fixture. Only the experimental kernel range
 // makes reuse of a released ephemeral probe deterministic.
 in:=mieruIntent(t,transport)
 endpoint:=in.Inbound.Listeners[0].Endpoint
 var local net.Addr
 if transport=="tcp" {
  destination,e:=net.Listen("tcp4","127.0.0.1:18001");if e!=nil {t.Fatal(e)};defer destination.Close()
  client,e:=net.DialTimeout("tcp4",destination.Addr().String(),time.Second);if e!=nil {t.Fatal(e)};defer client.Close()
  accepted,e:=destination.Accept();if e!=nil {t.Fatal(e)};defer accepted.Close()
  local=client.LocalAddr()
 } else {
  client,e:=net.ListenPacket("udp4","127.0.0.1:0");if e!=nil {t.Fatal(e)};defer client.Close();local=client.LocalAddr()
 }
 t.Logf("controlled_owner network=%s selected_listener=%s:%d autobound_client=%s",transport,endpoint.Host,endpoint.Port,local)
 p38Event("autobound-client-owned",nil,transport,local.String(),nil)
 h:=startMieru(t,in)
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
 if err=h.Close(ctx);err!=nil {t.Fatal(err)}
 address:=net.JoinHostPort(endpoint.Host,portString(endpoint.Port))
 if transport=="tcp" {l,e:=net.Listen("tcp4",address);if e!=nil {t.Fatal("closed listener not released",e)};l.Close()
 } else {p,e:=net.ListenPacket("udp4",address);if e!=nil {t.Fatal("closed listener not released",e)};p.Close()}
 t.Log("Start/Health/Close/rebind completed while the independent client retained its socket")
}
'''


def save(path, obj):
    with path.open('x') as f:
        json.dump(obj, f, indent=2)


def blob(commit, path):
    return subprocess.check_output(['git', 'show', commit+':'+path], cwd=ROOT).decode()


def fixed_fixture(source):
    start = source.index('func MieruIntent(')
    end = source.index('// MieruIntentAt ', start)
    source = source[:start] + '''func MieruIntent(t *testing.T, transport string) ports.RuntimeIntent {
 t.Helper()
 port := testkit.PeerPortAt(t, transport, "127.0.0.1")
 return MieruIntentAt(t, transport, access.Endpoint{Host: "127.0.0.1", Port: uint16(port)})
}

''' + source[end:]
    return source.replace('import (', 'import (\n "github.com/ike-sh/Splicore/internal/splicore/testkit"', 1)


def observed_backend(source):
    source = source.replace('if e := h.server.Start(); e != nil {', 'p38Event("start",h,"","",nil)\n if e := h.server.Start(); e != nil {\n p38Event("start-error",h,"","",e)', 1)
    source = source.replace('l, e := (&net.ListenConfig{}).Listen(ctx, network, address)', 'l, e := (&net.ListenConfig{}).Listen(ctx, network, address)\n p38Event("bind-tcp",h,network,address,e)', 1)
    source = source.replace('p, e := (&net.ListenConfig{}).ListenPacket(ctx, network, address)', 'p, e := (&net.ListenConfig{}).ListenPacket(ctx, network, address)\n p38Event("bind-udp",h,network,address,e)', 1)
    source = source.replace('close(h.done)', 'p38Event("close-joined",h,"","",nil)\n close(h.done)', 1)
    return source


def run_case(args):
    assert sys.platform == 'linux' and os.environ.get('SPLICORE_PRIVATE_NETNS') == '1'
    parent_ns = os.environ.get('SPLICORE_P38_PARENT_NETNS')
    assert parent_ns and os.readlink('/proc/self/ns/net') != parent_ns, 'must own a separate network namespace'
    causal = args.mode.startswith('causal-')
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('p36', ROOT/'scripts/qualification/integration-diagnostics.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    overlay = module.overlay(VERSIONS[args.version], out)
    replacements = json.loads(overlay.read_text())['Replace']
    fixture = blob(VERSIONS[args.version], FIXTURE)
    if args.mode == 'causal-fixed': fixture = fixed_fixture(fixture)
    path = out/'fixed-fixtures.go';path.write_text(fixture);replacements[str(ROOT/FIXTURE)]=str(path)
    backend = blob(VERSIONS[args.version], BACKEND)
    if args.mode != 'pristine': backend = observed_backend(backend)
    path = out/'fixed-mieru.go';path.write_text(backend);replacements[str(ROOT/BACKEND)]=str(path)
    path = out/'probe_test.go';path.write_text(PROBE)
    replacements[str(ROOT/'protocol/mieru/backend/p38_probe_test.go')]=str(path)
    overlay.write_text(json.dumps({'Replace': replacements}, indent=2))
    range_path = Path('/proc/sys/net/ipv4/ip_local_port_range')
    original_range = range_path.read_text()
    if causal: range_path.write_text('42000 42000\n')
    runtime = tempfile.mkdtemp(prefix='m8-')
    env = dict(os.environ, TMPDIR=runtime, GOTMPDIR=runtime, CGO_ENABLED='1' if args.profile=='race' else '0',
               GOMAXPROCS='4', GOTOOLCHAIN='local', GOTELEMETRY='off', GOFLAGS='-mod=readonly', SPLICORE_P38_TRANSPORT=args.transport)
    command = ['go','test','-mod=readonly','-overlay='+str(overlay),'-json','-count=1','-timeout=1200s','-tags=with_quic,with_utls,with_gvisor']
    if args.profile=='race': command.append('-race')
    command += ['-run','^TestP38EphemeralOwnership$' if causal else '^TestMieruNativeMultiInboundLifecycle10x$','./protocol/mieru/backend']
    save(out/'identity.json', {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'version':args.version,'commit':VERSIONS[args.version],
         'mode':args.mode,'profile':args.profile,'transport':args.transport,'command':command,'go':subprocess.check_output(['go','version'],text=True).strip(),
         'machine':platform.machine(),'kernel':platform.platform(),'cpu_affinity':sorted(os.sched_getaffinity(0)),
         'original_ephemeral_range':original_range,'experiment_ephemeral_range':range_path.read_text(),
         'observer':'extra proc/fd reads and stderr writes affect scheduling; pristine source has no bind observer'})
    with (out/'test.stdout').open('xb') as stdout, (out/'test.stderr').open('xb') as stderr:
        result = subprocess.run(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,timeout=1500)
    text = (out/'test.stdout').read_text(errors='replace')
    expected = 1 if args.mode=='causal-old' else 0
    valid = result.returncode==expected and (expected==0 or ('port_conflict' in text and 'controlled_owner' in text))
    row={'exit_code':result.returncode,'expected_exit':expected,'experiment_expectation_met':valid,
         'test_result':'FAIL' if result.returncode else 'PASS','historical_owner':'UNRESOLVED; controlled ownership is not an original-log owner reconstruction'}
    save(out/'result.json',row); print(json.dumps(row),flush=True)
    return 0 if valid else 1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['case','native']);p.add_argument('--version',choices=VERSIONS,default='P7')
    p.add_argument('--mode',choices=['pristine','observed','causal-old','causal-fixed'],default='pristine');p.add_argument('--profile',choices=['default','race'],default='default')
    p.add_argument('--transport',choices=['tcp','udp'],default='tcp');p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.action=='case': return run_case(args)
    assert platform.machine()=='x86_64' and sys.platform=='linux'
    args.output.mkdir(parents=True,exist_ok=False);results=[]
    cases=[(v,m,profile,'tcp') for m,profile in [('pristine','default'),('observed','default'),('observed','race')] for v in VERSIONS]
    cases += [('P7',m,'default',t) for t in ['tcp','udp'] for m in ['causal-old','causal-fixed']]
    for i,(version,mode,profile,transport) in enumerate(cases,1):
        dest=args.output/f'{i:02d}-{version}-{mode}-{profile}-{transport}'
        cmd=[sys.executable,str(ROOT/'scripts/dev/isolated-linux.py'),'--',sys.executable,__file__,'case','--version',version,'--mode',mode,'--profile',profile,'--transport',transport,'--output',str(dest)]
        code=subprocess.run(cmd,cwd=ROOT,env=dict(os.environ,SPLICORE_P38_PARENT_NETNS=os.readlink('/proc/self/ns/net'))).returncode;results.append({'case':dest.name,'controller_exit':code})
    save(args.output/'campaign.json',{'cases':results,'budget':13,'historical_ARM64_root':'ROOT_CAUSE_UNRESOLVED','overall_PR14':'NOT_QUALIFIED'})
    return int(any(x['controller_exit'] for x in results))


if __name__=='__main__': sys.exit(main())
