#!/usr/bin/env python3
"""Finite native Windows DNS fixture controls, separate from qualification."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
FIXED = 'c2041f765046f362850b555078a9155f6ca3aa6e'
TARGET = 'TestProtectedDNSUDPTruncationFallsBackToTCP'
FALLBACK = 'internal/splicore/networkruntime/dns_fallback_test.go'
DNS = 'internal/splicore/networkruntime/dns_test.go'
DUAL = 'internal/splicore/testkit/dual_peer_port.go'

OWNED_METHOD = '''
// OwnedSockets exposes the retained pair for in-process test servers. Callers
// use these exact sockets and keep the lease until both servers have stopped;
// they must not release and rebind them during handoff.
func (p *DualPeerPort) OwnedSockets() (net.Listener, net.PacketConn) {
 var tcp net.Listener
 var udp net.PacketConn
 for _, socket := range p.sockets {
  if listener, ok := socket.(net.Listener); ok { tcp = listener }
  if packet, ok := socket.(net.PacketConn); ok { udp = packet }
 }
 return tcp, udp
}
'''

PAIR_HELPER = '''
// dnsFallbackPairFixture owns both kernel sockets before either DNS server
// starts. TCP and UDP use the same literal IP and numeric port throughout.
func dnsFallbackPairFixture(t *testing.T, tcpHandler, udpHandler dns.Handler) access.Endpoint {
 t.Helper()
 pair := testkit.ReserveDualPeerPort(t, "127.0.0.1")
 tcp, udp := pair.OwnedSockets()
 if tcp == nil || udp == nil || tcp.Addr().String() != udp.LocalAddr().String() {
  t.Fatal("DNS fallback requires one retained TCP/UDP endpoint")
 }
 for _, server := range []*dns.Server{{Listener:tcp, Net:"tcp", Handler:tcpHandler}, {PacketConn:udp, Net:"udp", Handler:udpHandler}} {
  ready, done := make(chan struct{}), make(chan error, 1)
  server.NotifyStartedFunc = func() { close(ready) }
  go func() { done <- server.ActivateAndServe() }()
  <-ready
  t.Cleanup(func() {
   if err := server.Shutdown(); err != nil { t.Error(err) }
   if err := <-done; err != nil { t.Error(err) }
  })
 }
 return access.Endpoint{Host:pair.Host, Port:uint16(pair.Port)}
}
'''

PROBE = r'''//go:build windows

package networkruntime
import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "os/exec"
 "strconv"
 "syscall"
 "testing"
 "time"
 "golang.org/x/sys/windows"
)
// Winsock2.h defines SO_EXCLUSIVEADDRUSE as the complement of SO_REUSEADDR.
const p39Exclusive = ^windows.SO_REUSEADDR
var p39Address string
func p39Err(err error) map[string]any {
 var errno syscall.Errno
 errors.As(err,&errno)
 return map[string]any{"text":fmt.Sprint(err),"errno":uint64(errno),"error_type":fmt.Sprintf("%T",err)}
}
func p39Options(socket any) map[string]any {
 out:=map[string]any{}
 if c,ok:=socket.(interface{SyscallConn()(syscall.RawConn,error)});ok {
  raw,err:=c.SyscallConn();if err!=nil {out["raw_error"]=p39Err(err);return out}
  err=raw.Control(func(fd uintptr) {
   for name,option:=range map[string]int{"exclusive":p39Exclusive,"reuse":windows.SO_REUSEADDR} {
    v,e:=windows.GetsockoptInt(windows.Handle(fd),windows.SOL_SOCKET,option)
    out[name]=map[string]any{"value":v,"error":p39Err(e)}
   }
  });out["control_error"]=p39Err(err)
 }
 return out
}
func p39Emit(t *testing.T,stage,address string,err error,extra map[string]any) {
 p39Address=address
 record:=map[string]any{"at":time.Now().UTC(),"stage":stage,"pid":os.Getpid(),"address":address,"error":p39Err(err),"extra":extra}
 b,_:=json.Marshal(record);t.Logf("P39_SOCKET %s",b)
}
func p39Snapshot(t *testing.T,stage,address string) {
 if os.Getenv("SPLICORE_P39_OBSERVE")!="1" {return}
 record:=map[string]any{}
 commands:=[][]string{{"netstat","-ano"},{"netsh","interface","ipv4","show","excludedportrange","protocol=udp"},{"netsh","interface","ipv4","show","excludedportrange","protocol=tcp"}}
 _,port,_:=net.SplitHostPort(address);n,_:=strconv.Atoi(port)
 if n>0 {
  script:=fmt.Sprintf("$ErrorActionPreference='Continue'; Get-NetUDPEndpoint -LocalPort %d | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress; Get-NetTCPConnection -LocalPort %d | Select-Object LocalAddress,LocalPort,State,OwningProcess | ConvertTo-Json -Compress",n,n)
  commands=append(commands,[]string{"powershell","-NoProfile","-NonInteractive","-Command",script})
 }
 for i,args:=range commands {b,e:=exec.Command(args[0],args[1:]...).CombinedOutput();record[strconv.Itoa(i)]=map[string]any{"command":args,"output":string(b),"error":p39Err(e)}}
 p39Emit(t,stage,address,nil,record)
}
func TestP39SocketOwner(t *testing.T) {
 address:=os.Getenv("SPLICORE_P39_CHILD_ADDRESS");if address=="" {return}
 lc:=net.ListenConfig{}
 if os.Getenv("SPLICORE_P39_CHILD_EXCLUSIVE")=="1" {
  lc.Control=func(_, _ string, raw syscall.RawConn) error {
   var err error
   if e:=raw.Control(func(fd uintptr){err=windows.SetsockoptInt(windows.Handle(fd),windows.SOL_SOCKET,p39Exclusive,1)});e!=nil {return e};return err
  }
 }
 socket,err:=lc.ListenPacket(context.Background(),"udp4",address)
 record:=map[string]any{"pid":os.Getpid(),"address":address,"error":p39Err(err)}
 if err==nil {record["local"]=socket.LocalAddr().String();record["options"]=p39Options(socket)}
 b,_:=json.Marshal(record);fmt.Println(string(b))
 if err==nil {_,_=io.Copy(io.Discard,os.Stdin);_ = socket.Close()}
}
func p39Contender(t *testing.T,address string,paired bool) {
 mode:=os.Getenv("SPLICORE_P39_CONTENDER");if mode=="" {return}
 _,port,err:=net.SplitHostPort(address);if err!=nil {t.Fatal(err)}
 host:="127.0.0.1";if mode=="exclusive" {host="0.0.0.0"}
 executable,err:=os.Executable();if err!=nil {t.Fatal(err)}
 command:=exec.Command(executable,"-test.run=^TestP39SocketOwner$")
 command.Env=append(os.Environ(),"SPLICORE_P39_CHILD_ADDRESS="+net.JoinHostPort(host,port),"SPLICORE_P39_CHILD_EXCLUSIVE="+map[bool]string{true:"1",false:"0"}[mode=="exclusive"])
 stdin,err:=command.StdinPipe();if err!=nil {t.Fatal(err)}
 stdout,err:=command.StdoutPipe();if err!=nil {t.Fatal(err)}
 if err=command.Start();err!=nil {t.Fatal(err)}
 t.Cleanup(func(){stdin.Close();io.Copy(io.Discard,stdout);if err:=command.Wait();err!=nil {t.Error("controlled owner did not exit cleanly",err)}})
 var record struct {PID int `json:"pid"`; Address string `json:"address"`; Error struct {Errno uint64 `json:"errno"`} `json:"error"`; Options map[string]any `json:"options"`}
 if err=json.NewDecoder(stdout).Decode(&record);err!=nil {t.Fatal(err)}
 p39Emit(t,"contender-result",address,nil,map[string]any{"child_pid":record.PID,"child_address":record.Address,"child_errno":record.Error.Errno,"child_options":record.Options,"child_executable":command.Path,"paired":paired,"mode":mode})
 if paired {
  if record.Error.Errno!=10013 && record.Error.Errno!=10048 {t.Fatal("paired fixture did not exclude independent UDP owner",record.Error.Errno)}
 } else if record.Error.Errno!=0 {t.Fatal("controlled UDP owner could not acquire the unreserved endpoint",record.Error.Errno)}
 p39Snapshot(t,"contender-snapshot",address)
}
func p39TCP(t *testing.T,l net.Listener) {
 address:=l.Addr().String();p39Emit(t,"tcp-ready-udp-unowned",address,nil,map[string]any{"tcp_options":p39Options(l)})
 p39Contender(t,address,false)
}
func p39HavePair(t *testing.T,l net.Listener,p net.PacketConn) {
 address:=l.Addr().String();p39Address=address
 if os.Getenv("SPLICORE_P39_OBSERVE")=="1" {p39Emit(t,"tcp-udp-pair-owned",address,nil,map[string]any{"tcp":l.Addr().String(),"udp":p.LocalAddr().String(),"tcp_options":p39Options(l),"udp_options":p39Options(p)})}
 p39Contender(t,address,true)
}
func p39ListenUDP(t *testing.T,network,address string)(net.PacketConn,error) {
 p,err:=net.ListenPacket(network,address)
 extra:=map[string]any{}
 if err==nil {extra["local"]=p.LocalAddr().String();extra["options"]=p39Options(p)}
 p39Emit(t,"original-udp-bind",address,err,extra)
 if err!=nil {p39Snapshot(t,"failed-udp-bind-snapshot",address)}
 return p,err
}
func TestP39PairCleanup(t *testing.T) {
 if os.Getenv("SPLICORE_P39_CLEANUP")!="1" {return}
 if !t.Run("fallback",TestProtectedDNSUDPTruncationFallsBackToTCP) {return}
 address:=p39Address;if address=="" {t.Fatal("missing owned pair address")}
 p39Snapshot(t,"after-original-cleanup",address)
 tcp,err:=net.Listen("tcp4",address);if err!=nil {t.Fatal("TCP not released after DNS shutdown",err)};defer tcp.Close()
 udp,err:=net.ListenPacket("udp4",address);if err!=nil {t.Fatal("UDP not released after DNS shutdown",err)};defer udp.Close()
 p39Emit(t,"cleanup-both-rebound",address,nil,map[string]any{"tcp":tcp.Addr().String(),"udp":udp.LocalAddr().String()})
}
'''


def save(path, data):
    with path.open('x', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def blob(path):
    return subprocess.check_output(['git', 'show', FIXED+':'+path], cwd=ROOT).decode()


def pair_source(source):
    start = source.index('\tendpoint := dnsTCPFixture(')
    end = source.index('\tx := testkit.NewUnderlay(t)', start)
    replacement = '''\tendpoint := dnsFallbackPairFixture(t, answerHandler(&tcpQueries, "192.0.2.42"), dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
        udpQueries.Add(1)
        m := new(dns.Msg)
        m.SetReply(r)
        m.Truncated = true
        _ = w.WriteMsg(m)
    }))
'''
    source = source[:start] + replacement + source[end:]
    return source.replace('\n\t"net"', '', 1)


def make_overlay(out, paired, observed):
    replacements = {}
    files = {FALLBACK:blob(FALLBACK), DNS:blob(DNS), DUAL:blob(DUAL)}
    if paired:
        files[FALLBACK]=pair_source(files[FALLBACK]); files[DNS]+=PAIR_HELPER;files[DUAL]+=OWNED_METHOD
        files[DNS]=files[DNS].replace('tcp, udp := pair.OwnedSockets()', 'tcp, udp := pair.OwnedSockets()\n p39HavePair(t,tcp,udp)',1)
    elif observed:
        files[DNS]=files[DNS].replace('endpoint := access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}', 'p39TCP(t,l)\n endpoint := access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}',1)
        files[FALLBACK]=files[FALLBACK].replace('net.ListenPacket("udp",','p39ListenUDP(t,"udp",',1)
    for i,(name,content) in enumerate(files.items()):
        path=out/(str(i)+'-'+Path(name).name);path.write_text(content);replacements[str(ROOT/name)]=str(path)
    path=out/'p39_probe_windows_test.go';path.write_text(PROBE);replacements[str(ROOT/'internal/splicore/networkruntime/p39_probe_windows_test.go')]=str(path)
    overlay=out/'overlay.json';save(overlay,{'Replace':replacements})
    save(out/'source-proof.json',{'fixed':FIXED,'original':{n:hashlib.sha256(blob(n).encode()).hexdigest() for n in files},'observed':{n:hashlib.sha256(c.encode()).hexdigest() for n,c in files.items()},'original_assertions_tail_unchanged':files[FALLBACK][files[FALLBACK].index('\tx := testkit.NewUnderlay(t)'):]==blob(FALLBACK)[blob(FALLBACK).index('\tx := testkit.NewUnderlay(t)'):]})
    return overlay


def snapshot(out, label):
    commands=[['netstat','-ano'],['powershell','-NoProfile','-NonInteractive','-Command',"Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress"]]
    for family in ['ipv4','ipv6']:
        for protocol in ['tcp','udp']:
            for name in ['dynamicport','excludedportrange']:
                commands.append(['netsh','interface',family,'show',name,'protocol='+protocol])
    rows=[]
    for command in commands:
        result=subprocess.run(command,capture_output=True,timeout=60)
        rows.append({'command':command,'exit_code':result.returncode,'stdout':result.stdout.decode(errors='replace'),'stderr':result.stderr.decode(errors='replace')})
    save(out/(label+'.json'),{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'rows':rows})


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--campaign',choices=['original','path-control'],default='original');args=parser.parse_args()
    assert sys.platform=='win32', 'Native Windows required'
    arch=json.loads(subprocess.check_output(['go','env','-json','GOARCH','GOOS','GOVERSION'],text=True))
    assert arch['GOOS']=='windows' and arch['GOVERSION']=='go1.26.3'
    assert arch['GOARCH'] in ['arm64','amd64'] and platform.machine().lower() in ['arm64','amd64'], 'native machine/toolchain required'
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    save(out/'host.json',{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'machine':platform.machine(),'platform':platform.platform(),'go':arch,'campaign':args.campaign,'original_temp':tempfile.gettempdir(),'original_temp_realpath':os.path.realpath(tempfile.gettempdir()),'runner':{k:os.environ.get(k) for k in ['ImageOS','ImageVersion','RUNNER_ARCH','RUNNER_NAME','GITHUB_RUN_ID','GITHUB_SHA']}})
    snapshot(out,'environment-before')
    cases=[{'paired':p,'observed':o,'scope':s,'contender':''} for o in [False,True] for p in [False,True] for s in ['target','package']]
    cases += [{'paired':p,'observed':True,'scope':'target','contender':c} for c in ['ordinary','exclusive'] for p in [False,True]]
    cases += [{'paired':True,'observed':True,'scope':'cleanup','contender':''}]
    if args.campaign=='path-control':cases=[{'paired':p,'observed':True,'scope':'package','contender':''} for p in [False,True]]
    runtime_parent=out/'runtime';runtime_parent.mkdir()
    results=[]
    for i,case in enumerate(cases,1):
        dest=out/f"{i:02d}-{'paired' if case['paired'] else 'original'}-{'observed' if case['observed'] else 'pristine'}-{case['scope']}-{case['contender'] or 'natural'}";dest.mkdir()
        overlay=make_overlay(dest,case['paired'],case['observed'])
        runtime=tempfile.mkdtemp(prefix='d9-',dir=runtime_parent)
        env=dict(os.environ,TEMP=runtime,TMP=runtime,GOTMPDIR=runtime,CGO_ENABLED='0',GOMAXPROCS='4',GOTOOLCHAIN='local',GOTELEMETRY='off',GOFLAGS='-mod=readonly',SPLICORE_P39_OBSERVE='1' if case['observed'] else '',SPLICORE_P39_CONTENDER=case['contender'],SPLICORE_P39_CLEANUP='1' if case['scope']=='cleanup' else '')
        command=['go','test','-mod=readonly','-overlay='+str(overlay),'-tags=with_quic,with_utls,with_gvisor','-json','-count=1','-timeout=1200s']
        if case['scope']!='package':command+=['-run','^'+('TestP39PairCleanup' if case['scope']=='cleanup' else TARGET)+'$']
        command+=['./internal/splicore/networkruntime']
        save(dest/'identity.json',{**case,'fixed_source':FIXED,'command':command,'runtime_root':runtime,'runtime_root_realpath':os.path.realpath(runtime),'campaign':args.campaign,'go':arch,'observer':'Extra logging/snapshots and controlled child creation can alter scheduling; target assertions and timeouts unchanged.'})
        with (dest/'test.stdout').open('xb') as stdout,(dest/'test.stderr').open('xb') as stderr:
            result=subprocess.run(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,timeout=1500)
        content=(dest/'test.stdout').read_text(errors='replace')
        expected=1 if case['contender'] and not case['paired'] else 0
        met=result.returncode==expected and (expected==0 or ('contender-result' in content and 'original-udp-bind' in content))
        row={'case':dest.name,'exit_code':result.returncode,'expected_exit':expected,'expectation_met':met,'actual_test_result':'PASS' if result.returncode==0 else 'FAIL'}
        save(dest/'result.json',row);results.append(row);print(json.dumps(row),flush=True)
    snapshot(out,'environment-after')
    save(out/'campaign.json',{'cases':results,'budget':len(cases),'campaign':args.campaign,'historical_DNS_owner':'ROOT_CAUSE_UNRESOLVED until exact historical evidence supports attribution','historical_ARM64_root':'ROOT_CAUSE_UNRESOLVED','overall_PR14':'NOT_QUALIFIED'})
    return int(any(not row['expectation_met'] for row in results))


if __name__=='__main__':sys.exit(main())
