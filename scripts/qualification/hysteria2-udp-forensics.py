#!/usr/bin/env python3
"""Finite native UDP path observations; never qualify by replaying green tests."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = {'M': '497f5509e1e66f28c480189b486e8fa3cbe4ba06',
            'H': 'c963bf8a1117f203f37f00c0c2cde36c77ff6c28'}
TARGET = 'TestOwnedHysteria2ParallelAuthAttributionAndDomainTargets'
NATIVE = 'internal/splicore/engine/native/'
BACKEND = 'protocol/hysteria2/backend/'
CARRIER = 'internal/splicore/streamtransport/hysteria/'
PACKETIO = 'internal/splicore/engine/packetio/'
IMPORT = '"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"'

TRACE = r'''package packetio
import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os"
 "sync"
 "sync/atomic"
 "syscall"
 "time"
)
var p310Enabled atomic.Bool
var p310Records struct { sync.Mutex; Rows []map[string]any; Dropped int; Start time.Time }
func P310Start() { p310Records.Lock(); p310Records.Rows=nil; p310Records.Dropped=0; p310Records.Start=time.Now(); p310Enabled.Store(true); p310Records.Unlock() }
func P310(stage string, fields ...any) {
 if !p310Enabled.Load() {return}
 at:=time.Now(); row:=map[string]any{"stage":stage,"at":at.UTC(),"elapsed_ns":at.Sub(p310Records.Start).Nanoseconds()}
 for i:=0;i+1<len(fields);i+=2 {row[fields[i].(string)]=fields[i+1]}
 p310Records.Lock(); defer p310Records.Unlock()
 if len(p310Records.Rows)>=30000 {p310Records.Dropped++;return}
 row["sequence"]=len(p310Records.Rows);p310Records.Rows=append(p310Records.Rows,row)
}
func P310Hash(b []byte) string {if !p310Enabled.Load(){return ""};d:=sha256.Sum256(b);return hex.EncodeToString(d[:])}
func P310Ptr(p any) string {return fmt.Sprintf("%T:%p",p,p)}
func P310Err(e error) any {var errno syscall.Errno;errors.As(e,&errno);return map[string]any{"text":fmt.Sprint(e),"errno":uint64(errno),"type":fmt.Sprintf("%T",e)}}
func P310Save(path string) error {
 p310Enabled.Store(false);p310Records.Lock();defer p310Records.Unlock()
 b,e:=json.MarshalIndent(map[string]any{"events":p310Records.Rows,"dropped":p310Records.Dropped},"","  ");if e!=nil{return e};return os.WriteFile(path,b,0600)
}
func P310WriteTo(p net.PacketConn,b []byte,a net.Addr,user,flow int)(int,error) {
 P310("client-write-begin","user",user,"flow",flow,"local",p.LocalAddr().String(),"bytes",len(b),"payload_sha256",P310Hash(b))
 n,e:=p.WriteTo(b,a);P310("client-write-end","user",user,"flow",flow,"n",n,"error",P310Err(e));return n,e
}
func P310ReadFrom(p net.PacketConn,b []byte,user,flow int)(int,net.Addr,error) {
 n,a,e:=p.ReadFrom(b);P310("client-read-end","user",user,"flow",flow,"n",n,"remote",fmt.Sprint(a),"payload_sha256",P310Hash(b[:n]),"error",P310Err(e));return n,a,e
}
type p310Conn struct {net.Conn; label,id string}
func P310Wrap(c net.Conn,label,id string) net.Conn {P310("target-dial-success","owner",id,"target",label,"socket",P310Ptr(c),"local",c.LocalAddr().String(),"remote",c.RemoteAddr().String());return &p310Conn{c,label,id}}
func (c *p310Conn) Read(b []byte)(int,error) {n,e:=c.Conn.Read(b);P310("target-read","owner",c.id,"socket",P310Ptr(c.Conn),"local",c.LocalAddr().String(),"remote",c.RemoteAddr().String(),"n",n,"payload_sha256",P310Hash(b[:n]),"error",P310Err(e));return n,e}
func (c *p310Conn) Write(b []byte)(int,error) {n,e:=c.Conn.Write(b);P310("target-write","owner",c.id,"socket",P310Ptr(c.Conn),"local",c.LocalAddr().String(),"remote",c.RemoteAddr().String(),"n",n,"payload_sha256",P310Hash(b),"error",P310Err(e));return n,e}
func (c *p310Conn) Close() error {e:=c.Conn.Close();P310("target-close","owner",c.id,"socket",P310Ptr(c.Conn),"error",P310Err(e));return e}
'''

CARRIER_TRACE = r'''package quic
import (
 "crypto/sha256"
 "encoding/hex"
 "sync/atomic"
)
type p310Observer struct { f func(string,...any) }
var p310Hook atomic.Pointer[p310Observer]
func P310SetObserver(f func(string,...any)) {if f==nil {p310Hook.Store(nil)} else {p310Hook.Store(&p310Observer{f})}}
func p310Observe(stage string,b []byte,fields ...any) {
 observer:=p310Hook.Load();if observer==nil{return}
 sum:=sha256.Sum256(b);fields=append(fields,"frame_sha256",hex.EncodeToString(sum[:]),"bytes",len(b))
 observer.f(stage,fields...)
}
'''


def save(path, data):
    with path.open('x', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def observed_sources(commit, directory, replacements, literal):
    proofs = []

    def edit(path, changes, imports=True):
        original = git('show', commit+':'+path).decode()
        source = original
        changes = list(changes)
        if imports and IMPORT not in source:
            changes.insert(0, ('import (', 'import (\n'+IMPORT))
        for before, after in changes:
            assert source.count(before) == 1, (path, before, source.count(before))
            source = source.replace(before, after, 1)
        restored = source
        for before, after in reversed(changes):
            assert restored.count(after) == 1, (path, after)
            restored = restored.replace(after, before, 1)
        assert restored == original
        output = directory / ('observed-'+path.replace('/', '_'))
        output.write_text(source)
        replacements[str(ROOT/path)] = str(output)
        proofs.append({'path': path, 'original_sha256': hashlib.sha256(original.encode()).hexdigest(),
                       'observed_sha256': hashlib.sha256(source.encode()).hexdigest(),
                       'removing_observation_restores_all_original_bytes': True})

    edit(NATIVE+'hysteria2_owned_test.go', [
        ('import (', 'import (\n"os"'),
        ('func '+TARGET+'(t *testing.T) {', 'func '+TARGET+'(t *testing.T) {\npacketio.P310Start(); t.Cleanup(func(){if e:=packetio.P310Save(os.Getenv("SPLICORE_P310_TRACE"));e!=nil{t.Error(e)}})'),
        ('udst := localhostUDP(t)', 'udst := localhostUDP(t)\n'+('udst.Host = "'+literal+'"\n' if literal else '')+'packetio.P310("test-target","target",udst)'),
        ('\t\t\t\twant := bytes.Repeat([]byte{byte(user), byte(flow), 71, 0}, 1024)', '\t\t\t\twant := bytes.Repeat([]byte{byte(user), byte(flow), 71, 0}, 1024)\npacketio.P310("flow-map","user",user,"flow",flow,"binding",string(in.Bindings[user].ID),"local",p.LocalAddr().String(),"payload_sha256",packetio.P310Hash(want),"target",udst)'),
        ('p.WriteTo(want, nil)', 'packetio.P310WriteTo(p,want,nil,user,flow)'),
        ('n, _, e := p.ReadFrom(b)', 'n, _, e := packetio.P310ReadFrom(p,b,user,flow)'),
        ('s := h.(ports.AttributedStats).BindingStats(b.ID)', 's := h.(ports.AttributedStats).BindingStats(b.ID)\npacketio.P310("binding-final-stats","binding",string(b.ID),"stats",s)'),
        ('if h.Stats().Active != 0 {\n\t\tt.Fatal("parallel resource baseline")', 'packetio.P310("final-resource","stats",h.Stats())\nif h.Stats().Active != 0 {\n\t\tt.Fatal("parallel resource baseline")'),
    ])
    edit(NATIVE+'localhost_fixture_test.go', [
        ('n, peer, err := packet.ReadFrom(buffer)', 'n, peer, err := packet.ReadFrom(buffer)\npacketio.P310("echo-read","network",network,"local",packet.LocalAddr().String(),"peer",fmt.Sprint(peer),"n",n,"payload_sha256",packetio.P310Hash(buffer[:n]),"error",packetio.P310Err(err))'),
        ('written, err := packet.WriteTo(buffer[:n], peer)', 'written, err := packet.WriteTo(buffer[:n], peer)\npacketio.P310("echo-write","network",network,"local",packet.LocalAddr().String(),"peer",fmt.Sprint(peer),"n",written,"payload_sha256",packetio.P310Hash(buffer[:n]),"error",packetio.P310Err(err))'),
    ])
    edit(NATIVE+'hysteria2.go', [
        ('return id, ok\n}', 'packetio.P310("auth-result","binding",id,"accepted",ok)\nreturn id, ok\n}'),
        ('counted := traffic.Packet(p, h.total, user)', 'packetio.P310("server-udp-start","binding",id,"packet",packetio.P310Ptr(p))\ndefer func(){packetio.P310("server-udp-exit","binding",id,"packet",packetio.P310Ptr(p),"ctx_error",packetio.P310Err(ctx.Err()))}()\ncounted := traffic.Packet(p, h.total, user)'),
        ('return h.protected.DialContext(ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))', 'packetio.P310("target-dial-begin","binding",id,"packet",packetio.P310Ptr(p),"target",dst)\nc,e:=h.protected.DialContext(ctx,"udp",net.JoinHostPort(dst.Host,portString(dst.Port)))\nif e!=nil{packetio.P310("target-dial-error","binding",id,"target",dst,"error",packetio.P310Err(e));return nil,e};return packetio.P310Wrap(c,dst.Host,id),nil'),
    ])
    edit('internal/splicore/engine/traffic/traffic.go', [
        ('n, a, e := p.PacketConn.ReadFrom(b)', 'n, a, e := p.PacketConn.ReadFrom(b)\npacketio.P310("account-upload","packet",packetio.P310Ptr(p.PacketConn),"n",n,"payload_sha256",packetio.P310Hash(b[:n]),"error",packetio.P310Err(e))'),
        ('n, e := p.PacketConn.WriteTo(b, a)', 'n, e := p.PacketConn.WriteTo(b, a)\npacketio.P310("account-download","packet",packetio.P310Ptr(p.PacketConn),"n",n,"payload_sha256",packetio.P310Hash(b),"error",packetio.P310Err(e))'),
    ])
    edit(BACKEND+'packet.go', [
        ('p.closeOnce.Do(func() {', 'p.closeOnce.Do(func() {\npacketio.P310("packet-close","packet",packetio.P310Ptr(p),"session",p.session,"ctx_error",packetio.P310Err(p.ctx.Err()))'),
        ('maxSize := 1197', 'packetio.P310("packet-write","packet",packetio.P310Ptr(p),"session",session,"bytes",len(b),"payload_sha256",packetio.P310Hash(b),"target",dst)\nmaxSize := 1197'),
        ('if err := send(writeCtx, frame); err != nil {', 'packetio.P310("fragment-send","packet",packetio.P310Ptr(p),"session",session,"frame_sha256",packetio.P310Hash(frame))\nif err := send(writeCtx, frame); err != nil {\npacketio.P310("fragment-send-error","session",session,"error",packetio.P310Err(err))'),
        ('p.Deliver(d.Payload, netaddr.UDP(d.Destination))', 'packetio.P310("packet-deliver","packet",packetio.P310Ptr(p),"session",d.Session,"packet_id",d.Packet,"bytes",len(d.Payload),"payload_sha256",packetio.P310Hash(d.Payload))\np.Deliver(d.Payload, netaddr.UDP(d.Destination))'),
    ], imports=False)
    edit(BACKEND+'server.go', [
        ('\t\t\tdefault:\n\t\t\t}', '\t\t\tdefault:\npacketio.P310("server-incoming-drop","connection",packetio.P310Ptr(p.connection),"frame_sha256",packetio.P310Hash(b))\n\t\t\t}'),
        ('d, e := wire.DecodeDatagram(b)', 'd, e := wire.DecodeDatagram(b)\npacketio.P310("server-frame","connection",packetio.P310Ptr(p.connection),"binding",p.connection.Identity(),"session",d.Session,"packet_id",d.Packet,"index",d.Index,"count",d.Count,"frame_sha256",packetio.P310Hash(b),"error",packetio.P310Err(e))'),
        ('d, complete := fragments.Add(d)', 'd, complete := fragments.Add(d)\npacketio.P310("server-assembly","connection",packetio.P310Ptr(p.connection),"binding",p.connection.Identity(),"session",d.Session,"complete",complete,"pending",fragments.Pending(),"payload_sha256",packetio.P310Hash(d.Payload))'),
    ])
    edit(BACKEND+'client.go', [
        ('peer.packets[peer.next] = p', 'peer.packets[peer.next] = p\npacketio.P310("client-packet-open","connection",packetio.P310Ptr(q),"packet",packetio.P310Ptr(p),"session",p.session,"local",q.QUIC.LocalAddr().String(),"remote",q.QUIC.RemoteAddr().String(),"target",dst)'),
        ('d, e := wire.DecodeDatagram(b)', 'd, e := wire.DecodeDatagram(b)\npacketio.P310("client-frame","connection",packetio.P310Ptr(p.connection),"session",d.Session,"packet_id",d.Packet,"index",d.Index,"count",d.Count,"frame_sha256",packetio.P310Hash(b),"error",packetio.P310Err(e))'),
        ('if packet == nil || packet.ctx.Err() != nil {', 'if packet == nil || packet.ctx.Err() != nil {\npacketio.P310("client-unknown-session","session",d.Session)'),
    ])
    edit(CARRIER+'connection.go', [
        ('packetio.NewWriter(ctx, q.SendDatagram)', 'packetio.NewWriter(ctx,func(b []byte) error {e:=q.SendDatagram(b);packetio.P310("quic-send-admission","local",q.LocalAddr().String(),"remote",q.RemoteAddr().String(),"frame_sha256",packetio.P310Hash(b),"bytes",len(b),"error",packetio.P310Err(e));return e})'),
        ('b, e := c.QUIC.ReceiveDatagram(c.ctx)', 'b, e := c.QUIC.ReceiveDatagram(c.ctx)\npacketio.P310("quic-receive","connection",packetio.P310Ptr(c),"binding",c.Identity(),"local",c.QUIC.LocalAddr().String(),"remote",c.QUIC.RemoteAddr().String(),"frame_sha256",packetio.P310Hash(b),"bytes",len(b),"error",packetio.P310Err(e))'),
        ('c.discarded.Add(1)', 'c.discarded.Add(1)\npacketio.P310("carrier-preauth-drop","connection",packetio.P310Ptr(c),"admitted",c.admitted.Load(),"udp",c.UDP,"frame_sha256",packetio.P310Hash(b))'),
        ('\t\t\tdefault:\n\t\t\t}', '\t\t\tdefault:\npacketio.P310("carrier-queue-drop","connection",packetio.P310Ptr(c),"frame_sha256",packetio.P310Hash(b))\n\t\t\t}'),
        ('c.workers.Wait()', 'c.workers.Wait()\npacketio.P310("carrier-joined","connection",packetio.P310Ptr(c),"binding",c.Identity(),"discarded",c.discarded.Load())'),
    ], imports=False)
    edit(PACKETIO+'queue.go', [
        ('case q.in <- v:\n\tdefault:\n\t}', 'case q.in <- v:\nP310("queue-delivered","queue",P310Ptr(q),"bytes",len(payload),"payload_sha256",P310Hash(payload))\n\tdefault:\nP310("queue-drop","queue",P310Ptr(q),"payload_sha256",P310Hash(payload))\n\t}'),
    ], imports=False)
    trace = directory/'p310_forensics.go'
    trace.write_text(TRACE)
    replacements[str(ROOT/PACKETIO/'p310_forensics.go')] = str(trace)
    save(directory/'observation-proof.json', {'files': proofs, 'literal_target_contrast': literal or None,
                                             'original_assertions_preserved': True,
                                             'disturbance': 'Bounded in-memory records use allocation, hashes, locks and time reads; they may change scheduling. Disk serialization occurs after original cleanup.'})


def carrier_observer(out, replacements):
    module=json.loads(subprocess.check_output(['go','list','-m','-json','github.com/apernet/quic-go'],cwd=ROOT,text=True))
    assert module['Version']=='v0.63.1-0.20261004180939-a10df75c260c'
    original_directory=Path(module['Dir']).resolve()
    # Go intentionally rejects overlays inside GOMODCACHE. Observe a byte-for-
    # byte copy of this pinned third-party dependency via a private modfile;
    # neither the module cache nor the project's go.mod/go.sum is modified.
    directory=out/'quic-carrier-observation-module'
    shutil.copytree(original_directory,directory)
    modfile=out/'carrier-observation.mod';sumfile=out/'carrier-observation.sum'
    modfile.write_bytes(git('show',VERSIONS['H']+':go.mod'))
    sumfile.write_bytes(git('show',VERSIONS['H']+':go.sum'))
    subprocess.run(['go','mod','edit','-modfile='+str(modfile),'-replace=github.com/apernet/quic-go='+str(directory)],cwd=ROOT,check=True)
    proof=[]
    edits={
      'connection.go':[
        ('return c.datagramQueue.Add(f)', 'e:=c.datagramQueue.Add(f)\np310Observe("library-send-admission",f.Data,"queue",fmt.Sprintf("%p",c.datagramQueue),"local",c.LocalAddr().String(),"remote",c.RemoteAddr().String(),"maxDataLen",int64(maxDataLen),"error",fmt.Sprint(e));return e'),
      ],
      'datagram_queue.go':[
        ('"context"','"context"\n"fmt"'),
        ('h.sendQueue.PushBack(f)', 'h.sendQueue.PushBack(f)\np310Observe("library-queued",f.Data,"queue",fmt.Sprintf("%p",h),"queued_count",h.sendQueue.Len())'),
        ('\tif !queued && h.logger.Debug() {', '\tp310Observe("library-received-queue",f.Data,"queue",fmt.Sprintf("%p",h),"queued",queued)\n\tif !queued && h.logger.Debug() {'),
      ],
      'packet_packer.go':[
        ('pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})', 'p310Observe("library-packer-selected",f.Data,"queue",fmt.Sprintf("%p",p.datagramQueue),"size",int64(size),"maxPayloadSize",int64(maxPayloadSize),"ackLength",int64(pl.length))\npl.frames = append(pl.frames, ackhandler.Frame{Frame: f})'),
        ('} else if pl.ack == nil {', '} else if pl.ack == nil {\np310Observe("library-discard-no-ack",f.Data,"queue",fmt.Sprintf("%p",p.datagramQueue),"size",int64(size),"maxPayloadSize",int64(maxPayloadSize),"ackLength",int64(pl.length))'),
        ('if p.peekTimes > DatagramFrameMaxPeekTimes {', 'if p.peekTimes > DatagramFrameMaxPeekTimes {\np310Observe("library-discard-peeks",f.Data,"queue",fmt.Sprintf("%p",p.datagramQueue),"size",int64(size),"maxPayloadSize",int64(maxPayloadSize),"ackLength",int64(pl.length),"peekTimes",p.peekTimes)'),
      ],
    }
    for name,changes in edits.items():
        original=(directory/name).read_text();source=original
        for before,after in changes:
            assert source.count(before)==1,(name,before,source.count(before));source=source.replace(before,after,1)
        restored=source
        for before,after in reversed(changes):restored=restored.replace(after,before,1)
        assert restored==original
        path=out/('carrier-'+name);path.write_text(source);replacements[str(directory/name)]=str(path)
        proof.append({'file':name,'original_sha256':hashlib.sha256(original.encode()).hexdigest(),'observed_sha256':hashlib.sha256(source.encode()).hexdigest(),'removing_observation_restores_all_original_bytes':True})
    helper=out/'p310_carrier_trace.go';helper.write_text(CARRIER_TRACE);replacements[str(directory/'p310_carrier_trace.go')]=str(helper)
    native_path=replacements[str(ROOT/NATIVE/'hysteria2_owned_test.go')]
    source=Path(native_path).read_text()
    source=source.replace('import (','import (\n"github.com/apernet/quic-go"',1)
    source=source.replace('packetio.P310Start();','packetio.P310Start();quic.P310SetObserver(packetio.P310);',1)
    source=source.replace('t.Cleanup(func(){if e:=packetio.P310Save','t.Cleanup(func(){quic.P310SetObserver(nil);if e:=packetio.P310Save',1)
    Path(native_path).write_text(source)
    save(out/'carrier-proof.json',{'module':module,'private_third_party_copy':str(directory),'private_modfile':str(modfile),'files':proof,'native_final_sha256':hashlib.sha256(source.encode()).hexdigest(),'no_on_disk_module_cache_change':True,'production_go_mod_go_sum_unchanged':True,'pinned_original_version_unchanged':True,'budget':4,'observation_only':'Only a copied pinned third-party module is selected by the private diagnostic modfile, with overlay logging at admission/queue/selected/discard branches. No conditional/size/ACK/queue policy changes; this is not the production qualification build.'})


def make_overlay(version, out, observed, literal='', carrier=False):
    spec = importlib.util.spec_from_file_location('p36', ROOT/'scripts/qualification/integration-diagnostics.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    mapping = module.overlay(VERSIONS[version], out)
    replacements = json.loads(mapping.read_text())['Replace']
    if observed:
        observed_sources(VERSIONS[version], out, replacements, literal)
        if carrier:
            carrier_observer(out,replacements)
    mapping.write_text(json.dumps({'Replace': replacements}, indent=2))
    return mapping


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--local-sanity', action='store_true')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--campaign', choices=['natural','carrier'], default='natural')
    args = parser.parse_args()
    go = json.loads(subprocess.check_output(['go','env','-json','GOARCH','GOOS','GOVERSION'], text=True))
    arch = {'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}.get(platform.machine().lower())
    assert arch == go['GOARCH'] and go['GOVERSION'] == 'go1.26.3'
    assert (sys.platform == 'win32' and arch in ['arm64','amd64']) or (sys.platform == 'linux' and (arch == 'arm64' or args.local_sanity or args.prepare_only))
    if sys.platform == 'linux' and not args.prepare_only:
        assert os.environ.get('SPLICORE_PRIVATE_NETNS') == '1'
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    save(out/'host.json',{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'go':go,'machine':platform.machine(),'platform':platform.platform(),'runner':{k:os.environ.get(k) for k in ['ImageOS','ImageVersion','RUNNER_ARCH','RUNNER_OS','RUNNER_NAME','GITHUB_RUN_ID','GITHUB_SHA']},'cpu_count':os.cpu_count(),'cpu_affinity':sorted(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else None})
    cases = [{'version':v,'observed':o,'scope':s,'literal':''} for o in [False,True] for v in ['M','H'] for s in ['target','package']]
    cases += [{'version':'H','observed':True,'scope':'target','literal':ip} for ip in ['127.0.0.1','::1']]
    if args.campaign=='carrier':
        assert (sys.platform=='win32' and arch=='arm64') or args.prepare_only
        cases=[{'version':'H','observed':True,'scope':'package','literal':''} for _ in range(4)]
    if args.local_sanity or args.prepare_only:
        cases=[{'version':'H','observed':o,'scope':'target','literal':''} for o in [False,True]]
    save(out/'registered-cases.json',{'cases':cases,'budget':len(cases),'prepare_only':args.prepare_only,'versions':VERSIONS})
    rows=[]
    for i,case in enumerate(cases,1):
        dest=out/f"{i:02d}-{case['version']}-{'buffered' if case['observed'] else 'pristine'}-{case['scope']}-{case['literal'].replace(':','6') or 'domain'}";dest.mkdir()
        overlay=make_overlay(case['version'],dest,case['observed'],case['literal'],args.campaign=='carrier')
        if args.prepare_only:
            continue
        if sys.platform=='win32':
            parent=out/'runtime';parent.mkdir(exist_ok=True)
            runtime=Path(tempfile.mkdtemp(prefix='hy2-',dir=parent))
        else:
            runtime=Path(tempfile.mkdtemp(prefix='h10-'))
        env=dict(os.environ,TEMP=str(runtime),TMP=str(runtime),TMPDIR=str(runtime),GOTMPDIR=str(runtime),GOMAXPROCS='4',CGO_ENABLED='0',GOTOOLCHAIN='local',GOTELEMETRY='off',GOFLAGS='-mod=readonly',SPLICORE_P310_TRACE=str(dest/'trace.json'))
        command=['go','test','-mod=readonly','-overlay='+str(overlay),'-json','-count=1','-timeout=1200s']
        if args.campaign=='carrier':command+=['-modfile='+str(dest/'carrier-observation.mod')]
        if case['scope']=='target':command+=['-run','^'+TARGET+'$']
        command+=['./internal/splicore/engine/native']
        save(dest/'identity.json',{**case,'fixed_source':VERSIONS[case['version']],'fixed_tree':git('rev-parse',VERSIONS[case['version']]+'^{tree}').decode().strip(),'command':command,'runtime':str(runtime),'runtime_realpath':os.path.realpath(runtime),'go':go,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
        with (dest/'test.stdout').open('xb') as stdout,(dest/'test.stderr').open('xb') as stderr:
            result=subprocess.run(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,timeout=1500)
        shutil.move(str(runtime),str(dest/'runtime-retained'))
        events=[]
        for line in (dest/'test.stdout').read_text(errors='replace').splitlines():
            try:e=json.loads(line)
            except ValueError:continue
            if e.get('Test')==TARGET and e.get('Action') in ['pass','fail','skip']:events.append(e)
        row={'case':dest.name,'exit_code':result.returncode,'actual_process_result':'PASS' if result.returncode==0 else 'FAIL','target_results':events}
        save(dest/'result.json',row);rows.append(row);print(json.dumps(row),flush=True)
    save(out/'campaign.json',{'cases':rows,'budget':len(cases),'prepare_only':args.prepare_only,'overall_PR14':'NOT_QUALIFIED','historical_ARM64':'ROOT_CAUSE_UNRESOLVED'})
    return int(any(r['exit_code']!=0 for r in rows))


if __name__=='__main__':sys.exit(main())
