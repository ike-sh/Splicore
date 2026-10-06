"""Real SS peers in a loopback-only Linux network namespace.

Usage: python3 scripts/splicore-shadowsocks-interop.py external-evidence
Pinned reference binaries are reused read-only. Synthetic configs are temporary,
outside the source tree. Readiness observation never retries test traffic.
"""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("fixture", pathlib.Path(__file__).with_name("splicore-snell-interop.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

def ready(proc, predicate):
    deadline = time.monotonic() + 15
    while not predicate():
        if proc.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("owned peer readiness failed")
        os.sched_yield()

def listening(port):
    return any(int(line.split()[1].split(":")[1], 16) == port and line.split()[3] == "0A"
               for path in ("/proc/net/tcp", "/proc/net/tcp6")
               for line in pathlib.Path(path).read_text().splitlines()[1:])

def main():
    evidence = pathlib.Path(sys.argv[1]).resolve()
    assert not evidence.is_relative_to(pathlib.Path(__file__).resolve().parent.parent)
    assert len(subprocess.check_output(["ip", "-o", "link", "show"]).splitlines()) == 1
    evidence.mkdir(parents=True, exist_ok=True)
    root = evidence.parent
    exe = root / "artifacts/splicore-accepted-race"
    refs = pathlib.Path("/mnt/d/splicore-validation/splicore-phase2-20261001/clients")
    records = {r["client"]:r for r in json.loads((refs / "clients.json").read_text())}
    for name in ("sing-box", "mihomo"):
        assert hashlib.sha256((refs / name).read_bytes()).hexdigest() == records[name]["binary_sha256"]
    (evidence / "references.json").write_text(json.dumps(records, indent=2))
    os.umask(0o077)
    children, logs, secrets, rows = [], [], [], []
    tcp = fixture.EchoTCP(("127.0.0.1", 0), fixture.Echo)
    udp = fixture.EchoUDP(("127.0.0.1", 0), fixture.UDPEcho)
    threads = []
    for server in (tcp, udp):
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); threads.append(thread)
    private_base = pathlib.Path("/root/splicore-phase16-private")
    private_base.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ss-private-", dir=private_base) as directory:
        work = pathlib.Path(directory)
        state = work / "state"; state.mkdir(mode=0o700)
        key, api = state / "key", work / "control.sock"
        subprocess.run([str(exe), "key", "init", "--file", str(key)], check=True, stdout=subprocess.DEVNULL)
        bootstrap = work / "bootstrap.yaml"
        bootstrap.write_text(f"schema: 1\nstate_directory: {state}\nkey_file: {key}\napi:\n  unix_socket: {api}\n")
        def launch(args, name):
            log = (evidence / (name + ".log")).open("wb"); logs.append(log)
            p = subprocess.Popen(list(map(str,args)), stdout=log, stderr=subprocess.STDOUT); children.append(p); return p
        def request(method, path, body=None):
            c = fixture.UnixHTTP(api)
            try:
                c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers={"Content-Type":"application/json"})
                r = c.getresponse(); raw = r.read()
                if r.status != 200: raise RuntimeError(f"API rejected {path} status={r.status}")
                if not path.endswith("/export"): assert not any(s.encode() in raw for s in secrets)
                return json.loads(raw)
            finally: c.close()
        def mutation(document):
            p = request("POST", "/api/v1/client/plan", document)
            return request("POST", "/api/v1/client/apply", {"document":document,"digest":p["digest"],"revision":p["revision"]})
        def key_for(method):
            value = base64.b64encode(os.urandom(16 if "aes-128" in method else 32)).decode() if method.startswith("2022-") else "SYNTHETIC-SS-"+os.urandom(18).hex()
            secrets.append(value); return value
        def reference(name, config, local, label):
            home = work / label; home.mkdir(); path = home / "config.json"; path.write_text(json.dumps(config))
            if name == "sing-box": p = launch([refs/name,"run","-c",path],label)
            else:
                controller = home / "controller.sock"; config["external-controller-unix"] = str(controller); path.write_text(json.dumps(config))
                p = launch([refs/name,"-d",home,"-f",path],label)
            ready(p,lambda:listening(local))
            if name == "mihomo":
                ready(p,lambda:controller.exists()); c = fixture.UnixHTTP(controller)
                try:
                    c.request("PUT","/configs?force=true",json.dumps({"path":str(path)}),headers={"Content-Type":"application/json"});r=c.getresponse();r.read();assert r.status==204
                finally:c.close()
            return p
        def transfer(client, server, method, port, mode="single"):
            fixture.tcp_payload(port,tcp.server_address,32768)
            fixture.udp_payload(port,udp.server_address)
            fixture.tcp_payload(port,tcp.server_address,262144)
            row=dict(client=client,server=server,method=method,mode=mode,TCP="PASS",UDP="PASS",bytes_TCP=294912,result="PASS")
            rows.append(row);print(json.dumps(row),flush=True)
        try:
            daemon = launch([exe,"run","--config",bootstrap],"splicore-daemon")
            ready(daemon,lambda:api.exists());request("GET","/api/v1/system")
            methods=("aes-128-gcm","aes-256-gcm","chacha20-ietf-poly1305","2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")
            for method in methods:
                remote = fixture.free_port(); multi = method.startswith("2022-blake3-aes")
                users = [{"account_name":"synthetic-A","key" if method.startswith("2022-") else "password":key_for(method)}]
                if multi:users.append({"account_name":"synthetic-B","key":key_for(method)})
                doc = {"schema":1,"name":"interop-"+method,"listener":{"host":"127.0.0.1","port":remote},"display_endpoint":{"host":"127.0.0.1","port":remote},"settings":{"method":method,"udp":True,"multi_user":multi},"users":users}
                if multi:doc["server_key"]=key_for(method)
                input_file, plan_file = work / "inbound.json", work / "plan.json"
                input_file.write_text(json.dumps(doc))
                subprocess.run([str(exe),"inbound","validate","--protocol","shadowsocks","--file",str(input_file)],check=True,stdout=subprocess.DEVNULL)
                plan_file.write_bytes(subprocess.check_output([str(exe),"inbound","plan","--protocol","shadowsocks","--file",str(input_file),"--config",str(bootstrap)]))
                created=json.loads(subprocess.check_output([str(exe),"inbound","apply","--protocol","shadowsocks","--file",str(input_file),"--plan",str(plan_file),"--config",str(bootstrap)]))
                for binding in created["bindings"]:
                    for name in ("sing-box","mihomo"):
                        version=records[name]["version"]
                        x=request("POST","/api/v1/inbounds/"+created["inbound_id"]+"/export",{"format":name,"client_version":version,"binding_id":binding["binding_id"]})
                        out=json.loads(x["content"]);local=fixture.free_port();label="client-"+str(len(rows))
                        if name=="sing-box":config={"log":{"disabled":True},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":local}],"outbounds":[out],"route":{"final":out["tag"]}}
                        else:config={"socks-port":local,"allow-lan":False,"bind-address":"127.0.0.1","log-level":"silent","mode":"rule","proxies":out["proxies"],"rules":["MATCH,"+out["proxies"][0]["name"]]}
                        p=reference(name,config,local,label);transfer(name,"Splicore",method,local,"multi" if multi else "single");fixture.stop(p)
                # Real Splicore client to each independent ecosystem's server.
                for name in ("sing-box","mihomo"):
                    password=key_for(method);remote=fixture.free_port();label="server-"+str(len(rows))
                    if name=="sing-box":config={"log":{"disabled":True},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":remote,"method":method,"password":password}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
                    else:config={"log-level":"silent","mode":"rule","listeners":[{"name":"ss-in","type":"shadowsocks","listen":"127.0.0.1","port":remote,"cipher":method,"password":password,"udp":True}],"rules":["MATCH,DIRECT"]}
                    p=reference(name,config,remote,label)
                    edition="2022" if method.startswith("2022-") else "2017"
                    node={"name":label,"protocol":{"protocol":"shadowsocks","wire_version":edition,"feature_profile":"base"},"endpoint":{"host":"127.0.0.1","port":remote},"transport":{"kind":"tcp"},"security":{"kind":"none"},"options":{"schema_version":1,"data":{"method":method,"udp":True}}}
                    nid=mutation({"resource":"node","action":"create","node":node,"credential":{"kind":"psk" if edition=="2022" else "password","value":password}})["id"]
                    oid=mutation({"resource":"outbound","action":"create","outbound":{"name":label,"kind":"proxy","node_id":nid,"engine":"native"}})["id"]
                    local=fixture.free_port();mutation({"resource":"local-inbound","action":"create","local_inbound":{"name":label,"kind":"socks5","listen":{"host":"127.0.0.1","port":local},"selected_outbound":oid}})
                    transfer("Splicore",name,method,local);fixture.stop(p)
            for args in (("doctor",),("inbound","list"),("node","list")):
                output=subprocess.check_output([str(exe),*args,"--config",str(bootstrap)],stderr=subprocess.STDOUT);assert not any(s.encode() in output for s in secrets)
            bundle=work/"support.tar.gz"
            subprocess.run([str(exe),"support-bundle","--config",str(bootstrap),"--output",str(bundle)],check=True,stdout=subprocess.DEVNULL)
            with tarfile.open(bundle,"r:gz") as archive:
                for member in archive:
                    if member.isfile():
                        body=archive.extractfile(member).read()
                        assert not any(s.encode() in body for s in secrets)
            fixture.stop(daemon)
            for log in logs:log.flush()
            for path in evidence.glob("*.log"):
                body=path.read_bytes();assert not any(s.encode() in body for s in secrets);assert not any(s in body for s in (b"WARNING: DATA RACE",b"fatal error: checkptr",b"panic:"))
            for path in state.glob("*.db*"):assert not any(s.encode() in path.read_bytes() for s in secrets)
            (evidence/"results.json").write_text(json.dumps({"result":"PASS","matrix":rows,"CLI":"PASS","API":"PASS","support_bundle":"PASS","diagnostics_secret_safe":"PASS","runtime_sha256":hashlib.sha256(exe.read_bytes()).hexdigest()},indent=2))
        finally:
            for p in reversed(children):fixture.stop(p)
            for log in logs:log.close()
            for server,thread in zip((tcp,udp),threads):server.shutdown();server.server_close();thread.join(timeout=5);assert not thread.is_alive()
    (evidence/"cleanup.json").write_text(json.dumps({"children_joined":all(p.poll() is not None for p in children),"private_configs_removed":not work.exists()}))

if __name__=="__main__":main()
