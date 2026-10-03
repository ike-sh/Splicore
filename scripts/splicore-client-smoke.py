"""Phase 10 real client traffic in the existing disposable systemd service lab.

Splicore B is the installed splicore.service, simultaneously serving Phase 9
inbounds. Splicore A and pinned sing-box reference SERVERS are owned loopback
fixtures. B's client data path is entirely embedded; no external client process.
All fixtures, secrets and outputs are in the external /lab and /var/tmp trees.
"""
import argparse,concurrent.futures,hashlib,importlib.util,ipaddress,json,os,pathlib,socket,struct,subprocess,sys,tarfile,threading,time
sys.dont_write_bytecode=True
ROOT=pathlib.Path('/lab');WORK=ROOT/'client';EXE='/usr/local/bin/splicore';API='/run/splicore/splicore.sock'
spec=importlib.util.spec_from_file_location('helper',pathlib.Path(__file__).with_name('splicore-snell-interop.py'));h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class LocalDNS(h.socketserver.BaseRequestHandler):
 def handle(self):
  # The namespace's resolv.conf points to loopback. Answer only the synthetic
  # localhost target; this fixture never forwards or contacts another resolver.
  query,udp=self.request
  if len(query)<17 or query[4:6]!=bytes([0,1]):return
  offset=12;labels=[]
  while offset<len(query) and query[offset]:
   length=query[offset];offset+=1
   if length>63 or offset+length>len(query):return
   labels.append(query[offset:offset+length].lower());offset+=length
  offset+=1
  if offset+4>len(query):return
  kind,cls=struct.unpack('!HH',query[offset:offset+4]);question=query[12:offset+4]
  known=b'.'.join(labels)==b'localhost';payload=socket.inet_pton(socket.AF_INET if kind==1 else socket.AF_INET6,'127.0.0.1' if kind==1 else '::1') if known and kind in (1,28) and cls==1 else b''
  answer=bytes([192,12])+struct.pack('!HHIH',kind,1,60,len(payload))+payload if payload else b''
  udp.sendto(query[:2]+struct.pack('!HHHHH',0x8180 if known else 0x8183,1,int(bool(payload)),0,0)+question+answer,self.client_address)
def request(api,method,path,data=None):
 c=h.UnixHTTP(api)
 try:
  c.request(method,path,json.dumps(data).encode() if data is not None else None,{'Content-Type':'application/json'});r=c.getresponse();raw=r.read()
  if r.status!=200:raise RuntimeError('client control rejected '+str(r.status)+' '+path)
  return json.loads(raw)
 finally:c.close()
def mutate(api,doc):
 p=request(api,'POST','/api/v1/client/plan',doc)
 return request(api,'POST','/api/v1/client/apply',{'document':doc,'digest':p['digest'],'revision':p['revision']})
def server_create(api,port,version,psk):
 doc={'schema':1,'account_name':'synthetic','name':'server-'+str(version),'listener':{'host':'127.0.0.1','port':port},'display_endpoint':{'host':'127.0.0.1','port':port},'settings':{'version':version},'psk':psk}
 p=request(api,'POST','/api/v1/creation/snell/plan',doc)
 return request(api,'POST','/api/v1/creation/snell/apply',{'document':doc,'digest':p['digest'],'revision':p['revision']})
def wait_api(api,p):
 end=time.monotonic()+15
 while time.monotonic()<end:
  if p.poll() is not None:raise RuntimeError('fixture exited before readiness')
  if pathlib.Path(api).exists():return request(api,'GET','/api/v1/system')
 raise RuntimeError('fixture API readiness deadline')
def payload(port,dest,size):
 data=(b'0123456789abcdef'*(size//16+1))[:size]
 with socket.create_connection(('127.0.0.1',port),timeout=5) as c:
  c.sendall(bytes([5,1,0]));assert h.exact(c,2)==bytes([5,0])
  host,target_port=dest
  try:
   ip=ipaddress.ip_address(host);address=bytes([1 if ip.version==4 else 4])+ip.packed
  except ValueError:
   encoded=host.encode('ascii');address=bytes([3,len(encoded)])+encoded
  c.sendall(bytes([5,1,0])+address+target_port.to_bytes(2,'big'))
  reply=h.exact(c,4)
  if reply[1]!=0:raise RuntimeError('SOCKS command rejected')
  length=4 if reply[3]==1 else 16 if reply[3]==4 else h.exact(c,1)[0]
  h.exact(c,length+2)
  c.settimeout(15)
  with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
   send=pool.submit(c.sendall,data);received=h.exact(c,size);send.result()
 if len(received)!=size or hashlib.sha256(received).digest()!=hashlib.sha256(data).digest():raise RuntimeError('payload integrity failure')
 return hashlib.sha256(data).hexdigest()
def main():
 parser=argparse.ArgumentParser();parser.add_argument('stage');args=parser.parse_args();os.umask(0o077)
 assert pathlib.Path('/etc/splicore-lab').read_text()=='Splicore disposable lab 1\n'
 assert len(subprocess.check_output(['ip','-o','link','show']).splitlines())==1
 assert hashlib.sha256((ROOT/'clients/sing-box').read_bytes()).hexdigest()=='9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9'
 WORK.mkdir(mode=0o700,exist_ok=True);fixture=WORK/'fixture.json';initial=not fixture.exists()
 if initial:
  cfg={'a_ports':{str(v):h.free_port() for v in (5,6)},'reference_ports':{str(v):h.free_port() for v in (5,6)},'psk':'SyntheticPhase10ServicePSK123456','locals':{key:h.free_port() for key in ['direct','a5','a6','ref5','ref6','self6']}}
  fixture.write_text(json.dumps(cfg));fixture.chmod(0o600)
 else:cfg=json.loads(fixture.read_text())
 private=pathlib.Path('/var/tmp/splicore-phase10-a');private.mkdir(mode=0o700,exist_ok=True);key=private/'key';aapi=private/'api.sock';bootstrap=private/'bootstrap.yaml'
 if not key.exists():subprocess.run([EXE,'key','init','--file',str(key)],check=True,capture_output=True)
 bootstrap.write_text(f'schema: 1\nstate_directory: {private}\nkey_file: {key}\napi:\n  unix_socket: {aapi}\n')
 aLog=(WORK/(args.stage+'-a.log')).open('wb');rLog=(WORK/(args.stage+'-reference.log')).open('wb')
 a=subprocess.Popen([EXE,'run','--config',str(bootstrap)],stdout=aLog,stderr=subprocess.STDOUT)
 reference=None;targets=[];result={'stage':args.stage,'result':'PASS','external_client_processes':0}
 try:
  dns=h.EchoUDP(('127.0.0.1',53),LocalDNS);targets.append(dns);threading.Thread(target=dns.serve_forever,daemon=True).start()
  wait_api(str(aapi),a)
  if not request(str(aapi),'GET','/api/v1/inbounds')['items']:
   for v in (5,6):server_create(str(aapi),cfg['a_ports'][str(v)],v,cfg['psk'])
  refconf=WORK/'reference-server.json';refconf.write_text(json.dumps({'log':{'disabled':True},'inbounds':[{'type':'snell','tag':'reference-'+str(v),'listen':'127.0.0.1','listen_port':cfg['reference_ports'][str(v)],'version':v,'psk':cfg['psk']} for v in (5,6)],'outbounds':[{'type':'direct'}]}))
  reference=subprocess.Popen([str(ROOT/'clients/sing-box'),'run','-c',str(refconf)],stdout=rLog,stderr=subprocess.STDOUT)
  for port in cfg['reference_ports'].values():
   deadline=time.monotonic()+15
   while time.monotonic()<deadline:
    if reference.poll() is not None:raise RuntimeError('reference server exited')
    try:
     with socket.create_connection(('127.0.0.1',port),timeout=.1):break
    except OSError:pass
   else:raise RuntimeError('reference server readiness deadline')
  if initial:
   cfg['node_ids']={};cfg['outbound_ids']={}
   own=next(i for i in request(API,'GET','/api/v1/inbounds')['items'] if i['inbound']['protocol']['protocol']=='snell')
   # Runtime input comes from the canonical fixture, never an exporter parse.
   own_doc=json.loads((ROOT/'installed/server-documents.json').read_text())['snell'];cfg['self_psk']=own_doc['psk']
   for kind in ['a5','a6','ref5','ref6','self6']:
    v=int(kind[-1]);port=own_doc['listener']['port'] if kind=='self6' else cfg['a_ports' if kind[0]=='a' else 'reference_ports'][str(v)]
    node={'name':'synthetic-'+kind,'protocol':{'protocol':'snell','wire_version':str(v),'feature_profile':'base'},'endpoint':{'host':'localhost','port':port},'transport':{'kind':'tcp'},'security':{'kind':'none'},'options':{'schema_version':1,'data':{'version':v}},'metadata':{}}
    nid=mutate(API,{'resource':'node','action':'create','node':node,'credential':{'kind':'psk','value':cfg['self_psk'] if kind=='self6' else cfg['psk']}})['id'];cfg['node_ids'][kind]=nid
    oid=mutate(API,{'resource':'outbound','action':'create','outbound':{'name':'synthetic-'+kind,'kind':'proxy','node_id':nid,'engine':'native'}})['id'];cfg['outbound_ids'][kind]=oid
   mutate(API,{'resource':'route','action':'update','route':{'default_outbound':cfg['outbound_ids']['a5']}})
   for kind,port in cfg['locals'].items():
    spec={'name':'synthetic-'+kind,'listen':{'port':port}}
    if kind!='a5':spec['selected_outbound']='direct' if kind=='direct' else cfg['outbound_ids'][kind]
    mutate(API,{'resource':'local-inbound','action':'create','local_inbound':spec})
   fixture.write_text(json.dumps(cfg));fixture.chmod(0o600)
  target=h.EchoTCP(('127.0.0.1',0),h.Echo);targets.append(target);threading.Thread(target=target.serve_forever,daemon=True).start();dest=target.server_address
  # localhost has both address families in this lab. Serve the same target port
  # on both so remote resolution is independent of the resolver's address order.
  class IPv6Echo(h.EchoTCP):address_family=socket.AF_INET6
  v6=IPv6Echo(('::1',dest[1]),h.Echo);targets.append(v6);threading.Thread(target=v6.serve_forever,daemon=True).start()
  cells=[]
  for kind,port in cfg['locals'].items():
   for host in ['127.0.0.1','localhost']:
    print(args.stage,kind,host,flush=True)
    digest=payload(port,(host,dest[1]),4*1024*1024 if kind=='a5' and host=='127.0.0.1' else 32768)
    cells.append({'outbound':kind,'target':host,'sha256':digest,'result':'PASS'})
  for kind in ['direct','a5','a6']:payload(cfg['locals'][kind],('::1',v6.server_address[1]),32768);cells.append({'outbound':kind,'target':'::1','result':'PASS'})
  barrier=threading.Barrier(17)
  def concurrent_traffic(kind):barrier.wait(timeout=15);return payload(cfg['locals'][kind],dest,65536)
  with concurrent.futures.ThreadPoolExecutor(max_workers=17) as pool:list(pool.map(concurrent_traffic,['a5']*16+['self6']))
  result.update(cells=cells,concurrent=16,server_client_concurrent=True,integrity_bytes=4*1024*1024,server_inbounds=len(request(API,'GET','/api/v1/inbounds')['items']))
  if args.stage=='initial':
   # Persisted client intent survives an actual restart of the same installed unit.
   before=request(API,'GET','/api/v1/client/runtime')['state'];subprocess.run(['systemctl','restart','splicore.service'],check=True)
   after=request(API,'GET','/api/v1/client/runtime')['state'];assert before==after
   payload(cfg['locals']['a5'],dest,65536);payload(cfg['locals']['direct'],dest,65536);result['systemctl_restart']='PASS'
   # Stop A while B server/API/DIRECT stay live. Restore A without restarting B.
   h.stop(a)
   try:payload(cfg['locals']['a5'],dest,1024)
   except (OSError,RuntimeError):pass
   else:raise RuntimeError('offline remote unexpectedly relayed payload')
   payload(cfg['locals']['direct'],dest,32768);payload(cfg['locals']['self6'],dest,32768);assert request(API,'GET','/api/v1/inbounds')['items'];assert request(API,'GET','/api/v1/system')['client_runtime']
   a=subprocess.Popen([EXE,'run','--config',str(bootstrap)],stdout=aLog,stderr=subprocess.STDOUT);wait_api(str(aapi),a);payload(cfg['locals']['a5'],dest,32768);result['partial_failure_reconnect']='PASS'
  secret_values=[cfg['psk'],cfg['self_psk']]
  status=request(API,'GET','/api/v1/client/runtime');assert not any(value in json.dumps(status) for value in secret_values)
  doctor=subprocess.run([EXE,'doctor','--config','/etc/splicore/splicore.yaml'],capture_output=True,check=True);assert b'local_listeners' in doctor.stdout and not any(value.encode() in doctor.stdout for value in secret_values)
  (WORK/(args.stage+'-doctor.json')).write_bytes(doctor.stdout)
  (WORK/(args.stage+'-status.json')).write_text(json.dumps(status,indent=2)+'\n')
  if args.stage=='initial':
   archive=WORK/'support.tar.gz';subprocess.run([EXE,'support-bundle','--config','/etc/splicore/splicore.yaml','--output',str(archive)],check=True,capture_output=True)
   with tarfile.open(archive) as tar:
    assert 'client.redacted.json' in tar.getnames()
    for member in tar:
     content=tar.extractfile(member).read();assert not any(value.encode() in content for value in secret_values)
   result['support_secret_gate']='PASS'
  (WORK/(args.stage+'-result.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
 finally:
  h.stop(a)
  if reference is not None:h.stop(reference)
  for server in targets:server.shutdown();server.server_close()
  aLog.close();rLog.close()
if __name__=='__main__':main()
