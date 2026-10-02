"""Installed-unit loopback smoke; invoke only through splicore-service-lab.py.

The disposable lab binds external evidence/fixtures at /lab. This driver uses
only the installed unit, canonical API and pinned local reference clients.
It never starts its own Splicore daemon or downloads third-party artifacts.
"""
import argparse,copy,hashlib,importlib.util,json,os,pathlib,pwd,secrets,socket,sqlite3,subprocess,sys,threading,time,uuid
sys.dont_write_bytecode=True
os.environ['OPENSSL_CONF']='/dev/null'
root=pathlib.Path('/lab');work=root/'installed';work.mkdir(mode=0o700,exist_ok=True)
spec=importlib.util.spec_from_file_location('helper',pathlib.Path(__file__).with_name('splicore-snell-interop.py'));h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
exe='/usr/local/bin/splicore';config='/etc/splicore/splicore.yaml';api='/run/splicore/splicore.sock'
rows=[];children=[];logs=[];secret_values=[]
def run(*args,check=True,name=None):
 p=subprocess.run(args,capture_output=True,timeout=100)
 if name:(work/(name+'.log')).write_bytes(p.stdout+p.stderr)
 if check and p.returncode:raise RuntimeError('command failed: '+args[0]+' '+str(p.returncode))
 return p
def request(method,path,data=None):
 c=h.UnixHTTP(api)
 try:
  c.request(method,path,json.dumps(data).encode() if data is not None else None,{'Content-Type':'application/json'});r=c.getresponse();b=r.read()
  assert r.status==200,(method,path,r.status)
  return json.loads(b)
 finally:c.close()
def create(protocol,doc,label):
 existing=next((i for i in request('GET','/api/v1/inbounds')['items'] if i['inbound']['name']==doc['name']),None)
 if existing:
  rows.append({'label':label,'protocol':protocol,'inbound_id':existing['inbound']['id'],'binding_id':existing['bindings'][0]['binding_id'],'port':doc['listener']['port']});return
 p=request('POST','/api/v1/creation/'+protocol+'/plan',doc)
 a=request('POST','/api/v1/creation/'+protocol+'/apply',{'document':doc,'digest':p['digest'],'revision':p['revision']})
 rows.append({'label':label,'protocol':protocol,'inbound_id':a['inbound_id'],'binding_id':a.get('binding_id') or a['bindings'][0]['binding_id'],'port':doc['listener']['port']})
def launch(args,name,env=None):
 f=(work/(name+'.log')).open('wb');logs.append(f);p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,env=env);children.append(p);return p
def client(row):
 label=row['label'];client='xray' if row['protocol']=='vless' and 'xray' in label else 'mieru' if row['protocol']=='mieru' else 'sing-box' if row['protocol']=='snell' else 'mihomo'
 version={'xray':'26.3.27','mieru':'3.38.0','mihomo':'1.19.30','sing-box':'1.14.1'}[client]
 e=request('POST','/api/v1/inbounds/'+row['inbound_id']+'/export',{'format':client,'client_version':version,'binding_id':row['binding_id']})
 out=json.loads(e['content']);port=h.free_port();private=pathlib.Path('/var/tmp/splicore-probe');private.mkdir(mode=0o700,exist_ok=True);home=private/(label+'-'+secrets.token_hex(4));home.mkdir(mode=0o700);path=home/'client.json'
 if row['protocol']=='snell':
  sensitive=out['psk'];saved=work/'synthetic-secrets.json';values=json.loads(saved.read_text())
  if sensitive not in values:values.append(sensitive);saved.write_text(json.dumps(values))
 if client=='xray':
  conf={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':True}}],'outbounds':[out]};args=['/lab/xray','run','-config',str(path)];env=None
 elif client=='mieru':
  conf=dict(out,rpcPort=h.free_port(),socks5Port=port,socks5ListenLAN=False,loggingLevel='ERROR',advancedSettings={'noCheckUpdate':True});args=['/lab/clients/mieru','run'];env=dict(os.environ,MIERU_CONFIG_JSON_FILE=str(path))
 elif client=='sing-box':
  conf={'log':{'disabled':True},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':port}],'outbounds':[out]};args=['/lab/clients/sing-box','run','-c',str(path)];env=None
 else:
  node=out['proxies'][0] if 'proxies' in out else out
  controller=home/'controller.sock'
  conf={'socks-port':port,'allow-lan':False,'bind-address':'127.0.0.1','ipv6':True,'mode':'rule','log-level':'silent','external-controller-unix':str(controller),'proxies':[node],'rules':['MATCH,'+node['name']]};args=['/lab/clients/mihomo','-d',str(home),'-f',str(path)];env=None
 path.write_text(json.dumps(conf));p=launch(args,label,env)
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  assert p.poll() is None,'client exited before readiness'
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.1):pass
   if client=='mihomo':
    if not controller.exists():continue
    c=h.UnixHTTP(controller);c.request('PUT','/configs?force=true',json.dumps({'path':str(path)}),{'Content-Type':'application/json'});r=c.getresponse();r.read();assert r.status==204;c.close()
   return p,port
  except OSError:pass
 raise RuntimeError('client readiness timeout')
def smoke(stage):
 tcp=h.EchoTCP(('127.0.0.1',0),h.Echo);udp=h.EchoUDP(('127.0.0.1',0),h.UDPEcho)
 for s in (tcp,udp):threading.Thread(target=s.serve_forever,daemon=True).start()
 results=[]
 try:
  for row in rows:
   print(stage,row['label'],flush=True);p,port=client(row)
   try:
    t=h.tcp_payload(port,tcp.server_address,32768)
    u=h.udp_payload(port,udp.server_address) if row['protocol'] in ('snell','hysteria2','tuic','mieru') else None
    results.append({'stage':stage,'protocol':row['label'],'tcp_bytes':t,'udp_bytes':u,'result':'PASS'})
   finally:h.stop(p)
 finally:
  for s in (tcp,udp):s.shutdown();s.server_close()
 return results
def setup():
 run(exe,'package','engine','--artifact','/lab/xray',name='engine-install')
 text=pathlib.Path(config).read_text()
 if 'binary_path:' not in text:text=text.replace('xray:\n','xray:\n  binary_path: /var/lib/splicore/engines/xray-artifact/xray-26.3.27\n');pathlib.Path(config).write_text(text)
 run('systemctl','restart','splicore.service',name='engine-restart')
 uid=pwd.getpwnam('splicore').pw_uid;gid=pwd.getpwnam('splicore').pw_gid
 tls=pathlib.Path('/var/lib/splicore/tls');tls.mkdir(mode=0o700,exist_ok=True);os.chown(tls,uid,gid)
 ca=work/'ca.pem';cak=work/'ca.key';cert=tls/'cert.pem';key=tls/'key.pem';csr=work/'server.csr';ext=work/'extension.cnf';sni='service.synthetic.test'
 ext.write_text('subjectAltName=DNS:'+sni+'\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n')
 for args in [('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(cak),'-out',str(ca),'-days','1','-subj','/CN=Splicore Synthetic CA','-addext','basicConstraints=critical,CA:TRUE'),('openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN='+sni),('openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(cak),'-CAcreateserial','-out',str(cert),'-days','1','-extfile',str(ext))]:run(*args)
 for p in (cert,key):os.chown(p,uid,gid);os.chmod(p,0o600)
 base={'schema':1,'listener':{'host':'127.0.0.1','port':80},'display_endpoint':{'host':'127.0.0.1','port':80}}
 snell=dict(copy.deepcopy(base),name='installed-snell',account_name='SnellUser',settings={'version':6});create('snell',snell,'snell')
 for protocol,port in [('hysteria2',443),('tuic',444)]:
  password='Synthetic-'+protocol+'-Password-Phase9';secret_values.append(password)
  doc=dict(copy.deepcopy(base),name='installed-'+protocol,users=[{'account_name':protocol+'User','password':password}],settings={'tls':{'server_name':sni,'certificate_file':str(cert),'private_key_file':str(key),'ca_certificate':ca.read_text()}})
  doc['listener']['port']=doc['display_endpoint']['port']=port
  if protocol=='tuic':doc['settings'].update(version=5,congestion_control='cubic',udp_relay_mode='native',zero_rtt_handshake=False);doc['users'][0]['uuid']=str(uuid.uuid4());secret_values.append(doc['users'][0]['uuid'])
  create(protocol,doc,protocol)
 for engine,port,masked in [('native',446,False),('xray',447,False),('xray',448,True)]:
  value=str(uuid.uuid4());secret_values.append(value)
  doc=dict(copy.deepcopy(base),name='installed-vless-'+engine+('-sudoku' if masked else ''),engine=engine,users=[{'account_name':'Vless-'+str(port),'uuid':value}],settings={'security':'none','flow':'none','transport':'tcp','packet_encoding':'xudp'})
  doc['listener']['port']=doc['display_endpoint']['port']=port
  label='vless-'+engine
  if masked:
   password=secrets.token_hex(16).upper();secret_values.append(password);doc['settings']['engine_options']={'finalmask':{'tcp':[{'type':'sudoku','settings':{'ascii':'prefer_ascii','padding_min':0,'padding_max':3}}]}};doc['transport_secret']={'password':password};label+='-sudoku'
  create('vless',doc,label)
 for transport,port in [('tcp',449),('udp',450)]:
  password='Synthetic-Mieru-'+transport+'-Password-Phase9';secret_values.append(password)
  doc=dict(copy.deepcopy(base),name='installed-mieru-'+transport,users=[{'account_name':'Mieru-'+transport,'username':'Mieru-'+transport,'password':password}],settings={'transport':transport,'mtu':1500,'multiplex':'default'})
  doc['listener']['port']=doc['display_endpoint']['port']=port;create('mieru',doc,'mieru-'+transport)
 (work/'inbounds.json').write_text(json.dumps(rows,indent=2)+'\n')
 (work/'synthetic-secrets.json').write_text(json.dumps(secret_values))
def main():
 parser=argparse.ArgumentParser();parser.add_argument('stage');a=parser.parse_args()
 os.umask(0o077)
 assert pathlib.Path('/etc/hostname').read_text().strip()=='splicore-p9-lab'
 assert pathlib.Path('/etc/splicore-lab').read_text()=='Splicore disposable lab 1\n'
 assert len(run('ip','-o','link','show').stdout.splitlines())==1
 pinned={'mihomo':'20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494','sing-box':'9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9','mieru':'70d4224ecf5cd8e1fb32c0759eb386147b39c3729e2ddacc3f685a239339f699'}
 for name,digest in pinned.items():assert hashlib.sha256((root/'clients'/name).read_bytes()).hexdigest()==digest
 assert hashlib.sha256((root/'xray').read_bytes()).hexdigest()=='8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed'
 try:
  if a.stage=='initial':setup()
  else:rows.extend(json.loads((work/'inbounds.json').read_text()))
  result=smoke(a.stage)
  (work/(a.stage+'-smoke.json')).write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps({'stage':a.stage,'cells':len(result),'result':'PASS'}),flush=True)
 finally:
  for p in children:
   if p.poll() is None:h.stop(p)
  for f in logs:f.close()
if __name__=='__main__':main()
