"""Phase 11 installed client traffic, only in the owned loopback service lab.

Nodes use public canonical creation fixtures. Exporter output is never runtime
input. The pinned reference servers are separate evidence from self interop.
"""
import argparse, concurrent.futures, copy, hashlib, importlib.util, ipaddress, json, os
import pathlib, socket, struct, subprocess, sys, tarfile, threading

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('base', pathlib.Path(__file__).with_name('splicore-client-smoke.py'))
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
h = base.h
ROOT = pathlib.Path('/lab'); WORK = ROOT/'expansion'; API = base.API

def request(method, path, data=None): return base.request(API, method, path, data)
def mutate(doc): return base.mutate(API, doc)

def address(host, port):
    try:
        ip = ipaddress.ip_address(host); value = bytes([1 if ip.version == 4 else 4])+ip.packed
    except ValueError:
        value = host.encode('ascii'); value = bytes([3, len(value)])+value
    return value+struct.pack('!H', port)

def read_address(c, kind):
    count = 4 if kind == 1 else 16 if kind == 4 else h.exact(c, 1)[0]
    raw = h.exact(c, count)
    host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, raw) if kind != 3 else raw.decode('ascii')
    return host, int.from_bytes(h.exact(c, 2), 'big')

def udp_payload(port, target, payload, local_host='127.0.0.1'):
    family = socket.AF_INET6 if ':' in local_host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as pc:
        pc.bind((local_host, 0)); pc.settimeout(6)
        with socket.create_connection((local_host, port), timeout=6) as control:
            control.sendall(bytes([5, 1, 0])); assert h.exact(control, 2) == bytes([5, 0])
            control.sendall(bytes([5, 3, 0])+address(local_host, pc.getsockname()[1]))
            reply = h.exact(control, 4); assert reply[1] == 0
            relay = read_address(control, reply[3]); pc.sendto(bytes(3)+address(*target)+payload, relay)
            received, _ = pc.recvfrom(65535)
            assert received[:3] == bytes(3)
            offset = 4+(4 if received[3] == 1 else 16 if received[3] == 4 else 1+received[4])+2
            assert received[offset:] == payload, 'UDP cross-talk or integrity failure'

def node_fixture(label, doc, ca):
    protocol = 'vless' if label.startswith('vless') else 'mieru' if label.startswith('mieru') else label
    settings = doc['settings']; security = {'kind': 'none'}; transport = 'tcp'
    wire, feature = {'snell': ('6', 'base'), 'hysteria2': ('2', 'base'), 'tuic': ('5', 'base'), 'vless': ('0', 'plain'), 'mieru': ('2', 'base')}[protocol]
    if protocol == 'snell': options = settings; credential = {'kind': 'psk', 'value': doc['psk']}
    elif protocol in ('hysteria2', 'tuic'):
        transport = 'quic'; security = {'kind': 'tls', 'tls': {'enabled': True, 'server_name': settings['tls']['server_name'], 'trust': 'explicit_ca', 'ca_certificate': ca, 'alpn': ['h3']}}
        user = doc['users'][0]
        if protocol == 'hysteria2': options = {}; credential = {'kind': 'password', 'value': user['password']}
        else:
            options = {key: settings[key] for key in ('version', 'congestion_control', 'udp_relay_mode', 'zero_rtt_handshake')}
            credential = {'kind': 'uuid_password', 'value': json.dumps({key: user[key] for key in ('uuid', 'password')})}
    elif protocol == 'vless':
        options = {key: settings[key] for key in ('security', 'flow', 'packet_encoding')}
        credential = {'kind': 'uuid', 'value': doc['users'][0]['uuid']}
    else:
        options = settings; transport = settings['transport']
        credential = {'kind': 'username_password', 'value': json.dumps({key: doc['users'][0][key] for key in ('username', 'password')})}
    node = {'name': 'phase11-'+label, 'protocol': {'protocol': protocol, 'wire_version': wire, 'feature_profile': feature}, 'endpoint': copy.deepcopy(doc['listener']), 'transport': {'kind': transport}, 'security': security, 'options': {'schema_version': 1, 'data': options}, 'metadata': {}}
    return node, credential

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('stage'); args = parser.parse_args(); os.umask(0o077)
    assert pathlib.Path('/etc/splicore-lab').read_text() == 'Splicore disposable lab 1\n'
    assert len(subprocess.check_output(['ip', '-o', 'link', 'show']).splitlines()) == 1
    assert hashlib.sha256((ROOT/'xray').read_bytes()).hexdigest() == '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed'
    assert hashlib.sha256((ROOT/'clients/sing-box').read_bytes()).hexdigest() == '9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9'
    WORK.mkdir(mode=0o700, exist_ok=True)
    docs = json.loads((ROOT/'installed/server-documents.json').read_text()); ca = (ROOT/'installed/ca.pem').read_text()
    fixture = WORK/'fixture.json'; initial = not fixture.exists()
    cfg = {'cells': []} if initial else json.loads(fixture.read_text())
    servers = []; children = []; logs = []
    result = {'stage': args.stage, 'result': 'PASS', 'external_client_processes': 0}
    try:
        class TCP6(h.EchoTCP): address_family = socket.AF_INET6
        class UDP6(h.EchoUDP): address_family = socket.AF_INET6
        tcp = h.EchoTCP(('127.0.0.1', 0), h.Echo); tcp6 = TCP6(('::1', tcp.server_address[1]), h.Echo)
        udp = h.EchoUDP(('127.0.0.1', 0), h.UDPEcho); udp6 = UDP6(('::1', udp.server_address[1]), h.UDPEcho)
        dns = h.EchoUDP(('127.0.0.1', 53), base.LocalDNS)
        servers.extend([tcp, tcp6, udp, udp6, dns])
        for server in servers: threading.Thread(target=server.serve_forever, daemon=True).start()
        if initial:
            for label in ('snell', 'hysteria2', 'tuic', 'vless-native', 'vless-xray', 'mieru-tcp', 'mieru-udp'):
                print('create canonical node', label, flush=True)
                node, credential = node_fixture(label, docs[label], ca)
                nid = mutate({'resource': 'node', 'action': 'create', 'node': node, 'credential': credential})['id']
                engines = ('native', 'xray') if label == 'vless-native' else ('xray',) if label == 'vless-xray' else ('native',)
                for engine in engines:
                    oid = mutate({'resource': 'outbound', 'action': 'create', 'outbound': {'name': label+'-'+engine, 'kind': 'proxy', 'node_id': nid, 'engine': engine}})['id']
                    port = h.free_port()
                    lid = mutate({'resource': 'local-inbound', 'action': 'create', 'local_inbound': {'name': label+'-'+engine, 'listen': {'port': port}, 'selected_outbound': oid}})['id']
                    cfg['cells'].append({'label': label+'-'+engine, 'node': nid, 'outbound': oid, 'local': lid, 'port': port})
            port = h.free_port()
            cfg['ipv6_local'] = {'port': port, 'id': mutate({'resource': 'local-inbound', 'action': 'create', 'local_inbound': {'name': 'phase11-local-v6', 'listen': {'host': '::1', 'port': port}, 'selected_outbound': 'direct'}})['id']}
            fixture.write_text(json.dumps(cfg, indent=2)+'\n')
        cells = []
        for cell in cfg['cells']:
            for host in ('127.0.0.1', '::1', 'localhost'):
                print(args.stage, cell['label'], host, flush=True)
                base.payload(cell['port'], (host, tcp.server_address[1]), 4*1024*1024 if host == '127.0.0.1' else 32768)
                udp_payload(cell['port'], (host, udp.server_address[1]), (cell['label']+host).encode())
                cells.append({'adapter': cell['label'], 'target': host, 'tcp': 'PASS', 'udp': 'PASS'})
        udp_payload(cfg['ipv6_local']['port'], ('::1', udp.server_address[1]), b'IPv6-local-UDP', '::1')
        result.update(cells=cells, local_ipv6_udp='PASS', integrity_bytes_per_adapter=4*1024*1024)
        def mixed(index):
            cell = cfg['cells'][index % len(cfg['cells'])]
            udp_payload(cell['port'], udp.server_address, ('association-'+str(index)).encode())
            base.payload(cell['port'], tcp.server_address, 65536)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool: list(pool.map(mixed, range(16)))
        result.update(concurrent_udp=16, mixed_tcp_udp='PASS', server_inbounds=len(request('GET', '/api/v1/inbounds')['items']))
        if args.stage == 'reinstall':
            # Persist one offline endpoint, restart, observe its passive health,
            # and prove every other adapter survives. Restore without a restart.
            cell = cfg['cells'][1]; status = request('GET', '/api/v1/client/runtime')
            node = next(n for n in status['state']['nodes'] if n['id'] == cell['node']); saved = copy.deepcopy(node)
            node['endpoint']['port'] = h.free_port()
            mutate({'resource': 'node', 'action': 'update', 'id': node['id'], 'node': node})
            before = request('GET', '/api/v1/client/runtime')['state']
            subprocess.run(['systemctl', 'restart', 'splicore.service'], check=True)
            assert request('GET', '/api/v1/client/runtime')['state'] == before
            try: base.payload(cell['port'], tcp.server_address, 1024)
            except (OSError, RuntimeError): pass
            else: raise RuntimeError('offline endpoint forwarded payload')
            for index, other in enumerate(cfg['cells']):
                if other['node'] != cell['node']: mixed(index)
            health = next(o for o in request('GET', '/api/v1/client/runtime')['outbounds'] if o['id'] == cell['outbound'])
            assert not health['available'] and health['last_error']
            mutate({'resource': 'node', 'action': 'update', 'id': saved['id'], 'node': saved}); mixed(1)
            result['restart_all_outbounds'] = 'PASS'
            result['offline_restart_isolation_recovery'] = 'PASS'
        # Reference implementations are separate processes, never a client data path.
        ref_inbounds = []; ref_nodes = []
        for label in ('snell', 'hysteria2', 'tuic', 'vless-native'):
            doc = docs[label]; node, credential = node_fixture(label, doc, ca); remote = h.free_port()
            protocol = node['protocol']['protocol']; inbound = {'type': protocol, 'tag': label, 'listen': '127.0.0.1', 'listen_port': remote}
            if protocol == 'snell': inbound.update(version=6, psk=doc['psk'])
            elif protocol in ('hysteria2', 'tuic'):
                inbound['users'] = [{key: value for key, value in doc['users'][0].items() if key in ('uuid', 'password')}]
                inbound['tls'] = {'enabled': True, 'server_name': doc['settings']['tls']['server_name'], 'alpn': ['h3'], 'certificate_path': doc['settings']['tls']['certificate_file'], 'key_path': doc['settings']['tls']['private_key_file']}
                if protocol == 'tuic': inbound['congestion_control'] = 'cubic'
            else: inbound['users'] = [{'uuid': doc['users'][0]['uuid']}]
            ref_inbounds.append(inbound); node['name'] = 'reference-'+label; node['endpoint']['port'] = remote; ref_nodes.append((node, credential, 'sing-box 1.14.1'))
        path = WORK/'reference.json'; path.write_text(json.dumps({'log': {'disabled': True}, 'inbounds': ref_inbounds, 'outbounds': [{'type': 'direct'}]}))
        log = (WORK/(args.stage+'-reference.log')).open('wb'); logs.append(log)
        reference = subprocess.Popen([str(ROOT/'clients/sing-box'), 'run', '-c', str(path)], stdout=log, stderr=subprocess.STDOUT); children.append(reference)
        h.wait_port(ref_inbounds[0]['listen_port'], reference)
        remote = h.free_port(); node, credential = node_fixture('vless-xray', docs['vless-xray'], ca)
        refpath = WORK/'reference-xray.json'
        refpath.write_text(json.dumps({'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': remote, 'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': [{'id': docs['vless-xray']['users'][0]['uuid'], 'flow': ''}]}, 'streamSettings': {'network': 'raw', 'security': 'none'}}], 'outbounds': [{'protocol': 'freedom'}]}))
        xlog = (WORK/(args.stage+'-reference-xray.log')).open('wb'); logs.append(xlog)
        xref = subprocess.Popen([str(ROOT/'xray'), 'run', '-config', str(refpath)], stdout=xlog, stderr=subprocess.STDOUT); children.append(xref)
        h.wait_port(remote, xref); node['name'] = 'reference-xray'; node['endpoint']['port'] = remote
        ref_nodes.append((node, credential, 'Xray 26.3.27'))
        refs = []
        for node, credential, reference_label in ref_nodes:
            nid = mutate({'resource': 'node', 'action': 'create', 'node': node, 'credential': credential})['id']
            engines = ('native', 'xray') if node['protocol']['protocol'] == 'vless' else ('native',)
            for engine in engines:
                print('reference', node['protocol']['protocol'], engine, flush=True)
                oid = mutate({'resource': 'outbound', 'action': 'create', 'outbound': {'name': 'reference-'+engine, 'kind': 'proxy', 'node_id': nid, 'engine': engine}})['id']
                port = h.free_port(); lid = mutate({'resource': 'local-inbound', 'action': 'create', 'local_inbound': {'name': 'reference-'+engine, 'listen': {'port': port}, 'selected_outbound': oid}})['id']
                try:
                    base.payload(port, tcp.server_address, 32768); udp_payload(port, udp.server_address, b'reference-interop')
                    refs.append({'protocol': node['protocol']['protocol'], 'engine': engine, 'reference': reference_label, 'tcp': 'PASS', 'udp': 'PASS'})
                finally:
                    mutate({'resource': 'local-inbound', 'action': 'delete', 'id': lid}); mutate({'resource': 'outbound', 'action': 'delete', 'id': oid})
            mutate({'resource': 'node', 'action': 'delete', 'id': nid})
        result['reference'] = refs
        secrets = json.loads((ROOT/'installed/synthetic-secrets.json').read_text())
        # Exercise the same generic CLI contract for every protocol, using private
        # documents and plans instead of putting secrets or engine config in argv.
        cli_cells = []
        state = request('GET', '/api/v1/client/runtime')['state']
        for nid in dict.fromkeys(cell['node'] for cell in cfg['cells']):
            node = next(n for n in state['nodes'] if n['id'] == nid); node['name'] = 'cli-'+node['protocol']['protocol']+'-'+args.stage
            document = WORK/'cli-mutation.json'; document.write_text(json.dumps({'resource': 'node', 'action': 'update', 'id': nid, 'node': node}))
            command = [base.EXE, 'node']; flags = ['--config', '/etc/splicore/splicore.yaml', '--file', str(document)]
            validated = subprocess.run(command+['validate']+flags, capture_output=True, check=True)
            planned = subprocess.run(command+['plan']+flags, capture_output=True, check=True)
            planpath = WORK/'cli-plan.json'; planpath.write_bytes(planned.stdout)
            applied = subprocess.run(command+['apply']+flags+['--plan', str(planpath)], capture_output=True, check=True)
            assert not any(value.encode() in validated.stdout+planned.stdout+applied.stdout for value in secrets)
            cli_cells.append({'protocol': node['protocol']['protocol'], 'validate_plan_apply': 'PASS'})
        result['unified_cli'] = cli_cells
        status = request('GET', '/api/v1/client/runtime'); raw = json.dumps(status).encode()
        assert not any(value.encode() in raw for value in secrets)
        (WORK/(args.stage+'-status.json')).write_bytes(raw)
        doctor = subprocess.run([base.EXE, 'doctor', '--config', '/etc/splicore/splicore.yaml'], capture_output=True, check=True)
        assert not any(value.encode() in doctor.stdout+doctor.stderr for value in secrets)
        result['status_doctor_secret_gate'] = 'PASS'
        (WORK/(args.stage+'-result.json')).write_text(json.dumps(result, indent=2)+'\n'); print(json.dumps(result), flush=True)
    finally:
        for child in children: h.stop(child)
        for log in logs: log.close()
        for server in servers: server.shutdown(); server.server_close()

if __name__ == '__main__': main()
