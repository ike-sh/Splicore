"""Phase 12 acceptance through the installed core in the owned service lab.

Import in the lab's campaign driver and retain Fixtures until that campaign ends.
Every DNS, HTTP and payload endpoint is an owned loopback fixture. No downloads.
"""
import copy, importlib.util, json, pathlib, socket, socketserver, struct
import subprocess, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('expansion', pathlib.Path(__file__).with_name('splicore-client-expansion-smoke.py'))
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
ROOT = pathlib.Path('/lab'); WORK = ROOT/'network'

def uid(): return str(uuid.uuid4())
def action(kind, ident=None): return dict(kind=kind, **({'id': ident} if ident else {}))
def request(method, path, body=None):
    control = base.h.UnixHTTP(base.API)
    try:
        control.request(method, path, json.dumps(body).encode() if body is not None else None, {'Content-Type': 'application/json'})
        reply = control.getresponse(); raw = reply.read(4 << 20)
        if reply.status != 200:
            problem = json.loads(raw)
            error = {key: problem.get(key) for key in ('code', 'message')}
            raise RuntimeError('network control rejected '+str(reply.status)+' '+path+' '+json.dumps(error))
        return json.loads(raw)
    finally: control.close()
def mutate(document):
    plan = request('POST', '/api/v1/client/plan', document)
    return request('POST', '/api/v1/client/apply', dict(document=document, digest=plan['digest'], revision=plan['revision']))
def status(): return request('GET', '/api/v1/client/runtime')
def replace(config): return mutate({'resource': 'network', 'action': 'replace', 'network': config})
def held(port, target):
    conn = socket.create_connection(('127.0.0.1', port), timeout=5)
    conn.sendall(bytes([5, 1, 0])); assert base.h.exact(conn, 2) == bytes([5, 0])
    conn.sendall(bytes([5, 1, 0])+base.address(*target[:2]))
    reply = base.h.exact(conn, 4); assert reply[1] == 0, 'Phase 12 SOCKS rejection'
    base.read_address(conn, reply[3]); return conn
def exchange(conn, payload):
    conn.sendall(payload); assert base.h.exact(conn, len(payload)) == payload
def traffic(port, target):
    with held(port, target) as conn: exchange(conn, b'Phase12-installed-payload')
def sessions(ident): return int(next(o for o in status()['outbounds'] if o['id'] == ident)['stats']['sessions_total'])
def wait_group(ident, ready):
    deadline = time.monotonic()+20
    event = threading.Event()
    while time.monotonic() < deadline:
        group = next(g for g in status()['network_runtime']['groups'] if g['id'] == ident)
        if ready(group): return group
        event.wait(.02)  # Observe a scheduler transition; no failed operation is retried.
    raise RuntimeError('bounded health observation deadline')

class Association:
    def __init__(self, port):
        self.pc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.pc.bind(('127.0.0.1', 0)); self.pc.settimeout(5)
        self.control = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.control.sendall(bytes([5, 1, 0])); assert base.h.exact(self.control, 2) == bytes([5, 0])
        self.control.sendall(bytes([5, 3, 0])+base.address('127.0.0.1', self.pc.getsockname()[1]))
        reply = base.h.exact(self.control, 4); assert reply[1] == 0
        self.relay = base.read_address(self.control, reply[3])
    def exchange(self, target, payload):
        self.pc.sendto(bytes(3)+base.address(*target)+payload, self.relay)
        raw, _ = self.pc.recvfrom(65535)
        assert raw[:3] == bytes(3)
        offset = 4+(4 if raw[3] == 1 else 16 if raw[3] == 4 else 1+raw[4])+2
        assert raw[offset:] == payload
    def close(self): self.pc.close(); self.control.close()

class Fixtures:
    def __init__(self):
        assert pathlib.Path('/etc/splicore-lab').read_text() == 'Splicore disposable lab 1\n'
        assert len(subprocess.check_output(['ip', '-o', 'link', 'show']).splitlines()) == 1
        self.servers = []; self.counts = [0, 0]; self.lock = threading.Lock(); self.http_count = 0
        class TCP6(base.h.EchoTCP): address_family = socket.AF_INET6
        self.tcp4 = base.h.EchoTCP(('127.0.0.1', 0), base.h.Echo)
        self.tcp6 = TCP6(('::1', 0), base.h.Echo)
        self.udp1 = base.h.EchoUDP(('127.0.0.1', 0), base.h.UDPEcho)
        self.udp2 = base.h.EchoUDP(('127.0.0.1', 0), base.h.UDPEcho)
        owner = self
        def answer(query, index):
            assert len(query) >= 17 and query[4:6] == bytes([0, 1])
            offset = 12
            while query[offset]:
                size = query[offset]; assert size <= 63; offset += size+1
            offset += 1; kind, cls = struct.unpack('!HH', query[offset:offset+4]); assert cls == 1
            with owner.lock: owner.counts[index] += 1
            payload = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, '127.0.0.1' if kind == 1 else '::1') if kind in (1, 28) else b''
            record = bytes([192, 12])+struct.pack('!HHIH', kind, 1, 60, len(payload))+payload if payload else b''
            return query[:2]+struct.pack('!HHHHH', 0x8180, 1, bool(record), 0, 0)+query[12:offset+4]+record
        class UDPDNS(socketserver.BaseRequestHandler):
            def handle(self):
                query, pc = self.request; pc.sendto(answer(query, 0), self.client_address)
        class TCPDNS(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                size = int.from_bytes(base.h.exact(self.request, 2), 'big')
                reply = answer(base.h.exact(self.request, size), 1)
                self.request.sendall(len(reply).to_bytes(2, 'big')+reply)
        class Probe(BaseHTTPRequestHandler):
            def do_GET(self):
                assert not self.headers.get('Proxy-Authorization') and not self.headers.get('Authorization')
                with owner.lock: owner.http_count += 1
                self.send_response(204); self.end_headers()
            def log_message(self, *_): pass
        class TCPServer(socketserver.ThreadingTCPServer):
            daemon_threads = True
        self.dns_a = base.h.EchoUDP(('127.0.0.1', 0), UDPDNS)
        self.dns_b = TCPServer(('127.0.0.1', 0), TCPDNS)
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), Probe)
        self.servers = [self.tcp4, self.tcp6, self.udp1, self.udp2, self.dns_a, self.dns_b, self.http]
        self.threads = []
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); self.threads.append(thread)
    def close(self):
        for server in self.servers: server.shutdown(); server.server_close()
        for thread in self.threads: thread.join(5); assert not thread.is_alive()
    def counts_copy(self):
        with self.lock: return list(self.counts)

def run(stage, fixtures):
    WORK.mkdir(mode=0o700, exist_ok=True)
    fixture = WORK/'fixture.json'; initial = not fixture.exists()
    cfg = {} if initial else json.loads(fixture.read_text())
    all_state = status()
    if not initial:
        assert all_state['state']['network'] == cfg['last_network'], 'committed graph was not restored'
        assert all_state['network_runtime']['dns']['entries'] == 0, 'runtime cache treated as authority'
    cells = json.loads((ROOT/'expansion/fixture.json').read_text())['cells']
    selected = [next(c for c in cells if c['label'] == label) for label in ['snell-native', 'hysteria2-native', 'tuic-native']]
    members = [action('outbound', c['outbound']) for c in selected]
    if initial:
        cfg = dict(selector=uid(), balance=uid(), url_test=uid(), fallback=uid(), system=uid(), direct_dns=uid(), proxy_dns=uid(), ruleset=uid(), port=base.h.free_port())
        cfg['local'] = mutate({'resource': 'local-inbound', 'action': 'create', 'local_inbound': {'name': 'phase12-routing', 'listen': {'port': cfg['port']}}})['id']
        cfg['rule_ids'] = [uid() for _ in range(104)]; cfg['dns_rule_ids'] = [uid(), uid(), uid()]
    direct = action('direct'); group = action('group', cfg['selector'])
    rule = lambda ident, name, match, act: dict(id=ident, name=name, match=match, action=act)
    # Every route is scoped to this separate listener; other client fixtures retain their contract.
    scope = {'local_inbounds': [cfg['local']]}
    route_rule = lambda n, name, match, act: rule(cfg['rule_ids'][n], name, dict(scope, **match), act)
    endpoint = lambda server: dict(host='127.0.0.1', port=server.server_address[1])
    config = dict(
        route={'rules': [
            route_rule(0, 'domain selector', {'domain_suffixes': ['example.p12.local']}, group),
            route_rule(1, 'IPv4 HY2', {'ip_cidrs': ['127.0.0.0/8']}, members[1]),
            route_rule(2, 'IPv6 TUIC', {'ip_cidrs': ['::1/128']}, members[2]),
            route_rule(3, 'explicit direct', {}, direct)]},
        rule_sets=[dict(id=cfg['ruleset'], name='private DNS domains', type='inline', status='enabled', revision='1', rules=[{'domain_suffixes': ['proxy.p12.local']}])],
        policy_groups=[dict(id=cfg['selector'], name='selector', type='selector', members=members, selector={'selected': members[0]})],
        dns_servers=[
            dict(id=cfg['system'], name='explicit system bootstrap', type='system', endpoint={'host': '', 'port': 0}, detour=direct, tls={'enabled': False}),
            dict(id=cfg['direct_dns'], name='owned direct resolver', type='udp', endpoint=endpoint(fixtures.dns_a), detour=direct, tls={'enabled': False}),
            dict(id=cfg['proxy_dns'], name='owned proxy resolver', type='tcp', endpoint=endpoint(fixtures.dns_b), detour=group, tls={'enabled': False})],
        dns_rules=[
            dict(id=cfg['dns_rule_ids'][0], name='proxy split', match={'rule_sets': [cfg['ruleset']]}, server=cfg['proxy_dns']),
            dict(id=cfg['dns_rule_ids'][1], name='direct split', match={'domain_suffixes': ['p12.local']}, server=cfg['direct_dns'])],
        dns=dict(enabled=True, default_server=cfg['system'], bootstrap_server=cfg['system'], strategy='ipv4_only', cache={'capacity': 64}, timeout_seconds=3))
    replace(config)
    result = dict(stage=stage, result='PASS', installed_core=True, fixture_network='owned loopback only', canonical_recovery='PASS' if not initial else 'not applicable')
    port = cfg['port']; target = fixtures.tcp4.server_address
    before = sessions(members[0]['id'])
    traffic(port, ('a.example.p12.local', target[1]))
    assert sessions(members[0]['id']) == before+1
    # Domain only DIRECT precedes resolved IP CIDR for the named direct fixture.
    config['route']['rules'].insert(1, rule(uid(), 'domain direct', dict(scope, domains=['other.p12.local']), direct)); replace(config)
    before = sessions('direct'); traffic(port, ('other.p12.local', target[1])); assert sessions('direct') == before+1
    result['A_domain_selector_snell_direct'] = 'PASS'
    for cell, target_ip in zip(selected[1:], [fixtures.tcp4.server_address, fixtures.tcp6.server_address]):
        before = sessions(cell['outbound']); traffic(port, target_ip); assert sessions(cell['outbound']) == before+1
    result['B_IPv4_HY2_IPv6_TUIC'] = 'PASS'
    probe = dict(url='http://127.0.0.1:'+str(fixtures.http.server_address[1])+'/health', interval_seconds=1, timeout_seconds=2, expected_status=204)
    config['policy_groups'].append(dict(id=cfg['url_test'], name='URL-Test', type='url_test', members=members, url_test={'probe': probe, 'tolerance_ms': 0})); replace(config)
    observed = wait_group(cfg['url_test'], lambda g: all(m['health']['state'] == 'healthy' and not m['health']['last_probe'].startswith('0001-') for m in g['members']))
    expected = min(enumerate(observed['members']), key=lambda item: (item[1]['health']['latency_ms'], item[0]))[1]['member']
    assert observed['selected'] == expected and fixtures.http_count >= 3
    result['C_three_outbound_HTTP_latency'] = 'PASS'
    config['policy_groups'].append(dict(id=cfg['fallback'], name='Fallback', type='fallback', members=[members[1], members[0], members[2]], fallback={'probe': probe})); replace(config)
    wait_group(cfg['fallback'], lambda g: g['available'] and g['selected'] == members[1])
    primary = next(i for i in request('GET', '/api/v1/inbounds')['items'] if i['inbound']['protocol']['protocol'] == 'hysteria2')
    def bindings(enabled):
        for binding in primary['bindings']:
            view = request('GET', '/api/v1/inbounds/'+primary['inbound']['id'])
            current = next(b for b in view['bindings'] if b['binding_id'] == binding['binding_id'])
            revision = status()['state']['revision']
            request('POST', '/api/v1/inbounds/'+primary['inbound']['id']+'/binding', dict(binding_id=current['binding_id'], enabled=enabled, resource_revision=current['revision'], revision=revision))
    try:
        bindings(False); wait_group(cfg['fallback'], lambda g: g['available'] and g['selected'] == members[0])
    finally: bindings(True)
    wait_group(cfg['fallback'], lambda g: g['available'] and g['selected'] == members[1])
    result['D_primary_down_secondary_recovery'] = 'PASS'
    config['policy_groups'].append(dict(id=cfg['balance'], name='round robin', type='load_balance', members=members, load_balance={'algorithm': 'round_robin'}))
    balanced = rule(uid(), 'balanced listener', scope, action('group', cfg['balance']))
    config['route']['rules'].insert(0, balanced); replace(config)
    before = [sessions(a['id']) for a in members]
    for _ in range(6): traffic(port, fixtures.tcp4.server_address)
    assert [sessions(a['id'])-n for a, n in zip(members, before)] == [2, 2, 2]
    udp = Association(port)
    try:
        for i in range(8):
            udp.exchange(fixtures.udp1.server_address, ('affinity'+str(i)).encode())
            udp.exchange(fixtures.udp2.server_address, ('other-flow'+str(i)).encode())
        assert next(g for g in status()['network_runtime']['groups'] if g['id'] == cfg['balance'])['selection_count'] == '7'
    finally: udp.close()
    result['E_round_robin_UDP_affinity'] = 'PASS'
    request('POST', '/api/v1/dns/cache/flush', {});before = fixtures.counts_copy()
    answer = request('POST', '/api/v1/dns/lookup', {'domain': 'split.proxy.p12.local'})
    assert answer['server'] == cfg['proxy_dns'] and fixtures.counts_copy() == [before[0], before[1]+1]
    request('POST', '/api/v1/dns/lookup', {'domain': 'split.direct.p12.local'})
    assert fixtures.counts_copy() == [before[0]+1, before[1]+1]
    result['F_proxy_direct_DNS_no_leak'] = 'PASS'
    config['route']['rules'].pop(0); replace(config)
    original = held(port, ('held.example.p12.local', fixtures.tcp4.server_address[1])); udp = Association(port)
    try:
        exchange(original, b'old TCP');udp.exchange(('held.example.p12.local', fixtures.udp1.server_address[1]), b'old UDP')
        changed = copy.deepcopy(config)
        changed['policy_groups'][0]['selector']['selected'] = members[2]
        changed['dns_rules'].insert(0, dict(id=cfg['dns_rule_ids'][2], name='atomic DNS update', match={'domain_suffixes': ['example.p12.local']}, server=cfg['proxy_dns']))
        changed['route']['rules'] = [rule(ident, 'atomic rule '+str(i), dict(scope, domains=['unused-'+str(i)+'.p12.local']), action('reject')) for i, ident in enumerate(cfg['rule_ids'][4:])] + changed['route']['rules']
        errors = []
        def continuing():
            try:
                for _ in range(8): exchange(original, b'concurrent old TCP')
            except Exception as error: errors.append(type(error).__name__)
        worker = threading.Thread(target=continuing); worker.start()
        servers_before = sorted((r['inbound']['id'], r['inbound']['engine']) for r in request('GET', '/api/v1/inbounds')['items'])
        daemon_before = subprocess.check_output(['systemctl', 'show', 'splicore.service', '-p', 'MainPID', '--value'])
        replace(changed);worker.join(10);assert not worker.is_alive() and not errors
        exchange(original, b'survives commit')
        udp.exchange(('held.example.p12.local', fixtures.udp1.server_address[1]), b'old affinity after update')
        udp.exchange(('new-flow.example.p12.local', fixtures.udp2.server_address[1]), b'old snapshot new UDP flow')
        before = sessions(members[2]['id']);traffic(port, ('new.example.p12.local', fixtures.tcp4.server_address[1]));assert sessions(members[2]['id']) == before+1
        assert all(s['outbound_id'] == members[0]['id'] for s in status()['sessions'] if s['local_inbound_id'] == cfg['local'] and s['kind'] == 'udp_association')
        servers_after = sorted((r['inbound']['id'], r['inbound']['engine']) for r in request('GET', '/api/v1/inbounds')['items'])
        assert servers_before == servers_after and len(servers_after) == 6
        assert all(engine == 'native' for _, engine in servers_after)
        assert subprocess.check_output(['systemctl', 'show', 'splicore.service', '-p', 'MainPID', '--value']) == daemon_before
        result.update(G_atomic_100_rules_group_DNS_TCP_UDP='PASS', H_server_client_coexistence='PASS')
    finally: original.close();udp.close()
    # CLI reads and explicit DNS query/flush use the same protected installed core.
    for args in [('network', 'export'), ('route', 'status'), ('policy', 'status'), ('dns', 'status'), ('dns', 'lookup', '--domain', 'cli.proxy.p12.local'), ('dns', 'flush')]:
        subprocess.run(['/usr/local/bin/splicore', *args, '--config', '/etc/splicore/splicore.yaml'], check=True, stdout=subprocess.DEVNULL)
    canonical = subprocess.run(['/usr/local/bin/splicore', 'network', 'export', '--config', '/etc/splicore/splicore.yaml'], check=True, capture_output=True).stdout
    document, plan_file = WORK/'cli-network.json', WORK/'cli-plan.json'
    document.write_bytes(canonical)
    subprocess.run(['/usr/local/bin/splicore', 'network', 'validate', '--file', str(document), '--config', '/etc/splicore/splicore.yaml'], check=True, stdout=subprocess.DEVNULL)
    plan = subprocess.run(['/usr/local/bin/splicore', 'network', 'plan', '--file', str(document), '--config', '/etc/splicore/splicore.yaml'], check=True, capture_output=True)
    plan_file.write_bytes(plan.stdout)
    subprocess.run(['/usr/local/bin/splicore', 'network', 'apply', '--file', str(document), '--plan', str(plan_file), '--config', '/etc/splicore/splicore.yaml'], check=True, stdout=subprocess.DEVNULL)
    assert status()['state']['network'] == json.loads(canonical), 'canonical CLI round trip changed intent'
    query = WORK/'cli-query.json'
    query.write_text(json.dumps(dict(domain='cli.example.p12.local', port=443, network='tcp', local_inbound=cfg['local'])))
    subprocess.run(['/usr/local/bin/splicore', 'route', 'explain', '--file', str(query), '--config', '/etc/splicore/splicore.yaml'], check=True, stdout=subprocess.DEVNULL)
    result['canonical_CLI_round_trip'] = 'PASS'
    cfg['last_network'] = status()['state']['network']
    fixture.write_text(json.dumps(cfg, indent=2)+'\n');fixture.chmod(0o600)
    (WORK/(stage+'-status.json')).write_text(json.dumps(status(), indent=2)+'\n')
    (WORK/(stage+'-result.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result), flush=True)
