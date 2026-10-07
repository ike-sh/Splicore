"""Standard TLS Trojan peers, both directions. Run in an isolated loopback lab.

Usage: python3 scripts/splicore-trojan-interop.py /external/root
Root supplies splicore and pinned clients/{mihomo,sing-box,clients.json}.
Synthetic secrets and raw logs stay in root/private; only redacted evidence is
printed. External cores are test peers and never production subprocesses.
"""
import concurrent.futures
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('helper', pathlib.Path(__file__).with_name('splicore-snell-interop.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        value = bytes([1 if ip.version == 4 else 4]) + ip.packed
    except ValueError:
        raw = host.encode('ascii')
        value = bytes([3, len(raw)]) + raw
    return value + struct.pack('!H', port)


def read_address(c, kind):
    n = 4 if kind == 1 else 16 if kind == 4 else h.exact(c, 1)[0]
    b = h.exact(c, n)
    host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, b) if kind != 3 else b.decode('ascii')
    return host, int.from_bytes(h.exact(c, 2), 'big')


def socks(port, target, command):
    c = socket.create_connection(('127.0.0.1', port), timeout=5)
    c.sendall(bytes([5, 1, 0]))
    assert h.exact(c, 2) == bytes([5, 0])
    c.sendall(bytes([5, command, 0]) + address(*target))
    reply = h.exact(c, 4)
    assert reply[1] == 0
    return c, read_address(c, reply[3])


def traffic(port, tcp, udp, udp_domains=True):
    started = time.monotonic()
    count = 0
    for host in ('127.0.0.1', '::1', 'localhost'):
        c, _ = socks(port, (host, tcp), 1)
        with c, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            data = bytes(range(256)) * 4096
            pending = pool.submit(c.sendall, data)
            assert h.exact(c, len(data)) == data
            pending.result(timeout=10)
            count += len(data)
    control, relay = socks(port, ('0.0.0.0', 0), 3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as p:
        p.settimeout(5)
        for host in (('127.0.0.1', '::1', 'localhost') if udp_domains else ('127.0.0.1', '::1')):
            for size in (0, 1, 1400, 8192):
                data = bytes([size % 251]) * size
                p.sendto(bytes(3) + address(host, udp) + data, relay)
                try: raw, _ = p.recvfrom(65535)
                except TimeoutError: raise RuntimeError(f'UDP interop timeout host={host} size={size}') from None
                assert raw[:3] == bytes(3)
                offset = 4 + (4 if raw[3] == 1 else 16 if raw[3] == 4 else 1 + raw[4]) + 2
                assert raw[offset:] == data
                count += size
    return {'tcp_bytes': 3 * 1048576, 'udp_datagrams': 12 if udp_domains else 8, 'udp_domain': 'PASS' if udp_domains else 'PEER_UNSUPPORTED_T18-COMPAT-003', 'payload_bytes': count, 'seconds': time.monotonic() - started}


def main():
    root = pathlib.Path(sys.argv[1]).resolve()
    assert not root.is_relative_to(pathlib.Path(__file__).resolve().parent.parent)
    assert os.readlink('/proc/self/ns/net') != os.environ['SPLICORE_INTEROP_PARENT_NS']
    os.umask(0o077)
    private = root / 'private'
    private.mkdir(mode=0o700)
    state = private / 'state'
    state.mkdir(mode=0o700)
    api, key = private / 'control.sock', state / 'key'
    exe = str(root / 'splicore')
    bootstrap = private / 'bootstrap.yaml'
    subprocess.run([exe, 'key', 'init', '--file', str(key)], check=True, capture_output=True)
    bootstrap.write_text(f'schema: 1\nstate_directory: {state}\nkey_file: {key}\napi:\n  unix_socket: {api}\n')
    ca, ca_key, cert, cert_key, csr = [private / s for s in ('ca.pem', 'ca.key', 'cert.pem', 'cert.key', 'cert.csr')]
    ext = private / 'ext.cnf'
    ext.write_text('subjectAltName=DNS:trojan.synthetic.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n')
    commands = [
        ['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(ca_key), '-out', str(ca), '-days', '1', '-subj', '/CN=Splicore synthetic CA', '-addext', 'basicConstraints=critical,CA:TRUE'],
        ['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(cert_key), '-out', str(csr), '-subj', '/CN=trojan.synthetic.test'],
        ['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key), '-CAcreateserial', '-out', str(cert), '-days', '1', '-extfile', str(ext)],
    ]
    for args in commands:
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes, logs, servers, matrix = [], [], [], []
    class TCP6(h.EchoTCP): address_family = socket.AF_INET6
    class UDP6(h.EchoUDP): address_family = socket.AF_INET6
    tcp = h.EchoTCP(('127.0.0.1', 0), h.Echo)
    udp = h.EchoUDP(('127.0.0.1', 0), h.UDPEcho)
    servers = [tcp, udp, TCP6(('::1', tcp.server_address[1]), h.Echo), UDP6(('::1', udp.server_address[1]), h.UDPEcho)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    def launch(args, name):
        log = (root / (name + '.log')).open('wb')
        logs.append(log)
        p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        processes.append(p)
        return p
    def request(method, path, data=None):
        c = h.UnixHTTP(api)
        try:
            c.request(method, path, json.dumps(data).encode() if data is not None else None, {'Content-Type': 'application/json'})
            r = c.getresponse(); raw = r.read()
            assert r.status == 200, (path, r.status)
            return json.loads(raw)
        finally: c.close()
    def cli(*args):
        cp = subprocess.run([exe, *args, '--config', str(bootstrap)], capture_output=True)
        assert cp.returncode == 0, 'CLI rejected operation'
        return json.loads(cp.stdout)
    def mutate(doc):
        p = request('POST', '/api/v1/client/plan', doc)
        return request('POST', '/api/v1/client/apply', {'document': doc, 'digest': p['digest'], 'revision': p['revision']})
    try:
        daemon = launch([exe, 'run', '--config', str(bootstrap)], 'splicore')
        deadline = time.monotonic() + 15
        while True:
            assert daemon.poll() is None
            try: request('GET', '/api/v1/system'); break
            except OSError:
                assert time.monotonic() < deadline
                os.sched_yield()
        port = h.free_port()
        users = [{'account_name': 'synthetic-A', 'password': 'SyntheticTrojanInteropA'}, {'account_name': 'synthetic-B', 'password': 'SyntheticTrojanInteropB'}]
        doc = {'schema': 1, 'name': 'Trojan-interop', 'engine': 'native', 'listener': {'host': '127.0.0.1', 'port': port}, 'display_endpoint': {'host': '127.0.0.1', 'port': port}, 'settings': {'tls': {'server_name': 'trojan.synthetic.test', 'certificate_file': str(cert), 'private_key_file': str(cert_key), 'ca_certificate': ca.read_text()}}, 'users': users}
        fixture, planned = private / 'creation.json', private / 'plan.json'
        fixture.write_text(json.dumps(doc))
        cli('inbound', 'validate', '--protocol', 'trojan', '--file', str(fixture))
        plan = cli('inbound', 'plan', '--protocol', 'trojan', '--file', str(fixture))
        planned.write_text(json.dumps(plan))
        created = cli('inbound', 'apply', '--protocol', 'trojan', '--file', str(fixture), '--plan', str(planned))
        inbound = created['inbound_id']
        cli('inbound', 'get', '--id', inbound)
        for peer, version in (('mihomo', '1.19.30'), ('sing-box', '1.14.1')):
            for user, binding in zip(users, created['bindings']):
                x = cli('inbound', 'export', '--id', inbound, '--binding-id', binding['binding_id'], '--format', peer, '--client-version', version)
                exported = json.loads(x['content'])
                local = h.free_port(); config_path = private / f'{peer}-{len(matrix)}.json'
                if peer == 'mihomo':
                    home = private / f'mihomo-home-{len(matrix)}'; home.mkdir()
                    controller = h.free_port()
                    config = {'socks-port': local, 'external-controller': f'127.0.0.1:{controller}', 'allow-lan': False, 'bind-address': '127.0.0.1', 'mode': 'rule', 'log-level': 'silent', 'ipv6': True, **exported, 'rules': ['MATCH,' + exported['proxies'][0]['name']]}
                    config_path = home / 'config.json'
                    args = [str(root/'clients/mihomo'), '-d', str(home), '-f', str(config_path)]
                    check = args + ['-t']
                else:
                    config = {'log': {'disabled': True}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': local}], 'outbounds': [exported], 'dns': {'servers': [{'type': 'local', 'tag': 'local'}]}, 'route': {'default_domain_resolver': 'local'}}
                    args = [str(root/'clients/sing-box'), 'run', '-c', str(config_path)]
                    check = [args[0], 'check', '-c', str(config_path)]
                config_path.write_text(json.dumps(config)); subprocess.run(check, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p = launch(args, f'{peer}-client-{len(matrix)}'); h.wait_port(local, p)
                if peer == 'mihomo': h.wait_mihomo_config(controller, config_path, p, exported['proxies'][0]['name'])
                result = traffic(local, tcp.server_address[1], udp.server_address[1])
                matrix.append({'client': peer, 'server': 'Splicore', 'version': version, 'user': user['account_name'], 'TCP': 'PASS', 'UDP': 'PASS', 'TLS_verify': 'PASS', 'SNI': 'PASS', **result})
                h.stop(p)
            remote = h.free_port(); config_path = private / f'{peer}-server.json'
            if peer == 'mihomo':
                home = private
                controller = h.free_port()
                config = {'mode': 'rule', 'log-level': 'info', 'external-controller': f'127.0.0.1:{controller}', 'ipv6': True, 'rules': ['MATCH,DIRECT'], 'listeners': [{'name': 'Trojan-peer', 'type': 'trojan', 'listen': '127.0.0.1', 'port': remote, 'users': [{'username': 'synthetic', 'password': users[0]['password']}], 'certificate': str(cert), 'private-key': str(cert_key)}]}
                args = [str(root/'clients/mihomo'), '-d', str(home), '-f', str(config_path)]
                check = args + ['-t']
            else:
                config = {'log': {'disabled': True}, 'inbounds': [{'type': 'trojan', 'listen': '127.0.0.1', 'listen_port': remote, 'users': [{'name': 'synthetic', 'password': users[0]['password']}], 'tls': {'enabled': True, 'certificate_path': str(cert), 'key_path': str(cert_key)}}], 'outbounds': [{'type': 'direct'}], 'dns': {'servers': [{'type': 'local', 'tag': 'local'}]}, 'route': {'default_domain_resolver': 'local'}}
                args = [str(root/'clients/sing-box'), 'run', '-c', str(config_path)]; check = [args[0], 'check', '-c', str(config_path)]
            config_path.write_text(json.dumps(config)); subprocess.run(check, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p = launch(args, peer+'-server')
            if peer == 'mihomo': h.wait_mihomo_config(controller, config_path, p, 'DIRECT')
            h.wait_port(remote, p)
            for target_port, label in ((remote, peer), (port, 'Splicore')):
                node = {'name': 'synthetic-'+label, 'protocol': {'protocol': 'trojan', 'wire_version': 'standard', 'feature_profile': 'base'}, 'endpoint': {'host': '127.0.0.1', 'port': target_port}, 'transport': {'kind': 'tcp'}, 'security': {'kind': 'tls', 'tls': {'enabled': True, 'server_name': 'trojan.synthetic.test', 'trust': 'explicit_ca', 'ca_certificate': ca.read_text()}}, 'options': {'schema_version': 1, 'data': {'udp': True}}, 'metadata': {}}
                nid = mutate({'resource': 'node', 'action': 'create', 'node': node, 'credential': {'kind': 'password', 'value': users[0]['password']}})['id']
                oid = mutate({'resource': 'outbound', 'action': 'create', 'outbound': {'name': 'proxy-'+label, 'kind': 'proxy', 'node_id': nid, 'engine': 'native'}})['id']
                local = h.free_port()
                mutate({'resource': 'local-inbound', 'action': 'create', 'local_inbound': {'name': 'SOCKS-'+label, 'listen': {'port': local}, 'selected_outbound': oid}})
                result = traffic(local, tcp.server_address[1], udp.server_address[1], udp_domains=label != 'mihomo')
                matrix.append({'client': 'Splicore', 'server': label, 'version': version if label != 'Splicore' else 'Phase18', 'TCP': 'PASS', 'UDP': 'PASS', 'TLS_verify': 'PASS', 'SNI': 'PASS', **result})
            h.stop(p)
        # Owned diagnostics include no password, derived credential, or private key.
        for file in root.glob('*.log'):
            raw = file.read_bytes()
            for user in users:
                assert user['password'].encode() not in raw
                assert hashlib.sha224(user['password'].encode()).hexdigest().encode() not in raw
            assert b'BEGIN PRIVATE KEY' not in raw
        (root/'results.json').write_text(json.dumps({'result': 'PASS', 'matrix': matrix, 'versions': json.loads((root/'clients/clients.json').read_text()), 'splicore_sha256': hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest()}, indent=2)+'\n')
        print(json.dumps({'result': 'PASS', 'matrix': matrix}), flush=True)
    finally:
        for p in reversed(processes): h.stop(p)
        for server in servers: server.shutdown(); server.server_close()
        for log in logs: log.close()


if __name__ == '__main__': main()
