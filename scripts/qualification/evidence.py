#!/usr/bin/env python3
"""Record qualification context and export a bounded, public-safe projection."""
import argparse
from collections import deque
import ctypes
from datetime import datetime, timezone
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
ARTIFACT_LIMIT = 24 * MIB
FILE_LIMIT = 2 * MIB
FILE_COUNT = 512
STAGE = r'(?:release-build|(?:default|full)-(?:build|vet|test)|race(?:-test)?|product-smoke)'
NAME = r'[A-Za-z0-9_.:@/+%\[\]=-]{1,400}'
STAMP = r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,12})?(?:Z|[+-]\d\d:\d\d)'
ENDPOINT = r'(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]|192\.0\.2\.29|\[2001:db8::29\]):\d{1,5}'
GO_KEYS = ('GOVERSION', 'GOHOSTOS', 'GOHOSTARCH', 'GOOS', 'GOARCH', 'GOAMD64', 'CGO_ENABLED',
           'GOTOOLCHAIN', 'GOENV', 'GOFLAGS', 'GOTELEMETRY')
ACTIONS = ('start', 'run', 'pause', 'cont', 'pass', 'fail', 'skip', 'output', 'build-output', 'build-fail')


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def probe(args, env=None, limit=128 * 1024):
    try:
        result = subprocess.run(args, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, check=True)
        if len(result.stdout) <= limit:
            return result.stdout.decode('utf-8', errors='replace').strip()
    except (subprocess.SubprocessError, OSError):
        return None


def read_small(path, limit=4096):
    try:
        with Path(path).open(encoding='ascii', errors='replace') as file:
            return file.read(limit).strip()
    except OSError:
        return None


def go_settings(env=None):
    env = os.environ if env is None else env
    value = json.loads(probe(['go', 'env', '-json', *GO_KEYS], env) or '{}')
    # GOENV may otherwise expose a user-specific path. Record the explicit
    # process settings used by the qualification commands.
    value['GOENV'] = 'off' if value.get('GOENV') == 'off' else 'default'
    value['GOMAXPROCS'] = env.get('GOMAXPROCS')
    return value


def resources():
    value = {'logical_cpus': os.cpu_count(), 'cpu_model': platform.processor() or None}
    if os.name == 'nt':
        # MEMORYSTATUSEX has two DWORDs followed by seven unsigned 64-bit fields.
        class MemoryStatus(ctypes.Structure):
            _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32), ('totals', ctypes.c_uint64 * 7)]
        memory = MemoryStatus(length=ctypes.sizeof(MemoryStatus))
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
            value.update(memory_bytes=memory.totals[0], available_memory_bytes=memory.totals[1])
        handles = ctypes.c_uint32()
        kernel = ctypes.windll.kernel32
        process = ctypes.c_void_p(-1)
        if kernel.GetProcessHandleCount(process, ctypes.byref(handles)):
            value['collector_handle_count'] = handles.value
        affinity, system_affinity = ctypes.c_size_t(), ctypes.c_size_t()
        if kernel.GetProcessAffinityMask(process, ctypes.byref(affinity), ctypes.byref(system_affinity)):
            value['available_cpus'] = bin(affinity.value).count('1')
        return value
    import resource
    value['available_cpus'] = len(os.sched_getaffinity(0))
    memory = read_small('/proc/meminfo') or ''
    for field, key in [('MemTotal', 'memory_bytes'), ('MemAvailable', 'available_memory_bytes')]:
        match = re.search(r'^' + field + r':\s+(\d+) kB', memory, re.M)
        if match:
            value[key] = int(match[1]) * 1024
    cpu = re.search(r'^model name\s*:\s*([^\n]+)', read_small('/proc/cpuinfo') or '', re.M)
    if cpu:
        value['cpu_model'] = cpu[1]
    value['load_average'] = list(os.getloadavg())
    value['limits'] = {name: resource.getrlimit(getattr(resource, 'RLIMIT_' + name))
                       for name in ('NOFILE', 'NPROC', 'AS', 'MEMLOCK')}
    value['collector_fd_count'] = len(list(Path('/proc/self/fd').iterdir()))
    value['cgroup_limits'] = {name: read_small('/sys/fs/cgroup/' + name)
                              for name in ('cpu.max', 'memory.max', 'pids.max')}
    return value


def namespace(env):
    if platform.system() != 'Linux':
        return {'private': False, 'kind': 'windows-host'}
    addresses = json.loads(probe(['ip', '-j', 'address', 'show', 'dev', 'lo'], env) or '[]')
    loopback = [record['local'] for interface in addresses for record in interface.get('addr_info', [])
                if test_endpoint(record.get('local', ''))]
    return {'private': env.get('SPLICORE_PRIVATE_NETNS') == '1', 'kind': 'linux-netns',
            'id': os.stat('/proc/self/ns/net').st_ino, 'loopback_mtu': read_small('/sys/class/net/lo/mtu'),
            'loopback_addresses': sorted(loopback),
            'kernel_fixtures': env.get('SPLICORE_PHASE36_KERNEL') == '1',
            'ephemeral_ports': read_small('/proc/sys/net/ipv4/ip_local_port_range'),
            'reserved_ports': read_small('/proc/sys/net/ipv4/ip_local_reserved_ports')}


def windows_port_ranges():
    ranges = {}
    for family, protocol, query in itertools.product(('ipv4', 'ipv6'), ('tcp', 'udp'),
                                                     ('dynamicport', 'excludedportrange')):
        output = probe(['netsh', 'interface', family, 'show', query, 'protocol=' + protocol])
        ranges[f'{family}/{protocol}/{query}'] = ([list(map(int, re.findall(r'\d+', line)))
                                                   for line in output.splitlines()[:128]
                                                   if re.fullmatch(r'\s*(?:[^\d:]+:\s*)?\d+(?:\s+\d+)?\s*\*?\s*', line)]
                                                  if output is not None else None)
    return ranges


def fingerprint(target, label, kind):
    names = ('REPOSITORY', 'EVENT_NAME', 'REF', 'RUN_ID', 'RUN_ATTEMPT', 'JOB', 'SHA')
    env = os.environ
    run = {name.lower(): env.get('GITHUB_' + name) for name in names}
    return {'schema': 1, 'kind': kind, 'target': target, 'recorded_at': timestamp(), 'run': run,
            'source': {'commit': probe(['git', 'rev-parse', 'HEAD']), 'tree': probe(['git', 'rev-parse', 'HEAD^{tree}'])},
            'runner': {'label': label, 'image_os': env.get('ImageOS'), 'image_version': env.get('ImageVersion'),
                       'os': platform.system(), 'architecture': platform.machine(), 'kernel': platform.release(),
                       'kernel_version': platform.version(), 'runner_arch': env.get('RUNNER_ARCH')},
            'go': go_settings(), 'resources': resources(), 'network': namespace(env),
            'windows_port_ranges': windows_port_ranges() if os.name == 'nt' else None}


def test_context(env):
    return {'go': go_settings(env), 'network': namespace(env)}


def test_endpoint(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_loopback or str(ip) in ('192.0.2.29', '2001:db8::29')


def local_sockets():
    if os.name == 'nt':
        output = probe(['netstat', '-ano'])
        if output is None:
            return None
        rows = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[0] in ('TCP', 'UDP') and re.fullmatch(ENDPOINT, fields[1]) and fields[-1].isdigit():
                rows.append({'protocol': fields[0], 'local': fields[1], 'pid': int(fields[-1]),
                             'state': fields[3] if fields[0] == 'TCP' else 'BOUND'})
        return rows[:64]
    rows = []
    for name in ('tcp', 'tcp6', 'udp', 'udp6'):
        try:
            with Path('/proc/self/net', name).open(encoding='ascii') as table:
                next(table, None)
                for line in itertools.islice(table, 256):
                    _, local, _, state, queues, *_ = line.split()
                    addr, port = local.split(':')
                    raw = bytes.fromhex(addr)
                    if sys.byteorder == 'little':
                        raw = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
                    ip = str(ipaddress.ip_address(raw))
                    if test_endpoint(ip):
                        tx, rx = (int(q, 16) for q in queues.split(':'))
                        rows.append({'protocol': name, 'local_address': ip, 'port': int(port, 16),
                                     'state': state, 'tx_queue': tx, 'rx_queue': rx})
        except OSError:
            continue
    return rows[:64]


def failure_snapshot(path, env):
    try:
        save(path, {'recorded_at': timestamp(), 'resources': resources(), 'network': namespace(env),
                    'local_sockets': local_sockets()})
    except Exception:
        # This snapshot is advisory and must preserve the command's exit status.
        print('Failure snapshot unavailable', flush=True)


def safe_output(line):
    """Keep known diagnostic fields. Unclassified text can contain fixture secrets."""
    line = line.strip()
    location = re.match(r'([\w.-]+\.go:\d+):\s*', line)
    prefix = location[0] if location else ''
    body = line[len(prefix):]
    if body in ('WARNING: DATA RACE', '==================', 'testing: race detected during execution of test',
                'FAIL', 'PASS', 'Start snell quic proxy server'):
        return prefix + body
    if re.fullmatch(r'(?:Read|Write|Previous read|Previous write) at 0x[0-9a-f]+ by goroutine \d+:', body):
        return body
    if re.fullmatch(r'Goroutine \d+ \((?:running|finished)\) created at:', body):
        return body
    frame = re.fullmatch(r'([\w./*()\[\]-]+)\(.*\)(?:\s*\+0x[0-9a-f]+)?', body)
    if frame:
        return frame[1] + '([arguments omitted])'
    source = re.fullmatch(r'.*[/\\]([\w.-]+\.go:\d+)(?: \+0x[0-9a-f]+)?', body)
    if source:
        return source[1]
    # Keep fixed fixture events and only the stable fields of older log formats.
    fields = [r'(?:xray_peer_start|peer_start) pid=\d+ address=(?:' + ENDPOINT + r'|pending)(?: handoff=(?:true|false) release_at=' + STAMP + r')? started_at=' + STAMP,
              r'peer_exit pid=\d+ exit_code=-?\d+ at=' + STAMP,
              r'peer_ready pid=\d+ (?:address=' + ENDPOINT + r'|assigned_port=\d{1,5}) at=' + STAMP,
              r'xray_peer_rebind network=(?:tcp|udp) address=' + ENDPOINT + r' at=' + STAMP,
              r'peer_rebind address=' + ENDPOINT + r' TCP=(?:true|false) UDP=(?:true|false)',
              r'peer_handoff at=' + STAMP + r' address=' + ENDPOINT + r' parent_TCP_and_UDP=released child_start=next no_start_retry=true',
              r'peer_listeners pid=\d+ address=' + ENDPOINT + r' TCP=SOCKS-sentinel-verified UDP=H3-marker-and-occupied actual_H3_payload=required-next']
    if any(re.fullmatch(pattern, body) for pattern in fields):
        return prefix + body
    owner = re.fullmatch(r'child_socket_owner pid=(\d+) socket=.{1,180} network=(tcp|udp) address=('
                         + ENDPOINT + r') at=(' + STAMP + r')', body)
    if owner:
        pid, protocol, address, at = owner.groups()
        return f'{prefix}child_socket_owner pid={pid} network={protocol} address={address} at={at}'
    missing_owner = re.fullmatch(r'child pid=(\d+) does not own (tcp|udp) listener at (' + ENDPOINT + ')', body)
    if missing_owner:
        return prefix + missing_owner[0]
    ready = re.search(r'\[Warning\] core: Xray (\d+\.\d+\.\d+) started\b', body)
    if ready:
        return f'Xray {ready[1]} started'
    if 'Start snell quic proxy server' in body:
        return 'Start snell quic proxy server'
    for marker in ('i/o timeout', 'context deadline exceeded', 'connection refused', 'connection reset by peer',
                   'address already in use', 'permission denied', 'test timed out', 'Xray rejected profile',
                   'external Xray startup timeout', 'official listener not ready', 'tcp_connect'):
        if marker in body:
            return prefix + marker
    return '[redacted]\n' if line else ''


DNS_FALLBACK_RESULT = r'(?:ok|timeout|socket_error|error) errno=\d{1,10}'
DNS_FALLBACK_FIELDS = (
    r'dns_fallback_stage stage=(?:tcp_bind|tcp_retry_close|tcp_ready|tcp_shutdown|tcp_serve|udp_bind|udp_ready|udp_shutdown|udp_serve|'
    r'underlay_begin|engine_start|lookup) port=\d{1,5} result=' + DNS_FALLBACK_RESULT,
    r'dns_fallback_reply network=(?:udp|tcp) id=\d{1,5} tc=(?:true|false) rcode=\d{1,4} answers=\d{1,5} result='
    + DNS_FALLBACK_RESULT,
    r'dns_fallback_answer addresses=\d{1,5} matched=(?:true|false)',
    r'dns_fallback_assertion check=(?:answer|counts|protection)',
    r'dns_fallback_counts udp=\d{1,9} tcp=\d{1,9} protection=\d{1,9} fallback=(?:unobserved|tcp_protect|matching_tcp_reply)',
)
SNELL_V5_FIELDS = (
    r'snell_v5_flow id=(?:[1-9]|1[0-2]) udp_port=\d{1,5} echo_port=\d{1,5} written=\d{1,5} received=\d{1,5} '
    r'phase=(?:listen|write|read|payload|complete) timeout=(?:true|false) elapsed_ms=\d{1,8}',
    r'snell_v5_echo port=\d{1,5} received=\d{1,9} sent=\d{1,9}',
    r'snell_v5_peer pid=\d{1,10} exit_code=-?\d{1,10} cleanup_kill=(?:requested|already_done|error)',
)
PHASE20_COUNT = r'(?:0|[1-9]\d{0,8})'
PHASE20_ROUND = r'(?:[1-9]|1[0-9]|2[0-5])'
PHASE20_SCOPE = r'(?:stage=warmup round=0|stage=round round=' + PHASE20_ROUND + r')'
PHASE20_RESOURCES = (r'goroutines=' + PHASE20_COUNT + r' fds=' + PHASE20_COUNT +
                     r' listeners=' + PHASE20_COUNT + r' sessions=' + PHASE20_COUNT +
                     r' udp_workers=' + PHASE20_COUNT + r' fds_known=(?:true|false)'
                     r' status_known=(?:true|false) stack_complete=(?:true|false)')
PHASE20_LIFECYCLE_FIELDS = (
    r'phase20_lifecycle stage=setup round=0 event=runtime_stop result=(?:ok|plan_error|apply_error)',
    r'phase20_lifecycle ' + PHASE20_SCOPE +
    r' event=runtime_(?:start|stop) result=(?:ok|plan_error|apply_error)',
    r'phase20_lifecycle ' + PHASE20_SCOPE + r' event=idle_wait result=(?:ok|error)',
    r'phase20_lifecycle ' + PHASE20_SCOPE +
    r' event=running_sample result=observed stopped=false ' + PHASE20_RESOURCES,
    r'phase20_lifecycle ' + PHASE20_SCOPE +
    r' event=stopped_sample result=observed stopped=true ' + PHASE20_RESOURCES,
    r'phase20_lifecycle stage=warmup round=0 event=complete result=ok stopped=true ' + PHASE20_RESOURCES,
    r'phase20_lifecycle stage=warmup round=0 event=fd_category '
    r'(?:result=observed category=(?:socket|pipe|anon_inode|file|unknown) count=' + PHASE20_COUNT +
    r'|result=unavailable category=(?:socket|pipe|anon_inode|file|unknown) count=0)',
    r'phase20_lifecycle stage=round round=' + PHASE20_ROUND + r' event=resource_check result=ok',
    r'phase20_lifecycle stage=final round=25 event=resource_check result=observed '
    r'baseline_goroutines=' + PHASE20_COUNT + r' baseline_fds=' + PHASE20_COUNT +
    r' baseline_listeners=' + PHASE20_COUNT + r' baseline_sessions=' + PHASE20_COUNT +
    r' baseline_udp_workers=' + PHASE20_COUNT + r' baseline_fds_known=(?:true|false)'
    r' baseline_status_known=(?:true|false) baseline_stack_complete=(?:true|false)'
    r' final_goroutines=' + PHASE20_COUNT + r' final_fds=' + PHASE20_COUNT +
    r' final_listeners=' + PHASE20_COUNT + r' final_sessions=' + PHASE20_COUNT +
    r' final_udp_workers=' + PHASE20_COUNT + r' final_fds_known=(?:true|false)'
    r' final_status_known=(?:true|false) final_stack_complete=(?:true|false)',
    r'phase20_lifecycle stage=assertion round=25 event=failure result=fail check=goroutines '
    r'baseline=' + PHASE20_COUNT + r' actual=' + PHASE20_COUNT + r' limit=' + PHASE20_COUNT,
    r'phase20_lifecycle stage=assertion round=' + PHASE20_ROUND +
    r' event=failure result=fail check=(?:fds|sessions|udp_workers) '
    r'baseline=' + PHASE20_COUNT + r' actual=' + PHASE20_COUNT + r' limit=' + PHASE20_COUNT,
    r'phase20_lifecycle stage=assertion round=(?:0|' + PHASE20_ROUND +
    r') event=failure result=fail check=(?:idle|wrong_auth)',
    r'phase20_lifecycle stage=assertion round=25 event=failure result=fail '
    r'check=(?:status|account_count|account_stats|status_secret)',
    r'phase20_lifecycle stage=classification round=25 event=goroutine_snapshot result=observed '
    r'captured=' + PHASE20_COUNT + r' truncated=(?:true|false)',
    r'phase20_lifecycle stage=classification round=25 event=goroutine_category result=observed '
    r'category=(?:testing|sql|echo_accept|echo_connection|client_listener|client_udp|runtime_background|unknown) '
    r'count=' + PHASE20_COUNT,
    r'phase20_lifecycle stage=final round=25 event=assertion result=ok check=goroutines '
    r'baseline=' + PHASE20_COUNT + r' actual=' + PHASE20_COUNT + r' limit=' + PHASE20_COUNT,
    r'phase20_lifecycle stage=final round=25 event=complete result=ok',
)
SENSITIVE_OBSERVATION = re.compile(
    r'(?:authorization|cookie|set-cookie|password|passwd|psk|private[_-]?key|secret|token|bearer|credential|api[_-]?key)\s*[:=]',
    re.IGNORECASE,
)


def protocol_observation(event):
    if not isinstance(event, dict) or event.get('Action') != 'output':
        return ''
    package, test = event.get('Package'), event.get('Test')
    output = event.get('Output')
    if not isinstance(test, str) or not isinstance(output, str) or len(output.encode('utf-8')) > 512:
        return ''
    if SENSITIVE_OBSERVATION.search(output):
        return ''
    if (package == 'github.com/ike-sh/Splicore/internal/splicore/networkruntime'
            and test == 'TestProtectedDNSUDPTruncationFallsBackToTCP'):
        source, fields = 'dns_fallback_test.go', DNS_FALLBACK_FIELDS
        line = output.strip()
        site = re.match(re.escape(source) + r':\d{1,6}: ', line)
    elif (package == 'github.com/ike-sh/Splicore/internal/splicore/engine/native'
          and re.fullmatch(r'TestSnellV5NativeAndOfficial/Official_(?:true|false)(?:/(?:127\.0\.0\.1|::1))?', test)):
        source, fields = 'snell_v5_test.go', SNELL_V5_FIELDS
        line = output.strip()
        site = re.match(re.escape(source) + r':\d{1,6}: ', line)
    elif (package == 'github.com/ike-sh/Splicore/internal/splicore/application'
          and test == 'TestPhase20ProxyLifetimeAuthRotation25'):
        if '\r' in output or not output.endswith('\n') or output.count('\n') != 1:
            return ''
        line = output[:-1]
        if line.startswith('    '):
            line = line[4:]
        elif line != line.lstrip(' '):
            return ''
        source, fields = 'proxy_interfaces_test.go', PHASE20_LIFECYCLE_FIELDS
        site = re.match(re.escape(source) + r':[1-9]\d{0,5}: ', line)
    else:
        return ''
    if site and any(re.fullmatch(pattern, line[site.end():]) for pattern in fields):
        return line
    return ''


def protocol_observations(path):
    """Preserve the selected fixture observations outside the general log tail."""
    scanned = 0
    lines = []
    limit = b'{"Evidence":"protocol observation scan reached its limit"}\n'
    with path.open('rb') as stream:
        for raw in stream:
            scanned += len(raw)
            if scanned > 64 * MIB or len(lines) >= 256:
                return b''.join(lines) + limit
            if not raw.startswith(b'{') or not any(marker in raw for marker in
                    (b'snell_v5_', b'dns_fallback_', b'phase20_lifecycle')):
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            if protocol_observation(event):
                lines.append((safe_event(raw) + '\n').encode('utf-8'))
    return b''.join(lines)


def safe_event(line):
    try:
        event = json.loads(line)
    except ValueError:
        return safe_output(line)
    if not isinstance(event, dict) or event.get('Action') not in ACTIONS:
        return ''
    result = {'Action': event['Action']}
    for field in ('Package', 'Test', 'ImportPath', 'FailedBuild', 'Time'):
        if isinstance(event.get(field), str) and re.fullmatch(STAMP if field == 'Time' else NAME, event[field]):
            result[field] = event[field]
    if type(event.get('Elapsed')) in (int, float):
        result['Elapsed'] = event['Elapsed']
    if isinstance(event.get('Output'), str):
        observation = protocol_observation(event)
        result['Output'] = (observation or '\n'.join(
            safe_output(part).rstrip('\n') for part in event['Output'].splitlines())) + '\n'
    return json.dumps(result, separators=(',', ':'))


def plain_file(path):
    # Windows directory junctions are reparse points but not all are symlinks.
    for entry in (path, *path.parents):
        metadata = entry.lstat()
        if entry.is_symlink() or getattr(metadata, 'st_file_attributes', 0) & 0x400:
            return False
    return path.is_file()


def projected_log(path):
    with path.open('rb') as stream:
        truncated = path.stat().st_size > 8 * MIB
        if truncated:
            stream.seek(-8 * MIB, os.SEEK_END)
            stream.readline(16 * 1024)
        lines = deque()
        size = 0
        for raw in stream:
            text = raw.decode('utf-8', errors='replace')
            safe = safe_event(text) if text.startswith('{') else safe_output(text)
            if not safe:
                continue
            data = (safe.rstrip('\n') + '\n').encode('utf-8')
            lines.append(data)
            size += len(data)
            while size > FILE_LIMIT - 64:
                size -= len(lines.popleft())
                truncated = True
        prefix = b'{"Evidence":"truncated; retained tail"}\n' if truncated else b''
        return prefix + b''.join(lines)


def failure_events(path, status):
    """Preserve the failing Go tests' events even if the general log loses its head."""
    tests = set(status.get('failed_tests', ()))
    packages = set(status.get('failing_packages', ()))
    selected = bytearray()
    consumed = 0
    truncated = b'{"Evidence":"failure event scan reached its limit"}\n'
    with path.open('rb') as stream:
        for raw in stream:
            consumed += len(raw)
            if consumed > 64 * MIB:
                return bytes(selected) + truncated
            if not raw.startswith(b'{'):
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            package, test = event.get('Package', ''), event.get('Test', '')
            if (event.get('Action') not in ('fail', 'build-fail')
                    and f'{package}/{test}' not in tests and (test or package not in packages)):
                continue
            data = (safe_event(raw.decode('utf-8', errors='replace')) + '\n').encode('utf-8')
            if len(selected) + len(data) + len(truncated) > FILE_LIMIT:
                return bytes(selected) + truncated
            selected.extend(data)
    return bytes(selected)


def read_json(path):
    try:
        if plain_file(path) and path.stat().st_size <= FILE_LIMIT:
            value = json.loads(path.read_bytes())
            if isinstance(value, dict):
                return value
    except (OSError, ValueError):
        pass


def public_command(command):
    public = []
    for index, arg in enumerate(command):
        if index == 0 or (index == 1 and arg.endswith('.py')):
            arg = arg.replace('\\', '/').rsplit('/', 1)[-1]
        if index and command[index - 1] == '-o':
            arg = '${RELEASE_OUTPUT}/' + arg.replace('\\', '/').rsplit('/', 1)[-1]
        public.append(arg)
    return public


def stage_record(value):
    result = {key: value[key] for key in ('started_at', 'finished_at', 'exit_code', 'result', 'child_pid',
                                          'timeout_seconds', 'execution', 'test_counts', 'failed_tests',
                                          'failing_packages', 'behavior_policy', 'policy_result', 'policy_failed_tests') if key in value}
    result['command'] = public_command(value['command'])
    return result


def test_identities(tests):
    # Use the same identity boundary as Go JSON events, without log payloads.
    results = {name: action for name, action in tests.items()
               if name.startswith('github.com/ike-sh/Splicore/') and re.fullmatch(NAME, name)
               and action in ('pass', 'fail', 'skip')}
    return {'results': results, 'omitted': len(tests) - len(results)}


def peer_logs(root):
    for scope in ('vless-encryption-evidence', 'h3-evidence', 'wg-evidence', 'snell-evidence'):
        folder = root / scope
        if not folder.is_dir() or folder.is_symlink():
            continue
        for path in sorted(itertools.islice(itertools.chain(folder.glob('*/*'), folder.glob('*')), 2048)):
            if path.name in ('peer.log', 'official.log') or re.fullmatch(r'[\w.-]+\.peer\.log|official-[\w.-]+\.stderr', path.name):
                yield path
            elif re.fullmatch(r'[\w.-]+\.peer-exit\.json', path.name):
                yield path


def peer_identity(reference, compiler):
    pinned = read_json(reference / 'REFERENCE_MANIFEST.json') or {}
    sources = dict(xray=read_json(reference / 'xray/reference.json'), snell=pinned.get('snell'),
                   wireguard=pinned.get('wireguard'), windows_race_toolchain=read_json(compiler / 'toolchain.json'))
    fields = {'version': r'v[\d.]+', 'binary_sha256': r'[a-f0-9]{64}', 'archive_sha256': r'[a-f0-9]{64}',
              'sha256': r'[a-f0-9]{64}', 'source': r'scripts/dev/wireguard-peer',
              'engine': r'golang\.zx2c4\.com/wireguard@v[\d.-]+[a-f0-9]+', 'status': r'NOT EXECUTED',
              'url': r'https://(?:github\.com/(?:XTLS/Xray-core|mstorsjo/llvm-mingw)/releases/download|dl\.nssurge\.com/snell)/[A-Za-z0-9/_.-]+'}
    return {name: {field: value[field] for field, pattern in fields.items()
                   if isinstance(value.get(field), str) and re.fullmatch(pattern, value[field])}
            for name, value in sources.items() if isinstance(value, dict)}


def performance_summary(path):
    source = read_json(path)
    if source is None:
        return None
    metrics = ('connections', 'tcp_goodput_mbps', 'udp_sent', 'udp_received', 'udp_loss_percent',
               'udp_goodput_mbps', 'peak_rss_bytes', 'peak_goroutines', 'peak_os_resources')
    profiles = json.loads((ROOT / 'scripts/performance/profiles.json').read_bytes())['profiles']['ci']
    scenarios = {row['name'] for row in profiles}
    runs = {}
    for name, run in source.get('runs', {}).items():
        if not re.fullmatch(r'\d{5}-clean', name):
            continue
        runs[name] = {'exit_code': run['exit_code'], 'elapsed_seconds': run['elapsed_seconds'], 'results': {
            scenario: {key: row[key] for key in metrics if type(row.get(key)) in (int, float)}
            for scenario, row in run['results'].items() if scenario in scenarios}}
    return {'classification': source['classification'], 'failed_runs': source['failed_runs'], 'runs': runs}


def export(private, public, target, label, kind):
    if private == public or private in public.parents or public in private.parents:
        raise ValueError('Public and private evidence directories must be disjoint')
    public.mkdir(parents=True, exist_ok=False)
    manifest = {'schema': 1, 'files': {}, 'limits': {'total_bytes': ARTIFACT_LIMIT, 'file_bytes': FILE_LIMIT,
                                                   'file_count': FILE_COUNT}, 'omitted_by_limits': 0}
    used = 0

    def add(name, data):
        nonlocal used
        # Reserve the full per-file allowance for the final SHA256 inventory.
        if len(data) > FILE_LIMIT or used + len(data) > ARTIFACT_LIMIT - FILE_LIMIT or len(manifest['files']) >= FILE_COUNT - 1:
            manifest['omitted_by_limits'] += 1
            return
        path = public / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        manifest['files'][name] = {'bytes': len(data), 'sha256': sha256(data)}
        used += len(data)

    reference = private / 'reference'
    runner_file = private / 'runner.json'
    runner = read_json(runner_file) or fingerprint(target, label, kind)
    runner['reference'] = peer_identity(reference, private / 'compiler')
    stages = {}
    indexes = {}
    for path in sorted((private / 'raw').glob('*.json')):
        if re.fullmatch(STAGE, path.stem):
            value = read_json(path)
            if value is not None:
                status = stage_record(value)
                stages[path.stem] = status
                add('commands/' + path.name, json_bytes(status))
                if isinstance(value.get('tests'), dict) and value['tests']:
                    indexes[path.stem] = test_identities(value['tests'])
    runner['test_commands'] = {name: {key: value[key] for key in ('command', 'timeout_seconds', 'execution')}
                               for name, value in stages.items() if '-test' in name or name == 'race'}
    runner['fingerprint_sha256'] = sha256(json_bytes(runner))
    add('fingerprint.json', json_bytes(runner))

    for name, status in stages.items():
        if status['result'] == 'PASS' and status.get('policy_result') != 'FAIL':
            continue
        path = private / 'raw' / (name + '.stdout')
        if path.is_file() and plain_file(path) and (events := failure_events(path, status)):
            add('commands/' + name + '.failures.jsonl', events)
    for name, index in indexes.items():
        add(f'commands/{name}.test-identities.json', json_bytes(index))
        path = private / 'raw' / (name + '.stdout')
        if path.is_file() and plain_file(path) and (observations := protocol_observations(path)):
            add(f'commands/{name}.protocol-observations.jsonl', observations)
    for path in sorted((private / 'raw').glob('*')):
        if not re.fullmatch(STAGE + r'\.(?:stdout|stderr|failure\.json)', path.name) or not plain_file(path):
            continue
        if path.suffix == '.json':
            if (value := read_json(path)) is not None:
                add('commands/' + path.name, json_bytes(value))
        else:
            add('commands/' + path.name, projected_log(path))
    for path in peer_logs(reference):
        if len(manifest['files']) >= FILE_COUNT - 2:
            manifest['omitted_by_limits'] += 1
            break
        if not plain_file(path):
            continue
        key = 'peers/' + path.relative_to(reference).as_posix()
        if path.suffix == '.json':
            if (value := read_json(path)) is not None:
                fields = ('exit_code', 'exited_before_cleanup', 'cleanup_kill_requested')
                add(key, json_bytes({field: value[field] for field in fields if type(value.get(field)) in (bool, int)}))
        else:
            add(key, projected_log(path))
    summary_file = private / 'raw/summary.json'
    if summary_file.is_file() and (value := read_json(summary_file)) is not None:
        fields = ('classification', 'target', 'power_loss', 'native_startup', 'native_traffic', 'native_full_qualification')
        add('native-summary.json', json_bytes({key: value[key] for key in fields if key in value}))
    if kind == 'performance' and (value := performance_summary(private / 'performance/summary.json')) is not None:
        add('performance-summary.json', json_bytes(value))
    manifest.update(source=runner['source'], run=runner['run'], target=target, kind=kind)
    save(public / 'SHA256_MANIFEST.json', manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('fingerprint', 'export'))
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--public', type=Path)
    parser.add_argument('--target', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--kind', default='release',
                        choices=('release', 'windows-race', 'performance', 'product-smoke'))
    args = parser.parse_args()
    if args.action == 'fingerprint':
        save(args.private.resolve() / 'runner.json', fingerprint(args.target, args.label, args.kind))
    else:
        if args.public is None:
            parser.error('--public is required for export')
        export(args.private.resolve(), args.public.resolve(), args.target, args.label, args.kind)


if __name__ == '__main__':
    main()
