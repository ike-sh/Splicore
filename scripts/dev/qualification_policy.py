"""Validate executed behavior identities; source presence is never qualification."""
from collections import Counter
import json
import os
from pathlib import PurePosixPath

PREFIX = 'github.com/ike-sh/Splicore/'
RUNTIME_TESTS = {
    'TestRuntimeBinaryTrafficShutdownAndRestart': (
        'plain', 'plain-native-sudoku', 'encrypted', 'encrypted-native-sudoku',
    ),
    'TestManagedSOCKS5Processes': (
        'independent-wire-client/127.0.0.1', 'independent-wire-client/::1',
        'independent-wire-client/localhost', 'reverse-half-close-and-abort',
        'two-core-outbound-and-restart',
    ),
    'TestManagedSOCKS5UDPProcesses': (
        'independent-rfc1928', 'independent-rfc1928/ipv4', 'independent-rfc1928/ipv6', 'independent-rfc1928/domain',
        'same-ip-isolation-and-invalid-frames', 'scoped-direct-and-reject',
        'same-ip-isolation-and-invalid-frames/concurrent-bindings/alice',
        'same-ip-isolation-and-invalid-frames/concurrent-bindings/bob',
        'two-core-tcp-udp-dns-and-restart', 'credential-revocation-and-stop',
    ),
    'TestManagedHTTPProxyProcesses': (
        'port-conflict', 'curl-forward', 'curl-connect', 'scoped-direct-and-reject',
        'local-http-entry', 'two-core-outbound-and-recovery',
    ),
}
RUNTIME_CASES = tuple(
    f'cmd/splicore/{name}' + (f'/{leaf}' if leaf else '')
    for name, leaves in RUNTIME_TESTS.items() for leaf in ('', *leaves)
)
MANAGED_SOCKS5_UDP_CASES = (
    'internal/splicore/protocol/proxy/TestManagedSOCKS5UDPRelaySettings',
    'internal/splicore/engine/native/TestManagedSOCKS5UDPProtectedRelayLifecycle',
    'internal/splicore/engine/native/TestManagedSOCKS5UDPPortExhaustionAndIdle',
    'internal/splicore/engine/native/TestManagedSOCKS5UDPAssociationAndFlowBounds',
    'internal/splicore/engine/native/TestManagedSOCKS5UDPDatagramWriteError',
)
MANAGED_HTTP_CASES = (
    'internal/splicore/protocol/proxy/TestManagedHTTPCreationRequiresAuthentication',
    'internal/splicore/engine/native/TestManagedHTTPRejectedWithoutTarget',
    'internal/splicore/engine/native/TestManagedHTTPForwardingStreamsAndSanitizes',
    'internal/splicore/engine/native/TestManagedHTTPForwardingBoundaries/connection-close',
    'internal/splicore/engine/native/TestManagedHTTPForwardingBoundaries/truncated-upload',
    'internal/splicore/engine/native/TestManagedHTTPForwardingBoundaries/client-cancellation',
    'internal/splicore/engine/native/TestManagedHTTPConnectionBoundsAndCancellation/slow-header',
    'internal/splicore/engine/native/TestManagedHTTPConnectionBoundsAndCancellation/unavailable-target',
    'internal/splicore/engine/native/TestManagedHTTPConnectionBoundsAndCancellation/resolved-self-target',
    'internal/splicore/engine/native/TestManagedHTTPConnectionBoundsAndCancellation/total-limit-and-idle-tunnel',
    'internal/splicore/engine/native/TestManagedHTTPConnectionBoundsAndCancellation/bounded-admission-and-pending-dial-cancel',
    'internal/splicore/storage/sqlite/TestManagedHTTPCommittedAdmission/revoke-commits-credential-and-binding',
)
SYMLINK_TEST = 'TestRootFileTraversalAndHTTPHTTPSProxyBoundaries/file/symlink'
SYMLINK_PROOFS = {
    'real file symlink created:', 'file boundary assertion completed: path=/escape status=',
    'outside-secret=false', 'real file symlink cleanup completed',
}


def verify_windows_underlay(event_log, cases):
    packages = {PREFIX + package: set(tests) for package, tests in cases.items()}
    parents = {package: {name.split('/')[0] for name in tests} for package, tests in packages.items()}
    counts = Counter()
    proofs = set()
    if event_log is None:
        raise RuntimeError('Missing Windows file and underlay event log')
    with event_log.open('rb') as stream:
        for line in stream:
            if not line.startswith(b'{'):
                continue
            event = json.loads(line)
            package, name, action = event.get('Package'), event.get('Test', ''), event.get('Action')
            if package not in packages:
                continue
            if name.split('/')[0] in parents[package] and action in ('skip', 'fail'):
                raise RuntimeError(f'Windows file or underlay test did not pass: {package}/{name}')
            if not name or name in packages[package]:
                counts[package, name, action] += 1
            if name == SYMLINK_TEST and action == 'output':
                proofs.update(marker for marker in SYMLINK_PROOFS if marker in event['Output'])
    for package, tests in packages.items():
        if counts[package, '', 'pass'] != 1:
            raise RuntimeError('Windows file or underlay package did not pass: ' + package)
        for name in tests:
            if any(counts[package, name, action] != 1 for action in ('run', 'pass')):
                raise RuntimeError(f'Expected one Windows run and pass event: {package}/{name}')
    if proofs != SYMLINK_PROOFS:
        raise RuntimeError('Missing Windows symlink evidence: ' + ', '.join(sorted(SYMLINK_PROOFS - proofs)))


def validate(root, result, target, profile, event_log=None):
    tests = {name.removeprefix(PREFIX): action for name, action in result['tests'].items()}
    policy = json.loads((root / 'distribution/qualification-profile.json').read_text())
    required = {
        'internal/splicore/clientruntime/TestPhase15OwnedNetworkLifecycle10x',
        'internal/splicore/clientruntime/TestPhase15UDPCancellationCloseJoin',
        'internal/splicore/clientruntime/TestProviderFetchProtectedHTTPAndHTTPS',
        'internal/splicore/streamtransport/hysteria/TestMasqueradeProtectedDialAndNoDefault',
        'internal/splicore/storage/sqlite/TestInspectIsReadOnly',
        'protocol/vless/encryption/TestEncryptedStreams',
        'protocol/vless/encryption/TestPinnedReferenceRawMatrix',
        'internal/splicore/storage/sqlite/TestPersistenceReliability',
        'internal/splicore/protocol/socks5/TestPhase20NegotiationAndPartialFrames',
        'internal/splicore/protocol/proxy/TestManagedSOCKS5CreationRequiresAuthentication',
        'internal/splicore/engine/native/TestManagedSOCKS5AuthenticationAndRouting',
        'internal/splicore/engine/native/TestManagedSOCKS5ConnectionBoundsAndCancellation',
        'internal/splicore/storage/sqlite/TestManagedSOCKS5CommittedAdmission',
        *MANAGED_SOCKS5_UDP_CASES,
        *MANAGED_HTTP_CASES,
    }
    if profile != 'race':
        required.update(RUNTIME_CASES)
    if profile != 'default':
        gates = json.loads((root / 'distribution/feature-gates.json').read_text())
        for feature in gates['features']:
            for path, names in feature['tests'].items():
                if profile == 'race' and path.startswith('cmd/'):
                    continue
                if '_windows_test.go' in path and not target.startswith('windows'):
                    continue
                if '_linux_test.go' in path and not target.startswith('linux'):
                    continue
                required.update(str(PurePosixPath(path).parent / name) for name in names)
        required.add('internal/splicore/engine/native/TestSnellV5IPv6UnderlayAndUDP443/false')
    if os.environ.get('GITHUB_ACTIONS'):
        required.add('internal/splicore/streamtransport/hysteria/' + SYMLINK_TEST)
        if target == 'windows-amd64' and profile == 'default':
            cases = policy['windows_file_underlay']
            verify_windows_underlay(event_log, cases)
            required.update(f'{package}/{name}' for package, names in cases.items() for name in names)
    missing = sorted(name for name in required if tests.get(name) != 'pass')
    if missing:
        raise RuntimeError('Missing/failed/skipped required behaviors: ' + ', '.join(missing))
    not_executed = []
    for name, action in tests.items():
        if action != 'skip':
            continue
        reason = policy['optional_campaigns'].get(name)
        if profile == 'default':
            reason = reason or policy['default_only'].get(name)
            if not reason and any(name == key or name.startswith(key) for key in policy['default_only_prefixes']):
                reason = 'Default build excludes with_quic; full build must execute this behavior'
        if target.startswith('windows') and name in policy['windows_optional_nic_ipv6']:
            reason = 'NOT EXECUTED: no configured global NIC IPv6; loopback IPv6 and tunnel IPv6 gates remain required'
        if not reason:
            raise RuntimeError('Unexpected skipped behavior: ' + name)
        not_executed.append({'test': name, 'reason': reason})
    return {'result': 'PASS', 'required_passed': sorted(required), 'not_executed': not_executed}
