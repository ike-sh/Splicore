"""Validate executed behavior identities; source presence is never qualification."""
import json
import os
from pathlib import PurePosixPath

PREFIX = 'github.com/ike-sh/Splicore/'


def validate(root, result, target, profile):
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
    }
    if profile != 'race':
        required.add('cmd/splicore/TestRuntimeBinaryTrafficShutdownAndRestart')
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
        required.add('internal/splicore/streamtransport/hysteria/TestRootFileTraversalAndHTTPHTTPSProxyBoundaries/file/symlink')
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
