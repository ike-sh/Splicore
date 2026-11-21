import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification_policy import PREFIX, RUNTIME_CASES, SYMLINK_PROOFS, SYMLINK_TEST, validate, verify_windows_underlay

ROOT = Path(__file__).resolve().parents[2]
BASE = [
    'internal/splicore/clientruntime/TestPhase15OwnedNetworkLifecycle10x',
    'internal/splicore/clientruntime/TestPhase15UDPCancellationCloseJoin',
    'internal/splicore/clientruntime/TestProviderFetchProtectedHTTPAndHTTPS',
    'internal/splicore/streamtransport/hysteria/TestMasqueradeProtectedDialAndNoDefault',
    'internal/splicore/storage/sqlite/TestInspectIsReadOnly',
    'internal/splicore/storage/sqlite/TestPersistenceReliability',
    'protocol/vless/encryption/TestEncryptedStreams',
    'internal/splicore/protocol/socks5/TestPhase20NegotiationAndPartialFrames',
    'internal/splicore/protocol/proxy/TestManagedSOCKS5CreationRequiresAuthentication',
    'internal/splicore/engine/native/TestManagedSOCKS5AuthenticationAndRouting',
    'internal/splicore/engine/native/TestManagedSOCKS5ConnectionBoundsAndCancellation',
    'internal/splicore/storage/sqlite/TestManagedSOCKS5CommittedAdmission',
    *RUNTIME_CASES,
    'protocol/vless/encryption/TestPinnedReferenceRawMatrix',
]


@patch.dict('os.environ', {'GITHUB_ACTIONS': ''})
class QualificationTests(unittest.TestCase):
    def test_missing_or_skipped_encryption_never_qualifies(self):
        for action in ('missing', 'skip', 'fail'):
            tests = dict.fromkeys(BASE, 'pass')
            if action == 'missing':
                del tests[BASE[-1]]
            else:
                tests[BASE[-1]] = action
            with self.subTest(action=action), self.assertRaisesRegex(RuntimeError, 'required behaviors'):
                validate(ROOT, {'tests': tests}, 'linux-amd64', 'default')

    def test_unknown_skip_rejects_a_successful_go_exit(self):
        tests = dict.fromkeys(BASE, 'pass')
        tests['protocol/vless/encryption/TestUnexpectedSecurityBoundary'] = 'skip'
        with self.assertRaisesRegex(RuntimeError, 'Unexpected skipped'):
            validate(ROOT, {'tests': tests}, 'linux-amd64', 'default')

    def test_missing_socks_process_leaf_fails_native_gates(self):
        tests = dict.fromkeys(BASE, 'pass')
        del tests['cmd/splicore/TestManagedSOCKS5Processes/independent-wire-client/::1']
        with self.assertRaisesRegex(RuntimeError, 'TestManagedSOCKS5Processes/independent-wire-client/::1'):
            validate(ROOT, {'tests': tests}, 'windows-amd64', 'default')

    def test_explicit_optional_oracle_is_reported_not_executed(self):
        tests = dict.fromkeys(BASE, 'pass')
        tests['internal/splicore/engine/native/TestAnyTLSOfficialCompatibility'] = 'skip'
        result = validate(ROOT, {'tests': tests}, 'linux-amd64', 'default')
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(len(result['not_executed']), 1)
        self.assertEqual(len(result['required_passed']), len(BASE))

    def test_missing_restored_interop_rejects_full_profile(self):
        with self.assertRaisesRegex(RuntimeError, 'TestPhase33PinnedProtocols'):
            validate(ROOT, {'tests': dict.fromkeys(BASE, 'pass')}, 'windows-amd64', 'full')

    def test_windows_gate_requires_run_pass_and_real_symlink_evidence(self):
        cases = json.loads((ROOT/'distribution/qualification-profile.json').read_bytes())['windows_file_underlay']
        events = []
        for package, names in cases.items():
            events.append(dict(Package=PREFIX+package, Action='pass'))
            events.extend(dict(Package=PREFIX+package, Test=name, Action=action)
                          for name in names for action in ('run', 'pass'))
            if SYMLINK_TEST in names:
                events.extend(dict(Package=PREFIX+package, Test=SYMLINK_TEST, Action='output', Output=marker)
                              for marker in sorted(SYMLINK_PROOFS))
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder)/'go.jsonl'
            log.write_text('\n'.join(map(json.dumps, events)), encoding='utf-8')
            verify_windows_underlay(log, cases)
            log.write_text('\n'.join(map(json.dumps, events[:-1])), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'Expected one Windows run and pass event'):
                verify_windows_underlay(log, cases)
            log.write_text('\n'.join(json.dumps(event) for event in events if event.get('Output') != 'real file symlink cleanup completed'), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'Missing Windows symlink evidence'):
                verify_windows_underlay(log, cases)
