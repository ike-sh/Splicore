import unittest
from pathlib import Path
from unittest.mock import patch

from qualification_policy import validate

ROOT = Path(__file__).resolve().parents[2]
BASE = [
    'cmd/splicore/TestRuntimeBinaryTrafficShutdownAndRestart',
    'internal/splicore/clientruntime/TestProviderFetchProtectedHTTPAndHTTPS',
    'internal/splicore/streamtransport/hysteria/TestMasqueradeProtectedDialAndNoDefault',
    'internal/splicore/storage/sqlite/TestInspectIsReadOnly',
    'protocol/vless/encryption/TestEncryptedStreams',
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
