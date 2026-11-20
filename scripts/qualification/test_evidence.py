import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import evidence

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS.parent))
import release

spec = importlib.util.spec_from_file_location('comparison', SCRIPTS / 'compare-environments.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


EXIT = 42
PACKAGE = 'github.com/ike-sh/Splicore/scripts/qualification/diagnostic'
TEST = 'TestInjectedRequired/child'
MARKER = 'synthetic-fixture-secret-only'


def fixture():
    print(json.dumps(dict(Action='run', Package=PACKAGE, Test=TEST, Time=evidence.timestamp())))
    for line in ('WARNING: DATA RACE', 'injected_test.go:42: i/o timeout', 'vault_master_key=' + MARKER):
        print(json.dumps(dict(Action='output', Package=PACKAGE, Test=TEST, Output=line + '\n')))
    print(json.dumps(dict(Action='fail', Package=PACKAGE, Test=TEST, Time=evidence.timestamp(), Elapsed=0)))
    print('Authorization: Bearer ' + MARKER, file=sys.stderr)
    return EXIT


def run_fixture(private):
    peer = private / 'reference/wg-evidence/TestInjectedRequired'
    peer.mkdir(mode=0o700, parents=True)
    (peer / 'config.json').write_text(json.dumps({'private_key': MARKER}), encoding='utf-8')
    (peer / 'peer.log').write_text('[Warning] core: Xray 26.10.21 started\npassword=' + MARKER + '\n', encoding='utf-8')
    try:
        release.run_logged([sys.executable, str(Path(__file__).resolve()), '--fixture'], os.environ.copy(),
                           private / 'raw', 'full-test', timeout=30)
    except release.LoggedFailure as error:
        print(error, file=sys.stderr)
        return error.exit_code
    raise RuntimeError('Synthetic required test unexpectedly succeeded')


class EvidenceTests(unittest.TestCase):
    def test_injected_exit_and_public_projection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            private, public = root / 'private', root / 'public'
            target = release.native_target()
            args = ['--private', str(private), '--target', target, '--label', 'unit-test', '--kind', 'release']
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', GH_TOKEN='unit-test-env-secret-marker')
            subprocess.run([sys.executable, str(SCRIPTS / 'evidence.py'), 'fingerprint', *args], env=env, check=True)
            failed = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--run-fixture', str(private)],
                                    env=env, capture_output=True)
            self.assertEqual(failed.returncode, 42, failed.stderr)
            stdout = private / 'raw/full-test.stdout'
            stderr = private / 'raw/full-test.stderr'
            original = stdout.read_bytes(), stderr.read_bytes()
            secret = b'synthetic-fixture-secret-only'
            self.assertTrue(all(secret in stream for stream in original))
            self.assertNotIn(secret, failed.stdout + failed.stderr)
            export = [sys.executable, str(SCRIPTS / 'evidence.py'), 'export', *args, '--public', str(public)]
            subprocess.run(export, check=True, env=env)
            self.assertEqual((stdout.read_bytes(), stderr.read_bytes()), original)
            manifest = json.loads((public / 'SHA256_MANIFEST.json').read_bytes())
            self.assertEqual(manifest['kind'], 'release')
            self.assertIn('commands/full-test.failure.json', manifest['files'])
            status = json.loads((public / 'commands/full-test.json').read_bytes())
            self.assertEqual(status['exit_code'], 42)
            self.assertEqual(status['result'], 'FAIL')
            self.assertEqual(status['failed_tests'], ['github.com/ike-sh/Splicore/scripts/qualification/diagnostic/TestInjectedRequired/child'])
            self.assertGreaterEqual(status['finished_at'], status['started_at'])
            recorded = json.loads((public / 'fingerprint.json').read_bytes())
            self.assertIn('full-test', recorded['test_commands'])
            self.assertEqual(recorded['target'], target)
            self.assertTrue(recorded['runner']['kernel'])
            self.assertTrue(recorded['runner']['architecture'])
            self.assertIn(b'WARNING: DATA RACE', (public / 'commands/full-test.stdout').read_bytes())
            self.assertIn(b'WARNING: DATA RACE', (public / 'commands/full-test.failures.jsonl').read_bytes())
            self.assertIn(b'Xray 26.10.21 started', (public / 'peers/wg-evidence/TestInjectedRequired/peer.log').read_bytes())
            for name, entry in manifest['files'].items():
                data = (public / name).read_bytes()
                self.assertEqual(entry, {'bytes': len(data), 'sha256': evidence.sha256(data)})
                self.assertNotIn(secret, data)
                self.assertNotIn(b'unit-test-env-secret-marker', data)
            self.assertFalse(list(public.rglob('config.json')))
            self.assertFalse(list(private.rglob('RELEASE_MANIFEST.json')))

    def test_timeout_diagnostics_and_original_output_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            command = [sys.executable, '-c', 'import time; print("before timeout", flush=True); time.sleep(30)']
            with self.assertRaises(release.LoggedFailure) as failure:
                release.run_logged(command, os.environ.copy(), path, 'full-test', timeout=1)
            self.assertEqual(failure.exception.exit_code, 124)
            self.assertIn(b'before timeout', (path / 'full-test.stdout').read_bytes())
            status = json.loads((path / 'full-test.json').read_bytes())
            self.assertEqual(status['result'], 'TIMEOUT')
            self.assertIsInstance(status['exit_code'], int)
            with self.assertRaises(FileExistsError):
                release.run_logged(command, os.environ.copy(), path, 'full-test', timeout=1)

    def test_export_bounds_log_and_drops_non_fixture_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            private, public = root / 'private', root / 'public'
            raw = private / 'raw'
            raw.mkdir(parents=True)
            log = raw / 'full-test.stdout'
            with log.open('wb') as output:
                for _ in range(10000):
                    output.write(b'private log text ' * 60 + b'\n')
                output.write(b'WARNING: DATA RACE\n')
            (raw / 'support-bundle.zip').write_bytes(b'excluded')
            fingerprint = evidence.fingerprint(release.native_target(), 'unit-test', 'release')
            with patch.object(evidence, 'fingerprint', return_value=fingerprint):
                evidence.export(private, public, release.native_target(), 'unit-test', 'release')
            safe = (public / 'commands/full-test.stdout').read_bytes()
            self.assertTrue(safe.startswith(b'{"Evidence":"truncated; retained tail"}'))
            self.assertLessEqual(len(safe), evidence.FILE_LIMIT)
            self.assertTrue(safe.endswith(b'WARNING: DATA RACE\n'))
            self.assertFalse(list(public.rglob('support-bundle.zip')))

    def test_peer_log_links_are_ineligible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            secret = root / 'outside.log'
            secret.write_text('WARNING: DATA RACE', encoding='utf-8')
            log = root / 'peer.log'
            try:
                log.symlink_to(secret)
            except OSError:
                self.skipTest('Symlink creation is unavailable on this host')
            self.assertFalse(evidence.plain_file(log))

    def test_failure_events_survive_general_log_truncation(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / 'race.stdout'
            package = 'github.com/ike-sh/Splicore/protocol/synthetic'
            test = 'TestRace/subtest'
            with log.open('w', encoding='utf-8') as stream:
                for action, output in [('run', ''), ('output', 'WARNING: DATA RACE'),
                                       ('output', 'password=synthetic-failure-event-marker'), ('fail', '')]:
                    stream.write(json.dumps(dict(Action=action, Package=package, Test=test, Output=output)) + '\n')
                for _ in range(1000):
                    stream.write(json.dumps(dict(Action='pass', Package=package, Test='TestPassing')) + '\n')
            with patch.object(evidence, 'FILE_LIMIT', 2048):
                self.assertNotIn(b'WARNING: DATA RACE', evidence.projected_log(log))
                failure = evidence.failure_events(log, {'failed_tests': [package + '/' + test]})
            self.assertIn(b'WARNING: DATA RACE', failure)
            self.assertIn(b'"Action":"fail"', failure)
            self.assertNotIn(b'synthetic-failure-event-marker', failure)
            self.assertNotIn(b'TestPassing', failure)


class ComparisonTests(unittest.TestCase):
    def test_tree_identity_and_host_image_drift(self):
        def row(commit, tree, image, node):
            return {'source': {'commit': commit, 'tree': tree}, 'runner': {'image_version': image},
                    'go': {'GOVERSION': 'go1.26.3'}, 'network': {'id': node}, 'resources': {'load_average': [node]},
                    'test_commands': {name: {'command': ['go', 'test'], 'execution': {}}
                                      for name in ('default-test', 'full-test', 'race')}, 'reference': {}, 'windows_port_ranges': None}

        pr = {'linux-amd64': row('pr', 'same-tree', '20261116.376.1', 1)}
        tag = {'linux-amd64': row('tag', 'same-tree', '20261111.127.1', 2)}
        results = comparison.compare(pr, tag, 'same-tree')
        self.assertEqual(results['linux-amd64']['result'], 'DIFFERENCES')
        self.assertEqual(results['linux-amd64']['differences'], [{'field': 'runner.image_version',
                                                                 'pr': '20261116.376.1', 'current': '20261111.127.1'}])
        self.assertEqual(results['windows-amd64']['result'], 'INCOMPLETE')
        tag['linux-amd64']['runner']['image_version'] = None
        self.assertEqual(comparison.compare(pr, tag, 'same-tree')['linux-amd64']['result'], 'INCOMPLETE')
        self.assertEqual(comparison.compare(pr, tag, 'different-tree')['linux-amd64']['result'], 'NOT_EXECUTED')


if __name__ == '__main__':
    if sys.argv[1:] == ['--fixture']:
        sys.exit(fixture())
    if len(sys.argv) == 3 and sys.argv[1] == '--run-fixture':
        sys.exit(run_fixture(Path(sys.argv[2])))
    unittest.main()
