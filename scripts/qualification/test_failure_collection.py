"""A failed profile must remain failed while later independent profiles run."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release_collection_test', ROOT/'scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class FailureCollection(unittest.TestCase):
    def test_failed_exit_and_policy_are_retained_before_later_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            out, failures, executed = Path(temporary), [], []

            def command(args, env, directory, name):
                executed.append(name)
                result = dict(exit_code=1 if name == 'default-test' else 0,
                              tests={'fixture/TestRecovery': 'fail' if name == 'default-test' else 'pass'})
                release.save(directory/(name+'.json'), result)
                release.require(result['exit_code'] == 0, 'original default gate failed')
                return result

            def policy(result):
                release.require(result['tests']['fixture/TestRecovery'] == 'pass', 'original behavior assertion failed')
                return {'result': 'PASS'}

            with patch.object(release, 'run_logged', side_effect=command):
                results = [release.qualification_step([], os.environ, out, name, failures, policy)
                           for name in ('default-test', 'full-test', 'race')]
            self.assertEqual(executed, ['default-test', 'full-test', 'race'])
            self.assertEqual(len(failures), 2)
            self.assertEqual(results[0]['exit_code'], 1)
            self.assertEqual(results[0]['behavior_policy']['result'], 'FAIL')
            self.assertEqual(json.loads((out/'default-test.json').read_text())['tests']['fixture/TestRecovery'], 'fail')
            with self.assertRaisesRegex(RuntimeError, 'qualification failed'):
                release.require(not failures, 'qualification failed')

    def test_missing_execution_evidence_cannot_be_converted_to_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(release, 'run_logged', side_effect=RuntimeError('infrastructure unavailable')):
                with self.assertRaises(FileNotFoundError):
                    release.qualification_step([], os.environ, Path(temporary), 'full-test', [])


if __name__ == '__main__':
    unittest.main()
