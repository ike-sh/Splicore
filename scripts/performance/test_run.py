"""Regression for zero-duration samples observed on the native Windows runner."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('performance_run', Path(__file__).with_name('run.py'))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class Summaries(unittest.TestCase):
    def summarize(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'raw.jsonl'
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return run.summarize(path)['windows-sample']

    def test_zero_duration_is_unavailable_without_changing_raw_timing(self):
        rows = [dict(kind='connection', scenario='windows-sample', network='tcp', status='BASELINE',
                     bytes_per_direction=65536, mode='duplex', transfer_ns=0),
                dict(kind='group', scenario='windows-sample', elapsed_ns=1000000),
                dict(kind='outcome', scenario='windows-sample', passed=True)]
        result = self.summarize(rows)
        self.assertEqual(result['tcp_connection_mbps'], [None])
        self.assertEqual(result['timing_not_executed']['transfer_below_timer_resolution'], 1)
        self.assertEqual(rows[0]['transfer_ns'], 0)

    def test_failed_startup_without_connection_cannot_be_a_baseline(self):
        result = self.summarize([dict(kind='outcome', scenario='windows-sample', passed=False)])
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['connections'], 0)


if __name__ == '__main__':
    unittest.main()
