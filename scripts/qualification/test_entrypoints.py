"""Entrypoints must not shadow Python's standard platform module."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Entrypoints(unittest.TestCase):
    def test_direct_script_startup_imports_standard_platform(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        for script in ['native.py', 'fetch-windows-race-toolchain.py']:
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, str(ROOT/'scripts/qualification'/script), '--help'], cwd=ROOT, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, '-c', 'import platform; print(platform.machine()); print(platform.platform())'],
                                cwd=ROOT/'scripts/qualification', env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
