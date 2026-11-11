#!/usr/bin/env python3
"""Check the versioned restoration inventory before CI/release qualification.

This catches accidental source/test removal, and complements real test execution.
It never turns a presence check into a runtime qualification result.
"""
import json
from pathlib import Path, PurePosixPath
import re


def check(root, verbose=True):
    manifest = json.loads((root / 'distribution/feature-gates.json').read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or not manifest.get('features'):
        raise RuntimeError('Missing restoration inventory')
    seen = set()
    for feature in manifest['features']:
        if feature['id'] in seen:
            raise RuntimeError('Duplicate feature gate')
        seen.add(feature['id'])
        for name in feature['files'] + list(feature['tests']):
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or not (root / name).is_file():
                raise RuntimeError('Restored feature source/test missing: ' + name)
        for name, functions in feature['tests'].items():
            text = (root / name).read_text(encoding='utf-8')
            for function in functions:
                if not re.search(r'^func\s+' + re.escape(function) + r'\(t \*testing.T\)', text, re.M):
                    raise RuntimeError('Restored feature regression removed: ' + function)
    if verbose:
        print('FEATURE_INVENTORY_PASS: ' + ', '.join(sorted(seen)))


if __name__ == '__main__':
    check(Path(__file__).resolve().parents[2])
