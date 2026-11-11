#!/usr/bin/env python3
"""Check the versioned restoration inventory before CI/release qualification.

This catches accidental source/test removal, and complements real test execution.
It never turns a presence check into a runtime qualification result.
"""
import json
from pathlib import Path, PurePosixPath
import re


def check(root, verbose=True):
    historical = json.loads((root / 'distribution/historical-features.json').read_text(encoding='utf-8'))
    rows = historical.get('features', [])
    if historical.get('schema') != 1 or len(rows) != 61 or {row['id'] for row in rows} != set(range(1, 62)):
        raise RuntimeError('The complete 61-item historical inventory is required')
    for row in rows:
        if row['disposition'] not in {'retained', 'restored', 'retired', 'archived'} or not row.get('qualification'):
            raise RuntimeError('Unassigned historical feature: ' + row['feature'])
        if row.get('status') not in {'MAIN_VERIFIED', 'RESTORED_AND_VERIFIED',
                                      'EQUIVALENT_IMPLEMENTATION', 'INTENTIONALLY_REMOVED',
                                      'ISOLATED_NOT_QUALIFIED'}:
            raise RuntimeError('Missing explicit historical feature status: ' + row['feature'])
        for name in row['files']:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or not (root / name).is_file():
                raise RuntimeError('Historical implementation removed: ' + name)
    for name in ('internal/splicore/amneziawgendpoint', 'third_party/amneziawg-go'):
        if (root / name).exists():
            raise RuntimeError('Retired AmneziaWG implementation was reintroduced: ' + name)
    module = (root / 'go.mod').read_text(encoding='utf-8')
    if re.search(r'^\s*(?:require\s+|replace\s+)?github\.com/(?:amnezia-vpn/|xtls/xray-core)', module, re.I | re.M):
        raise RuntimeError('Retired/external core production dependency was reintroduced')
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
