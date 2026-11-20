#!/usr/bin/env python3
"""Exercise evidence collection with a synthetic failing child in a dispatch run."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release
from qualification import evidence

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private', type=Path)
    parser.add_argument('--fixture', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fixture:
        return fixture()
    if args.private is None:
        parser.error('--private is required')
    peer = args.private / 'reference/wg-evidence/TestInjectedRequired'
    peer.mkdir(mode=0o700, parents=True)
    (peer / 'config.json').write_text(json.dumps({'private_key': MARKER}), encoding='utf-8')
    (peer / 'peer.log').write_text('[Warning] core: Xray 26.10.21 started\npassword=' + MARKER + '\n', encoding='utf-8')
    try:
        release.run_logged([sys.executable, str(Path(__file__).resolve()), '--fixture'], os.environ.copy(),
                           args.private / 'raw', 'injected-test', timeout=30)
    except release.LoggedFailure as error:
        print(error, file=sys.stderr)
        return error.exit_code
    raise RuntimeError('Synthetic required test unexpectedly succeeded')


if __name__ == '__main__':
    sys.exit(main())
