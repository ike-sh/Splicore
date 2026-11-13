#!/usr/bin/env python3
"""Fetch a pinned, test-only native Windows compiler without system installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import urllib.request
import zipfile

VERSION = '20261104'
NAME = 'llvm-mingw-'+VERSION+'-ucrt-x86_64'
SHA256 = '552191b5754c49a5a20723276a6fc56541ea1922c4c50b7b669022333fc1b40f'
URL = 'https://github.com/mstorsjo/llvm-mingw/releases/download/'+VERSION+'/'+NAME+'.zip'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--github-env', type=Path)
    args = parser.parse_args()
    if os.name!='nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise RuntimeError('native Windows amd64 compiler host required')
    root = args.output.resolve()
    source = Path(__file__).resolve().parents[2]
    if root == source or source in root.parents:
        raise RuntimeError('toolchain output must be outside source')
    root.mkdir(parents=True, exist_ok=True)
    archive = root/(NAME+'.zip')
    if not archive.exists():
        with urllib.request.urlopen(URL, timeout=60) as response, archive.open('xb') as output:
            while block := response.read(1<<20):
                output.write(block)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA256:
        raise RuntimeError('compiler archive digest mismatch')
    destination = root/NAME
    if destination.exists():
        raise RuntimeError('use a fresh extraction destination')
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            if root not in (root/member.filename).resolve().parents:
                raise RuntimeError('unsafe compiler archive path')
        package.extractall(root)
    compiler = destination/'bin/x86_64-w64-mingw32-gcc.exe'
    if not compiler.is_file():
        raise RuntimeError('compiler archive missing expected executable')
    (root/'toolchain.json').write_text(json.dumps(dict(url=URL, sha256=SHA256, compiler=str(compiler), test_only=True), indent=2)+'\n')
    if args.github_env:
        with args.github_env.open('a', encoding='utf-8') as output:
            output.write('CC='+str(compiler)+'\n')
    print('Verified test-only compiler', VERSION, SHA256)


if __name__=='__main__':
    main()
