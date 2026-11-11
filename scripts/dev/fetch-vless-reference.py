#!/usr/bin/env python3
"""Fetch a digest-pinned, test-only Xray peer; never used by the product build."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import urllib.request
import zipfile

RELEASE = 'v26.10.21'
ASSETS = {
    'Linux': ('Xray-linux-64.zip', '0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978', 'xray'),
    'Windows': ('Xray-windows-64.zip', 'fc58c39ee2f2717b4c54d28d374362389e5319b20ae44aea76ea45a5243ec827', 'xray.exe'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--github-env', type=Path)
    args = parser.parse_args()
    if platform.machine().casefold() not in ('x86_64', 'amd64'):
        raise RuntimeError('The pinned independent peer is qualified for amd64 only')
    name, expected, executable = ASSETS[platform.system()]
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    archive = root / name
    if not archive.exists():
        with urllib.request.urlopen(f'https://github.com/XTLS/Xray-core/releases/download/{RELEASE}/{name}', timeout=60) as response:
            with archive.open('xb') as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Independent reference archive digest mismatch')
    with zipfile.ZipFile(archive) as package:
        data = package.read(executable)
    binary = root / executable
    if binary.exists() and binary.read_bytes() != data:
        raise RuntimeError('Refusing to overwrite a different reference binary')
    if not binary.exists():
        binary.write_bytes(data)
    if os.name != 'nt':
        binary.chmod(0o755)
    if args.github_env:
        with args.github_env.open('a', encoding='utf-8') as env:
            env.write(f'SPLICORE_VLESS_ENCRYPTION_REFERENCE={binary}\n')
    print(f'Test-only Xray {RELEASE}; archive sha256={expected}; binary={binary}')


if __name__ == '__main__':
    main()
