#!/usr/bin/env python3
"""Fetch digest-pinned independent test peers. Nothing here is a runtime dependency."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fetch(path, url, expected):
    if not path.exists():
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Splicore-test-qualification'}), timeout=60) as response:
            data = response.read()
        if sha(data) != expected:
            raise RuntimeError('Reference digest mismatch: ' + path.name)
        path.write_bytes(data)
    if sha(path.read_bytes()) != expected:
        raise RuntimeError('Existing reference digest mismatch: ' + path.name)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--github-env', type=Path)
    args = parser.parse_args()
    if platform.machine().casefold() not in ('amd64', 'x86_64'):
        raise RuntimeError('Independent test peers require native amd64')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    # Qualification owns an offline network namespace. Populate every module,
    # including test-only dependencies, while downloads are still available.
    subprocess.run(['go', 'mod', 'download'], cwd=ROOT, check=True)
    command = [sys.executable, str(ROOT / 'scripts/dev/fetch-vless-reference.py'), '--output', str(root / 'xray')]
    if args.github_env:
        command += ['--github-env', str(args.github_env)]
    subprocess.run(command, check=True)
    env = {'SPLICORE_PHASE32_PEER_LOGS': str(root / 'vless-encryption-evidence'),
           'SPLICORE_PHASE33_PEER_LOGS': str(root / 'h3-evidence'), 'SPLICORE_PHASE34_PEER_LOGS': str(root / 'wg-evidence')}
    manifest = {'shadowquic': {'status': 'ISOLATED_NOT_QUALIFIED', 'included': False}}
    if os.name != 'nt':
        url = 'https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip'
        package = fetch(root / 'snell-v5.0.1.zip', url, '9bea1c2b9e35b73b31634856c04d18c393072b9e5dcde6a32781d8b8f908c539')
        with zipfile.ZipFile(package) as archive:
            data = archive.read('snell-server')
        expected = '5b2e221f2c6e29b1db8e47053e1221be29d5627da807cb932b089f514a3609f0'
        if sha(data) != expected:
            raise RuntimeError('Snell executable digest mismatch')
        snell = root / 'snell-server'
        if snell.exists() and snell.read_bytes() != data:
            raise RuntimeError('Refusing to replace a different Snell executable')
        snell.write_bytes(data)
        snell.chmod(0o755)
        env.update(SPLICORE_SNELL_V5_REFERENCE=str(snell), SPLICORE_SNELL_V5_EVIDENCE=str(root / 'snell-evidence'))
        manifest['snell'] = {'version': 'v5.0.1', 'url': url, 'binary_sha256': expected}
    peer = root / ('wireguard-peer.exe' if os.name == 'nt' else 'wireguard-peer')
    if peer.exists():
        raise RuntimeError('Use a fresh peer output directory; refusing to overwrite a WireGuard peer')
    subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(peer), './scripts/dev/wireguard-peer'], cwd=ROOT, check=True)
    env['SPLICORE_PHASE34_WG_REFERENCE'] = str(peer)
    manifest['wireguard'] = {'source': 'scripts/dev/wireguard-peer', 'engine': 'golang.zx2c4.com/wireguard@v0.0.0-20261024220952-b3bc704ef0ee', 'binary_sha256': sha(peer.read_bytes()), 'test_only': True}
    for key in ('SPLICORE_PHASE32_PEER_LOGS', 'SPLICORE_PHASE33_PEER_LOGS', 'SPLICORE_PHASE34_PEER_LOGS', 'SPLICORE_SNELL_V5_EVIDENCE'):
        if key in env:
            Path(env[key]).mkdir(exist_ok=True)
    if args.github_env:
        with args.github_env.open('a', encoding='utf-8') as output:
            for key, value in env.items():
                output.write(key + '=' + value + '\n')
    (root / 'REFERENCE_MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
