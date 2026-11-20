#!/usr/bin/env python3
"""Stage and verify an immutable snapshot of a GitHub Release draft before publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release
from qualification import evidence

REHEARSAL_TAG = 'v0.6.4'
REHEARSAL_COMMIT = '6ff2101e76f73941ecbd780ce2cb68869cb32cee'


def gh(*args, output=subprocess.PIPE):
    cli = shutil.which('gh') or shutil.which('gh.exe') or 'gh'
    return subprocess.run([cli, *args], stdout=output, check=True, timeout=180).stdout


def api(repo, suffix, *args):
    return json.loads(gh('api', f'repos/{repo}/{suffix}', *args))


def require_tag(version, commit):
    release.require(os.environ.get('GITHUB_EVENT_NAME') == 'push'
                    and os.environ.get('GITHUB_REF') == 'refs/tags/' + version
                    and os.environ.get('GITHUB_SHA') == commit, 'release mutation requires the exact Tag push')


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def snapshot(record, version, commit, *, draft):
    release.require(type(record['id']) is int and record['id'] > 0 and record['draft'] is draft
                    and record['tag_name'] == version and record['target_commitish'] == commit,
                    'release ID, draft state, tag or target commit mismatch')
    assets = {}
    expected = {release.archive_name(version, target) for target in release.TARGETS}
    expected.update((f'splicore-{version}-source.tar.gz', 'SHA256SUMS', 'RELEASE_MANIFEST.json'))
    for asset in record['assets']:
        name = asset['name']
        release.require(name in expected and name not in assets and asset['state'] == 'uploaded'
                        and type(asset['id']) is int and asset['id'] > 0 and 0 < asset['size']
                        and re.fullmatch(r'sha256:[a-f0-9]{64}', asset['digest'] or ''),
                        'unexpected asset or incomplete release asset metadata')
        assets[name] = {key: asset[key] for key in ('id', 'size', 'digest')}
    release.require(assets.keys() == expected, 'release asset inventory mismatch')
    return {'id': record['id'], 'version': version, 'commit': commit, 'assets': assets}


def download_verified(repo, record, destination, expected_sums=None):
    destination.mkdir(parents=True)
    for name, asset in record['assets'].items():
        path = destination / name
        with path.open('xb') as stream:
            gh('api', f'repos/{repo}/releases/assets/{asset["id"]}', '-H', 'Accept: application/octet-stream', output=stream)
        release.require(path.stat().st_size == asset['size'] and 'sha256:' + file_sha256(path) == asset['digest'],
                        'release download size or SHA256 mismatch: ' + name)
    meta = release.verify(destination, checksums_sha256=expected_sums)
    release.require(meta['version'] == record['version'] and meta['commit'] == record['commit'],
                    'downloaded release source identity mismatch')
    return file_sha256(destination / 'SHA256SUMS')


def stage(repo, version, commit, payload, destination):
    require_tag(version, commit)
    candidate = payload / 'final'
    meta = release.verify(candidate)
    release.require(meta['version'] == version and meta['commit'] == commit, 'candidate source identity mismatch')
    sums = file_sha256(candidate / 'SHA256SUMS')
    pages = api(repo, 'releases?per_page=100', '--paginate', '--slurp')
    release.require(all(row['tag_name'] != version for page in pages for row in page),
                    'Refusing to modify an existing draft or published Release')
    gh('release', 'create', version, '--repo', repo, '--verify-tag', '--draft', '--target', commit,
       '--title', 'Splicore ' + version, '--notes-file', str(payload / 'RELEASE_NOTES.md'),
       *map(str, sorted(candidate.iterdir())))
    view = json.loads(gh('release', 'view', version, '--repo', repo, '--json', 'databaseId'))
    draft = snapshot(api(repo, f'releases/{view["databaseId"]}'), version, commit, draft=True)
    release.require(draft['id'] == view['databaseId'], 'draft lookup returned a different release')
    download_verified(repo, draft, destination, sums)
    return {'id': draft['id'], 'snapshot_sha256': evidence.sha256(evidence.json_bytes(draft)), 'sums_sha256': sums}


def publish(repo, version, commit, draft_id, expected_snapshot):
    require_tag(version, commit)
    release.require(os.environ.get('PUBLICATION_GATE') == 'success', 'both native smoke jobs must authorize publication')
    release.require(api(repo, f'commits/{version}')['sha'] == commit, 'release tag no longer points to the qualified commit')
    path = f'releases/{draft_id}'
    draft = snapshot(api(repo, path), version, commit, draft=True)
    release.require(draft['id'] == draft_id and evidence.sha256(evidence.json_bytes(draft)) == expected_snapshot,
                    'draft assets changed after download qualification')
    published = api(repo, path, '--method', 'PATCH', '-F', 'draft=false', '-f', 'make_latest=true')
    release.require(published['id'] == draft_id and published['draft'] is False, 'publication result differs from the qualified draft')
    print(f'Published qualified draft {draft_id} for {version}', flush=True)


def rehearsal(repo, destination):
    # The transport round trip uses existing public assets as a frozen fixture.
    # The rehearsal has read-only credentials and no release mutation path.
    fixture = snapshot(api(repo, f'releases/tags/{REHEARSAL_TAG}'), REHEARSAL_TAG, REHEARSAL_COMMIT, draft=False)
    return {'sums_sha256': download_verified(repo, fixture, destination)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'publish', 'rehearsal'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--payload', type=Path)
    args = parser.parse_args()
    repo = os.environ['GITHUB_REPOSITORY']
    if args.action == 'publish':
        publish(repo, os.environ['RELEASE_VERSION'], os.environ['RELEASE_COMMIT'], int(os.environ['DRAFT_ID']),
                os.environ['DRAFT_SNAPSHOT_SHA256'])
        return
    if args.output is None or (args.action == 'stage' and args.payload is None):
        parser.error('stage and rehearsal require --output, and stage also requires --payload')
    if args.action == 'stage':
        outputs = stage(repo, os.environ['RELEASE_VERSION'], os.environ['RELEASE_COMMIT'], args.payload, args.output)
    else:
        outputs = rehearsal(repo, args.output)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key, value in outputs.items():
            output.write(f'{key}={value}\n')
    print(json.dumps(outputs, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError, ValueError, KeyError) as error:
        sys.exit(str(error))
