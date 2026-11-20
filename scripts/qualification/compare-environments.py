#!/usr/bin/env python3
"""Compare a main/Tag qualification run to a PR run of the same source tree."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
import evidence

TARGETS = ('linux-amd64', 'windows-amd64', 'linux-arm64', 'windows-arm64')
CHANGING_RESOURCES = ('available_memory_bytes', 'load_average', 'collector_fd_count', 'collector_handle_count')


def gh(args):
    return subprocess.check_output(['gh', *args], text=True, stderr=subprocess.DEVNULL, timeout=180)


def download(run_id, attempt, directory):
    pattern = f'qualification-*-r{run_id}-a{attempt}'
    directory.mkdir(parents=True, exist_ok=True)
    try:
        gh(['run', 'download', str(run_id), '--repo', os.environ['GITHUB_REPOSITORY'], '-p', pattern, '-D', str(directory)])
    except (OSError, subprocess.SubprocessError):
        # A job may have failed before upload or the attempt may have expired.
        pass
    result = {}
    for target in TARGETS:
        folder = directory / f'qualification-{target}-r{run_id}-a{attempt}'
        path = folder / 'fingerprint.json'
        manifest = evidence.read_json(folder / 'SHA256_MANIFEST.json') or {}
        value = evidence.read_json(path)
        if value is None or manifest.get('files', {}).get(path.name, {}).get('sha256') != evidence.sha256(path.read_bytes()):
            continue
        checksum = value.pop('fingerprint_sha256', None)
        run = value.get('run', {})
        if (checksum == evidence.sha256(evidence.json_bytes(value)) and value.get('kind') == 'release'
                and value.get('target') == target and value['source']['commit'] == run.get('sha')
                and run.get('run_id') == str(run_id) and run.get('run_attempt') == str(attempt)
                and run.get('repository') == os.environ['GITHUB_REPOSITORY']):
            result[target] = value
    return result


def comparison_fields(row):
    network = {key: value for key, value in row['network'].items() if key != 'id'}
    resources = {key: value for key, value in row['resources'].items() if key not in CHANGING_RESOURCES}
    commands = {}
    for name, command in row['test_commands'].items():
        context = command['execution'].copy()
        if 'network' in context:
            context['network'] = {key: value for key, value in context['network'].items() if key != 'id'}
        commands[name] = dict(command, execution=context)
    return dict(runner=row['runner'], go=row['go'], network=network, resources=resources, test_commands=commands,
                independent_peers=row['reference'], windows_port_ranges=row['windows_port_ranges'])


def diff(before, after, path=''):
    if isinstance(before, dict) and isinstance(after, dict):
        return [difference for key in sorted(before.keys() | after.keys())
                for difference in diff(before.get(key), after.get(key), f'{path}.{key}' if path else key)]
    return [] if before == after else [{'field': path, 'pr': before, 'current': after}]


def compare(pr, current, tree):
    rows = {}
    for target in TARGETS:
        before = pr.get(target)
        after = current.get(target)
        if not before or not after or before['source']['tree'] != tree or after['source']['tree'] != tree:
            rows[target] = {'result': 'NOT_EXECUTED', 'reason': 'Both source-matched fingerprints are required'}
            continue
        required = set()
        if target.endswith('-amd64'):
            required.update(('default-test', 'full-test'))
        if target == 'linux-amd64':
            required.add('race')
        missing = []
        for name, row in [('PR', before), ('current', after)]:
            if not row['runner']['image_version']:
                missing.append(name + ' runner image version')
            if not row['go'].get('GOVERSION'):
                missing.append(name + ' Go version')
            if required - row['test_commands'].keys():
                missing.append(name + ' test commands')
        differences = diff(comparison_fields(before), comparison_fields(after))
        rows[target] = {'result': 'INCOMPLETE' if missing else 'DIFFERENCES' if differences else 'NO_RECORDED_DIFFERENCES',
                        'differences': differences, 'missing': missing,
                        'pr_source': before['source'], 'current_source': after['source']}
    return rows


def find_pr(tree, directory):
    repo = os.environ['GITHUB_REPOSITORY']
    sha = os.environ['GITHUB_SHA']
    pulls = json.loads(gh(['api', f'repos/{repo}/commits/{sha}/pulls?per_page=10']))
    for pr in pulls:
        if pr.get('merge_commit_sha') != sha or not pr.get('merged_at') or pr['base']['ref'] != 'main':
            continue
        head = pr['head']['sha']
        runs = json.loads(gh(['api', f'repos/{repo}/actions/workflows/release.yml/runs?event=pull_request&status=success&head_sha={head}&per_page=10']))
        for run in runs['workflow_runs']:
            run_id, attempt = run['id'], run['run_attempt']
            rows = download(run_id, attempt, directory / f'{run_id}-{attempt}')
            eligible = {target: row for target, row in rows.items() if row['source']['tree'] == tree
                        and row['run']['event_name'] == 'pull_request' and row['run']['ref'] == f"refs/pull/{pr['number']}/merge"}
            if eligible:
                return {'pr': pr['number'], 'run_id': run_id, 'attempt': attempt}, eligible
    return None, {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    tree = evidence.probe(['git', 'rev-parse', 'HEAD^{tree}'])
    report = {'schema': 1, 'source_commit': os.environ['GITHUB_SHA'], 'source_tree': tree,
              'event': os.environ['GITHUB_EVENT_NAME'], 'ref': os.environ['GITHUB_REF'],
              'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'pr': None}
    if report['ref'] == 'refs/heads/main' or report['ref'].startswith('refs/tags/'):
        scratch = args.output.parent / 'fingerprint-inputs'
        try:
            baseline, pr = find_pr(tree, scratch / 'pr')
            current = download(report['run_id'], report['attempt'], scratch / 'current')
            report.update(pr=baseline, targets=compare(pr, current, tree))
            if baseline is None:
                report['reason'] = 'No completed successful Official release PR run with matching tree and retained fingerprints'
        except (subprocess.SubprocessError, OSError, ValueError, KeyError):
            report['reason'] = 'GitHub comparison inputs unavailable'
    else:
        report['reason'] = 'The matching main or Tag run will perform the comparison with this PR'
    report.setdefault('targets', compare({}, {}, tree))
    report['result'] = ('NOT_EXECUTED' if not report['pr'] else 'INCOMPLETE'
                        if any(row['result'] in ('INCOMPLETE', 'NOT_EXECUTED') for row in report['targets'].values())
                        else 'DIFFERENCES' if any(row['differences'] for row in report['targets'].values())
                        else 'NO_RECORDED_DIFFERENCES')
    evidence.save(args.output, report)
    summary = ['## Qualification environment comparison', '', f"**{report['result']}**", '',
               report.get('reason', 'Compared recorded fields for the same source tree.'), '']
    for target, row in report['targets'].items():
        summary.append(f"- {target} · {row['result']} · {len(row.get('differences', []))} changed fields")
    summary += ['', 'The JSON artifact lists values for each changed field. Hosted runner labels allow image updates.', '']
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as output:
        output.write('\n'.join(summary))


if __name__ == '__main__':
    main()
