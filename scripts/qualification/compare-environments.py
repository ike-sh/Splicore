#!/usr/bin/env python3
"""Compare a main/Tag qualification run to a PR run of the same source tree."""
import argparse
from datetime import datetime
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
import evidence

JOBS = {
    'linux-amd64': 'build (linux-amd64, ubuntu-24.04, true)',
    'windows-amd64': 'build (windows-amd64, windows-2025-vs2026, true)',
    'linux-arm64': 'build (linux-arm64, ubuntu-24.04, false)',
    'windows-arm64': 'build (windows-arm64, ubuntu-24.04, false)',
}
TARGETS = tuple(JOBS)
WORKFLOW = '.github/workflows/release.yml'
CHANGING_RESOURCES = ('available_memory_bytes', 'load_average', 'collector_fd_count', 'collector_handle_count')


def gh(args):
    cli = shutil.which('gh') or shutil.which('gh.exe') or 'gh'
    return subprocess.check_output([cli, *args], stderr=subprocess.DEVNULL, timeout=90)


def api(path):
    return json.loads(gh(['api', path]))


def pages(path, field):
    return [item for page in json.loads(gh(['api', path, '--paginate', '--slurp'])) for item in page[field]]


def execution_key(job):
    return (job['status'], job['conclusion'], job['started_at'], job['completed_at'], job['runner_id'], job['steps'])


def original_job(run, name, effective_jobs, all_jobs):
    latest = [job for job in effective_jobs if job['name'] == name]
    if len(latest) != 1:
        raise ValueError('Expected exactly one effective job')
    effective = latest[0]
    history = sorted((job for job in all_jobs if job['name'] == name), key=lambda job: job['run_attempt'])
    if (not history or history[-1] != effective or len({job['run_attempt'] for job in history}) != len(history)
            or any(job['run_id'] != run['id'] or job['head_sha'] != run['head_sha']
                   or not 1 <= job['run_attempt'] <= run['run_attempt'] for job in history)):
        raise ValueError('Effective job does not match run history')
    if effective['status'] != 'completed' or effective['conclusion'] != 'success':
        raise ValueError('Effective job did not succeed')
    if not effective['started_at'] or not effective['completed_at'] or not effective['steps']:
        raise ValueError('Effective job has no execution record')
    # GitHub synthesizes an attempt-N job for a carried success. It preserves
    # the runner, execution timestamps and steps, but assigns a new job ID.
    original = effective
    for prior in reversed(history[:-1]):
        if prior['run_attempt'] != original['run_attempt'] - 1 or execution_key(prior) != execution_key(effective):
            break
        original = prior
    return effective, original


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (AttributeError, ValueError):
        raise ValueError('Invalid execution timestamp') from None
    if result.tzinfo is None:
        raise ValueError('Missing execution timestamp timezone')
    return result


def verified_fingerprint(repo, run, target, job, artifacts, ref, tree, source_commit, commits):
    attempt = job['run_attempt']
    name = f'qualification-{target}-r{run["id"]}-a{attempt}'
    matches = [item for item in artifacts if item['name'] == name and not item['expired']]
    if len(matches) != 1:
        raise ValueError('Artifact missing, expired or ambiguous for the original execution')
    artifact = matches[0]
    origin = artifact['workflow_run']
    if (origin['id'] != run['id'] or origin['head_sha'] != run['head_sha']
            or origin['repository_id'] != run['repository']['id']
            or not timestamp(job['started_at']) <= timestamp(artifact['created_at']) <= timestamp(job['completed_at'])):
        raise ValueError('Artifact does not belong to the original execution')
    size = artifact['size_in_bytes']
    if not 0 < size <= evidence.ARTIFACT_LIMIT + evidence.MIB:
        raise ValueError('Artifact exceeds the diagnostic size budget')
    data = gh(['api', f'repos/{repo}/actions/artifacts/{artifact["id"]}/zip'])
    archive_digest = 'sha256:' + evidence.sha256(data)
    if len(data) != size or archive_digest != artifact['digest']:
        raise ValueError('Artifact ZIP SHA256 or size mismatch')

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        def member(filename):
            entries = [entry for entry in archive.infolist() if entry.filename == filename]
            if len(entries) != 1 or entries[0].file_size > evidence.FILE_LIMIT:
                raise ValueError('Missing, duplicate or oversized evidence member')
            return archive.read(entries[0])

        manifest = json.loads(member('SHA256_MANIFEST.json'))
        fingerprint = member('fingerprint.json')
    if manifest['files'].get('fingerprint.json') != {'sha256': evidence.sha256(fingerprint), 'bytes': len(fingerprint)}:
        raise ValueError('Fingerprint SHA256 or size mismatch in inventory')
    value = json.loads(fingerprint)
    checksum = value.pop('fingerprint_sha256')
    if checksum != evidence.sha256(evidence.json_bytes(value)):
        raise ValueError('Fingerprint canonical SHA256 mismatch')
    source = value['source']
    expected_run = {'repository': repo, 'event_name': run['event'], 'ref': ref, 'job': 'build', 'sha': source['commit'],
                    'run_id': str(run['id']), 'run_attempt': str(attempt)}
    if (value['run'] != expected_run or value['kind'] != 'release' or value['target'] != target
            or any(manifest[key] != value[key] for key in ('run', 'source', 'target', 'kind'))
            or not timestamp(job['started_at']) <= timestamp(value['recorded_at']) <= timestamp(job['completed_at'])):
        raise ValueError('Fingerprint identity does not match the original execution')
    if source['tree'] != tree or not re.fullmatch(r'[a-f0-9]{40}', source['commit']):
        raise ValueError('Fingerprint source tree or commit is invalid')
    if source_commit is not None:
        if source['commit'] != source_commit:
            raise ValueError('Fingerprint commit differs from the checked out source')
    else:
        commit = source['commit']
        if commit not in commits:
            commits[commit] = api(f'repos/{repo}/git/commits/{commit}')
        record = commits[commit]
        if (record['sha'] != commit or record['tree']['sha'] != tree or len(record['parents']) != 2
                or record['parents'][1]['sha'] != run['head_sha']):
            raise ValueError('Fingerprint source is not a merge of the workflow PR head with the expected tree')
    value['verified_artifact'] = {'artifact_id': artifact['id'], 'artifact_name': name, 'sha256': archive_digest,
                                  'fingerprint_sha256': checksum}
    return value


def inspect_run(repo, run, ref, tree, source_commit=None):
    if run['path'] != WORKFLOW or run['repository']['full_name'] != repo:
        raise ValueError('Run is not this repository’s Official release workflow')
    base = f'repos/{repo}/actions/runs/{run["id"]}'
    effective = pages(base + '/jobs?filter=latest&per_page=100', 'jobs')
    history = pages(base + '/jobs?filter=all&per_page=100', 'jobs')
    artifacts = pages(base + '/artifacts?per_page=100', 'artifacts')
    # Do not combine snapshots taken across separate attempts of the same run.
    refreshed = api(base)
    if (refreshed['run_attempt'] != run['run_attempt']
            or (run.get('status') == 'completed' and any(refreshed[key] != run[key] for key in ('status', 'conclusion')))):
        raise ValueError('Run advanced to a different execution state during validation')
    rows, provenance, commits = {}, {}, {}
    for target, name in JOBS.items():
        proof = provenance[target] = {'result': 'INCOMPLETE'}
        try:
            latest, original = original_job(run, name, effective, history)
            proof.update(effective_job=latest['id'], original_job=original['id'], attempt=original['run_attempt'])
            value = verified_fingerprint(repo, run, target, original, artifacts, ref, tree, source_commit, commits)
            proof.update(value['verified_artifact'], result='VERIFIED', source=value['source'])
            rows[target] = value
        except ValueError as error:
            proof['reason'] = str(error)
        except (OSError, subprocess.SubprocessError, zipfile.BadZipFile, KeyError, TypeError):
            proof['reason'] = 'Artifact or job metadata unavailable or invalid'
    return rows, provenance


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


def latest_pr_run(repo, source_commit):
    pulls = api(f'repos/{repo}/commits/{source_commit}/pulls?per_page=10')
    matches = [pr for pr in pulls if pr.get('merge_commit_sha') == source_commit
               and pr.get('merged_at') and pr['base']['ref'] == 'main']
    if len(matches) != 1:
        return None, None
    pr = matches[0]
    head = pr['head']['sha']
    runs = api(f'repos/{repo}/actions/workflows/release.yml/runs?event=pull_request&head_sha={head}&per_page=100')
    candidates = [run for run in runs['workflow_runs'] if run['head_sha'] == head and run['event'] == 'pull_request'
                  and run['head_branch'] == pr['head']['ref'] and run['head_repository']['id'] == pr['head']['repo']['id']]
    if not candidates:
        return None, None
    # A newer run can supersede a past success, even with the same PR head.
    return pr['number'], max(candidates, key=lambda run: (run['created_at'], run['id']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--audit-pr-run', type=int, help='Read back an existing Official release PR run')
    parser.add_argument('--pr', type=int, help='PR number for --audit-pr-run')
    parser.add_argument('--tree', help='Expected source tree for --audit-pr-run')
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY'))
    args = parser.parse_args()
    if args.audit_pr_run is not None:
        if not args.repo or not args.pr or not re.fullmatch(r'[a-f0-9]{40}', args.tree or ''):
            parser.error('--audit-pr-run requires --repo, --pr and an expected --tree')
        run = api(f'repos/{args.repo}/actions/runs/{args.audit_pr_run}')
        if run['event'] != 'pull_request' or run['status'] != 'completed' or run['conclusion'] != 'success':
            parser.error('audit requires a completed successful PR run')
        rows, proof = inspect_run(args.repo, run, f'refs/pull/{args.pr}/merge', args.tree)
        evidence.save(args.output, {'run_id': run['id'], 'attempt': run['run_attempt'], 'source_tree': args.tree,
                                    'targets': proof, 'result': 'VERIFIED' if len(rows) == len(TARGETS) else 'INCOMPLETE'})
        return 0 if len(rows) == len(TARGETS) else 1
    tree = evidence.probe(['git', 'rev-parse', 'HEAD^{tree}'])
    report = {'schema': 2, 'source_commit': os.environ['GITHUB_SHA'], 'source_tree': tree,
              'event': os.environ['GITHUB_EVENT_NAME'], 'ref': os.environ['GITHUB_REF'],
              'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'pr': None}
    try:
        run = api(f'repos/{args.repo}/actions/runs/{report["run_id"]}')
        if (str(run['run_attempt']) != report['attempt'] or str(run['id']) != report['run_id']
                or run['event'] != report['event']):
            raise ValueError('Current Actions run identity differs from the workflow context')
        current, report['current_evidence'] = inspect_run(args.repo, run, report['ref'], tree, report['source_commit'])
        if report['ref'] == 'refs/heads/main' or report['ref'].startswith('refs/tags/'):
            number, baseline = latest_pr_run(args.repo, report['source_commit'])
            if baseline and baseline['status'] == 'completed' and baseline['conclusion'] == 'success':
                report['pr'] = {'pr': number, 'run_id': baseline['id'], 'attempt': baseline['run_attempt']}
                pr, report['pr_evidence'] = inspect_run(args.repo, baseline, f'refs/pull/{number}/merge', tree)
                report['targets'] = compare(pr, current, tree)
            else:
                report['reason'] = 'No latest successful Official release run for the merged PR'
        else:
            report['reason'] = 'The matching main or Tag run will perform the comparison with this PR'
    except (subprocess.SubprocessError, OSError, ValueError, KeyError, TypeError):
        report['reason'] = 'GitHub comparison inputs unavailable or invalid'
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
    return 0


if __name__ == '__main__':
    sys.exit(main())
