import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import evidence


def import_script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compare = import_script('compare-environments')
draft = import_script('release-draft')
REPO = 'ike-sh/Splicore'
REF = 'refs/pull/19/merge'
HEAD = 'a' * 40
MERGE = 'b' * 40
TREE = 'c' * 40


class QualificationProvenance(unittest.TestCase):
    def setUp(self):
        self.run = {'id': 51, 'run_attempt': 1, 'head_sha': HEAD, 'path': compare.WORKFLOW,
                    'event': 'pull_request', 'repository': {'id': 6, 'full_name': REPO}}
        self.history = []
        self.artifacts = []
        self.zips = {}
        for target in compare.TARGETS:
            self.add_job(target, 1)
            self.add_artifact(target, 1)

    def add_job(self, target, attempt, *, copied=False, conclusion='success'):
        time = 1 if copied else attempt
        job = {'id': len(self.history) + 1, 'name': compare.JOBS[target], 'run_id': self.run['id'],
               'head_sha': HEAD, 'run_attempt': attempt, 'status': 'completed', 'conclusion': conclusion,
               'runner_id': time, 'started_at': f'2026-11-20T0{time}:00:00Z',
               'completed_at': f'2026-11-20T0{time}:02:00Z', 'steps': [{'name': 'Qualify'}]}
        self.history.append(job)
        return job

    def add_artifact(self, target, attempt, *, tree=TREE, bad_inventory=False, fingerprint_attempt=None):
        run = {'run_id': '51', 'run_attempt': str(fingerprint_attempt or attempt), 'repository': REPO, 'event_name': 'pull_request',
               'job': 'build', 'ref': REF, 'sha': MERGE}
        source = {'commit': MERGE, 'tree': tree}
        value = {'kind': 'release', 'target': target, 'source': source, 'run': run,
                 'recorded_at': f'2026-11-20T0{attempt}:01:00Z'}
        value['fingerprint_sha256'] = evidence.sha256(evidence.json_bytes(value))
        fingerprint = evidence.json_bytes(value)
        manifest = {'target': target, 'kind': 'release', 'run': run, 'source': source,
                    'files': {'fingerprint.json': {'sha256': 'd' * 64 if bad_inventory else evidence.sha256(fingerprint),
                                                  'bytes': len(fingerprint)}}}
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('fingerprint.json', fingerprint)
            archive.writestr('SHA256_MANIFEST.json', evidence.json_bytes(manifest))
        data = stream.getvalue()
        artifact = {'id': len(self.artifacts) + 1, 'expired': False, 'digest': 'sha256:' + evidence.sha256(data),
                    'size_in_bytes': len(data), 'name': f'qualification-{target}-r51-a{attempt}',
                    'created_at': f'2026-11-20T0{attempt}:01:30Z',
                    'workflow_run': {'id': 51, 'head_sha': HEAD, 'repository_id': 6}}
        self.artifacts.append(artifact)
        self.zips[artifact['id']] = data
        return artifact

    def inspect(self):
        latest = [max((job for job in self.history if job['name'] == name), key=lambda job: job['run_attempt'])
                  for name in compare.JOBS.values()]

        def pages(path, field):
            if field == 'artifacts':
                return self.artifacts
            return latest if 'filter=latest' in path else self.history

        def api(path):
            if '/git/commits/' in path:
                return {'sha': MERGE, 'tree': {'sha': TREE}, 'parents': [{'sha': 'd' * 40}, {'sha': HEAD}]}
            return self.run

        with patch.object(compare, 'pages', side_effect=pages), patch.object(compare, 'api', side_effect=api), \
                patch.object(compare, 'gh', side_effect=lambda args: self.zips[int(args[1].split('/')[-2])]) as downloads:
            result = compare.inspect_run(REPO, self.run, REF, TREE)
        self.downloaded = [int(call.args[0][1].split('/')[-2]) for call in downloads.call_args_list]
        return result

    def rerun(self, conclusion='success'):
        self.run['run_attempt'] = 2
        for target in compare.TARGETS:
            # Mirror GitHub's new attempt-2 IDs for the three carried jobs.
            selected = target == 'linux-amd64'
            self.add_job(target, 2, copied=not selected, conclusion=conclusion if selected else 'success')

    def test_complete_first_attempt(self):
        rows, proof = self.inspect()
        self.assertEqual(set(rows), set(compare.TARGETS))
        self.assertTrue(all(data['attempt'] == 1 and data['original_job'] == data['effective_job'] for data in proof.values()))

    def test_partial_rerun_and_failure_then_success(self):
        self.history[0]['conclusion'] = 'failure'
        self.rerun()
        new = self.add_artifact('linux-amd64', 2)
        rows, proof = self.inspect()
        self.assertEqual(set(rows), set(compare.TARGETS))
        self.assertEqual(proof['linux-amd64']['artifact_id'], new['id'])
        self.assertEqual(proof['linux-amd64']['attempt'], 2)
        for target in ('windows-amd64', 'linux-arm64', 'windows-arm64'):
            self.assertEqual(proof[target]['attempt'], 1)
            self.assertNotEqual(proof[target]['original_job'], proof[target]['effective_job'])
        self.assertNotIn(1, self.downloaded)

    def test_new_failure_invalidates_older_success(self):
        self.rerun('failure')
        rows, proof = self.inspect()
        self.assertNotIn('linux-amd64', rows)
        self.assertIn('did not succeed', proof['linux-amd64']['reason'])
        self.assertNotIn(1, self.downloaded)

    def test_missing_artifact_for_new_success_does_not_fall_back(self):
        self.rerun()
        rows, proof = self.inspect()
        self.assertNotIn('linux-amd64', rows)
        self.assertIn('Artifact missing', proof['linux-amd64']['reason'])
        self.assertNotIn(1, self.downloaded)

    def test_sha256_validation_for_archive_and_fingerprint(self):
        self.artifacts[0]['digest'] = 'sha256:' + '0' * 64
        self.rerun()
        archive = self.add_artifact('linux-amd64', 2, bad_inventory=True)
        archive['digest'] = 'sha256:' + '0' * 64
        rows, proof = self.inspect()
        self.assertNotIn('linux-amd64', rows)
        self.assertIn('Artifact ZIP SHA256', proof['linux-amd64']['reason'])
        archive['digest'] = 'sha256:' + evidence.sha256(self.zips[archive['id']])
        rows, proof = self.inspect()
        self.assertNotIn('linux-amd64', rows)
        self.assertIn('Fingerprint SHA256', proof['linux-amd64']['reason'])

    def test_wrong_tree_and_attempt_are_rejected(self):
        self.rerun()
        wrong_tree = self.add_artifact('linux-amd64', 2, tree='d' * 40)
        rows, proof = self.inspect()
        self.assertNotIn('linux-amd64', rows)
        self.assertIn('source tree', proof['linux-amd64']['reason'])
        wrong_tree['expired'] = True
        self.add_artifact('linux-amd64', 2, fingerprint_attempt=1)
        rows, proof = self.inspect()
        self.assertNotIn('linux-amd64', rows)
        self.assertIn('original execution', proof['linux-amd64']['reason'])

    def test_latest_pr_lookup_does_not_filter_out_failures(self):
        pr = {'number': 19, 'merged_at': '2026-11-20', 'merge_commit_sha': MERGE,
              'base': {'ref': 'main'}, 'head': {'sha': HEAD, 'ref': 'codex/review', 'repo': {'id': 6}}}
        run = dict(self.run, head_branch='codex/review', head_repository={'id': 6}, created_at='2026-11-20T10:00:00Z')
        first = dict(run, conclusion='success')
        latest = dict(run, id=52, created_at='2026-11-20T11:00:00Z', conclusion='failure')
        with patch.object(compare, 'api', side_effect=[[pr], {'workflow_runs': [first, latest]}]) as api:
            self.assertEqual(compare.latest_pr_run(REPO, MERGE), (19, latest))
            self.assertNotIn('status=success', api.call_args.args[0])


class Publication(unittest.TestCase):
    version = 'v0.6.4'
    tag_env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/tags/' + version, 'GITHUB_SHA': HEAD}

    def release_record(self):
        names = [draft.release.archive_name(self.version, target) for target in draft.release.TARGETS]
        names += [f'splicore-{self.version}-source.tar.gz', 'SHA256SUMS', 'RELEASE_MANIFEST.json']
        return {'id': 42, 'draft': True, 'tag_name': self.version, 'target_commitish': HEAD,
                'assets': [{'id': index, 'name': name, 'state': 'uploaded', 'size': 4, 'digest': 'sha256:' + '0' * 64}
                           for index, name in enumerate(names, 1)]}

    def test_smoke_failure_and_non_tag_event_cannot_publish(self):
        for env in (dict(self.tag_env, PUBLICATION_GATE='failure'),
                    dict(self.tag_env, PUBLICATION_GATE='success', GITHUB_EVENT_NAME='workflow_dispatch')):
            with self.subTest(env=env), patch.dict('os.environ', env), patch.object(draft, 'api') as api:
                with self.assertRaises(RuntimeError):
                    draft.publish(REPO, self.version, HEAD, 42, '0' * 64)
                api.assert_not_called()

    def test_publish_checks_snapshot_then_updates_exact_release(self):
        record = self.release_record()
        check = draft.snapshot(record, self.version, HEAD, draft=True)
        digest = evidence.sha256(evidence.json_bytes(check))
        with patch.dict('os.environ', dict(self.tag_env, PUBLICATION_GATE='success')):
            with patch.object(draft, 'api', side_effect=[{'sha': HEAD}, record, {'id': 42, 'draft': False}]) as api:
                draft.publish(REPO, self.version, HEAD, 42, digest)
                self.assertEqual(api.call_count, 3)
                api.assert_called_with(REPO, 'releases/42', '--method', 'PATCH', '-F', 'draft=false', '-f', 'make_latest=true')
            record['assets'][0]['digest'] = 'sha256:' + 'f' * 64
            with patch.object(draft, 'api', side_effect=[{'sha': HEAD}, record]) as api:
                with self.assertRaisesRegex(RuntimeError, 'changed after download'):
                    draft.publish(REPO, self.version, HEAD, 42, digest)
                self.assertEqual(api.call_count, 2)

    def test_stage_creates_draft_and_requires_verified_download(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict('os.environ', self.tag_env):
            payload = Path(temp)
            (payload / 'final').mkdir()
            sums = payload / 'final/SHA256SUMS'
            sums.write_bytes(b'candidate checksums')
            record = self.release_record()
            destination = payload / 'downloaded'
            with patch.object(draft.release, 'verify', return_value={'version': self.version, 'commit': HEAD}), \
                    patch.object(draft, 'api', side_effect=[[[]], record]), \
                    patch.object(draft, 'gh', side_effect=[b'', json.dumps({'databaseId': 42}).encode()]) as call, \
                    patch.object(draft, 'download_verified', side_effect=RuntimeError('download checksum mismatch')) as download:
                with self.assertRaisesRegex(RuntimeError, 'download checksum mismatch'):
                    draft.stage(REPO, self.version, HEAD, payload, destination)
            self.assertIn('--draft', call.call_args_list[0].args)
            self.assertIn('--verify-tag', call.call_args_list[0].args)
            self.assertEqual(len(call.call_args_list), 2)
            self.assertEqual(download.call_args.args[-1], draft.file_sha256(sums))

    def test_missing_smoke_identity_is_not_a_pass(self):
        tests = {draft.release.RUNTIME_IDENTITY: 'pass'}
        with self.assertRaisesRegex(RuntimeError, 'plain-native-sudoku'):
            draft.release.require_runtime_tests({'tests': tests})
        tests.update({f'{draft.release.RUNTIME_IDENTITY}/{leaf}': 'pass' for leaf in draft.release.RUNTIME_LEAVES})
        draft.release.require_runtime_tests({'tests': tests})


if __name__ == '__main__':
    unittest.main()
