import unittest
from unittest.mock import patch
import guard


class GuardTests(unittest.TestCase):
    def test_windows_wsl_and_case(self):
        with patch('guard.shutil.which', return_value=None):
            self.assertEqual(guard.path_identity('D:\\Code\\Splicore'),
                             guard.path_identity('/mnt/d/code/splicore'))
            self.assertEqual(guard.path_identity('/d/code/Splicore'),
                             guard.path_identity('d:/code/splicore'))
            self.assertNotEqual(guard.path_identity('C:/code/Splicore'),
                                guard.path_identity('D:/code/Splicore'))

    def test_branch_and_remote(self):
        for name in ['main', 'release/v0.4.0', 'v0.3.0', 'fix/legacy', '']:
            self.assertFalse(guard.feature_branch(name))
        self.assertTrue(guard.feature_branch('codex/restore-vless'))
        for url in ['https://github.com/ike-sh/Splicore.git', 'git@github.com:ike-sh/Splicore.git']:
            self.assertTrue(guard.expected_remote(url))
        for url in ['https://github.com/other/Splicore', 'https://github.com/ike-sh/Splicore.evil',
                    'https://github.com.evil/ike-sh/Splicore', '/tmp/Splicore']:
            self.assertFalse(guard.expected_remote(url))

    def test_worktrees(self):
        root = '/canonical/source'
        with patch('guard.os.path.lexists', return_value=False):
            stale = guard.worktrees('worktree ' + root + '\n\nworktree /old/source\nprunable missing\n', root)
        self.assertEqual(stale, ['/old/source'])
        with self.assertRaisesRegex(RuntimeError, 'Additional worktree'):
            guard.worktrees('worktree /other/source\nHEAD abc\n', root)

    def test_artifacts_reports_and_secrets(self):
        for path in ['Reports/private.md', 'build/core', 'bin/core', '.env', 'state.db',
                     'private/CONVERGENCE_MASTER_TRACKER.md', 'proxy.exe']:
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                guard.check_blob(path, b'ordinary content')
        for data in [b'-----BEGIN PRIVATE KEY-----', b'ghp_' + b'a' * 36]:
            with self.assertRaises(RuntimeError):
                guard.check_blob('settings.txt', data)
        guard.check_blob('protocol/vless/encryption/testdata/vector.json', b'{"synthetic":"data"}')
        guard.check_blob('docs/DEVELOPMENT.md', b'public development rules')

    def test_dangerous_ref_updates(self):
        branch = 'codex/restore-vless'
        sha = 'a' * 40
        for remote, url, ref in [('origin', 'https://github.com/ike-sh/Splicore.git', 'refs/heads/main'),
                                 ('origin', 'https://github.com/ike-sh/Splicore.git', 'refs/tags/v0.3.0'),
                                 ('upstream', 'https://github.com/other/repo', 'refs/heads/' + branch)]:
            with self.subTest(ref=ref), self.assertRaises(RuntimeError):
                guard.check_push(remote, url, [f'refs/heads/{branch} {sha} {ref} {guard.ZERO}'], branch)

    def test_wrong_directory_and_wrong_branch_stop_before_pr_query(self):
        def fake_git(*args):
            if args == ('rev-parse', '--show-toplevel'):
                return '/unexpected/source'
            if args[:3] == ('config', '--local', '--get'):
                return '/canonical/source'
            raise AssertionError(args)
        with patch('guard.git', side_effect=fake_git), patch('guard.pending_prs') as prs:
            with self.assertRaisesRegex(RuntimeError, 'Wrong source directory'):
                guard.check_state()
            prs.assert_not_called()

    def test_pending_restoration_pr(self):
        with patch('guard.shutil.which', return_value='gh'), patch('guard.run', return_value='[{"number":7,"headRefName":"codex/restore-other","baseRefName":"main","title":"restore"}]'):
            with self.assertRaisesRegex(RuntimeError, '#7'):
                guard.pending_prs('codex/restore-vless')
            guard.pending_prs('codex/restore-other')

    def test_wrong_branch_and_outdated_base(self):
        def fake_git(*args):
            answers = {('rev-parse', '--show-toplevel'): '/canonical/source',
                       ('config', '--local', '--get', 'splicore.canonicalRoot'): '/canonical/source',
                       ('rev-parse', '--is-inside-work-tree'): 'true',
                       ('remote', 'get-url', '--all', 'origin'): 'https://github.com/ike-sh/Splicore.git',
                       ('remote', 'get-url', '--push', '--all', 'origin'): 'https://github.com/ike-sh/Splicore.git',
                       ('symbolic-ref', '--quiet', '--short', 'HEAD'): branch,
                       ('ls-remote', '--heads', 'origin', 'refs/heads/main'): 'new\trefs/heads/main',
                       ('merge-base', 'HEAD', 'origin/main'): 'old',
                       ('rev-parse', 'origin/main'): 'new'}
            return answers[args]
        for branch, message in [('main', 'short-lived'), ('codex/old', 'current origin/main')]:
            with self.subTest(branch=branch), patch('guard.git', side_effect=fake_git), patch('pathlib.Path.read_text', return_value='module github.com/ike-sh/Splicore\n'):
                with self.assertRaisesRegex(RuntimeError, message):
                    guard.check_state()


if __name__ == '__main__':
    unittest.main()
