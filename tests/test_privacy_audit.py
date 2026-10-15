import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/privacy_audit.py'
spec = importlib.util.spec_from_file_location('privacy_audit', SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PrivacyAuditTests(unittest.TestCase):
    def test_auditor_patterns_are_not_personal_paths(self):
        self.assertFalse(audit.content_findings(SCRIPT.read_bytes()))

    def test_hidden_history_leak_still_fails_after_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
            git('init', '-b', 'main')
            git('config', 'user.name', audit.NEUTRAL_NAME)
            git('config', 'user.email', audit.NEUTRAL_EMAIL)
            git('config', 'commit.gpgsign', 'false')
            (root/'README.md').write_text('/' + 'Users/' + 'synthetic-owner/private-file')
            git('add', 'README.md')
            git('commit', '-m', 'docs: synthetic fixture')
            (root/'README.md').write_text('Generic instructions only.')
            git('add', 'README.md')
            git('commit', '-m', 'docs: remove synthetic fixture')
            result = audit.audit(root)
            self.assertFalse(result['ok'])
            self.assertIn('user_home_path', {f['category'] for f in result['findings']})
            self.assertEqual(result['commits_checked'], 2)

    def test_private_data_types_and_denylists(self):
        self.assertFalse(audit.path_allowed('output.db'))
        self.assertFalse(audit.path_allowed('.private/profile.json'))
        self.assertEqual(audit.content_findings(b'fixture phrase', ['fixture phrase']), {'external_denylist'})
        self.assertEqual(audit.content_findings(('a' * 64).encode()), {'hex_secret'})
        self.assertFalse(audit.content_findings(b'neutral@example.invalid'))
        self.assertEqual(audit.content_findings(('fixture@' + 'example.com').encode()), {'personal_email'})

    def test_staged_path_and_unneutral_identity_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
            git('init', '-b', 'main')
            git('config', 'user.name', audit.NEUTRAL_NAME)
            git('config', 'user.email', audit.NEUTRAL_EMAIL)
            git('config', 'commit.gpgsign', 'false')
            (root/'README.md').write_text('Generic instructions only.')
            git('add', 'README.md')
            git('commit', '-m', 'docs: synthetic fixture')
            name = 'wx' + 'id_' + 'synthetic-staged.md'
            (root/name).write_text('Generic instructions only.')
            git('add', name)
            result = audit.audit(root)
            self.assertIn({'scope': 'index_path', 'category': 'account_identifier'}, result['findings'])
            git('config', 'user.name', 'Synthetic author')
            git('commit', '-m', 'docs: synthetic identity fixture')
            result = audit.audit(root)
            self.assertIn({'scope': 'history', 'category': 'non_neutral_identity'}, result['findings'])

    def test_account_identifiers_are_detected_without_echo(self):
        value = ('wx' + 'id_' + 'synthetic-account').encode()
        result = audit.content_findings(value)
        self.assertEqual(result, {'account_identifier'})
        self.assertNotIn(value.decode(), repr(result))


if __name__ == '__main__':
    unittest.main()
