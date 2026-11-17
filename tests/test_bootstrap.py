"""Metadata-only bootstrap tests; all runtime inputs are temporary fixtures."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/wechat-reader-portable/scripts'
sys.path.insert(0, str(SCRIPTS))
import bootstrap
import common
import reader


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='synthetic-bootstrap-')
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.db = self.root / 'synthetic-db'
        self.db.mkdir(mode=0o700)
        self.credential = self.root / 'synthetic-credential'
        self.binary = self.root / 'synthetic-tool'
        self.binary.write_bytes(b'not an executable program: synthetic metadata only')
        self.binary.chmod(0o700)
        fingerprint = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.config = dict(schema='wechat.reader-profile.v1', db_root=str(self.db),
                           credential_file=str(self.credential), reader_bin=str(self.binary),
                           acquire_bin=str(self.binary), reader_sha256=fingerprint,
                           acquire_sha256=fingerprint)
        self.profile = self.root / 'synthetic-profile.json'
        self.save_profile()

    def tearDown(self):
        self.temporary.cleanup()

    def save_profile(self):
        self.profile.write_text(json.dumps(self.config))
        self.profile.chmod(0o600)

    def add_credential(self):
        self.credential.write_bytes(b'SYNTHETIC_SECRET_MUST_NOT_BE_READ')
        self.credential.chmod(0o600)

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = bootstrap.main(list(args))
        self.assertEqual(stderr.getvalue(), '')
        result = json.loads(stdout.getvalue())
        for flag in ('capturePerformed', 'loginPerformed', 'appModified', 'permissionRequested'):
            self.assertIs(result[flag], False)
        self.assertEqual(result['route'], 'local_database_memory_helper')
        self.assertEqual(result['schema'], 'wechat.reader-bootstrap.v1')
        for value in (str(self.root), 'SYNTHETIC_SECRET', self.config['reader_sha256']):
            self.assertNotIn(value, stdout.getvalue())
        self.assertNotEqual(result['status'], 'ready')
        return code, result

    def inspect(self):
        return self.invoke('--profile', str(self.profile))

    def test_without_profile_and_missing_profile_have_stable_preparation_states(self):
        code, result = self.invoke()
        self.assertEqual(code, 3)
        self.assertEqual((result['status'], result['stage'], result['reason']),
                         ('preparation_required', 'profile_required', 'profile_not_configured'))
        code, result = self.invoke('--profile', str(self.root / 'absent-profile'))
        self.assertEqual(result['reason'], 'profile_missing')
        self.assertEqual(result['nextStep'], 'prepare_external_profile')

    def test_missing_credential_is_preparation_not_key_failure(self):
        code, result = self.inspect()
        self.assertEqual(code, 3)
        self.assertEqual((result['status'], result['stage'], result['reason']),
                         ('preparation_required', 'credential_acquisition_required', 'credential_missing'))
        self.assertEqual(result['nextStep'], 'review_private_copy_preparation')
        self.assertEqual(result['checks']['credentialMetadata'], 'missing')

    def test_missing_profile_still_requires_external_absolute_path(self):
        self.assertEqual(self.invoke('--profile', 'missing-profile.json')[1]['reason'], 'path_invalid')
        inside = SCRIPTS / 'synthetic-profile-that-does-not-exist.json'
        self.assertEqual(self.invoke('--profile', str(inside))[1]['reason'], 'runtime_inside_package')

    def test_missing_credential_parent_is_not_a_capture_ready_destination(self):
        self.config['credential_file'] = str(self.root / 'absent-parent' / 'absent-credential')
        self.save_profile()
        code, result = self.inspect()
        self.assertEqual(code, 2)
        self.assertEqual(result['reason'], 'credential_parent_unavailable')
        self.assertEqual(result['nextStep'], 'repair_credential_metadata')

    def test_metadata_valid_requires_doctor_and_never_reads_credential_or_database(self):
        self.add_credential()
        database = self.db / 'synthetic.db'
        database.write_bytes(b'SYNTHETIC_DATABASE_MUST_NOT_BE_READ')
        protected_inodes = {self.credential.stat().st_ino, database.stat().st_ino}
        read = os.read

        def guarded_read(fd, count):
            self.assertNotIn(os.fstat(fd).st_ino, protected_inodes)
            return read(fd, count)

        with patch('os.read', side_effect=guarded_read):
            code, result = self.inspect()
        self.assertEqual(code, 3)
        self.assertEqual((result['status'], result['stage'], result['reason']),
                         ('verification_required', 'database_verification_required', 'credential_metadata_valid'))
        self.assertEqual(result['nextStep'], 'run_doctor')

    def test_credential_mode_empty_oversized_and_hardlink_are_invalid(self):
        self.add_credential()
        cases = [('mode', lambda: self.credential.chmod(0o644)),
                 ('empty', lambda: self.credential.write_bytes(b'')),
                 ('oversized', lambda: self.credential.write_bytes(b'x' * 68)),
                 ('hardlink', lambda: os.link(self.credential, self.root / 'synthetic-link'))]
        for name, mutate in cases:
            with self.subTest(case=name):
                self.credential.chmod(0o600)
                self.credential.write_bytes(b'SYNTHETIC_SECRET_MUST_NOT_BE_READ')
                mutate()
                code, result = self.inspect()
                self.assertEqual(code, 2)
                self.assertEqual(result['reason'], 'credential_metadata_invalid')

    def test_credential_symlink_and_parent_symlink_are_invalid(self):
        self.add_credential()
        target = self.root / 'synthetic-target'
        self.credential.rename(target)
        self.credential.symlink_to(target)
        self.assertEqual(self.inspect()[1]['reason'], 'credential_metadata_invalid')
        self.credential.unlink()
        real = self.root / 'synthetic-real'
        real.mkdir(mode=0o700)
        link = self.root / 'synthetic-parent-link'
        link.symlink_to(real, target_is_directory=True)
        self.config['credential_file'] = str(link / 'absent')
        self.save_profile()
        self.assertEqual(self.inspect()[1]['reason'], 'credential_metadata_invalid')

    def test_permission_denial_is_not_reported_as_missing_credential(self):
        with patch.object(bootstrap, 'open_private_file', side_effect=PermissionError('SYNTHETIC_PRIVATE_PATH')):
            code, result = self.inspect()
        self.assertEqual(code, 2)
        self.assertEqual(result['reason'], 'credential_unavailable')
        self.assertEqual(result['checks']['credentialMetadata'], 'unavailable')

    def test_profile_mode_symlink_schema_and_package_path_are_rejected(self):
        self.profile.chmod(0o644)
        self.assertEqual(self.inspect()[1]['reason'], 'private_file_invalid')
        self.profile.chmod(0o600)
        target = self.root / 'synthetic-profile-target'
        self.profile.rename(target)
        self.profile.symlink_to(target)
        self.assertEqual(self.inspect()[1]['reason'], 'runtime_input_unavailable')
        self.profile.unlink()
        self.config['schema'] = 'synthetic-invalid'
        self.save_profile()
        self.assertEqual(self.inspect()[1]['reason'], 'profile_invalid')
        self.config['schema'] = 'wechat.reader-profile.v1'
        self.config['db_root'] = str(SCRIPTS)
        self.save_profile()
        self.assertEqual(self.inspect()[1]['reason'], 'runtime_inside_package')

    def test_wrong_fingerprint_missing_tool_and_database_owner_are_not_key_failure(self):
        self.config['reader_sha256'] = '0' * 64
        self.save_profile()
        self.assertEqual(self.inspect()[1]['reason'], 'tool_fingerprint_mismatch')
        self.config['reader_sha256'] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.binary.unlink()
        self.save_profile()
        self.assertEqual(self.inspect()[1]['reason'], 'runtime_input_missing')
        with patch.object(bootstrap, 'load_profile', side_effect=common.Failure('source_owner_invalid')):
            self.assertEqual(self.inspect()[1]['reason'], 'source_owner_invalid')

    def test_wrong_credential_owner_and_insecure_parent_are_rejected(self):
        self.add_credential()
        original = os.fstat
        inode = self.credential.stat().st_ino

        def foreign_owner(fd):
            metadata = original(fd)
            if metadata.st_ino == inode:
                values = list(metadata)
                values[4] = os.getuid() + 1
                return os.stat_result(values)
            return metadata

        with patch('os.fstat', side_effect=foreign_owner):
            self.assertEqual(self.inspect()[1]['reason'], 'credential_metadata_invalid')
        self.root.chmod(0o755)
        try:
            self.assertEqual(self.inspect()[1]['reason'], 'private_parent_invalid')
        finally:
            self.root.chmod(0o700)

    def test_tools_doctor_and_capture_are_never_executed_or_runtime_written(self):
        self.add_credential()
        with contextlib.ExitStack() as stack:
            for target in ('subprocess.Popen', 'subprocess.run', 'subprocess.check_output',
                           'os.system', 'os.mkdir', 'os.chmod', 'os.kill', 'reader.doctor',
                           'reader.query', 'common.run_json', 'pathlib.Path.write_text',
                           'pathlib.Path.write_bytes'):
                stack.enter_context(patch(target, side_effect=AssertionError('forbidden action')))
            code, result = self.inspect()
        self.assertEqual(code, 3)
        self.assertEqual(result['status'], 'verification_required')

    def test_sensitive_errors_and_unknown_failure_strings_never_escape(self):
        for error in (common.Failure('SYNTHETIC_PRIVATE_VALUE'),
                      OSError('SYNTHETIC_PRIVATE_VALUE'),
                      ValueError('SYNTHETIC_PRIVATE_VALUE')):
            with self.subTest(error=type(error).__name__), patch.object(bootstrap, 'load_profile', side_effect=error):
                code, result = self.inspect()
                self.assertEqual(code, 2)
                self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', json.dumps(result))
        with patch.object(bootstrap, 'open_private_file', side_effect=RuntimeError('SYNTHETIC_PRIVATE_VALUE')):
            self.assertEqual(self.inspect()[1]['reason'], 'credential_metadata_invalid')
        with patch.object(Path, 'lstat', side_effect=RuntimeError('SYNTHETIC_PRIVATE_VALUE')):
            self.assertEqual(self.inspect()[1]['reason'], 'profile_or_runtime_invalid')

    def test_profile_path_resolution_errors_are_sanitized_before_any_read(self):
        for error, reason in ((PermissionError('SYNTHETIC_PRIVATE_PATH'), 'runtime_input_unavailable'),
                              (OSError('SYNTHETIC_PRIVATE_PATH'), 'runtime_input_unavailable'),
                              (ValueError('SYNTHETIC_PRIVATE_PATH'), 'runtime_input_unavailable'),
                              (RuntimeError('SYNTHETIC_PRIVATE_PATH'), 'profile_or_runtime_invalid')):
            with self.subTest(error=type(error).__name__), \
                 patch.object(bootstrap, 'external_path', side_effect=error), \
                 patch.object(bootstrap, 'load_profile') as load:
                code, result = self.inspect()
                self.assertEqual((code, result['reason']), (2, reason))
                self.assertNotIn('SYNTHETIC_PRIVATE_PATH', json.dumps(result))
                load.assert_not_called()

    def test_python_gate_and_host_hints_are_metadata_only(self):
        with patch.object(bootstrap.sys, 'version_info', (3, 9, 0)), patch.object(bootstrap, 'load_profile') as load:
            code, result = self.inspect()
        self.assertEqual((code, result['reason']), (2, 'python_version_unsupported'))
        load.assert_not_called()
        for system, machine, os_hint, cpu_hint in [('Darwin', 'arm64', 'macos', 'apple_silicon'),
                                                  ('Linux', 'x86_64', 'other', 'other')]:
            with patch.object(bootstrap.platform, 'system', return_value=system), \
                 patch.object(bootstrap.platform, 'machine', return_value=machine):
                self.assertEqual(self.invoke()[1]['host'], {'os': os_hint, 'cpu': cpu_hint})

    def test_bad_arguments_are_sanitized(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            bootstrap.main(['--unknown-SYNTHETIC_PRIVATE_VALUE'])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(json.loads(stdout.getvalue())['reason'], 'argument_invalid')
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', stdout.getvalue() + stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
