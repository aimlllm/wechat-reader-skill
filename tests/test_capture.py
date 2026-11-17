"""Synthetic signature, protection and failure-path checks; no real apps."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/wechat-reader-portable/scripts'
sys.path.insert(0, str(SCRIPTS))
import capture_filtered as capture
import common


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='synthetic-capture-')
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.original = self.root / 'Original.app'
        self.private = self.root / 'Private.app'
        for app in (self.original, self.private):
            (app / 'Contents/MacOS').mkdir(parents=True)
            image = app / 'Contents/MacOS/WeChat'
            image.write_bytes(b'synthetic-application-image')
            image.chmod(0o700)
        self.db = self.root / 'synthetic-db'
        self.db.mkdir(mode=0o700)
        self.verifier = self.root / 'synthetic-verifier'
        self.verifier.write_bytes(b'synthetic-verifier-binary')
        self.verifier.chmod(0o700)
        self.args = SimpleNamespace(app_path=str(self.private), original_app_path=str(self.original),
            verify_bin=str(self.verifier), app_cdhash='1' * 40, original_cdhash='2' * 40,
            verify_cdhash='3' * 40, verifier_sha256=hashlib.sha256(self.verifier.read_bytes()).hexdigest(),
            db_root=str(self.db), output=str(self.root / 'synthetic-credential'), timeout_seconds=1)
        self.identifier = 'Identifier=com.tencent.xinWeChat\n'
        self.original_info = self.identifier + 'Authority=Synthetic authority\nflags=0x10000(runtime)\n'
        self.private_info = self.identifier + 'Signature=adhoc\nflags=0x2(adhoc)\n'
        self.rights = {'com.apple.application-identifier': 'synthetic.application',
                       'com.apple.developer.team-identifier': 'synthetic.team',
                       'com.apple.security.app-sandbox': True,
                       'com.apple.security.application-groups': ['synthetic.group']}
        self.private_rights = {key: value for key, value in self.rights.items() if key not in (
            'com.apple.application-identifier', 'com.apple.developer.team-identifier')}
        self.private_rights['com.apple.security.get-task-allow'] = True

    def tearDown(self):
        self.temporary.cleanup()

    def profiles(self, original_info=None, private_info=None, private_rights=None):
        return [(original_info or self.original_info, self.rights),
                (private_info or self.private_info, self.private_rights if private_rights is None else private_rights),
                ('synthetic verifier signature', None)]

    def preflight(self, profiles=None, sip='System Integrity Protection status: enabled.'):
        with patch.object(capture.platform, 'system', return_value='Darwin'), \
             patch.object(capture.platform, 'machine', return_value='arm64'), \
             patch.object(Path, 'is_file', return_value=True), \
             patch.object(capture, 'signature_profile', side_effect=profiles or self.profiles()), \
             patch.object(capture, 'signature_command', return_value=SimpleNamespace(stdout=sip.encode())):
            return capture.preflight(self.args)

    def flags(self):
        return [part for key in ('app_path', 'original_app_path', 'verify_bin', 'app_cdhash',
            'original_cdhash', 'verify_cdhash', 'verifier_sha256', 'db_root', 'output')
            for part in ('--' + key.replace('_', '-'), str(getattr(self.args, key)))]

    def test_preflight_only_runs_existing_metadata_checks_without_capture_side_effects(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        forbidden = ('capture', 'read_salt_inventory', 'write_secret', 'write_report',
                     'run_lldb', 'on_pbkdf', 'CandidateSession', 'find_wechat_pid')
        console = io.StringIO()
        existing_preflight = capture.preflight
        metadata_open = os.open
        def read_only_open(path, flags, *args, **kwargs):
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            return metadata_open(path, flags, *args, **kwargs)
        with contextlib.ExitStack() as stack:
            guards = [stack.enter_context(patch.object(capture, name,
                      side_effect=AssertionError('unexpected capture side effect'))) for name in forbidden]
            guards.append(stack.enter_context(patch.object(capture.subprocess, 'Popen',
                side_effect=AssertionError('unexpected debugger process'))))
            guards.append(stack.enter_context(patch.object(capture.tempfile, 'TemporaryDirectory',
                side_effect=AssertionError('unexpected output directory'))))
            for name in ('mkdir', 'chmod', 'chown', 'unlink', 'replace', 'rename', 'link'):
                guards.append(stack.enter_context(patch.object(capture.os, name,
                    side_effect=AssertionError('unexpected filesystem mutation'))))
            stack.enter_context(patch.object(capture.os, 'open', side_effect=read_only_open))
            checked = stack.enter_context(patch.object(capture, 'preflight', wraps=existing_preflight))
            stack.enter_context(patch.object(capture.platform, 'system', return_value='Darwin'))
            stack.enter_context(patch.object(capture.platform, 'machine', return_value='arm64'))
            stack.enter_context(patch.object(Path, 'is_file', return_value=True))
            stack.enter_context(patch.object(capture, 'signature_profile', side_effect=self.profiles()))
            stack.enter_context(patch.object(capture, 'signature_command',
                return_value=SimpleNamespace(stdout=b'System Integrity Protection status: enabled.')))
            stack.enter_context(contextlib.redirect_stdout(console))
            self.assertEqual(capture.main(['--preflight-only', *self.flags()]), 0)
            checked.assert_called_once()
            for key in vars(self.args):
                if key != 'timeout_seconds':
                    self.assertEqual(getattr(checked.call_args.args[0], key), getattr(self.args, key))
            for guard in guards:
                guard.assert_not_called()
        self.assertEqual(json.loads(console.getvalue()), {
            'status': 'preflight_passed', 'stage': 'local_capture_configuration',
            'capturePerformed': False, 'attachTested': False, 'credentialValidated': False})
        self.assertFalse(Path(self.args.output).exists())
        self.assertEqual(sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*')), before)
        for private in (str(self.root), self.args.app_cdhash, self.args.verifier_sha256):
            self.assertNotIn(private, console.getvalue())

    def test_preflight_only_keeps_all_required_inputs_and_mode_errors_sanitized(self):
        flags = self.flags()
        requests = [['--preflight-only', *flags[:offset], *flags[offset + 2:]]
                    for offset in range(0, len(flags), 2)]
        requests += [['--preflight-only', *flags, '--timeout-seconds', value]
                     for value in ('0', '301', 'SYNTHETIC_PRIVATE_VALUE')]
        requests += [['--preflight-only', '--self-test', *flags],
                     ['--preflight-only', *flags, '--SYNTHETIC_PRIVATE_VALUE']]
        for request in requests:
            with self.subTest(request=request), contextlib.ExitStack() as stack:
                preflight = stack.enter_context(patch.object(capture, 'preflight'))
                operation = stack.enter_context(patch.object(capture, 'capture'))
                self_test = stack.enter_context(patch.object(capture, 'self_test'))
                console = io.StringIO()
                stack.enter_context(contextlib.redirect_stdout(console))
                with self.assertRaises(SystemExit) as raised:
                    capture.main(request)
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(json.loads(console.getvalue()), {'status': 'failed', 'reason': 'argument_invalid'})
                for operation in (preflight, operation, self_test):
                    operation.assert_not_called()
                self.assertNotIn(str(self.root), console.getvalue())
                self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', console.getvalue())

    def test_preflight_only_failures_never_reveal_sensitive_exception_values(self):
        failures = (capture.CaptureFailure('SYNTHETIC_PRIVATE_SIGNATURE'),
                    common.Failure('SYNTHETIC_PRIVATE_FINGERPRINT'),
                    OSError('SYNTHETIC_PRIVATE_PATH'), ValueError('SYNTHETIC_PRIVATE_VALUE'),
                    RuntimeError('SYNTHETIC_PRIVATE_UNEXPECTED_ERROR'))
        for failure in failures:
            with self.subTest(kind=type(failure)), contextlib.ExitStack() as stack:
                preflight = stack.enter_context(patch.object(capture, 'preflight', side_effect=failure))
                guards = [stack.enter_context(patch.object(capture, name)) for name in
                          ('capture', 'read_salt_inventory', 'write_secret', 'write_report', 'run_lldb')]
                guards.append(stack.enter_context(patch.object(capture.subprocess, 'Popen')))
                console = io.StringIO()
                stack.enter_context(contextlib.redirect_stdout(console))
                code = capture.main(['--preflight-only', *self.flags()])
                self.assertIn(code, (1, 2))
                preflight.assert_called_once()
                for guard in guards:
                    guard.assert_not_called()
                report = json.loads(console.getvalue())
                self.assertEqual(report['reason'], 'capture_failed' if isinstance(failure, RuntimeError)
                                 else 'capture_preflight_or_tool_failed')
                self.assertNotIn('SYNTHETIC_PRIVATE', console.getvalue())
                self.assertNotIn(str(self.root), console.getvalue())
                self.assertFalse(Path(self.args.output).exists())

    def test_ordinary_capture_entrypoint_is_unchanged_without_preflight_only(self):
        with patch.object(capture, 'capture', return_value=7) as operation, \
             patch.object(capture, 'preflight') as metadata:
            self.assertEqual(capture.main(self.flags()), 7)
        operation.assert_called_once()
        self.assertFalse(operation.call_args.args[0].preflight_only)
        metadata.assert_not_called()

    def test_explicit_good_profiles_hashes_and_enabled_sip_pass_without_application_mutation(self):
        verifier, image, original, owner = self.preflight()
        self.assertEqual(verifier, self.verifier)
        self.assertEqual(image, str(self.private / 'Contents/MacOS/WeChat'))
        self.assertEqual(original, str(self.original / 'Contents/MacOS/WeChat'))
        self.assertEqual(owner, (os.getuid(), os.getgid()))
        self.assertFalse(Path(self.args.output).exists())

    def test_same_original_private_path_never_reaches_signature_or_debugger(self):
        self.args.app_path = self.args.original_app_path
        with patch.object(capture.platform, 'system', return_value='Darwin'), \
             patch.object(capture.platform, 'machine', return_value='arm64'), \
             patch.object(Path, 'is_file', return_value=True), \
             patch.object(capture, 'signature_profile') as signature:
            self.assertRaises(capture.CaptureFailure, capture.preflight, self.args)
        signature.assert_not_called()

    def test_system_protection_and_exact_entitlement_difference_are_required(self):
        self.assertRaises(capture.CaptureFailure, self.preflight, sip='System Integrity Protection status: disabled.')
        self.assertRaises(capture.CaptureFailure, self.preflight,
                          profiles=self.profiles(private_rights={'com.apple.security.get-task-allow': True}))
        self.assertRaises(capture.CaptureFailure, self.preflight, profiles=self.profiles(private_info=self.private_info + 'runtime)'))
        self.assertRaises(capture.CaptureFailure, self.preflight, profiles=self.profiles(original_info=self.identifier + 'Signature=adhoc'))

    def test_changed_verifier_hash_and_existing_destination_fail_closed(self):
        self.verifier.write_bytes(b'changed-synthetic-verifier')
        self.assertRaises(common.Failure, self.preflight)
        self.args.verifier_sha256 = hashlib.sha256(self.verifier.read_bytes()).hexdigest()
        Path(self.args.output).write_bytes(b'synthetic-existing-credential')
        self.assertRaises(capture.CaptureFailure, self.preflight)

    def test_signature_check_really_compares_cdhash_and_requires_codesign_success(self):
        details = (self.private_info + 'CDHash=' + '1' * 40 + '\n').encode()
        results = [subprocess.CompletedProcess([], 0, b'', b''),
                   subprocess.CompletedProcess([], 0, b'', details),
                   subprocess.CompletedProcess([], 0, plistlib.dumps(self.private_rights), b'')]
        with patch.object(capture.subprocess, 'run', side_effect=results) as runner:
            _, rights = capture.signature_profile(self.private, '1' * 40)
        self.assertEqual(rights, self.private_rights)
        self.assertIn('--strict', runner.call_args_list[0].args[0])
        for code, actual in [(1, details), (0, details.replace(('1' * 40).encode(), ('9' * 40).encode()))]:
            responses = [subprocess.CompletedProcess([], code, b'', b'PRIVATE_PATH_DIAGNOSTIC'),
                         subprocess.CompletedProcess([], 0, b'', actual)]
            with patch.object(capture.subprocess, 'run', side_effect=responses):
                self.assertRaises(capture.CaptureFailure, capture.signature_profile, self.private, '1' * 40)

    def test_verifier_signature_does_not_require_application_entitlements(self):
        details = ('CDHash=' + '3' * 40 + '\n').encode()
        with patch.object(capture, 'signature_command', side_effect=[SimpleNamespace(), SimpleNamespace(stderr=details)]) as command:
            _, rights = capture.signature_profile(self.verifier, '3' * 40, require_entitlements=False)
        self.assertIsNone(rights)
        self.assertEqual(command.call_count, 2)

    def test_all_flags_and_fingerprints_mandatory_before_capture(self):
        console = io.StringIO()
        with patch.object(capture, 'capture') as operation, contextlib.redirect_stdout(console):
            with self.assertRaises(SystemExit):
                capture.main(['--app-path', 'FAKE_PRIVATE_PATH'])
        operation.assert_not_called()
        self.assertNotIn('FAKE_PRIVATE_PATH', console.getvalue())

    def test_preflight_errors_never_echo_paths_or_raw_tool_details(self):
        flags = []
        for key in ('app_path', 'original_app_path', 'verify_bin', 'app_cdhash', 'original_cdhash',
                    'verify_cdhash', 'verifier_sha256', 'db_root', 'output'):
            flags += ['--' + key.replace('_', '-'), str(getattr(self.args, key))]
        console = io.StringIO()
        with patch.object(capture, 'preflight', side_effect=OSError('FAKE_PRIVATE_PATH')), contextlib.redirect_stdout(console):
            self.assertEqual(capture.main(flags), 2)
        self.assertNotIn('FAKE_PRIVATE_PATH', console.getvalue())
        self.assertNotIn(str(self.root), console.getvalue())

    def test_partial_candidate_is_preserved_but_never_successful(self):
        fake = subprocess.CompletedProcess([], 1,
            json.dumps({'verifiedSaltCount': 1, 'distinctSaltCount': 2, 'allVerified': False}).encode(), b'')
        with patch.object(capture.subprocess, 'run', return_value=fake):
            partial = capture.verify_candidate(self.verifier, self.db, b's' * 32, 1)
        self.assertFalse(partial['allVerified'])
        config = {'deadline': 100, 'report': str(self.root / 'synthetic-report.json')}
        config_path = self.root / 'synthetic-worker.json'
        config_path.write_text(json.dumps(config))
        session = SimpleNamespace(saved=True, fatal=None, seen=1, rejected=0, report=partial)
        with patch.dict(sys.modules, {'lldb': SimpleNamespace()}), \
             patch.object(capture, 'CandidateSession', return_value=session), \
             patch.object(capture.signal, 'signal'):
            capture.run_lldb(MagicMock(), config_path)
        report = json.loads(Path(config['report']).read_text())
        self.assertEqual(report['status'], 'partial_candidate_saved')
        worker = MagicMock()
        worker.poll.return_value = 0
        with patch.object(capture, 'preflight', return_value=(self.verifier, 'synthetic-private', 'synthetic-original', (os.getuid(), os.getgid()))), \
             patch.object(capture, 'read_salt_inventory', return_value={'synthetic-salt'}), \
             patch.object(capture.subprocess, 'Popen', return_value=worker), \
             patch.object(capture, 'final_report', return_value=report), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(capture.capture(self.args), 1)

    def test_abrupt_exit_during_write_never_publishes_truncated_canonical_credential(self):
        script = '''import os, sys
sys.path.insert(0, sys.argv[1])
import capture_filtered as helper
write = os.write
def crash(fd, data):
    write(fd, data[:2])
    os._exit(9)
os.write = crash
helper.write_secret(sys.argv[2], b's' * 32, (os.getuid(), os.getgid()))
'''
        result = subprocess.run([sys.executable, '-c', script, str(SCRIPTS), self.args.output],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 9)
        self.assertFalse(Path(self.args.output).exists())
        pending = list(self.root.glob('.capture-pending-*'))
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].stat().st_mode & 0o777, 0o600)

    def test_atomic_publication_preserves_racing_destination_and_cleans_temporary_file(self):
        original_link = os.link
        def racing_link(*args, **kwargs):
            Path(self.args.output).write_bytes(b'synthetic-preserved-file')
            return original_link(*args, **kwargs)
        with patch.object(capture.os, 'link', side_effect=racing_link):
            self.assertRaises(FileExistsError, capture.write_secret, self.args.output,
                              b's' * 32, (os.getuid(), os.getgid()))
        self.assertEqual(Path(self.args.output).read_bytes(), b'synthetic-preserved-file')
        self.assertEqual(list(self.root.glob('.capture-pending-*')), [])

    def test_broken_progress_pipe_still_terminates_debugger_and_does_not_certify_detach(self):
        worker = MagicMock()
        worker.poll.return_value = None
        worker.wait.return_value = 0
        with patch.object(capture, 'preflight', return_value=(self.verifier, 'synthetic-private', 'synthetic-original', (os.getuid(), os.getgid()))), \
             patch.object(capture, 'read_salt_inventory', return_value={'synthetic-salt'}), \
             patch.object(capture.subprocess, 'Popen', return_value=worker), \
             patch('builtins.print', side_effect=[BrokenPipeError('FAKE_PRIVATE_VALUE'), None]) as output:
            self.assertEqual(capture.capture(self.args), 1)
        worker.terminate.assert_called_once_with()
        worker.wait.assert_called_once_with(timeout=5)
        final = json.loads(output.call_args.args[0])
        self.assertEqual(final['status'], 'cleanup_unconfirmed')
        self.assertFalse(final['detachConfirmed'])
        self.assertNotIn('FAKE_PRIVATE_VALUE', output.call_args.args[0])

    def test_original_cancellation_target_restart_salt_candidate_and_detach_regressions(self):
        # Includes 23 independent simulated callback/LLDB/controller checks.
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(capture.self_test(), 0)


if __name__ == '__main__':
    unittest.main()
