"""Generated temporary fixtures only; never load a deployment profile."""
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
import common
import reader


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='synthetic-reader-')
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.db = self.root / 'synthetic-db'
        self.db.mkdir(mode=0o700)
        self.credential = self.root / 'synthetic-credential'
        self.credential.write_bytes(b'FAKE_CREDENTIAL_FOR_TESTS_ONLY')
        self.credential.chmod(0o600)
        self.binary = self.root / 'synthetic-cli'
        self.binary.write_text('#!' + sys.executable + '\n' + '''import json, sys
secret = sys.stdin.buffer.read()
if secret != b'FAKE_CREDENTIAL_FOR_TESTS_ONLY':
    print('PRIVATE_DIAGNOSTIC_MUST_NOT_ESCAPE', file=sys.stderr)
    sys.exit(9)
if 'verify' in sys.argv:
    print(json.dumps({'allVerified': True, 'databaseCount': 2, 'distinctSaltCount': 2, 'verifiedSaltCount': 2, 'privatePath': 'FAKE_PRIVATE_PATH'}))
elif 'find' in sys.argv:
    print(json.dumps([{'id': 'synthetic-group', 'displayName': 'Synthetic group'}]))
else:
    print(json.dumps({'ok': True, 'items': [{'id': 'FAKE_MESSAGE_ID', 'sender': 'FAKE_SENDER', 'conversationId': sys.argv[sys.argv.index('--conversation')+1], 'createdAtUnix': 100, 'content': {'Text': 'FAKE_MESSAGE_BODY'}}], 'consistency': {'coverageComplete': True}, 'page': {'returned': 1, 'hasMore': False}}))
''')
        self.binary.chmod(0o700)
        fingerprint = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.config = dict(schema='wechat.reader-profile.v1', db_root=str(self.db),
                           credential_file=str(self.credential), reader_bin=str(self.binary),
                           acquire_bin=str(self.binary), reader_sha256=fingerprint, acquire_sha256=fingerprint)
        self.profile = self.root / 'synthetic-profile.json'
        self.save_profile()

    def tearDown(self):
        self.temporary.cleanup()

    def save_profile(self):
        self.profile.write_text(json.dumps(self.config))
        self.profile.chmod(0o600)

    def invoke(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = reader.main(['--profile', str(self.profile), *args])
        return code, output.getvalue()

    def test_doctor_executes_verify_and_real_bounded_read_without_private_output(self):
        code, text = self.invoke('doctor', '--conversation', 'synthetic-group')
        report = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'ready')
        self.assertTrue(report['boundedMessageIdentityVerified'])
        self.assertEqual(report['verification']['databaseCount'], 2)
        for private in ('FAKE_MESSAGE', 'FAKE_SENDER', 'FAKE_PRIVATE_PATH', str(self.root), 'FAKE_CREDENTIAL'):
            self.assertNotIn(private, text)

    def test_doctor_requires_conversation_proof_and_complete_verification(self):
        code, text = self.invoke('doctor')
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(text)['status'], 'incomplete')
        partial = (1, dict(allVerified=False, databaseCount=2, distinctSaltCount=2, verifiedSaltCount=1))
        with patch.object(reader, 'query', return_value=partial):
            result = reader.doctor(self.config, 'synthetic-group')
        self.assertEqual(result['status'], 'incomplete')
        self.assertFalse(result['verification']['allVerified'])

    def test_false_identity_or_coverage_cannot_report_ready(self):
        verified = (0, dict(allVerified=True, databaseCount=2, distinctSaltCount=2, verifiedSaltCount=2))
        good = dict(id='synthetic-message', sender='synthetic-author', conversationId='synthetic-group', createdAtUnix=100)
        for items, coverage in [([], True), ([dict(good, conversationId='wrong-group')], True),
                                ([dict(good, sender='')], True), ([dict(good, createdAtUnix=True)], True), ([good], False)]:
            with patch.object(reader, 'query', side_effect=[verified, (0, {'ok': True, 'items': items, 'consistency': {'coverageComplete': coverage}})]):
                self.assertEqual(reader.doctor(self.config, 'synthetic-group')['status'], 'incomplete')

    def test_tool_unavailable_is_distinct_and_sanitized(self):
        with patch.object(reader, 'query', side_effect=OSError('FAKE_PRIVATE_PATH')):
            code, text = self.invoke('doctor', '--conversation', 'synthetic-group')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(text)['status'], 'check_unavailable')
        self.assertNotIn('FAKE_PRIVATE_PATH', text)

    def test_failure_codes_distinguish_safe_causes_without_arbitrary_values(self):
        for reason in ('private_file_invalid', 'tool_fingerprint_mismatch', 'tool_timeout'):
            with patch.object(reader, 'query', side_effect=common.Failure(reason)):
                code, text = self.invoke('doctor')
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(text)['reason'], reason)
        with patch.object(reader, 'query', side_effect=common.Failure('FAKE_PRIVATE_VALUE')):
            code, text = self.invoke('doctor')
        self.assertNotIn('FAKE_PRIVATE_VALUE', text)

    def test_successful_query_emits_safe_reading_schema(self):
        code, text = self.invoke('messages', '--conversation', 'synthetic-group', '--since', '90', '--until', '110', '--limit', '2')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)['schema'], 'wechat.reader-output.v1')
        self.assertEqual(json.loads(text)['items'][0]['text'], 'FAKE_MESSAGE_BODY')
        self.assertNotIn('FAKE_CREDENTIAL', text)
        code, text = self.invoke('find', 'Synthetic', '--limit', '2')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)['items'][0]['id'], 'synthetic-group')

    def page(self, content=None, **changes):
        item = dict(id='synthetic-message', conversationId='synthetic-group',
                    sender='synthetic-sender', senderDisplayName='Synthetic Sender',
                    createdAtUnix=100, serverId=12345, sortSequence=100000,
                    messageType=1, messageTypeLabel='Text', messageSubtype=0,
                    messageSubtypeLabel='None', content={'Text': 'ordinary text'} if content is None else content)
        item.update(changes)
        return dict(ok=True, schema='greenbubbles.query.v1', operation='messages.list',
                    source=dict(mode='liveEncrypted', identity='sha256:' + 'a' * 32),
                    consistency=dict(coverageComplete=True, crossDatabaseAtomic=False,
                                     databaseCount=2, observedAtUnixMilliseconds=100000),
                    items=[item], page=dict(limit=2, returned=1, hasMore=True, nextCursor='synthetic-cursor'),
                    warnings=[dict(code='syntheticWarning', count=1, shardId=2)])

    def project(self, result, operation='messages', limit='2'):
        args = [operation, '--conversation', 'synthetic-group', '--limit', limit]
        if operation == 'search':
            args += ['--query', 'ordinary']
        with patch.object(reader, 'query', return_value=(0, result)):
            return self.invoke(*args)

    def test_text_pagination_identity_and_safe_warning_metadata_survive(self):
        page = self.page({'Text': '中文与 URL https://example.com，a < 5。'})
        code, text = self.project(page)
        result = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['items'][0]['text'], '中文与 URL https://example.com，a < 5。')
        self.assertEqual(result['items'][0]['serverId'], 12345)
        self.assertEqual(result['source'], page['source'])
        self.assertEqual(result['page'], page['page'])
        self.assertEqual(result['consistency'], page['consistency'])
        self.assertEqual(result['warnings'], page['warnings'])

    def test_unknown_raw_media_and_all_unlisted_envelope_fields_never_escape(self):
        secret = 'SYNTHETIC_MEDIA_SECRET_MUST_NOT_ESCAPE'
        page = self.page({'Unknown': {'raw': '<img aeskey="' + secret + '"/>', 'cdnurl': secret}})
        for location in (page, page['source'], page['consistency'], page['page'], page['items'][0]):
            location['unlisted'] = secret
        page['warnings'][0].update(message='<msg>' + secret + '</msg>', raw_xml=secret)
        code, text = self.project(page)
        self.assertEqual(code, 0)
        result = json.loads(text)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['items'][0]['contentType'], 'Unknown')
        for forbidden in (secret, 'aeskey', 'cdnurl', 'raw_xml', 'unlisted', '<img', '<msg'):
            self.assertNotIn(forbidden, text)

    def test_quote_keeps_only_decoded_words_and_reference_metadata(self):
        secret = 'SYNTHETIC_QUOTE_SECRET_MUST_NOT_ESCAPE'
        quote = dict(reply_text='收到，我再核对。', refer_content='请检查文案。',
                     refer_sender='synthetic-person', refer_display_name='Synthetic Person',
                     refer_type=1, refer_server_id=123,
                     raw_xml='<appmsg aeskey="' + secret + '"/>', unknown=secret)
        code, text = self.project(self.page({'Quote': quote}))
        result = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['items'][0]['quote'], dict(replyText='收到，我再核对。',
            referText='请检查文案。', referSender='synthetic-person', referDisplayName='Synthetic Person',
            referType=1, referServerId=123))
        self.assertNotIn(secret, text)
        self.assertNotIn('raw_xml', text)

    def test_markup_credentials_and_unsupported_text_shapes_fail_closed(self):
        for content in ({'Text': '<msg aeskey="SYNTHETIC_SECRET"/>'},
                        {'Text': '&amp;lt;img aeskey=&quot;SYNTHETIC_SECRET&quot;/&amp;gt;'},
                        {'Text': 'aeskey=SYNTHETIC_SECRET'},
                        {'Text': {'content': 'SYNTHETIC_SECRET'}},
                        {'Quote': {'raw_xml': '<title>SYNTHETIC_SECRET</title>'}},
                        {'Text': 'safe', 'Unknown': 'SYNTHETIC_SECRET'}):
            with self.subTest(content=content):
                code, text = self.project(self.page(content))
                result = json.loads(text)
                self.assertEqual(code, 0)
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(result['items'][0]['decodeState'], 'incomplete')
                self.assertNotIn('SYNTHETIC_SECRET', text)
                self.assertNotIn('text', result['items'][0])

    def test_unsafe_quote_reference_is_not_parsed_from_xml_or_invented(self):
        code, text = self.project(self.page({'Quote': dict(reply_text='谢谢',
            refer_content='<msg aeskey="SYNTHETIC_SECRET"/>', raw_xml='<title>UNREAD_REFERENCE</title>')}))
        result = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['items'][0]['quote'], {'replyText': '谢谢'})
        self.assertNotIn('SYNTHETIC_SECRET', text)
        self.assertNotIn('UNREAD_REFERENCE', text)

    def test_search_is_explicitly_a_snippet_and_rejects_raw_markup(self):
        page = self.page(snippet='matched ordinary words', raw_xml='SYNTHETIC_SECRET')
        code, text = self.project(page, 'search')
        item = json.loads(text)['items'][0]
        self.assertEqual(code, 0)
        self.assertEqual(item['contentType'], 'SearchSnippet')
        self.assertEqual(item['decodeState'], 'snippet')
        self.assertEqual(item['snippet'], 'matched ordinary words')
        self.assertNotIn('text', item)
        self.assertNotIn('SYNTHETIC_SECRET', text)
        code, text = self.project(self.page(snippet='<img aeskey="SYNTHETIC_SECRET"/>'), 'search')
        self.assertEqual(json.loads(text)['status'], 'incomplete')
        self.assertNotIn('SYNTHETIC_SECRET', text)

    def test_find_has_bounded_scalar_projection_without_raw_extras(self):
        item = dict(id='synthetic-group', displayName='Synthetic group', kind='group',
                    raw_xml='<msg>SYNTHETIC_SECRET</msg>', content={'Text': 'SYNTHETIC_SECRET'},
                    alias='<img aeskey="SYNTHETIC_SECRET"/>')
        with patch.object(reader, 'query', return_value=(0, [item])):
            code, text = self.invoke('find', 'Synthetic', '--limit', '1')
        result = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(result['items'], [dict(id='synthetic-group', displayName='Synthetic group', kind='group')])
        self.assertNotIn('SYNTHETIC_SECRET', text)
        with patch.object(reader, 'query', return_value=(0, [item, item])):
            code, text = self.invoke('find', 'Synthetic', '--limit', '1')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(text)['reason'], 'query_result_invalid')

    def test_broken_page_cannot_silently_drop_a_continuation(self):
        page = self.page()
        page['page'].pop('nextCursor')
        code, text = self.project(page)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(text)['reason'], 'query_result_invalid')
        page = self.page()
        page['consistency']['coverageComplete'] = False
        code, text = self.project(page)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)['status'], 'incomplete')

    def test_bad_inputs_never_invoke_cli_or_echo_values(self):
        for args in [('messages', '--conversation', 'synthetic-group', '--limit', '201'),
                     ('messages', '--conversation', 'synthetic-group', '--since', '110', '--until', '90'),
                     ('search', '--conversation', 'synthetic-group', '--query', ''),
                     ('messages', '--conversation', 'synthetic-group', '--since', 'FAKE_PRIVATE_VALUE')]:
            with self.subTest(args=args), patch.object(reader, 'query') as query:
                try:
                    code, text = self.invoke(*args)
                except SystemExit as error:
                    self.assertEqual(error.code, 2)
                else:
                    self.assertEqual(code, 2)
                    self.assertNotIn('FAKE_PRIVATE_VALUE', text)
                query.assert_not_called()

    def test_private_input_permissions_symlinks_hardlinks_and_inside_package_rejected(self):
        self.profile.chmod(0o644)
        self.assertRaises(common.Failure, reader.load_profile, self.profile)
        self.profile.chmod(0o600)
        linked = self.root / 'synthetic-link'
        linked.symlink_to(self.profile)
        self.assertRaises(OSError, reader.load_profile, linked)
        linked.unlink()
        os.link(self.profile, linked)
        self.assertRaises(common.Failure, reader.load_profile, self.profile)
        linked.unlink()
        self.root.chmod(0o755)
        self.assertRaises(common.Failure, reader.load_profile, self.profile)
        self.root.chmod(0o700)
        with patch.object(common, 'package_root', return_value=self.root):
            self.assertRaises(common.Failure, reader.load_profile, self.profile)

    def test_missing_fingerprint_and_modified_binary_rejected(self):
        self.config.pop('reader_sha256')
        self.save_profile()
        self.assertRaises(common.Failure, reader.load_profile, self.profile)
        self.config['reader_sha256'] = '0' * 64
        self.save_profile()
        self.assertRaises(common.Failure, reader.load_profile, self.profile)

    def test_credential_file_is_checked_by_descriptor_before_child(self):
        self.credential.chmod(0o644)
        with patch.object(reader, 'run_json') as run:
            code, text = self.invoke('doctor')
        run.assert_not_called()
        self.assertEqual(code, 2)
        self.assertNotIn(str(self.root), text)

    def test_cli_timeout_output_limit_and_stderr_isolation(self):
        command = [sys.executable, '-c', 'import time; time.sleep(10)']
        with self.assertRaisesRegex(common.Failure, '^tool_timeout$'):
            common.run_json(command, timeout=0.05)
        with self.assertRaisesRegex(common.Failure, '^tool_result_too_large$'):
            common.run_json([sys.executable, '-c', 'print("x" * 5000)'], maximum=20)
        with self.assertRaisesRegex(common.Failure, '^tool_result_invalid$'):
            common.run_json([sys.executable, '-c', 'import sys; print("FAKE_PRIVATE_DIAGNOSTIC", file=sys.stderr)'])


if __name__ == '__main__':
    unittest.main()
