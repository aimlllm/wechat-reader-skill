#!/usr/bin/env python3
"""Explicit-profile, bounded read-only GreenBubbles queries."""
import argparse
import html
import json
import os
from pathlib import Path
import re
import sys
import time

from common import Failure, external_path, open_private_file, private_json, run_json, validate_database_root, verify_executable


FIELDS = {'schema', 'db_root', 'credential_file', 'reader_bin', 'acquire_bin',
          'reader_sha256', 'acquire_sha256'}
OUTPUT_SCHEMA = 'wechat.reader-output.v1'
SAFE_FAILURES = frozenset({'path_invalid', 'runtime_inside_package', 'private_parent_invalid',
    'private_file_invalid', 'private_file_too_large', 'profile_invalid', 'source_owner_invalid',
    'tool_metadata_invalid', 'tool_fingerprint_invalid', 'tool_fingerprint_mismatch',
    'tool_timeout', 'tool_result_too_large', 'tool_result_invalid', 'tool_unavailable',
    'verification_result_invalid', 'message_check_unavailable', 'query_scope_invalid',
    'cursor_invalid', 'time_scope_invalid', 'query_failed', 'query_result_invalid'})


class Parser(argparse.ArgumentParser):
    def error(self, message):
        del message
        print(json.dumps({'status': 'failed', 'reason': 'argument_invalid'}))
        raise SystemExit(2)


def plain_text(value, maximum=16384):
    """Accept already decoded text; never recover words from raw markup."""
    if not isinstance(value, str) or len(value.encode('utf-8')) > maximum:
        return None
    if any(ord(char) < 32 and char not in '\n\r\t' for char in value):
        return None
    inspected = value
    for _ in range(3):
        inspected = html.unescape(inspected)
    if (re.search(r'<(?:/?[A-Za-z][\w:.-]*(?:\s|/?>)|!|\?)', inspected)
            or re.search(r'(?i)\b(?:aes[_-]?key|auth[_-]?key|cdn(?:thumb)?(?:url|key)|'
                         r'cdnthumbaeskey|file[_-]?key)\b[\s\"\x27]*[:=]', inspected)):
        return None
    return value


def safe_fields(value, strings=(), integers=(), booleans=()):
    """Copy explicitly named scalar fields only, never nested upstream extras."""
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in strings:
        text = plain_text(value.get(key), 4096)
        if text is not None:
            result[key] = text
    for key in integers:
        number = value.get(key)
        if type(number) is int:
            result[key] = number
    for key in booleans:
        if type(value.get(key)) is bool:
            result[key] = value[key]
    return result


def project_message(value, operation, conversation):
    """Project the v0.10.0 Text/Quote model; unsupported payloads stay unknown."""
    if not isinstance(value, dict):
        return {'contentType': 'Unknown', 'decodeState': 'incomplete'}
    result = safe_fields(value,
        strings=('id', 'conversationId', 'sender', 'senderDisplayName',
                 'messageTypeLabel', 'messageSubtypeLabel'),
        integers=('createdAtUnix', 'sortSequence', 'serverId', 'messageType', 'messageSubtype', 'status'),
        booleans=('contentTruncated', 'snippetTruncated'))
    identity = (all(result.get(key) for key in ('id', 'sender'))
                and result.get('conversationId') == conversation
                and result.get('createdAtUnix', 0) > 0)
    result.update(contentType='Unknown', decodeState='incomplete')
    if not identity:
        return result
    if operation == 'search':
        snippet = plain_text(value.get('snippet'))
        if snippet is not None:
            result.update(contentType='SearchSnippet', decodeState='snippet', snippet=snippet)
        return result
    content = value.get('content')
    if not isinstance(content, dict) or len(content) != 1:
        return result
    if 'Text' in content:
        text = plain_text(content['Text'])
        if text is not None:
            result.update(contentType='Text', decodeState='complete', text=text)
    elif isinstance(content.get('Quote'), dict):
        fields = content['Quote']
        quote = {}
        for upstream, public in (('reply_text', 'replyText'), ('refer_content', 'referText'),
                                 ('refer_sender', 'referSender'), ('refer_display_name', 'referDisplayName')):
            text = plain_text(fields.get(upstream))
            if text is not None:
                quote[public] = text
        for upstream, public in (('refer_type', 'referType'), ('refer_server_id', 'referServerId')):
            number = fields.get(upstream)
            if type(number) is int:
                quote[public] = number
        if quote.get('replyText') or quote.get('referText'):
            result.update(contentType='Quote', quote=quote)
            if quote.get('replyText') and quote.get('referText'):
                result['decodeState'] = 'complete'
    if value.get('contentTruncated') is True:
        result['decodeState'] = 'incomplete'
    return result


def project_result(value, operation, limit, conversation=None):
    """Stable safe envelope; neither raw output nor an opt-in raw mode exists."""
    result = {'schema': OUTPUT_SCHEMA, 'operation': operation, 'ok': True,
              'status': 'ok', 'projectionComplete': True, 'source': {},
              'consistency': {}, 'warnings': []}
    if operation == 'find':
        if not isinstance(value, list) or len(value) > limit:
            raise Failure('query_result_invalid')
        items = []
        for item in value:
            projected = safe_fields(item, strings=('id', 'displayName', 'nickname', 'remark', 'alias'))
            if isinstance(item, dict) and item.get('kind') in (
                    'accountHolder', 'person', 'group', 'official', 'service', 'unknown'):
                projected['kind'] = item['kind']
            if not projected.get('id'):
                result['projectionComplete'] = False
            items.append(projected)
        result['items'] = items
        # Find has no cursor/coverage report upstream; do not invent completeness.
        result['page'] = {'limit': limit, 'returned': len(items)}
    else:
        if (not isinstance(value, dict) or value.get('ok') is not True
                or not isinstance(value.get('items'), list) or len(value['items']) > limit):
            raise Failure('query_result_invalid')
        page = safe_fields(value.get('page'), strings=('nextCursor',),
                           integers=('limit', 'returned'), booleans=('hasMore',))
        if (page.get('returned') != len(value['items']) or type(page.get('hasMore')) is not bool
                or (page['hasMore'] and not page.get('nextCursor'))):
            raise Failure('query_result_invalid')
        result['page'] = page
        source = value.get('source')
        if isinstance(source, dict) and source.get('mode') in ('liveEncrypted', 'snapshotEncrypted', 'decrypted'):
            result['source']['mode'] = source['mode']
        if (isinstance(source, dict) and isinstance(source.get('identity'), str)
                and re.fullmatch(r'sha256:[0-9a-fA-F]{32,64}', source['identity'])):
            result['source']['identity'] = source['identity']
        result['consistency'] = safe_fields(value.get('consistency'), strings=('guarantee',),
            integers=('databaseCount', 'observedAtUnixMilliseconds'),
            booleans=('crossDatabaseAtomic', 'coverageComplete'))
        warnings = value.get('warnings', [])
        if not isinstance(warnings, list):
            raise Failure('query_result_invalid')
        for warning in warnings[:200]:
            projected = safe_fields(warning, integers=('shardId', 'count'))
            code = warning.get('code') if isinstance(warning, dict) else None
            projected['code'] = code if isinstance(code, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}', code) else 'upstreamWarning'
            result['warnings'].append(projected)
        result['items'] = [project_message(item, operation, conversation) for item in value['items']]
        result['projectionComplete'] = all(item['decodeState'] != 'incomplete' for item in result['items'])
        if result['consistency'].get('coverageComplete') is not True or len(warnings) > 200:
            result['projectionComplete'] = False
    if not result['projectionComplete']:
        result['status'] = 'incomplete'
    return result


def load_profile(path):
    config = private_json(external_path(str(path)))
    if (not isinstance(config, dict) or set(config) != FIELDS
            or config.get('schema') != 'wechat.reader-profile.v1'):
        raise Failure('profile_invalid')
    for key in ('db_root', 'credential_file', 'reader_bin', 'acquire_bin'):
        config[key] = str(external_path(config[key]))
    validate_database_root(config['db_root'])
    verify_executable(config['reader_bin'], config['reader_sha256'])
    verify_executable(config['acquire_bin'], config['acquire_sha256'])
    return config


def query(config, command):
    fd = open_private_file(config['credential_file'], maximum=67)
    try:
        return run_json(command, fd)
    finally:
        os.close(fd)


def doctor(config, conversation=None):
    report = {'status': 'incomplete', 'capturePerformed': False,
              'credentialMetadataValid': True, 'toolFingerprintsVerified': True}
    code, verified = query(config, [config['acquire_bin'], 'verify', '--db-root', config['db_root'],
                                   '--passphrase-stdin', '--json'])
    if not isinstance(verified, dict):
        raise Failure('verification_result_invalid')
    counts = [verified.get(key) for key in ('databaseCount', 'distinctSaltCount', 'verifiedSaltCount')]
    if any(type(count) is not int or count < 0 for count in counts):
        raise Failure('verification_result_invalid')
    report['verification'] = dict(zip(('databaseCount', 'distinctSaltCount', 'verifiedSaltCount'), counts))
    valid = (code == 0 and verified.get('allVerified') is True and counts[0] >= counts[1] > 0
             and counts[1] == counts[2])
    report['verification']['allVerified'] = valid
    if not valid:
        report['reason'] = 'databases_not_all_verified'
        return report
    if conversation is None:
        report['reason'] = 'bounded_conversation_read_required'
        return report
    code, messages = query(config, [config['reader_bin'], 'messages', 'list', config['db_root'],
                                    '--passphrase-stdin', '--conversation', conversation, '--limit', '1', '--json'])
    if (code or not isinstance(messages, dict) or messages.get('ok') is not True
            or not isinstance(messages.get('items'), list)):
        raise Failure('message_check_unavailable')
    items = messages['items']
    proof = bool(items and isinstance(items[0], dict)
                 and isinstance(items[0].get('id'), str) and items[0]['id']
                 and isinstance(items[0].get('sender'), str) and items[0]['sender']
                 and type(items[0].get('createdAtUnix')) is int and items[0]['createdAtUnix'] > 0
                 and items[0].get('conversationId') == conversation)
    consistency = messages.get('consistency', {})
    coverage = isinstance(consistency, dict) and consistency.get('coverageComplete') is True
    report['boundedMessageIdentityVerified'] = proof
    report['coverageComplete'] = coverage
    if proof and coverage:
        report['status'] = 'ready'
    else:
        report['reason'] = 'message_identity_or_coverage_incomplete'
    return report


def bounded(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('limit_invalid') from None
    if not 1 <= number <= 200:
        raise argparse.ArgumentTypeError('limit_invalid')
    return number


def validate_query(args):
    for field in ('conversation', 'name', 'query'):
        value = getattr(args, field, None)
        if value is not None and (not value.strip() or len(value.encode()) > 4096 or '\0' in value):
            raise Failure('query_scope_invalid')
    cursor = getattr(args, 'cursor', None)
    if cursor is not None and (len(cursor) > 4096 or not cursor or '\0' in cursor):
        raise Failure('cursor_invalid')
    since, until = getattr(args, 'since', None), getattr(args, 'until', None)
    if ((since is not None and since < 0) or (until is not None and until < 0)
            or (since is not None and until is not None and since >= until)
            or (until is not None and until > int(time.time()) + 60)):
        raise Failure('time_scope_invalid')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    operations = parser.add_subparsers(dest='operation', required=True)
    check = operations.add_parser('doctor')
    check.add_argument('--conversation')
    find = operations.add_parser('find')
    find.add_argument('name')
    find.add_argument('--limit', type=bounded, default=50)
    for operation in ('messages', 'search'):
        request = operations.add_parser(operation)
        request.add_argument('--conversation', required=True)
        request.add_argument('--limit', type=bounded, default=20)
        request.add_argument('--since', type=int)
        request.add_argument('--until', type=int)
        request.add_argument('--cursor')
        if operation == 'search':
            request.add_argument('--query', required=True)
    args = parser.parse_args(argv)
    try:
        validate_query(args)
        config = load_profile(args.profile)
        if args.operation == 'doctor':
            result = doctor(config, args.conversation)
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result['status'] == 'ready' else 3
        if args.operation == 'find':
            command = [config['reader_bin'], 'conversations', 'find', args.name, config['db_root'],
                       '--passphrase-stdin', '--limit', str(args.limit)]
        else:
            command = [config['reader_bin'], 'messages', 'list' if args.operation == 'messages' else 'search',
                       config['db_root'], '--passphrase-stdin', '--conversation', args.conversation,
                       '--limit', str(args.limit), '--json']
            for key in ('since', 'until', 'cursor', 'query'):
                value = getattr(args, key, None)
                if value is not None:
                    command.extend(['--' + key, str(value)])
        code, result = query(config, command)
        if code or (isinstance(result, dict) and result.get('ok') is False):
            raise Failure('query_failed')
        result = project_result(result, args.operation, args.limit, getattr(args, 'conversation', None))
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError) as error:
        # Never release upstream stderr, exception strings, profile paths or IDs.
        reason = str(error) if isinstance(error, Failure) and str(error) in SAFE_FAILURES else (
            'private_input_unavailable' if isinstance(error, OSError) else 'profile_or_result_invalid')
        print(json.dumps({'status': 'check_unavailable' if args.operation == 'doctor' else 'failed',
                          'reason': reason}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
