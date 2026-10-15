#!/usr/bin/env python3
"""Audit distributable Git content and every reachable commit without printing matches."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

NEUTRAL_NAME = 'Skill Maintainers'
NEUTRAL_EMAIL = 'maintainers@example.invalid'
ALLOWED_SUFFIXES = {'.md', '.py', '.json', '.yaml', '.yml', '.txt'}
SPECIAL_FILES = {'.gitignore', 'LICENSE', 'AGENTS.md'}
FORBIDDEN_PARTS = {'.private', '.runtime', '.scratch', '.tools', 'profiles', 'outputs', 'node_modules', '__pycache__'}
PATTERNS = {
    'user_home_path': re.compile(r'(?:/Users/[^\s/\[\]\\]+/|/home/[^\s/\[\]\\]+/|[A-Z]:\\Users\\[^\s\\\[\]]+\\)'),
    'account_identifier': re.compile(r'\bwxid_[A-Za-z0-9_]+|\b\d{6,}@chatroom\b'),
    'credential': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[A-Z0-9]{16})\b'),
    'hex_secret': re.compile(r'(?<![A-Za-z0-9])[0-9a-fA-F]{64}(?![A-Za-z0-9])'),
    'opaque_chat_identity': re.compile(r'\beyJ[A-Za-z0-9_-]{100,}'),
    'device_identity': re.compile(r'(?i)(?:serial(?:number)?|hardware_uuid|computername|localhostname)\s*[:=]\s*["\']?[A-Za-z0-9-]{6,}'),
    'literal_signature': re.compile(r'(?i)(?:cdhash|signature_hash)\s*[:=]\s*["\']?[0-9a-f]{40}\b'),
}
EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PHONE = re.compile(r'(?<!\w)(?:\+\d[\d ()-]{8,}\d|1[3-9]\d{9})(?!\w)')


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL)


def path_allowed(name):
    path = Path(name)
    return (not any(p in FORBIDDEN_PARTS for p in path.parts)
            and (path.name in SPECIAL_FILES or path.suffix in ALLOWED_SUFFIXES))


def content_findings(data, forbidden=()):
    if b'\0' in data:
        return {'binary_content'}
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return {'non_utf8_content'}
    findings = {label for label, pattern in PATTERNS.items() if pattern.search(text)}
    if any(not match.group().endswith('@example.invalid') for match in EMAIL.finditer(text)):
        findings.add('personal_email')
    if PHONE.search(text):
        findings.add('phone_number')
    if any(value and value.casefold() in text.casefold() for value in forbidden):
        findings.add('external_denylist')
    return findings


def audit(root, forbidden=()):
    findings = []
    checked_blobs = set()
    refs = git(root, 'for-each-ref', '--format=%(refname)%00%(objecttype)%00%(objectname)').decode().splitlines()
    for record in refs:
        name, kind, oid = record.split('\0')
        for category in content_findings(name.encode(), forbidden):
            findings.append({'scope': 'ref_name', 'category': category})
        if kind == 'tag':
            tag = git(root, 'cat-file', '-p', oid).decode()
            tagger = next((line for line in tag.splitlines() if line.startswith('tagger ')), '')
            if not tagger.startswith(f'tagger {NEUTRAL_NAME} <{NEUTRAL_EMAIL}> '):
                findings.append({'scope': 'tag', 'category': 'non_neutral_identity'})
            for category in content_findings(tag.encode(), forbidden):
                findings.append({'scope': 'tag', 'category': category})
    commits = git(root, 'rev-list', '--all').decode().splitlines()
    if not commits:
        findings.append({'scope': 'history', 'category': 'no_commit'})
    for commit in commits:
        raw = git(root, 'show', '-s', '--format=%an%x00%ae%x00%cn%x00%ce%x00%B', commit).decode()
        author, email, committer, cemail, message = raw.split('\0', 4)
        if (author, email, committer, cemail) != (NEUTRAL_NAME, NEUTRAL_EMAIL, NEUTRAL_NAME, NEUTRAL_EMAIL):
            findings.append({'scope': 'history', 'category': 'non_neutral_identity'})
        for category in content_findings(message.encode(), forbidden):
            findings.append({'scope': 'commit_message', 'category': category})
        for entry in git(root, 'ls-tree', '-r', '-z', commit).split(b'\0'):
            if not entry:
                continue
            head, name = entry.split(b'\t', 1)
            mode, kind, oid = head.decode().split()
            name = name.decode()
            if mode not in ('100644', '100755') or kind != 'blob' or not path_allowed(name):
                findings.append({'scope': 'history_path', 'category': 'disallowed_file_type'})
            for category in content_findings(name.encode(), forbidden):
                findings.append({'scope': 'history_path', 'category': category})
            if oid not in checked_blobs:
                checked_blobs.add(oid)
                for category in content_findings(git(root, 'cat-file', 'blob', oid), forbidden):
                    findings.append({'scope': 'history_content', 'category': category})
    staged = git(root, 'ls-files', '--stage', '-z').split(b'\0')
    tracked = []
    for entry in staged:
        if not entry:
            continue
        head, name = entry.split(b'\t', 1)
        mode, oid, stage = head.decode().split()
        tracked.append(name)
        for category in content_findings(name, forbidden):
            findings.append({'scope': 'index_path', 'category': category})
        if mode not in ('100644', '100755') or stage != '0' or not path_allowed(name.decode()):
            findings.append({'scope': 'index', 'category': 'disallowed_file_type'})
        if oid not in checked_blobs:
            checked_blobs.add(oid)
            for category in content_findings(git(root, 'cat-file', 'blob', oid), forbidden):
                findings.append({'scope': 'index_content', 'category': category})
    working_count = 0
    for raw_name in tracked:
        if not raw_name:
            continue
        name = raw_name.decode()
        path = root / name
        working_count += 1
        if path.is_symlink() or not path.is_file() or not path_allowed(name):
            findings.append({'scope': 'working_tree', 'category': 'disallowed_file_type'})
            continue
        for category in content_findings(path.read_bytes(), forbidden):
            findings.append({'scope': 'working_tree', 'category': category})
    return {'ok': not findings, 'commits_checked': len(commits), 'blobs_checked': len(checked_blobs),
            'tracked_files_checked': working_count, 'refs_checked': len(refs), 'findings': findings,
            'limitation': 'Pattern checks complement manual review; arbitrary personal prose is not automatically recognizable.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--denylist-file', type=Path, help='Private external JSON string list; matches are never printed')
    args = parser.parse_args()
    try:
        root = args.repo.resolve(strict=True)
        forbidden = ()
        if args.denylist_file:
            denylist = args.denylist_file.resolve(strict=True)
            if denylist == root or root in denylist.parents:
                raise ValueError('external denylist required')
            forbidden = json.loads(denylist.read_text())
            if not isinstance(forbidden, list) or any(not isinstance(item, str) for item in forbidden):
                raise ValueError('string list required')
        result = audit(root, forbidden)
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError):
        print(json.dumps({'ok': False, 'findings': [{'scope': 'audit', 'category': 'audit_unavailable'}]}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
