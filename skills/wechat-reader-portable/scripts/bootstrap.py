#!/usr/bin/env python3
"""Inspect explicit runtime metadata without executing tools or reading secrets."""
import argparse
import json
import os
from pathlib import Path
import platform
import sys

from common import Failure, external_path, open_directory, open_private_file
from reader import load_profile


SCHEMA = 'wechat.reader-bootstrap.v1'
ROUTE = 'local_database_memory_helper'
PROFILE_FAILURES = frozenset({
    'path_invalid', 'runtime_inside_package', 'private_parent_invalid',
    'private_file_invalid', 'private_file_too_large', 'profile_invalid',
    'source_owner_invalid', 'tool_metadata_invalid', 'tool_fingerprint_invalid',
    'tool_fingerprint_mismatch',
})


def host_metadata():
    """Return coarse hints, never a hostname, full build, device model or paths."""
    try:
        system, machine = platform.system(), platform.machine()
        return {'os': 'macos' if system == 'Darwin' else 'other',
                'cpu': 'apple_silicon' if system == 'Darwin' and machine in ('arm64', 'aarch64') else 'other'}
    except Exception:
        return {'os': 'unknown', 'cpu': 'unknown'}


def report(status, stage, reason, next_step, *, profile_valid=False, credential='not_checked'):
    return {'schema': SCHEMA, 'route': ROUTE, 'status': status, 'stage': stage,
            'reason': reason, 'nextStep': next_step, 'host': host_metadata(),
            'checks': {'profileAndTools': 'valid' if profile_valid else 'not_verified',
                       'credentialMetadata': credential},
            'capturePerformed': False, 'loginPerformed': False,
            'appModified': False, 'permissionRequested': False}


def unavailable(stage, reason, next_step='repair_external_runtime', *, profile_valid=False,
                credential='not_checked'):
    return report('check_unavailable', stage, reason, next_step,
                  profile_valid=profile_valid, credential=credential)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        del message
        print(json.dumps(unavailable('profile_validation', 'argument_invalid'), sort_keys=True))
        raise SystemExit(2)


def inspect_profile(profile):
    """Reuse the reader's safe profile/tool checks; inspect no credential bytes."""
    try:
        profile = external_path(str(profile))
    except Failure as error:
        reason = str(error) if str(error) in PROFILE_FAILURES else 'profile_or_runtime_invalid'
        return unavailable('profile_validation', reason)
    try:
        profile.lstat()
    except FileNotFoundError:
        return report('preparation_required', 'profile_required', 'profile_missing',
                      'prepare_external_profile')
    except (OSError, ValueError):
        return unavailable('profile_validation', 'runtime_input_unavailable')
    except Exception:
        return unavailable('profile_validation', 'profile_or_runtime_invalid')
    try:
        config = load_profile(profile)
    except Failure as error:
        reason = str(error) if str(error) in PROFILE_FAILURES else 'profile_or_runtime_invalid'
        return unavailable('profile_validation', reason)
    except FileNotFoundError:
        return unavailable('profile_validation', 'runtime_input_missing')
    except OSError:
        return unavailable('profile_validation', 'runtime_input_unavailable')
    except Exception:
        return unavailable('profile_validation', 'profile_or_runtime_invalid')
    try:
        descriptor = open_private_file(config['credential_file'], maximum=67)
        try:
            if os.fstat(descriptor).st_size == 0:
                raise Failure('private_file_invalid')
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        # Missing parent directories are a runtime preparation problem, not
        # proof that a checked credential destination merely lacks its file.
        try:
            parent = open_directory(Path(config['credential_file']).parent)
            os.close(parent)
        except Exception:
            return unavailable('credential_metadata', 'credential_parent_unavailable',
                               'repair_credential_metadata', profile_valid=True,
                               credential='unavailable')
        return report('preparation_required', 'credential_acquisition_required',
                      'credential_missing', 'review_private_copy_preparation',
                      profile_valid=True, credential='missing')
    except PermissionError:
        return unavailable('credential_metadata', 'credential_unavailable',
                           'repair_credential_metadata', profile_valid=True, credential='unavailable')
    except Exception:
        return unavailable('credential_metadata', 'credential_metadata_invalid',
                           'repair_credential_metadata', profile_valid=True, credential='invalid')
    return report('verification_required', 'database_verification_required',
                  'credential_metadata_valid', 'run_doctor',
                  profile_valid=True, credential='valid')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('--profile', type=Path)
    args = parser.parse_args(argv)
    if sys.version_info[:2] < (3, 10):
        result = unavailable('environment', 'python_version_unsupported', 'use_supported_python')
    elif args.profile is None:
        result = report('preparation_required', 'profile_required', 'profile_not_configured',
                        'prepare_external_profile')
    else:
        result = inspect_profile(args.profile)
    print(json.dumps(result, sort_keys=True))
    # Metadata inspection cannot certify database access, even on a complete profile.
    return 2 if result['status'] == 'check_unavailable' else 3


if __name__ == '__main__':
    sys.exit(main())
