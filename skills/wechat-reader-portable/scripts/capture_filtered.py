#!/usr/bin/env python3
"""Explicit, externally fingerprinted private-copy PBKDF capture.

No application mutation, launch, login, or account discovery is performed.
The verifier is separately installed: https://github.com/bojieli/greenbubbles.
--self-test uses synthetic data only and neither loads LLDB nor reads WeChat.
"""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import pwd
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import plistlib
import re
import secrets

from common import Failure, external_path, open_directory, verify_executable
import time

PBKDF_PARAMETERS = {'x0': 2, 'x2': 32, 'x4': 16, 'x5': 5, 'x6': 256000}
SAFE_FAILURE_REASONS = frozenset({
    'capture_failure', 'process_image_unavailable', 'process_image_truncated',
    'process_owner_unavailable', 'target_owner_mismatch', 'target_image_mismatch',
    'process_inventory_unavailable', 'multiple_wechat_instances',
    'attached_pid_mismatch', 'attach_failed', 'continue_failed', 'detach_failed',
    'callback_failed', 'credential_write_failed', 'driver_failed',
})
_session = None  # Set only inside LLDB's separate process.
_libproc = None  # Loaded only for explicit process identity checks.


class CaptureFailure(Exception):
    """Messages are deliberately bounded and contain no private values."""

    def __init__(self, message, reason='capture_failure'):
        super().__init__(message)
        self.reason = reason if reason in SAFE_FAILURE_REASONS else 'capture_failure'


def parameter_match(values):
    return all(values.get(name) == expected for name, expected in PBKDF_PARAMETERS.items())


def selected_image_path(app_path):
    """Require an explicitly selected real bundle and its real main executable."""
    application = external_path(app_path)
    fd = open_directory(application)
    os.close(fd)
    image = application / 'Contents/MacOS/WeChat'
    if not application.is_dir() or image.is_symlink() or not image.is_file() or not os.access(image, os.X_OK):
        raise CaptureFailure('Selected application has no regular executable WeChat main image')
    return str(image)


def signature_command(arguments):
    """Metadata stays in-process; even trust-store failures release no paths."""
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        raise CaptureFailure('Signature metadata check unavailable') from None
    if result.returncode or len(result.stdout) + len(result.stderr) > 1024 * 1024:
        raise CaptureFailure('Signature metadata check unavailable')
    return result


def signature_profile(path, expected_cdhash, *, require_entitlements=True):
    if (not isinstance(expected_cdhash, str) or len(expected_cdhash) not in (40, 64)
            or not re.fullmatch(r'[0-9a-fA-F]+', expected_cdhash)):
        raise CaptureFailure('Explicit application fingerprint required')
    signature_command(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(path)])
    result = signature_command(['/usr/bin/codesign', '-d', '-vvv', str(path)])
    details = result.stderr.decode('utf-8', errors='strict')
    match = re.search(r'^CDHash=([0-9a-fA-F]+)$', details, re.M)
    if match is None or match.group(1).lower() != expected_cdhash.lower():
        raise CaptureFailure('Signature differs from externally reviewed fingerprint')
    if not require_entitlements:
        return details, None
    result = signature_command(['/usr/bin/codesign', '-d', '--entitlements', '-', '--xml', str(path)])
    try:
        entitlements = plistlib.loads(result.stdout)
    except (ValueError, plistlib.InvalidFileException):
        raise CaptureFailure('Entitlement metadata check unavailable') from None
    if not isinstance(entitlements, dict):
        raise CaptureFailure('Entitlement metadata check unavailable')
    return details, entitlements


def preflight(args):
    """Bind explicit fingerprints, system protection and exact owner/source."""
    if platform.system() != 'Darwin' or platform.machine() not in ('arm64', 'aarch64'):
        raise CaptureFailure('Live capture requires macOS Apple silicon')
    if not Path('/usr/bin/lldb').is_file():
        raise CaptureFailure('Apple LLDB is unavailable')
    owner = invoking_owner()
    image = selected_image_path(args.app_path)
    original_image = selected_image_path(args.original_app_path)
    if image == original_image or os.path.samefile(image, original_image):
        raise CaptureFailure('Official application cannot be the capture target', 'target_image_mismatch')
    app = Path(args.app_path)
    original = Path(args.original_app_path)
    verifier = external_path(args.verify_bin)
    verify_executable(verifier, args.verifier_sha256, owner_uid=owner[0])
    original_info, original_rights = signature_profile(original, args.original_cdhash)
    private_info, private_rights = signature_profile(app, args.app_cdhash)
    signature_profile(verifier, args.verify_cdhash, require_entitlements=False)
    if 'Signature=adhoc' in original_info or 'Authority=' not in original_info:
        raise CaptureFailure('Original application must retain a trusted original signature')
    expected_rights = {key: value for key, value in original_rights.items() if key not in (
        'com.apple.application-identifier', 'com.apple.developer.team-identifier')}
    expected_rights['com.apple.security.get-task-allow'] = True
    identifier = 'Identifier=com.tencent.xinWeChat\n'
    if (identifier not in original_info or identifier not in private_info
            or 'Signature=adhoc' not in private_info or 'runtime)' in private_info
            or private_rights != expected_rights):
        raise CaptureFailure('Private application differs from the reviewed debug profile')
    sip = signature_command(['/usr/bin/csrutil', 'status']).stdout.decode('utf-8', errors='strict')
    if not re.search(r'System Integrity Protection status:\s*enabled\.', sip):
        raise CaptureFailure('SIP must be enabled for this capture workflow')
    root = external_path(args.db_root)
    fd = open_directory(root)
    try:
        if os.fstat(fd).st_uid != owner[0]:
            raise CaptureFailure('Selected database root belongs to a different owner')
    finally:
        os.close(fd)
    # Require a ready, private external destination BEFORE a debugger exists.
    output = validate_destination(external_path(args.output), owner)
    if not output.parent.is_dir():
        raise CaptureFailure('Create the external private output directory first')
    return verifier, image, original_image, owner


def process_image_path(pid):
    """Return the full kernel main image path, or None for an exited process."""
    global _libproc
    if _libproc is None:
        _libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        _libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        _libproc.proc_pidpath.restype = ctypes.c_int
    # Apple SDK's PROC_PIDPATHINFO_MAXSIZE is 4*MAXPATHLEN, or 4096.
    buffer = ctypes.create_string_buffer(4096)
    ctypes.set_errno(0)
    length = _libproc.proc_pidpath(pid, buffer, len(buffer))
    if length <= 0:
        if ctypes.get_errno() in (errno.ESRCH, errno.ENOENT):
            return None  # Normal process-exit/restart race.
        raise CaptureFailure('Could not verify the selected process main image', 'process_image_unavailable')
    if b'\x00' not in buffer.raw or not buffer.value.startswith(b'/'):
        raise CaptureFailure('Process main image path is unavailable or truncated', 'process_image_truncated')
    return os.fsdecode(buffer.value)


def process_identity(pid, timeout=3):
    """Read complete kernel image path with libproc; ps supplies only numeric UID."""
    image = process_image_path(pid)
    if image is None:
        return None
    result = subprocess.run(['/bin/ps', '-o', 'uid=', '-p', str(pid)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=timeout)
    owner = result.stdout.strip()
    if result.returncode == 1 and not owner:
        return None
    if result.returncode != 0 or not owner.isdigit():
        raise CaptureFailure('Could not verify the selected process owner', 'process_owner_unavailable')
    return int(owner), image


def selected_process_matches(pid, owner_uid, expected_image, timeout=3):
    identity = process_identity(pid, timeout)
    if identity is None:
        return False
    if identity[0] != owner_uid:
        raise CaptureFailure('A different WeChat owner was detected; refusing capture', 'target_owner_mismatch')
    if identity[1] != expected_image:
        raise CaptureFailure('A different WeChat image was detected; refusing capture', 'target_image_mismatch')
    return True


def read_salt_inventory(root, deadline=None):
    """Read only 16-byte headers below the explicitly supplied database root."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise CaptureFailure('Database root must be a real directory')
    salts = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        if deadline is not None and time.monotonic() >= deadline:
            raise CaptureFailure('Database inventory exceeded the capture window')
        directories[:] = [name for name in directories if not (Path(directory) / name).is_symlink()]
        for name in files:
            if deadline is not None and time.monotonic() >= deadline:
                raise CaptureFailure('Database inventory exceeded the capture window')
            if not name.endswith('.db'):
                continue
            path = Path(directory) / name
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        continue
                    header = os.read(fd, 16)
                finally:
                    os.close(fd)
            except OSError:
                continue
            if len(header) == 16 and header != b'SQLite format 3\x00':
                salts.add(header.hex())
    if not salts:
        raise CaptureFailure('No encrypted database salts were found in the selected root')
    return salts


def invoking_owner():
    if os.geteuid() == 0 and os.environ.get('SUDO_USER'):
        user = pwd.getpwnam(os.environ['SUDO_USER'])
        return user.pw_uid, user.pw_gid
    return os.getuid(), os.getgid()


def validate_destination(output, owner=None):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise CaptureFailure('Credential destination already exists; refusing overwrite')
    # Do not follow user-provided symlinks, and do not chmod arbitrary directories.
    for parent in output.parents:
        if parent.is_symlink():
            raise CaptureFailure('Credential destination has a symlink ancestor')
    parent = output.parent
    if parent.exists():
        if not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) != 0o700:
            raise CaptureFailure('Existing credential directory must have mode 0700')
        if owner is not None and parent.stat().st_uid != owner[0]:
            raise CaptureFailure('Existing credential directory belongs to another user')
    elif not parent.parent.is_dir():
        raise CaptureFailure('Create the private credential directory parent first')
    return output


def write_secret(output, password, owner):
    """Exclusive output; no secret is sent to a terminal, log, or argv."""
    output = validate_destination(external_path(str(output)), owner)
    uid, gid = owner
    # Traverse through open directory descriptors so renamed ancestors cannot
    # redirect a privileged write or its failure cleanup.
    directory_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    parts = output.parent.parts[1:]
    created_parent = False
    try:
        for index, part in enumerate(parts):
            if part in ('.', '..'):
                raise CaptureFailure('Credential destination must not contain traversal components')
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                child_fd = os.open(part, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                if index != len(parts) - 1:
                    raise CaptureFailure('Credential destination ancestor is unavailable')
                os.mkdir(part, mode=0o700, dir_fd=directory_fd)
                child_fd = os.open(part, flags, dir_fd=directory_fd)
                created_parent = True
            os.close(directory_fd)
            directory_fd = child_fd
        if created_parent and os.geteuid() == 0:
            os.fchown(directory_fd, uid, gid)
        directory_info = os.fstat(directory_fd)
        if stat.S_IMODE(directory_info.st_mode) != 0o700 or directory_info.st_uid != uid:
            raise CaptureFailure('Credential directory ownership or mode changed')
        temporary_name = '.capture-pending-' + secrets.token_hex(16)
        fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
    except Exception:
        os.close(directory_fd)
        raise
    payload = bytearray(password.hex().encode('ascii') + b'\n')
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, uid, gid)
        elif uid != os.geteuid():
            raise CaptureFailure('Credential owner differs from the running user')
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise CaptureFailure('Credential write failed')
            view = view[written:]
        os.fsync(fd)
        # Only a fully written, fsynced file reaches the canonical name. link()
        # publishes atomically and refuses an existing destination; rename()
        # would overwrite it. A killed process can leave only a private pending
        # file or a complete canonical credential, never a truncated final file.
        os.link(temporary_name, output.name, src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
    finally:
        payload[:] = b'\x00' * len(payload)
        try:
            os.close(fd)
        finally:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)


def verify_candidate(verifier, root, password, timeout):
    """Official verifier performs HMAC validation; stdout/stderr stay private."""
    if timeout <= 0:
        return None
    secret_input = bytearray(password.hex().encode('ascii') + b'\n')
    try:
        result = subprocess.run(
            [str(verifier), 'verify', '--passphrase-stdin', '--db-root', str(root), '--json'],
            input=secret_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=min(30, timeout), check=False,
        )
        # Exit 1 can mean partial coverage: a positively verified salt is proof
        # of a valid candidate. Report partial coverage, never call it complete.
        if result.returncode not in (0, 1):
            return None
        report = json.loads(result.stdout)
        count = report.get('verifiedSaltCount')
        total = report.get('distinctSaltCount')
        if type(count) is not int or type(total) is not int or not 0 < count <= total:
            return None
        return {'verifiedSaltCount': count, 'distinctSaltCount': total,
                'allVerified': result.returncode == 0 and report.get('allVerified') is True and count == total}
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, AttributeError):
        return None
    finally:
        secret_input[:] = b'\x00' * len(secret_input)


def write_report(path, data):
    temporary = Path(str(path) + '.next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(data, out)
    os.replace(temporary, path)


class CandidateSession:
    def __init__(self, config, verifier_function=verify_candidate, clock=time.monotonic):
        self.config = config
        self.verifier_function = verifier_function
        self.clock = clock
        self.seen = 0
        self.rejected = 0
        self.saved = False
        self.fatal = None
        self.failure_reason = None
        self.failure_stage = None
        self.report = None

    def consider(self, values, password, salt):
        if self.saved or self.clock() >= self.config['deadline']:
            return False
        if not parameter_match(values) or len(password) != 32 or len(salt) != 16:
            return False
        if salt.hex() not in self.config['salts']:
            return False
        self.seen += 1
        remaining = self.config['deadline'] - self.clock()
        report = self.verifier_function(self.config['verifier'], self.config['root'], password, remaining)
        if not report or self.clock() >= self.config['deadline']:
            self.rejected += 1
            return False
        try:
            write_secret(self.config['output'], password, self.config['owner'])
        except Exception:
            self.fatal = 'credential_write_failed'
            self.failure_reason = 'credential_write_failed'
            self.failure_stage = 'credential_output'
            return True  # Stop so the driver can detach in its finally block.
        self.saved = True
        self.report = report
        return True


def on_pbkdf(frame, breakpoint_location, internal_dict):
    """LLDB callback: reads no candidate unless its parameters and salt match."""
    del breakpoint_location, internal_dict
    session = _session
    if session is None or time.monotonic() >= session.config['deadline']:
        return False
    import lldb
    try:
        values = {name: frame.FindRegister(name).GetValueAsUnsigned() for name in PBKDF_PARAMETERS}
        if not parameter_match(values):
            return False
        process = frame.GetThread().GetProcess()
        remaining = session.config['deadline'] - time.monotonic()
        if remaining <= 0 or not selected_process_matches(process.GetProcessID(),
                session.config['owner'][0], session.config['image'], min(3, remaining)):
            return False
        error = lldb.SBError()
        salt = process.ReadMemory(frame.FindRegister('x3').GetValueAsUnsigned(), 16, error)
        if not error.Success() or len(salt) != 16 or salt.hex() not in session.config['salts']:
            return False
        password = bytearray(process.ReadMemory(frame.FindRegister('x1').GetValueAsUnsigned(), 32, error))
        try:
            if not error.Success() or len(password) != 32:
                return False
            return session.consider(values, password, salt)
        finally:
            password[:] = b'\x00' * len(password)
    except CaptureFailure as error:
        session.fatal = 'target_rejected'
        session.failure_reason = error.reason
        session.failure_stage = 'callback_identity'
        return True
    except Exception:
        session.fatal = 'callback_failed'
        session.failure_reason = 'callback_failed'
        session.failure_stage = 'callback'
        return True


def find_wechat_pid(owner_uid, expected_image, original_image, timeout=3, on_wait=None):
    if expected_image == original_image:
        raise CaptureFailure("Official image cannot be a capture target", "target_image_mismatch")
    # Enumerate every exact-name match, including another user's/formal app,
    # so coexistence cannot silently switch the capture target.
    result = subprocess.run(['/usr/bin/pgrep', '-x', 'WeChat'], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=False, timeout=timeout)
    if result.returncode not in (0, 1):
        raise CaptureFailure('Could not inventory WeChat processes', 'process_inventory_unavailable')
    pids = [int(item) for item in result.stdout.split() if item.isdigit()]
    if len(pids) > 1:
        raise CaptureFailure('Multiple WeChat instances; refusing an ambiguous target', 'multiple_wechat_instances')
    identity = process_identity(pids[0], timeout) if pids else None
    if identity is None:
        if on_wait is not None:
            on_wait('selected_absent')
        return None
    if identity[0] != owner_uid:
        raise CaptureFailure('A different WeChat owner was detected; refusing capture', 'target_owner_mismatch')
    if identity[1] == expected_image:
        return pids[0]
    if identity[1] == original_image:
        if on_wait is not None:
            on_wait('original_sibling')
        return None  # Never attach the official sibling, including after logout.
    raise CaptureFailure('A different WeChat image was detected; refusing capture', 'target_image_mismatch')


def breakpoint_diagnostics(breakpoint):
    """Aggregate SB API metadata only; no addresses or symbol paths leave LLDB."""
    valid = bool(breakpoint.IsValid())
    return {'breakpointValid': valid,
            'breakpointLocationCount': int(breakpoint.GetNumLocations()) if valid else 0,
            'breakpointResolvedLocationCount': int(breakpoint.GetNumResolvedLocations()) if valid else 0}


def run_lldb(debugger, config_path):
    """Runs inside a separate LLDB process; always attempts a resuming detach."""
    global _session
    import lldb
    config = json.loads(Path(config_path).read_text())
    _session = CandidateSession(config)
    session = _session
    debugger.SetAsync(True)
    process = None
    target = None
    status = 'timed_out'
    reason = 'capture_window_expired'
    capture_stage = 'initializing'
    arm_generation = 0
    last_progress = None
    detach_failed = False
    breakpoint_report = {'breakpointValid': None, 'breakpointLocationCount': 0,
                         'breakpointResolvedLocationCount': 0}

    def progress(status_value, reason_value):
        nonlocal last_progress
        data = {'status': status_value, 'reason': reason_value,
                'captureStage': capture_stage, 'armGeneration': arm_generation,
                'candidateCount': session.seen}
        data.update(breakpoint_report)
        if data != last_progress:
            write_report(config['report'], data)
            last_progress = data

    def waiting(reason_value):
        progress('waiting_for_selected', reason_value)

    def cancelled(signum, frame):
        del signum, frame
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    try:
        while time.monotonic() < config['deadline'] and not session.saved and not session.fatal:
            remaining = config['deadline'] - time.monotonic()
            if remaining <= 0:
                break
            capture_stage = 'discovery'
            pid = find_wechat_pid(config['owner'][0], config['image'], config['original_image'], min(3, remaining), waiting)
            if pid is None:
                remaining = config['deadline'] - time.monotonic()
                if remaining > 0:
                    time.sleep(min(0.2, remaining))
                continue
            remaining = config['deadline'] - time.monotonic()
            capture_stage = 'pre_attach_validation'
            if remaining <= 0 or not selected_process_matches(pid, config['owner'][0],
                    config['image'], min(3, remaining)):
                continue
            listener = lldb.SBListener('filtered-capture')
            target = debugger.CreateTarget('')
            error = lldb.SBError()
            capture_stage = 'attaching'
            process = target.AttachToProcessWithID(listener, pid, error)
            if not error.Success() or not process.IsValid():
                remaining = config['deadline'] - time.monotonic()
                if remaining <= 0 or find_wechat_pid(config['owner'][0], config['image'], config['original_image'],
                        min(3, remaining), waiting) != pid:
                    debugger.DeleteTarget(target)
                    target = None
                    process = None
                    continue
                status = 'attach_failed'
                reason = 'attach_failed'
                break
            capture_stage = 'post_attach_validation'
            if process.GetProcessID() != pid:
                status = 'target_rejected'
                reason = 'attached_pid_mismatch'
                break
            # Close the discovery/attach race before setting a secret-reading
            # callback. A mismatch is detached by the driver's finally block.
            remaining = config['deadline'] - time.monotonic()
            if remaining <= 0:
                break
            if not selected_process_matches(process.GetProcessID(),
                    config['owner'][0], config['image'], min(3, remaining)):
                capture_stage = 'restart_cleanup'
                error = process.Detach(False)
                if not error.Success() and process.GetState() not in (lldb.eStateExited, lldb.eStateDetached):
                    detach_failed = True
                    status = 'detach_failed'
                    reason = 'detach_failed'
                    break
                process = None
                debugger.DeleteTarget(target)
                target = None
                continue  # The authorized clone may be restarting at login.
            capture_stage = 'breakpoint_setup'
            breakpoint = target.BreakpointCreateByName('CCKeyDerivationPBKDF')
            breakpoint_report = breakpoint_diagnostics(breakpoint)
            if not breakpoint_report['breakpointValid']:
                status = 'breakpoint_failed'
                reason = 'breakpoint_invalid'
                break  # finally detaches; no callback or Continue was installed.
            # Zero locations is a valid pending logical breakpoint: LLDB can
            # resolve it as a library loads. Record it without blocking login.
            breakpoint.SetCondition('$x0 == 2 && $x2 == 32 && $x4 == 16 && $x5 == 5 && $x6 == 256000')
            breakpoint.SetScriptCallbackFunction(__name__ + '.on_pbkdf')
            capture_stage = 'arming'
            error = process.Continue()
            if not error.Success():
                status = 'continue_failed'
                reason = 'continue_failed'
                break
            breakpoint_report = breakpoint_diagnostics(breakpoint)
            if not breakpoint_report['breakpointValid']:
                status = 'breakpoint_failed'
                reason = 'breakpoint_invalid'
                break
            arm_generation += 1
            capture_stage = 'monitoring'
            progress('armed', 'selected_attached')
            while time.monotonic() < config['deadline'] and not session.saved and not session.fatal:
                event = lldb.SBEvent()
                listener.WaitForEvent(1, event)
                state = process.GetState()
                if state in (lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid):
                    break
                breakpoint_report = breakpoint_diagnostics(breakpoint)
                if not breakpoint_report['breakpointValid']:
                    status = 'breakpoint_failed'
                    reason = 'breakpoint_invalid'
                    break
                progress('armed', 'selected_attached')
                # A rejected callback returns False and LLDB resumes itself.
                if state == lldb.eStateStopped and not session.saved and not session.fatal:
                    process.Continue()
            if session.saved or session.fatal or status == 'breakpoint_failed':
                break
            capture_stage = 'restart_cleanup'
            error = process.Detach(False)
            if not error.Success() and process.GetState() not in (lldb.eStateExited, lldb.eStateDetached):
                detach_failed = True
                status = 'detach_failed'
                reason = 'detach_failed'
                break
            process = None
            debugger.DeleteTarget(target)
            target = None
        if session.saved:
            complete = session.report and session.report.get('allVerified') is True
            status = 'captured' if complete else 'partial_candidate_saved'
            reason = 'verified_candidate' if complete else 'verified_partial_candidate'
            capture_stage = 'candidate_verified'
        elif session.fatal:
            status = session.fatal
            reason = session.failure_reason or 'callback_failed'
            capture_stage = session.failure_stage or 'callback'
    except KeyboardInterrupt:
        status = 'cancelled'
        reason = 'cancelled'
    except CaptureFailure as error:
        status = 'target_rejected'
        reason = error.reason
    except Exception:
        status = 'driver_failed'
        reason = 'driver_failed'
    finally:
        if process is not None and process.IsValid():
            state = process.GetState()
            if state not in (lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid):
                error = process.Detach(False)  # False means do not leave WeChat stopped.
                if not error.Success():
                    detach_failed = True
                    reason = 'detach_failed'
                    capture_stage = 'cleanup'
                    if process.GetState() == lldb.eStateStopped:
                        process.Continue()
        if target is not None:
            debugger.DeleteTarget(target)
        data = {'status': status, 'outputWritten': session.saved,
                'candidateCount': session.seen, 'rejectedCandidateCount': session.rejected,
                'detachConfirmed': not detach_failed, 'reason': reason,
                'captureStage': capture_stage, 'armGeneration': arm_generation}
        data.update(breakpoint_report)
        if session.report:
            data.update(session.report)
        write_report(config['report'], data)
        _session = None


def progress_notice(report, previous):
    """Only fixed console strings leave the private worker report."""
    if not isinstance(report, dict):
        return previous, None
    status = report.get('status')
    generation = report.get('armGeneration', 0)
    if type(generation) is not int or generation < 0:
        generation = 0
    if status == 'armed':
        current = (status, generation)
        message = 'Armed，监听已就绪；请在指定私有副本的登录窗口继续登录。'
    elif status == 'waiting_for_selected':
        reason = 'original_sibling' if report.get('reason') == 'original_sibling' else 'selected_absent'
        current = (status, generation, reason)
        if reason == 'original_sibling':
            message = 'WaitingForSelected: 正式微信已启动；请退出正式微信，再打开指定私有副本。监听仅等待该副本。'
        else:
            message = 'WaitingForSelected: 指定私有副本暂未运行，正在等待它重新启动。'
    else:
        return previous, None
    return current, message if current != previous else None


def final_report(report, interrupted, output_written):
    """Intermediate progress cannot certify that the debugger detached."""
    if isinstance(report, dict) and report.get('status') not in ('armed', 'waiting_for_selected'):
        return report
    intermediate = isinstance(report, dict) and report.get('status') in ('armed', 'waiting_for_selected')
    return {'status': 'cleanup_unconfirmed' if intermediate else ('cancelled' if interrupted else 'driver_failed'),
            'reason': 'intermediate_report' if intermediate else 'worker_report_unavailable',
            'captureStage': 'cleanup', 'outputWritten': output_written,
            'detachConfirmed': False}


def capture(args):
    verifier, image, original_image, owner = preflight(args)
    output = validate_destination(external_path(args.output), owner)
    if not output.parent.is_dir():
        raise CaptureFailure('Create the external private output directory first')
    root = external_path(args.db_root)
    deadline = time.monotonic() + args.timeout_seconds
    salts = read_salt_inventory(root, deadline)
    with tempfile.TemporaryDirectory(prefix='reader-filtered-', dir=output.parent) as directory:
        directory = Path(directory).resolve()
        os.chmod(directory, 0o700)
        report_path = directory / 'result.json'
        config_path = directory / 'config.json'
        config = {'root': str(root), 'output': str(output), 'verifier': str(verifier),
                  'salts': sorted(salts), 'owner': owner, 'deadline': deadline,
                  'report': str(report_path), 'image': image, 'original_image': original_image}
        write_report(config_path, config)
        module = Path(__file__).resolve()
        command = ['/usr/bin/lldb', '--no-lldbinit', '-b',
                   '-o', 'command script import ' + shlex.quote(str(module)),
                   '-o', 'script capture_filtered.run_lldb(lldb.debugger, ' + repr(str(config_path)) + ')',
                   '-o', 'quit']
        # LLDB output is discarded entirely; only our bounded status JSON exits.
        worker = None
        interrupted = False
        controller_failed = False
        announced_progress = None
        watchdog_deadline = deadline + 5
        cancellation_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        previous_handlers = {signum: signal.getsignal(signum) for signum in cancellation_signals}
        spawning = True
        cancellation_requested = False

        def cancel_controller(signum, frame):
            del signum, frame
            nonlocal cancellation_requested
            cancellation_requested = True
            # Register the worker before cancellation can interrupt Popen and
            # otherwise leave a newly spawned, separate-session LLDB orphaned.
            if not spawning:
                raise KeyboardInterrupt

        try:
            for signum in cancellation_signals:
                signal.signal(signum, cancel_controller)
            worker = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, start_new_session=True)
            spawning = False
            if cancellation_requested:
                raise KeyboardInterrupt
            print('正在准备监听；捕获窗口：%s 秒。请等待 Armed 提示。' % args.timeout_seconds, flush=True)
            while worker.poll() is None:
                try:
                    progress = json.loads(report_path.read_text())
                except (OSError, ValueError):
                    progress = {}
                announced_progress, message = progress_notice(progress, announced_progress)
                if message:
                    print(message, flush=True)
                remaining = watchdog_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, args.timeout_seconds + 5)
                time.sleep(min(0.2, remaining))
        except (KeyboardInterrupt, subprocess.TimeoutExpired):
            interrupted = True
        except Exception:
            controller_failed = True
        finally:
            # Repeated cancellation must not interrupt the bounded detach wait.
            if worker is not None and (interrupted or controller_failed or worker.poll() is None):
                for signum in cancellation_signals:
                    signal.signal(signum, signal.SIG_IGN)
                try:
                    worker.terminate()  # Signal only child LLDB, never the WeChat PID.
                    try:
                        worker.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        worker.kill()
                        worker.wait(timeout=3)
                finally:
                    for signum, handler in previous_handlers.items():
                        signal.signal(signum, handler)
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        try:
            report = json.loads(report_path.read_text())
        except (OSError, ValueError):
            report = None
        report = final_report(report, interrupted, output.exists())
        if controller_failed:
            report = {'status': 'cleanup_unconfirmed', 'reason': 'controller_failed',
                      'detachConfirmed': False, 'outputWritten': output.exists(), 'captureStage': 'cleanup'}
        print(json.dumps(report, sort_keys=True))
        return 0 if report.get('status') == 'captured' and report.get('detachConfirmed') is True else 1


def self_test():
    """Synthetic values only; do not invoke LLDB or the installed verifier."""
    import unittest
    import contextlib
    import io
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    SYNTHETIC_UID, SYNTHETIC_GID = os.getuid(), os.getgid()
    FOREIGN_UID = SYNTHETIC_UID + 1
    ORIGINAL_SIBLING_IMAGE = "/synthetic/original/WeChat.app/Contents/MacOS/WeChat"

    class SyntheticTests(unittest.TestCase):
        def config(self, directory, deadline=10):
            return {'salts': [(b's' * 16).hex()], 'deadline': deadline,
                    'output': str(Path(directory) / 'private' / 'synthetic-credential'),
                    'root': '/synthetic/database/root', 'verifier': '/synthetic/verifier',
                    'owner': (os.getuid(), os.getgid()),
                    'image': '/synthetic/selected/WeChat.app/Contents/MacOS/WeChat', 'original_image': ORIGINAL_SIBLING_IMAGE}

        def test_parameter_parser_rejects_unrelated_first_call(self):
            self.assertTrue(parameter_match(PBKDF_PARAMETERS))
            self.assertFalse(parameter_match(dict(PBKDF_PARAMETERS, x5=3, x6=1000)))
            self.assertFalse(parameter_match({'x2': 32}))

        def test_app_path_is_mandatory_without_capture(self):
            with patch.object(sys, 'argv', ['capture_filtered.py', '--db-root', '/synthetic/db',
                    '--output', '/synthetic/private/credential']), \
                 patch(__name__ + '.capture') as capture_mock, \
                 contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main()
                self.assertEqual(raised.exception.code, 2)
                capture_mock.assert_not_called()

        def test_full_kernel_image_path_preserves_long_unicode_path(self):
            image = '/synthetic/' + ('long directory ' * 30) + '/微信.app/Contents/MacOS/WeChat'
            encoded = os.fsencode(image) + b'\x00'
            def fake_pidpath(pid, buffer, size):
                self.assertEqual(pid, 17)
                self.assertGreater(size, len(encoded))
                ctypes.memmove(buffer, encoded, len(encoded))
                return len(encoded) - 1
            with patch(__name__ + '._libproc', SimpleNamespace(proc_pidpath=fake_pidpath)):
                self.assertEqual(process_image_path(17), image)

        def test_selection_rejects_other_image_and_other_uid(self):
            expected = '/synthetic/selected/WeChat.app/Contents/MacOS/WeChat'
            for identity, reason in [((SYNTHETIC_UID, ORIGINAL_SIBLING_IMAGE), 'target_image_mismatch'),
                    ((FOREIGN_UID, expected), 'target_owner_mismatch')]:
                with self.subTest(identity=identity), \
                     patch(__name__ + '.process_identity', return_value=identity):
                    with self.assertRaises(CaptureFailure) as raised:
                        selected_process_matches(17, SYNTHETIC_UID, expected)
                    self.assertEqual(raised.exception.reason, reason)

        def test_discovery_requires_single_exact_owner_image(self):
            expected = '/synthetic/selected/WeChat.app/Contents/MacOS/WeChat'
            with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'17\n', b'')), \
                 patch(__name__ + '.process_identity', return_value=(SYNTHETIC_UID, expected)):
                self.assertEqual(find_wechat_pid(SYNTHETIC_UID, expected, ORIGINAL_SIBLING_IMAGE), 17)
            with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'17\n18\n', b'')), \
                 patch(__name__ + '.process_identity') as inspect:
                self.assertRaises(CaptureFailure, find_wechat_pid, SYNTHETIC_UID, expected, ORIGINAL_SIBLING_IMAGE)
                inspect.assert_not_called()
            with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'17\n', b'')), \
                 patch(__name__ + '.process_identity', return_value=None):
                self.assertIsNone(find_wechat_pid(SYNTHETIC_UID, expected, ORIGINAL_SIBLING_IMAGE))

        def test_discovery_waits_only_for_exact_owned_original_sibling(self):
            expected = '/synthetic/selected/WeChat.app/Contents/MacOS/WeChat'
            for identity, wanted, reason in [((SYNTHETIC_UID, ORIGINAL_SIBLING_IMAGE), None, 'original_sibling'),
                    (None, None, 'selected_absent'), ((SYNTHETIC_UID, expected), 17, None)]:
                waits = []
                with self.subTest(identity=identity), \
                     patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'17\n', b'')), \
                     patch(__name__ + '.process_identity', return_value=identity):
                    self.assertEqual(find_wechat_pid(SYNTHETIC_UID, expected, ORIGINAL_SIBLING_IMAGE, on_wait=waits.append), wanted)
                    self.assertEqual(waits, [reason] if reason else [])
            # An explicitly supplied original image remains forbidden.
            self.assertRaises(CaptureFailure, find_wechat_pid, SYNTHETIC_UID,
                              ORIGINAL_SIBLING_IMAGE, ORIGINAL_SIBLING_IMAGE)

        def test_discovery_refuses_foreign_unknown_and_ambiguous_targets(self):
            expected = '/synthetic/selected/WeChat.app/Contents/MacOS/WeChat'
            cases = [(b'17\n', (FOREIGN_UID, ORIGINAL_SIBLING_IMAGE), 'target_owner_mismatch'),
                     (b'17\n', (SYNTHETIC_UID, '/synthetic/unknown/WeChat'), 'target_image_mismatch'),
                     (b'17\n18\n', (SYNTHETIC_UID, expected), 'multiple_wechat_instances')]
            for pids, identity, reason in cases:
                waits = []
                with self.subTest(reason=reason), \
                     patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, pids, b'')), \
                     patch(__name__ + '.process_identity', return_value=identity):
                    with self.assertRaises(CaptureFailure) as raised:
                        find_wechat_pid(SYNTHETIC_UID, expected, ORIGINAL_SIBLING_IMAGE, on_wait=waits.append)
                    self.assertEqual(raised.exception.reason, reason)
                    self.assertEqual(waits, [])

        def test_progress_reannounces_rearms_and_never_prints_report_values(self):
            previous = None
            notices = []
            reports = [{'status': 'armed', 'armGeneration': 1},
                       {'status': 'armed', 'armGeneration': 1},
                       {'status': 'waiting_for_selected', 'reason': 'original_sibling', 'armGeneration': 1},
                       {'status': 'armed', 'armGeneration': 2},
                       {'status': 'armed', 'armGeneration': 3},
                       {'status': 'waiting_for_selected', 'reason': '/synthetic/private-value', 'armGeneration': 3}]
            for report in reports:
                previous, message = progress_notice(report, previous)
                if message:
                    notices.append(message)
            self.assertEqual(sum(value.startswith('Armed') for value in notices), 3)
            self.assertEqual(sum(value.startswith('WaitingForSelected:') for value in notices), 2)
            self.assertNotIn('/synthetic/private-value', ''.join(notices))
            for status in ('armed', 'waiting_for_selected'):
                report = final_report({'status': status, 'detachConfirmed': True}, False, False)
                self.assertEqual(report['status'], 'cleanup_unconfirmed')
                self.assertFalse(report['detachConfirmed'])
            self.assertEqual(CaptureFailure('synthetic', '/synthetic/private-value').reason, 'capture_failure')

        def test_sudo_owner_is_saved_as_invoking_user(self):
            with patch.object(os, 'geteuid', return_value=0), \
                 patch.dict(os.environ, {'SUDO_USER': 'synthetic-owner'}), \
                 patch.object(pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=SYNTHETIC_UID, pw_gid=SYNTHETIC_GID)):
                self.assertEqual(invoking_owner(), (SYNTHETIC_UID, SYNTHETIC_GID))

        def test_controller_term_and_hup_take_cleanup_path_and_restore_handlers(self):
            # Popen, signal handlers and all source operations are synthetic.
            for signum in (signal.SIGTERM, signal.SIGHUP):
                for phase in ('spawn', 'poll'):
                    with self.subTest(signum=signum, phase=phase), tempfile.TemporaryDirectory() as directory:
                        args = SimpleNamespace(verify_bin='/synthetic/verifier', app_path='/synthetic/app',
                            db_root='/synthetic/db', output=str(Path(directory) / 'credential'), timeout_seconds=1)
                        previous = {signal.SIGINT: signal.default_int_handler,
                                    signal.SIGTERM: signal.SIG_DFL, signal.SIGHUP: signal.SIG_DFL}
                        handlers = dict(previous)
                        def install(signal_number, handler):
                            old = handlers[signal_number]
                            handlers[signal_number] = handler
                            return old
                        worker = MagicMock()
                        def spawn(*args, **kwargs):
                            if phase == 'spawn':
                                handlers[signum](signum, None)
                            return worker
                        def poll():
                            handlers[signum](signum, None)
                            return None
                        worker.poll.side_effect = poll
                        def confirm_ignored(*args, **kwargs):
                            self.assertTrue(all(value == signal.SIG_IGN for value in handlers.values()))
                            # Another TERM/HUP/INT is ignored through cleanup.
                            self.assertFalse(any(callable(value) for value in handlers.values()))
                            return 0
                        worker.terminate.side_effect = confirm_ignored
                        worker.wait.side_effect = confirm_ignored
                        console = io.StringIO()
                        with patch.object(platform, 'system', return_value='Darwin'), \
                             patch.object(platform, 'machine', return_value='arm64'), \
                             patch.object(Path, 'is_file', return_value=True), \
                             patch.object(os, 'access', return_value=True), \
                             patch(__name__ + '.preflight', return_value=(Path('/synthetic/verifier'), '/synthetic/selected/WeChat', ORIGINAL_SIBLING_IMAGE, (os.getuid(), os.getgid()))), \
                             patch(__name__ + '.validate_destination', return_value=Path(args.output)), \
                             patch(__name__ + '.read_salt_inventory', return_value={'synthetic-header'}), \
                             patch.object(signal, 'getsignal', side_effect=lambda number: handlers[number]), \
                             patch.object(signal, 'signal', side_effect=install), \
                             patch.object(subprocess, 'Popen', side_effect=spawn), \
                             patch.object(time, 'monotonic', return_value=0), \
                             contextlib.redirect_stdout(console):
                            self.assertEqual(capture(args), 1)
                        worker.terminate.assert_called_once_with()
                        worker.wait.assert_called_once_with(timeout=5)
                        worker.kill.assert_not_called()
                        self.assertEqual(handlers, previous)
                        self.assertEqual(json.loads(console.getvalue().splitlines()[-1])['status'], 'cancelled')
                        self.assertFalse(Path(args.output).exists())

        def test_invalid_candidate_continues_without_output(self):
            with tempfile.TemporaryDirectory() as directory:
                config = self.config(str(Path(directory).resolve()))
                session = CandidateSession(config, lambda *args: None, clock=lambda: 0)
                self.assertFalse(session.consider(PBKDF_PARAMETERS, bytearray(b'p' * 32), b's' * 16))
                self.assertEqual(session.rejected, 1)
                self.assertFalse(Path(config['output']).exists())
                self.assertFalse(session.saved)

        def test_unmatched_salt_never_invokes_verifier(self):
            with tempfile.TemporaryDirectory() as directory:
                calls = []
                session = CandidateSession(self.config(directory), lambda *args: calls.append(args), clock=lambda: 0)
                self.assertFalse(session.consider(PBKDF_PARAMETERS, b'p' * 32, b'x' * 16))
                self.assertEqual(calls, [])

        def test_timeout_leaves_no_output(self):
            with tempfile.TemporaryDirectory() as directory:
                config = self.config(directory, deadline=1)
                calls = []
                session = CandidateSession(config, lambda *args: calls.append(args), clock=lambda: 1)
                self.assertFalse(session.consider(PBKDF_PARAMETERS, b'p' * 32, b's' * 16))
                self.assertFalse(Path(config['output']).exists())
                self.assertEqual(calls, [])

        def test_driver_timeout_detaches_without_output(self):
            # Entire LLDB surface is fake: no debugger or process is opened.
            with tempfile.TemporaryDirectory() as directory:
                directory = str(Path(directory).resolve())
                config = self.config(directory, deadline=1)
                config['report'] = str(Path(directory) / 'result.json')
                config_path = Path(directory) / 'config.json'
                config_path.write_text(json.dumps(config))
                clock = [0]
                error = SimpleNamespace(Success=lambda: True)
                process = MagicMock()
                process.IsValid.return_value = True
                process.GetProcessID.return_value = 17
                process.Continue.return_value = error
                process.Detach.return_value = error
                process.GetState.return_value = 2
                target = MagicMock()
                target.AttachToProcessWithID.return_value = process
                target.BreakpointCreateByName.return_value.IsValid.return_value = True
                target.BreakpointCreateByName.return_value.GetNumLocations.return_value = 1
                target.BreakpointCreateByName.return_value.GetNumResolvedLocations.return_value = 1
                debugger = MagicMock()
                debugger.CreateTarget.return_value = target
                listener = MagicMock()
                listener.WaitForEvent.side_effect = lambda *args: clock.__setitem__(0, 2)
                fake_lldb = SimpleNamespace(SBListener=lambda *args: listener,
                    SBError=lambda: error, SBEvent=object, eStateExited=4,
                    eStateDetached=5, eStateInvalid=0, eStateStopped=3)
                with patch.dict(sys.modules, {'lldb': fake_lldb}), \
                     patch.object(time, 'monotonic', side_effect=lambda: clock[0]), \
                     patch.object(signal, 'signal'), \
                     patch(__name__ + '.find_wechat_pid', return_value=17), \
                     patch(__name__ + '.selected_process_matches', return_value=True):
                    run_lldb(debugger, config_path)
                report = json.loads(Path(config['report']).read_text())
                self.assertEqual(report['status'], 'timed_out')
                self.assertTrue(report['detachConfirmed'])
                self.assertFalse(report['outputWritten'])
                process.Detach.assert_called_once_with(False)
                debugger.SetAsync.assert_called_once_with(True)
                self.assertFalse(Path(config['output']).exists())

        def test_driver_skips_original_then_rearms_only_selected_clone(self):
            config = self.config('/synthetic/restart', deadline=10)
            config.update(owner=(SYNTHETIC_UID, SYNTHETIC_GID), report='/synthetic/report')
            clock = [0]
            states = [2, 2]
            error = SimpleNamespace(Success=lambda: True)
            processes = [MagicMock(), MagicMock()]
            for index, process in enumerate(processes):
                process.IsValid.return_value = True
                process.GetProcessID.return_value = 17 if index == 0 else 19
                process.Continue.return_value = error
                process.Detach.return_value = error
                process.GetState.side_effect = lambda index=index: states[index]
            target = MagicMock()
            target.AttachToProcessWithID.side_effect = processes
            target.BreakpointCreateByName.return_value.IsValid.return_value = True
            target.BreakpointCreateByName.return_value.GetNumLocations.return_value = 1
            target.BreakpointCreateByName.return_value.GetNumResolvedLocations.return_value = 1
            debugger = MagicMock()
            debugger.CreateTarget.return_value = target
            listener = MagicMock()
            waits = [0]
            def event(*args):
                waits[0] += 1
                if waits[0] == 1:
                    states[0], clock[0] = 4, 1
                else:
                    clock[0] = 11
            listener.WaitForEvent.side_effect = event
            fake_lldb = SimpleNamespace(SBListener=lambda *args: listener,
                SBError=lambda: error, SBEvent=object, eStateExited=4,
                eStateDetached=5, eStateInvalid=0, eStateStopped=3)
            pids = iter([b'17\n', b'18\n', b'19\n'])
            reports = []
            with patch.dict(sys.modules, {'lldb': fake_lldb}), \
                 patch.object(signal, 'signal'), \
                 patch.object(time, 'monotonic', side_effect=lambda: clock[0]), \
                 patch.object(time, 'sleep', side_effect=lambda value: clock.__setitem__(0, clock[0] + value)), \
                 patch.object(Path, 'read_text', return_value=json.dumps(config)), \
                 patch(__name__ + '.write_report', side_effect=lambda path, data: reports.append(data)), \
                 patch.object(subprocess, 'run', side_effect=lambda *args, **kwargs: subprocess.CompletedProcess([], 0, next(pids), b'')), \
                 patch(__name__ + '.process_identity', side_effect=lambda pid, *args: (SYNTHETIC_UID,
                     ORIGINAL_SIBLING_IMAGE if pid == 18 else config['image'])):
                run_lldb(debugger, '/synthetic/config')
            attached_pids = [call.args[1] for call in target.AttachToProcessWithID.call_args_list]
            self.assertEqual(attached_pids, [17, 19])
            self.assertEqual([item['armGeneration'] for item in reports if item['status'] == 'armed'], [1, 2])
            self.assertTrue(any(item['status'] == 'waiting_for_selected' and item['reason'] == 'original_sibling' for item in reports))
            self.assertEqual(reports[-1]['status'], 'timed_out')
            self.assertEqual(reports[-1]['reason'], 'capture_window_expired')
            self.assertTrue(reports[-1]['detachConfirmed'])
            self.assertFalse(reports[-1]['outputWritten'])
            self.assertEqual(config['deadline'], 10)
            for process in processes:
                process.Detach.assert_called_once_with(False)
                process.ReadMemory.assert_not_called()

        def test_driver_breakpoint_invalid_resolved_and_pending_diagnostics(self):
            for valid, locations, resolved in [(False, 0, 0), (True, 1, 1), (True, 0, 0)]:
                with self.subTest(valid=valid, locations=locations):
                    config = self.config('/synthetic/breakpoint', deadline=1)
                    config['report'] = '/synthetic/report'
                    clock = [0]
                    error = SimpleNamespace(Success=lambda: True)
                    process = MagicMock()
                    process.IsValid.return_value = True
                    process.GetProcessID.return_value = 17
                    process.Continue.return_value = error
                    process.Detach.return_value = error
                    process.GetState.return_value = 2
                    breakpoint = MagicMock()
                    breakpoint.IsValid.return_value = valid
                    breakpoint.GetNumLocations.return_value = locations
                    breakpoint.GetNumResolvedLocations.return_value = resolved
                    target = MagicMock()
                    target.AttachToProcessWithID.return_value = process
                    target.BreakpointCreateByName.return_value = breakpoint
                    debugger = MagicMock()
                    debugger.CreateTarget.return_value = target
                    listener = MagicMock()
                    listener.WaitForEvent.side_effect = lambda *args: clock.__setitem__(0, 2)
                    fake_lldb = SimpleNamespace(SBListener=lambda *args: listener,
                        SBError=lambda: error, SBEvent=object, eStateExited=4,
                        eStateDetached=5, eStateInvalid=0, eStateStopped=3)
                    reports = []
                    with patch.dict(sys.modules, {'lldb': fake_lldb}), \
                         patch.object(signal, 'signal'), \
                         patch.object(time, 'monotonic', side_effect=lambda: clock[0]), \
                         patch.object(Path, 'read_text', return_value=json.dumps(config)), \
                         patch(__name__ + '.write_report', side_effect=lambda path, data: reports.append(data)), \
                         patch(__name__ + '.find_wechat_pid', return_value=17), \
                         patch(__name__ + '.selected_process_matches', return_value=True):
                        run_lldb(debugger, '/synthetic/config')
                    self.assertEqual(reports[-1]['breakpointValid'], valid)
                    self.assertEqual(reports[-1]['breakpointLocationCount'], locations)
                    self.assertEqual(reports[-1]['breakpointResolvedLocationCount'], resolved)
                    self.assertTrue(reports[-1]['detachConfirmed'])
                    self.assertFalse(reports[-1]['outputWritten'])
                    process.Detach.assert_called_once_with(False)
                    process.ReadMemory.assert_not_called()
                    if valid:
                        armed = next(report for report in reports if report['status'] == 'armed')
                        self.assertEqual(armed['breakpointLocationCount'], locations)
                        self.assertEqual(armed['breakpointResolvedLocationCount'], resolved)
                        self.assertEqual(reports[-1]['status'], 'timed_out')
                        process.Continue.assert_called_once_with()
                    else:
                        self.assertEqual(reports[-1]['status'], 'breakpoint_failed')
                        self.assertEqual(reports[-1]['reason'], 'breakpoint_invalid')
                        self.assertEqual(reports[-1]['captureStage'], 'breakpoint_setup')
                        breakpoint.SetScriptCallbackFunction.assert_not_called()
                        process.Continue.assert_not_called()

        def test_driver_original_wait_keeps_original_deadline_without_attach(self):
            config = self.config('/synthetic/wait', deadline=1)
            config.update(owner=(SYNTHETIC_UID, SYNTHETIC_GID), report='/synthetic/report')
            clock = [0]
            reports = []
            debugger = MagicMock()
            with patch.dict(sys.modules, {'lldb': SimpleNamespace()}), \
                 patch.object(signal, 'signal'), \
                 patch.object(time, 'monotonic', side_effect=lambda: clock[0]), \
                 patch.object(time, 'sleep', side_effect=lambda value: clock.__setitem__(0, clock[0] + value)), \
                 patch.object(Path, 'read_text', return_value=json.dumps(config)), \
                 patch(__name__ + '.write_report', side_effect=lambda path, data: reports.append(data)), \
                 patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'18\n', b'')), \
                 patch(__name__ + '.process_identity', return_value=(SYNTHETIC_UID, ORIGINAL_SIBLING_IMAGE)):
                run_lldb(debugger, '/synthetic/config')
            debugger.CreateTarget.assert_not_called()
            self.assertEqual([item['status'] for item in reports], ['waiting_for_selected', 'timed_out'])
            self.assertEqual(reports[-1]['armGeneration'], 0)
            self.assertEqual(clock[0], 1)
            self.assertEqual(config['deadline'], 1)
            self.assertFalse(reports[-1]['outputWritten'])

        def test_driver_reports_safe_identity_rejection_reason_and_stage(self):
            config = self.config('/synthetic/rejection')
            config.update(owner=(SYNTHETIC_UID, SYNTHETIC_GID), report='/synthetic/report')
            for identity, reason in [((FOREIGN_UID, ORIGINAL_SIBLING_IMAGE), 'target_owner_mismatch'),
                    ((SYNTHETIC_UID, '/synthetic/private-value/WeChat'), 'target_image_mismatch')]:
                debugger = MagicMock()
                reports = []
                with self.subTest(reason=reason), \
                     patch.dict(sys.modules, {'lldb': SimpleNamespace()}), \
                     patch.object(signal, 'signal'), \
                     patch.object(time, 'monotonic', return_value=0), \
                     patch.object(Path, 'read_text', return_value=json.dumps(config)), \
                     patch(__name__ + '.write_report', side_effect=lambda path, data: reports.append(data)), \
                     patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'18\n', b'')), \
                     patch(__name__ + '.process_identity', return_value=identity):
                    run_lldb(debugger, '/synthetic/config')
                self.assertEqual(reports[-1]['status'], 'target_rejected')
                self.assertEqual(reports[-1]['reason'], reason)
                self.assertEqual(reports[-1]['captureStage'], 'discovery')
                self.assertNotIn('/synthetic/private-value', json.dumps(reports))
                debugger.CreateTarget.assert_not_called()

        def test_callback_still_refuses_original_before_reading_memory(self):
            config = self.config('/synthetic/callback')
            session = CandidateSession(config)
            frame = MagicMock()
            frame.FindRegister.side_effect = lambda name: SimpleNamespace(GetValueAsUnsigned=lambda: PBKDF_PARAMETERS[name])
            process = frame.GetThread.return_value.GetProcess.return_value
            process.GetProcessID.return_value = 17
            with patch(__name__ + '._session', session), \
                 patch.dict(sys.modules, {'lldb': SimpleNamespace()}), \
                 patch.object(time, 'monotonic', return_value=0), \
                 patch(__name__ + '.process_identity', return_value=(config['owner'][0], ORIGINAL_SIBLING_IMAGE)):
                self.assertTrue(on_pbkdf(frame, None, None))
            self.assertEqual(session.fatal, 'target_rejected')
            self.assertEqual(session.failure_reason, 'target_image_mismatch')
            self.assertEqual(session.failure_stage, 'callback_identity')
            process.ReadMemory.assert_not_called()
            self.assertEqual(session.seen, 0)

        def test_post_attach_disappearance_retries_then_rejects_other_image(self):
            with tempfile.TemporaryDirectory() as directory:
                directory = str(Path(directory).resolve())
                config = self.config(directory)
                config['report'] = str(Path(directory) / 'result.json')
                config_path = Path(directory) / 'config.json'
                config_path.write_text(json.dumps(config))
                error = SimpleNamespace(Success=lambda: True)
                process = MagicMock()
                process.IsValid.return_value = True
                process.GetProcessID.return_value = 17
                process.Detach.return_value = error
                process.GetState.return_value = 3
                target = MagicMock()
                target.AttachToProcessWithID.return_value = process
                debugger = MagicMock()
                debugger.CreateTarget.return_value = target
                fake_lldb = SimpleNamespace(SBListener=lambda *args: object(),
                    SBError=lambda: error, eStateExited=4, eStateDetached=5,
                    eStateInvalid=0, eStateStopped=3)
                with patch.dict(sys.modules, {'lldb': fake_lldb}), \
                     patch.object(signal, 'signal'), \
                     patch.object(time, 'monotonic', return_value=0), \
                     patch(__name__ + '.find_wechat_pid', side_effect=[17, 18]) as discovery, \
                     patch(__name__ + '.selected_process_matches',
                         side_effect=[True, False, CaptureFailure('synthetic mismatch')]):
                    run_lldb(debugger, config_path)
                report = json.loads(Path(config['report']).read_text())
                self.assertEqual(discovery.call_count, 2)
                self.assertEqual(report['status'], 'target_rejected')
                self.assertTrue(report['detachConfirmed'])
                self.assertFalse(report['outputWritten'])
                process.Detach.assert_called_once_with(False)
                target.BreakpointCreateByName.assert_not_called()
                self.assertFalse(Path(config['output']).exists())

        def test_rejected_then_verified_synthetic_candidate_is_private(self):
            with tempfile.TemporaryDirectory() as directory:
                config = self.config(str(Path(directory).resolve()))
                answers = iter([None, {'verifiedSaltCount': 1, 'distinctSaltCount': 1, 'allVerified': True}])
                session = CandidateSession(config, lambda *args: next(answers), clock=lambda: 0)
                self.assertFalse(session.consider(PBKDF_PARAMETERS, b'a' * 32, b's' * 16))
                self.assertTrue(session.consider(PBKDF_PARAMETERS, b'b' * 32, b's' * 16))
                output = Path(config['output'])
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o700)
                self.assertEqual(len(output.read_bytes()), 65)
                self.assertRaises(CaptureFailure, write_secret, output, b'c' * 32, config['owner'])

        def test_verifier_secret_is_stdin_only(self):
            fake = subprocess.CompletedProcess([], 0, b'{"verifiedSaltCount":1,"distinctSaltCount":1,"allVerified":true}', b'')
            with patch.object(subprocess, 'run', return_value=fake) as run:
                self.assertIsNotNone(verify_candidate('/synthetic/verifier', '/synthetic/root', b'p' * 32, 5))
                argv = run.call_args.args[0]
                self.assertNotIn((b'p' * 32).hex(), ' '.join(argv))
                self.assertIn('--passphrase-stdin', argv)
                # The stdin buffer is wiped even when verification succeeds.
                self.assertEqual(set(run.call_args.kwargs['input']), {0})

        def test_inventory_uses_synthetic_headers_and_ignores_symlinks(self):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'message.db').write_bytes(b's' * 16 + b'fake-encrypted-page')
                (root / 'plain.db').write_bytes(b'SQLite format 3\x00')
                (root / 'short.db').write_bytes(b'short')
                (root / 'link.db').symlink_to(root / 'plain.db')
                os.mkfifo(root / 'pipe.db')  # Must not block before fstat.
                self.assertEqual(read_salt_inventory(root), {(b's' * 16).hex()})

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticTests))
    return 0 if result.wasSuccessful() else 1


class Parser(argparse.ArgumentParser):
    def error(self, message):
        del message
        print(json.dumps({'status': 'failed', 'reason': 'argument_invalid'}))
        raise SystemExit(2)


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    for flag in ('db-root', 'output', 'app-path', 'app-cdhash', 'original-app-path',
                 'original-cdhash', 'verify-bin', 'verify-cdhash', 'verifier-sha256'):
        parser.add_argument('--' + flag)
    parser.add_argument('--timeout-seconds', type=int, default=300)
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    required = ('db_root', 'output', 'app_path', 'app_cdhash', 'original_app_path',
                'original_cdhash', 'verify_bin', 'verify_cdhash', 'verifier_sha256')
    if not all(getattr(args, key) for key in required) or not 1 <= args.timeout_seconds <= 300:
        parser.error('explicit_capture_inputs_required')
    try:
        return capture(args)
    except (CaptureFailure, Failure, OSError, ValueError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'status': 'check_unavailable', 'reason': 'capture_preflight_or_tool_failed'}))
        return 2
    except Exception:
        print(json.dumps({'status': 'failed', 'reason': 'capture_failed'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
