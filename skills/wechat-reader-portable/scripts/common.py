"""Private runtime inputs and bounded CLI execution; no account discovery."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time


MAX_RESULT_BYTES = 8 * 1024 * 1024


class Failure(Exception):
    """Only fixed, non-private classification codes may be released."""


def package_root():
    script = Path(__file__).resolve()
    for parent in script.parents:
        if (parent / '.git').exists():
            return parent
    return script.parents[1]


def external_path(value):
    if not isinstance(value, str) or not value or '\0' in value:
        raise Failure('path_invalid')
    path = Path(value)
    if not path.is_absolute() or any(part in ('.', '..') for part in path.parts):
        raise Failure('path_invalid')
    # Reject lexical AND resolved paths into a checkout or installed skill.
    boundary = package_root()
    if path.is_relative_to(boundary) or path.resolve().is_relative_to(boundary):
        raise Failure('runtime_inside_package')
    return path


def open_directory(path):
    """Walk real directory descriptors; reject symlinks in every component."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise Failure('path_invalid')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_private_file(path, *, maximum=None):
    path = external_path(str(path))
    parent = open_directory(path.parent)
    try:
        meta = os.fstat(parent)
        if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o700:
            raise Failure('private_parent_invalid')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                    or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1):
                raise Failure('private_file_invalid')
            if maximum is not None and meta.st_size > maximum:
                raise Failure('private_file_too_large')
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def private_json(path):
    fd = open_private_file(path, maximum=16384)
    try:
        raw = os.read(fd, 16385)
        if len(raw) > 16384:
            raise Failure('profile_invalid')
        return json.loads(raw)
    finally:
        os.close(fd)


def validate_database_root(path):
    fd = open_directory(external_path(str(path)))
    try:
        if os.fstat(fd).st_uid != os.getuid():
            raise Failure('source_owner_invalid')
    finally:
        os.close(fd)


def open_executable(path, owner_uid=None):
    path = external_path(str(path))
    parent = open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid not in (0, os.getuid() if owner_uid is None else owner_uid)
                    or meta.st_mode & 0o022 or not meta.st_mode & 0o111):
                raise Failure('tool_metadata_invalid')
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def verify_executable(path, expected, owner_uid=None):
    if (not isinstance(expected, str) or len(expected) != 64
            or any(char not in '0123456789abcdefABCDEF' for char in expected)):
        raise Failure('tool_fingerprint_invalid')
    fd = open_executable(path, owner_uid)
    try:
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != expected.lower():
            raise Failure('tool_fingerprint_mismatch')
    finally:
        os.close(fd)


def run_json(command, credential_fd=None, *, timeout=60, maximum=MAX_RESULT_BYTES):
    """Suppress diagnostic stderr; bound memory/time even for a broken CLI."""
    worker = None
    output = bytearray()
    try:
        worker = subprocess.Popen(command, stdin=credential_fd if credential_fd is not None else subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as poller:
            poller.register(worker.stdout, selectors.EVENT_READ)
            while poller.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Failure('tool_timeout')
                for key, _ in poller.select(min(remaining, 0.25)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        poller.unregister(key.fd)
                    elif len(output) + len(chunk) > maximum:
                        raise Failure('tool_result_too_large')
                    else:
                        output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Failure('tool_timeout')
        code = worker.wait(timeout=remaining)
        try:
            return code, json.loads(output)
        except (ValueError, UnicodeError):
            raise Failure('tool_result_invalid') from None
    except subprocess.TimeoutExpired:
        raise Failure('tool_timeout') from None
    except OSError:
        raise Failure('tool_unavailable') from None
    finally:
        if worker is not None:
            if worker.poll() is None:
                try:
                    os.killpg(worker.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                worker.wait()
            worker.stdout.close()
