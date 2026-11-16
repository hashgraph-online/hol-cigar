"""Private CPython worker launch using macOS's atomic descriptor-close policy.

Only the simple, absolute-path, three-stream SDK launch is accelerated. Popen
retains pipe ownership, errors, process handles, reaping and audit semantics.
The caller checks the CPython method signature and falls back before launch if
this optional backend cannot load. No descriptor scans or inherited-FD window.
"""

from __future__ import annotations

import ctypes
import errno
import os
import signal
import subprocess
import sys
from typing import Any

if sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise ImportError("unsupported worker spawn backend")

# Apple's public spawn.h declares both handles as opaque void pointers, pid_t
# as int, flags as short and sigset_t as uint32_t. Never dereference the opaque
# handles or load a library selected by PATH, the caller, or a source document.
_LIB: Any = ctypes.PyDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
_OPAQUE = ctypes.POINTER(ctypes.c_void_p)
_STRINGS = ctypes.POINTER(ctypes.c_char_p)
_SIGNATURES = {
    "posix_spawnattr_init": [_OPAQUE],
    "posix_spawnattr_destroy": [_OPAQUE],
    "posix_spawnattr_setflags": [_OPAQUE, ctypes.c_short],
    "posix_spawnattr_setsigdefault": [_OPAQUE, ctypes.POINTER(ctypes.c_uint32)],
    "posix_spawn_file_actions_init": [_OPAQUE],
    "posix_spawn_file_actions_destroy": [_OPAQUE],
    "posix_spawn_file_actions_adddup2": [_OPAQUE, ctypes.c_int, ctypes.c_int],
    "posix_spawn": [ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, _OPAQUE, _OPAQUE, _STRINGS, _STRINGS],
    "sigemptyset": [ctypes.POINTER(ctypes.c_uint32)],
    "sigaddset": [ctypes.POINTER(ctypes.c_uint32), ctypes.c_int],
}
for _name, _arguments in _SIGNATURES.items():
    _function = getattr(_LIB, _name)
    _function.argtypes, _function.restype = _arguments, ctypes.c_int
_LIB._NSGetEnviron.argtypes = []
_LIB._NSGetEnviron.restype = ctypes.POINTER(_STRINGS)
# This is a live view of the environment-pointer storage, not a stale copy or
# os.environ snapshot. PyDLL holds the GIL through conversion and the OS call;
# Python environment changes cannot invalidate the pointer during that call.
_ENVIRONMENT = _LIB._NSGetEnviron().contents


def _check(status: int) -> None:
    if status:
        code = status if status > 0 else ctypes.get_errno() or errno.EIO
        raise OSError(code, os.strerror(code))


def _argument_array(values: list[str]) -> Any:
    encoded = [os.fsencode(value) for value in values]
    if any(b"\0" in value for value in encoded):
        raise ValueError("embedded null byte")
    return (ctypes.c_char_p * (len(encoded) + 1))(*encoded, None)


class _SetupUnavailable(Exception):
    """Optional setup failed before an audit event or OS launch attempt."""


def _spawn(args: list[str], restore_signals: bool, descriptors: tuple[int, int, int], pid: ctypes.c_int) -> None:
    argument_array = _argument_array(args)
    path = os.fsencode(args[0])
    actions, attributes = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        try:
            _check(_LIB.posix_spawn_file_actions_init(ctypes.byref(actions)))
            _check(_LIB.posix_spawnattr_init(ctypes.byref(attributes)))
            flags = 0x4000  # POSIX_SPAWN_CLOEXEC_DEFAULT, public macOS ABI.
            if restore_signals:
                defaults = ctypes.c_uint32()
                _check(_LIB.sigemptyset(ctypes.byref(defaults)))
                for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
                    number = getattr(signal, name, None)
                    if number is not None:
                        _check(_LIB.sigaddset(ctypes.byref(defaults), number))
                _check(_LIB.posix_spawnattr_setsigdefault(ctypes.byref(attributes), ctypes.byref(defaults)))
                flags |= 0x0004  # POSIX_SPAWN_SETSIGDEF, matching Popen's signal restoration.
            _check(_LIB.posix_spawnattr_setflags(ctypes.byref(attributes), flags))
            for target, descriptor in enumerate(descriptors):
                _check(_LIB.posix_spawn_file_actions_adddup2(ctypes.byref(actions), descriptor, target))
        except OSError as error:
            raise _SetupUnavailable from error
        # Audit denial and any error/interrupt from the actual OS launch must
        # propagate, never trigger a fallback or a second launch attempt.
        sys.audit("subprocess.Popen", args[0], args, None, None)
        _check(
            _LIB.posix_spawn(
                ctypes.byref(pid), path, ctypes.byref(actions), ctypes.byref(attributes), argument_array, _ENVIRONMENT
            )
        )
    finally:
        # Apple's init writes a non-null handle only after successful allocation.
        # Inspect the handles rather than a Python flag: an interrupt may arrive
        # after a native init returns but before a following assignment executes.
        try:
            if attributes.value is not None:
                _LIB.posix_spawnattr_destroy(ctypes.byref(attributes))
        finally:
            if actions.value is not None:
                _LIB.posix_spawn_file_actions_destroy(ctypes.byref(actions))


class ClosedFdPopen(subprocess.Popen[bytes]):
    """Popen lifecycle with only a narrowly gated Darwin launch implementation."""

    def _execute_child(self, *values: Any, **keywords: Any) -> None:
        if len(values) != 23 or keywords:
            # typeshed intentionally omits this signature-gated CPython API.
            super()._execute_child(*values, **keywords)  # type: ignore[misc]
            return
        (
            args,
            executable,
            preexec_fn,
            close_fds,
            pass_fds,
            cwd,
            env,
            _startupinfo,
            _creationflags,
            shell,
            p2cread,
            p2cwrite,
            c2pread,
            c2pwrite,
            errread,
            errwrite,
            restore_signals,
            gid,
            gids,
            uid,
            umask,
            start_new_session,
            process_group,
        ) = values
        eligible = (
            type(args) is list
            and args
            and all(type(value) is str for value in args)
            and executable is None
            and os.path.isabs(args[0])
            and preexec_fn is None
            and close_fds
            and not pass_fds
            and cwd is None
            and env is None
            and not shell
            and not start_new_session
            and process_group == -1
            and gid is None
            and gids is None
            and uid is None
            and umask < 0
            and all(fd > 2 for fd in (p2cread, c2pwrite, errwrite))
        )
        if not eligible:
            super()._execute_child(*values, **keywords)  # type: ignore[misc]
            return
        pid = ctypes.c_int()
        try:
            try:
                _spawn(args, restore_signals, (p2cread, c2pwrite, errwrite), pid)
            except _SetupUnavailable:
                super()._execute_child(*values, **keywords)  # type: ignore[misc]
                return
        finally:
            # Retain Popen ownership even if an interrupt is delivered just
            # after successful OS creation. Never retry a dispatched launch.
            if pid.value > 0:
                self.pid = pid.value
                self._child_created = True
        # The same CPython method owns pipe closure on the standard spawn path.
        self._close_pipe_fds(p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)  # type: ignore[attr-defined]
