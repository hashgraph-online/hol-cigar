"""Real process/descriptor controls for accelerated and portable worker launch."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import signal
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from cigar_sdk import LocalContextGraph, context


def test_worker_launch_retains_process_lifecycle_and_platform_fallback():
    with LocalContextGraph("spawn-contract", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
        assert graph.stats()["documents"] == 0
        if sys.platform == "darwin":
            from cigar_sdk._macos_spawn import ClosedFdPopen

            assert type(graph._process) is ClosedFdPopen
        else:
            assert type(graph._process) is subprocess.Popen
    assert graph.cleanup_complete


def test_worker_factory_closes_intentionally_inheritable_data(tmp_path):
    canary = tmp_path / "descriptor-canary"
    canary.write_bytes(b"synthetic descriptor isolation control")
    with canary.open("rb") as stream:
        descriptor = stream.fileno()
        os.set_inheritable(descriptor, True)
        identity = os.fstat(descriptor)
        probe = (
            "import os,json\n"
            f"expected=({identity.st_dev},{identity.st_ino})\n"
            f"try:\n value=os.fstat({descriptor}); leaked=(value.st_dev,value.st_ino)==expected\n"
            "except OSError: leaked=False\nprint(json.dumps(leaked))"
        )
        argv = [sys.executable, "-I", "-c", probe]
        if os.name == "posix":
            # Explicitly pass only synthetic test data as a positive detector control.
            positive = subprocess.run(argv, pass_fds=(descriptor,), capture_output=True, check=True, timeout=10)
            assert json.loads(positive.stdout) is True
        process = context._worker_process(argv)
        out, _ = process.communicate(timeout=10)
        assert process.returncode == 0
        assert json.loads(out) is False


def test_unavailable_optional_backend_preserves_standard_spawn():
    with patch.dict(sys.modules, {"cigar_sdk._macos_spawn": None}):
        with LocalContextGraph("fallback-contract", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
            assert type(graph._process) is subprocess.Popen
            assert graph.stats()["documents"] == 0
    assert graph.cleanup_complete


def test_changed_cpython_spawn_signature_uses_the_original_implementation():
    original = subprocess.Popen._execute_child

    def interposed(process, *arguments, **keywords):
        return original(process, *arguments, **keywords)

    with patch.object(subprocess.Popen, "_execute_child", interposed):
        with LocalContextGraph("changed-spawn-signature", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
            assert type(graph._process) is subprocess.Popen
            assert graph.stats()["documents"] == 0
    assert graph.cleanup_complete


def test_runtime_without_the_required_gil_uses_standard_spawn():
    with patch.object(sys, "_is_gil_enabled", return_value=False, create=True):
        with LocalContextGraph("unsupported-spawn-runtime", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
            assert type(graph._process) is subprocess.Popen
            assert graph.stats()["documents"] == 0
    assert graph.cleanup_complete


def test_worker_spawn_preserves_native_environment_not_only_python_mapping(monkeypatch):
    name = "CIGAR_SPAWN_CONTROL_" + uuid.uuid4().hex
    if sys.platform == "darwin":
        from cigar_sdk._macos_spawn import _LIB

        _LIB.setenv.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        _LIB.setenv.restype = ctypes.c_int
        _LIB.unsetenv.argtypes, _LIB.unsetenv.restype = [ctypes.c_char_p], ctypes.c_int
        assert _LIB.setenv(name.encode(), b"native-control", 0) == 0
        assert name not in os.environ
    else:
        monkeypatch.setenv(name, "native-control")
    try:
        command = [sys.executable, "-I", "-c", f"import os,json; print(json.dumps(os.getenv({name!r})))"]
        process = context._worker_process(command)
        out, _ = process.communicate(timeout=10)
        assert process.returncode == 0
        assert json.loads(out) == "native-control"
    finally:
        if sys.platform == "darwin":
            assert _LIB.unsetenv(name.encode()) == 0


def test_explicit_environment_and_working_directory_delegate_without_semantic_changes(tmp_path):
    factory = subprocess.Popen
    if sys.platform == "darwin":
        from cigar_sdk._macos_spawn import ClosedFdPopen

        factory = ClosedFdPopen
    process = factory(
        [sys.executable, "-I", "-c", "import os,json; print(json.dumps([os.getenv('ONLY_CONTROL'),os.getcwd()]))"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=tmp_path,
        env={"ONLY_CONTROL": "provided"},
        close_fds=True,
    )
    out, _ = process.communicate(timeout=10)
    assert process.returncode == 0
    assert json.loads(out) == ["provided", str(tmp_path.resolve())]


def test_spawn_failure_stays_content_free_and_does_not_retry(tmp_path):
    missing = tmp_path / "nonexecutable-private-worker"
    missing.write_bytes(b"synthetic non-executable input\n")
    missing.chmod(0o600)
    with pytest.raises(context.LocalContextError) as raised:
        LocalContextGraph("spawn-error", worker_path=missing)
    assert raised.value.code == "WorkerUnavailable"
    assert str(missing) not in str(raised.value)


def test_interrupted_successful_spawn_retains_owned_pid_for_cleanup():
    if sys.platform != "darwin":
        # The unchanged portable path remains a Popen process with normal reaping.
        process = context._worker_process([sys.executable, "-I", "-c", "pass"])
        process.communicate(timeout=10)
        assert process.returncode == 0
        return
    from cigar_sdk import _macos_spawn

    original = _macos_spawn._spawn
    pids = []

    def interrupted(args, restore_signals, descriptors, pid):
        original(args, restore_signals, descriptors, pid)
        pids.append(pid.value)
        raise KeyboardInterrupt

    process = _macos_spawn.ClosedFdPopen.__new__(_macos_spawn.ClosedFdPopen)
    try:
        with patch.object(_macos_spawn, "_spawn", side_effect=interrupted), pytest.raises(KeyboardInterrupt):
            _macos_spawn.ClosedFdPopen.__init__(
                process,
                [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        assert pids == [process.pid]
        assert process._child_created
    finally:
        if process._child_created:
            process.kill()
            process.wait(timeout=5)
    assert process.returncode is not None


@pytest.mark.parametrize("initialization", ["actions", "attributes"])
def test_optional_setup_failure_falls_back_before_any_native_launch(initialization):
    if sys.platform != "darwin":
        with LocalContextGraph("portable-setup", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
            assert type(graph._process) is subprocess.Popen
            assert graph.stats()["documents"] == 0
        assert graph.cleanup_complete
        return
    from cigar_sdk import _macos_spawn

    library = _macos_spawn._LIB
    function = "posix_spawn_file_actions_init" if initialization == "actions" else "posix_spawnattr_init"
    with (
        patch.object(library, function, return_value=errno.ENOMEM),
        patch.object(library, "posix_spawn", wraps=library.posix_spawn) as native_launch,
        patch.object(
            library, "posix_spawn_file_actions_destroy", wraps=library.posix_spawn_file_actions_destroy
        ) as destroy,
    ):
        with LocalContextGraph("setup-fallback", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
            assert graph.stats()["documents"] == 0
        assert graph.cleanup_complete
        native_launch.assert_not_called()
        assert destroy.call_count == int(initialization == "attributes")


@pytest.mark.parametrize("initialization", ["actions", "attributes"])
def test_interrupted_native_setup_closes_allocations_and_pipes(initialization):
    if sys.platform != "darwin":
        with LocalContextGraph("portable-setup-interrupt", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
            assert type(graph._process) is subprocess.Popen
        assert graph.cleanup_complete
        return
    from cigar_sdk import _macos_spawn

    library = _macos_spawn._LIB
    function = "posix_spawn_file_actions_init" if initialization == "actions" else "posix_spawnattr_init"
    original = getattr(library, function)
    before = len(os.listdir("/dev/fd"))

    def interrupted(pointer):
        assert original(pointer) == 0
        raise KeyboardInterrupt

    with (
        patch.object(library, function, side_effect=interrupted),
        patch.object(library, "posix_spawn", wraps=library.posix_spawn) as native_launch,
        patch.object(
            library, "posix_spawn_file_actions_destroy", wraps=library.posix_spawn_file_actions_destroy
        ) as destroy,
        patch.object(library, "posix_spawnattr_destroy", wraps=library.posix_spawnattr_destroy) as destroy_attributes,
        pytest.raises(KeyboardInterrupt),
    ):
        LocalContextGraph("interrupted-setup", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    native_launch.assert_not_called()
    assert destroy.call_count == 1
    assert destroy_attributes.call_count == int(initialization == "attributes")
    assert len(os.listdir("/dev/fd")) == before


def test_restore_signals_preserves_standard_child_disposition():
    if os.name != "posix":
        process = context._worker_process([sys.executable, "-I", "-c", "pass"])
        process.communicate(timeout=10)
        assert process.returncode == 0
        return
    factory = subprocess.Popen
    if sys.platform == "darwin":
        from cigar_sdk._macos_spawn import ClosedFdPopen

        factory = ClosedFdPopen
    previous = signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    try:
        for restore in (True, False):
            process = factory(
                ["/bin/sleep", "30"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                restore_signals=restore,
            )
            try:
                process.send_signal(signal.SIGPIPE)
                if restore:
                    assert process.wait(timeout=5) == -signal.SIGPIPE
                else:
                    assert process.poll() is None
            finally:
                process.kill()
                process.wait(timeout=5)
    finally:
        signal.signal(signal.SIGPIPE, previous)


def test_host_audit_denial_is_preserved_in_a_disposable_interpreter():
    prefix = str(Path(context.__file__).parent.parent)
    script = f"""import sys,json
sys.path.insert(0,{prefix!r})
from cigar_sdk import context
events=[]
deny=False
def audit(event,arguments):
    if event=='subprocess.Popen':
        events.append(event)
        if deny: raise PermissionError('synthetic audit denial')
sys.addaudithook(audit)
first=context._worker_process([sys.executable,'-I','-c','pass'])
first.communicate(timeout=10)
assert first.returncode==0
deny=True
try:
    second=context._worker_process([sys.executable,'-I','-c','pass'])
except PermissionError:
    denied=True
else:
    denied=False
    second.kill()
    second.wait(timeout=5)
print(json.dumps({{'events':len(events),'denied':denied}}))
"""
    result = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, check=True, timeout=30)
    assert json.loads(result.stdout) == {"events": 2, "denied": True}


def test_concurrent_spawns_keep_inheritable_descriptors_private(tmp_path):
    canary = tmp_path / "concurrent-canary"
    canary.write_bytes(b"synthetic concurrent descriptor control")
    with canary.open("rb") as stream:
        os.set_inheritable(stream.fileno(), True)
        identity = os.fstat(stream.fileno())
        probe = (
            "import os,json\nleaked=False\n"
            "for fd in range(3,256):\n"
            " try: value=os.fstat(fd)\n"
            " except OSError: continue\n"
            f" leaked=leaked or (value.st_dev,value.st_ino)==({identity.st_dev},{identity.st_ino})\n"
            "print(json.dumps(leaked))"
        )

        def check(_):
            process = context._worker_process([sys.executable, "-I", "-c", probe])
            try:
                out, _ = process.communicate(timeout=10)
                assert process.returncode == 0
                assert json.loads(out) is False
            finally:
                process.kill()
                process.wait(timeout=5)

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(check, range(32)))
