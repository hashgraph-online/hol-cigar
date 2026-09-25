"""Failure and process-ownership tests using a real native worker."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import warnings
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from cigar_sdk import LocalContextError, LocalContextGraph


@pytest.fixture
def graph():
    value = LocalContextGraph("lifecycle", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    yield value
    value.close()


def test_concurrent_close_reaps_and_closes_streams(graph):
    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(lambda _: graph.close(), range(32)))
    assert graph.cleanup_complete
    assert graph._process.returncode is not None
    assert not graph._thread.is_alive()
    assert graph._process.stdin.closed and graph._process.stdout.closed
    with pytest.raises(LocalContextError, match="Closed"):
        graph.stats()


def test_worker_exit_during_call_has_stable_error(graph):
    graph._process.kill()
    graph._process.wait(timeout=5)
    with pytest.raises(LocalContextError) as raised:
        graph.stats()
    assert raised.value.code == "Transport"
    assert graph.cleanup_complete


def test_cleanup_wait_failure_does_not_replace_transport_error(graph):
    graph._process.kill()
    graph._process.wait(timeout=5)
    with patch.object(graph._process, "wait", side_effect=subprocess.TimeoutExpired("worker", 5)):
        with pytest.raises(LocalContextError) as raised:
            graph.stats()
    assert raised.value.code == "Transport"
    graph.close()
    assert graph.cleanup_complete


def test_cleanup_kill_failure_remains_retryable(graph):
    with (
        patch.object(graph._process, "kill", side_effect=OSError),
        patch.object(graph._process, "wait", side_effect=subprocess.TimeoutExpired("worker", 5)),
    ):
        graph.close()
    assert not graph.cleanup_complete
    graph.close()
    assert graph.cleanup_complete


def test_pid_guard_precedes_inherited_locks_and_never_signals_worker(graph):
    with (
        graph._lock,
        graph._close_lock,
        patch("cigar_sdk.context.os.getpid", return_value=-1),
        patch.object(graph._process, "kill") as kill,
    ):
        for operation in (graph.stats, graph.close, graph.__enter__):
            with pytest.raises(LocalContextError) as raised:
                operation()
            assert raised.value.code == "ForkedProcess"
        kill.assert_not_called()
    assert graph.stats()["documents"] == 0


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork contract")
def test_fork_with_owned_locks_rejects_child_and_preserves_parent(graph):
    reader, writer = os.pipe()
    with graph._lock, graph._close_lock, warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                codes = []
                for operation in (graph.stats, graph.close):
                    try:
                        operation()
                    except LocalContextError as error:
                        codes.append(error.code)
                with LocalContextGraph("child", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as child:
                    documents = child.stats()["documents"]
                os.write(writer, json.dumps([codes, documents]).encode())
                os._exit(0)
            except BaseException:
                os._exit(2)
        os.close(writer)
        try:
            ready, _, _ = select.select([reader], [], [], 10)
            if not ready:
                os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
            assert ready, "child blocked on inherited state"
            assert os.waitstatus_to_exitcode(status) == 0
            assert json.loads(os.read(reader, 4096)) == [["ForkedProcess", "ForkedProcess"], 0]
        finally:
            os.close(reader)
    assert graph.stats()["documents"] == 0
