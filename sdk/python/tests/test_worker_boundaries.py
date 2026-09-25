"""Fault-inject the local transport around a real worker without replacing graph semantics."""

from __future__ import annotations

import json
import os
import queue
from unittest.mock import patch

import pytest

from cigar_sdk import LocalContextError, LocalContextGraph, context


@pytest.fixture
def graph():
    value = LocalContextGraph("boundaries", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    yield value
    value.close()


def test_busy_call_does_not_interrupt_owner_or_close_graph(graph):
    graph._timeout = 0.01
    with graph._lock, pytest.raises(LocalContextError, match="Busy"):
        graph.stats()
    graph._timeout = 5
    assert graph.stats()["documents"] == 0


@pytest.mark.parametrize("value", [float("nan"), object(), "\ud800"])
def test_invalid_request_is_rejected_before_dispatch_and_graph_remains_usable(graph, value):
    with pytest.raises(LocalContextError, match="InvalidInput"):
        graph._call({"op": "stats", "extra": value})
    assert graph.stats()["documents"] == 0


def test_exact_request_frame_boundary_is_accepted_and_next_byte_rejected(graph):
    command = {"op": "stats", "extra": ""}
    base_size = len(
        (json.dumps({"id": 2, "command": command}, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    )
    command["extra"] = "x" * (context._MAX_FRAME - base_size)
    seen = []
    original = graph._jobs.put_nowait

    def receive(job):
        if job is None:
            return original(job)
        frame, response = job
        seen.append(len(frame))
        response.put_nowait(json.dumps({"id": json.loads(frame)["id"], "ok": True, "result": 0}).encode() + b"\n")

    with patch.object(graph._jobs, "put_nowait", side_effect=receive):
        assert graph._call(command) == 0
        command["extra"] += "x"
        with pytest.raises(LocalContextError, match="LimitExceeded"):
            graph._call(command)
    assert seen == [context._MAX_FRAME]
    assert graph.stats()["documents"] == 0


@pytest.mark.parametrize(
    "wire",
    [
        b"",
        b"{}",
        b"[]\n",
        b'{"id":2,"ok":1}\n',
        b'{"id":99,"ok":true,"result":0}\n',
        b'{"id":2,"ok":true}\n',
        b'{"id":2,"ok":false,"error":"PRIVATE_SECRET"}\n',
        b'{"id":2,"ok":false,"error":[]}\n',
        b"{" + b"[" * 2000 + b"\n",
    ],
)
def test_malformed_reply_closes_graph_without_echo(graph, wire):
    original = graph._jobs.put_nowait

    def receive(job):
        if job is None:
            return original(job)
        job[1].put_nowait(wire)

    with patch.object(graph._jobs, "put_nowait", side_effect=receive):
        with pytest.raises(LocalContextError) as raised:
            graph.stats()
    assert raised.value.code == "Transport" and "PRIVATE_SECRET" not in str(raised.value)
    assert graph.cleanup_complete


@pytest.mark.parametrize("extra", [0, 1])
def test_exact_response_byte_boundary(graph, extra):
    prefix = b'{"id":2,"ok":true,"result":"'
    suffix = b'"}\n'
    wire = prefix + b"x" * (context._MAX_RESPONSE - len(prefix) - len(suffix) + extra) + suffix
    original = graph._jobs.put_nowait

    def receive(job):
        if job is None:
            return original(job)
        job[1].put_nowait(wire)

    with patch.object(graph._jobs, "put_nowait", side_effect=receive):
        if extra:
            with pytest.raises(LocalContextError, match="Transport"):
                graph.stats()
        else:
            assert len(graph._call({"op": "stats"})) == context._MAX_RESPONSE - len(prefix) - len(suffix)
    if extra:
        assert graph.cleanup_complete
    else:
        assert graph.stats()["documents"] == 0


def test_queue_failure_does_not_mask_transport_error(graph):
    with patch.object(graph._jobs, "put_nowait", side_effect=queue.Full):
        with pytest.raises(LocalContextError, match="Transport"):
            graph.stats()
    graph.close()
    assert graph.cleanup_complete


def test_incompatible_handshake_and_thread_start_failure_reap_worker():
    worker = os.environ.get("CIGAR_TEST_WORKER")
    created = []
    original = context.subprocess.Popen

    def spawn(*args, **kwargs):
        process = original(*args, **kwargs)
        created.append(process)
        return process

    with patch.object(context.subprocess, "Popen", side_effect=spawn):
        with (
            patch.object(LocalContextGraph, "_call", return_value={}),
            pytest.raises(LocalContextError, match="IncompatibleWorker"),
        ):
            LocalContextGraph("bad-handshake", worker_path=worker)
        with (
            patch.object(context.threading.Thread, "start", side_effect=RuntimeError("no threads")),
            pytest.raises(RuntimeError),
        ):
            LocalContextGraph("thread-failure", worker_path=worker)
    assert len(created) == 2
    for process in created:
        assert process.poll() is not None and process.stdin.closed and process.stdout.closed


def test_launch_failure_and_remove_contract(graph):
    with patch.object(context.subprocess, "Popen", side_effect=OSError("PRIVATE_PATH")):
        with pytest.raises(LocalContextError, match="WorkerUnavailable"):
            LocalContextGraph("launch", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    assert not graph.remove("absent")
    graph.upsert({"id": "present", "source": "fixture", "text": "data"})
    assert graph.remove("present")


def test_thread_object_allocation_failure_never_launches_worker():
    with (
        patch.object(context.threading, "Thread", side_effect=RuntimeError("thread allocation")),
        patch.object(context.subprocess, "Popen") as spawn,
        pytest.raises(RuntimeError, match="thread allocation"),
    ):
        LocalContextGraph("thread-allocation", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    spawn.assert_not_called()
