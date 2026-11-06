"""Exercise real POSIX pipe framing, deadlines and concurrent descriptor ownership."""

import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from cigar_sdk import LocalContextError, LocalContextGraph, context

pytestmark = pytest.mark.skipif(not context._DIRECT_IO, reason="POSIX poll transport")


def wire_worker(tmp_path, mode):
    hello = {
        "protocol": context.LOCAL_CONTEXT_PROTOCOL,
        "core_version": context.LOCAL_CONTEXT_CORE_VERSION,
        "max_frame_bytes": context._MAX_FRAME,
        "max_response_bytes": context._MAX_RESPONSE,
        "capabilities": [],
    }
    script = f"""#!{sys.executable}
import json, os, sys, time
request = json.loads(sys.stdin.buffer.readline())
sys.stdout.write(json.dumps({{"id": request["id"], "ok": True, "result": {hello!r}}}) + "\\n")
sys.stdout.flush()
mode = {mode!r}
if mode == "stalled":
    time.sleep(10)
    sys.exit(0)
request = json.loads(sys.stdin.buffer.readline())
reply = (json.dumps({{"id": request["id"], "ok": True, "result": {{"documents": 0}}}}) + "\\n").encode()
if mode == "fragmented":
    for byte in reply:
        os.write(1, bytes([byte]))
elif mode == "wrong-id":
    os.write(1, b'{{"id":999,"ok":true,"result":{{}}}}\\n')
elif mode == "invalid":
    os.write(1, b'not-json\\n')
elif mode == "partial":
    os.write(1, b'{{"id":')
elif mode == "extra":
    os.write(1, reply + b'\\n')
elif mode == "oversize":
    os.write(1, b'x' * 65 + b'\\n')
elif mode == "boundary":
    reply = json.dumps({{"id": request["id"], "ok": True,
                        "result": {{"documents": 0, "padding": "x" * 131072}}}}).encode() + b'\\n'
    sys.stdout.buffer.write(reply)
    sys.stdout.buffer.flush()
"""
    path = tmp_path / "wire-worker"
    path.write_text(script)
    path.chmod(0o700)
    return path


def test_fragmented_response_and_process_cleanup(tmp_path):
    with LocalContextGraph("fragments", worker_path=wire_worker(tmp_path, "fragmented")) as graph:
        assert graph._direct_io and not graph._thread.is_alive()
        assert graph.stats() == {"documents": 0}
    assert graph.cleanup_complete


@pytest.mark.parametrize("mode", ["wrong-id", "invalid", "partial", "extra", "oversize"])
def test_malformed_actual_pipe_reply_fails_closed_and_reaps(tmp_path, mode):
    with LocalContextGraph("framing", worker_path=wire_worker(tmp_path, mode)) as graph:
        with patch.object(context, "_MAX_RESPONSE", 64), pytest.raises(LocalContextError, match="Transport"):
            graph.stats()
    assert graph.cleanup_complete and graph._process.returncode is not None


def test_blocked_raw_write_has_one_deadline_and_bounded_cleanup(tmp_path):
    graph = LocalContextGraph("blocked", worker_path=wire_worker(tmp_path, "stalled"))
    graph._timeout = 0.03
    started = time.monotonic()
    try:
        with pytest.raises(LocalContextError, match="Timeout"):
            graph._call({"op": "stats", "padding": "x" * (1024 * 1024)})
    finally:
        graph.close()
    assert time.monotonic() - started < 5.5
    assert graph.cleanup_complete


def test_lease_lock_wait_is_bounded_without_interrupting_worker():
    with LocalContextGraph("lease-wait", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
        graph._timeout = 0.01
        with graph._close_lock, pytest.raises(LocalContextError, match="Busy"):
            graph.stats()
        graph._timeout = 5
        assert graph.stats()["documents"] == 0


def test_concurrent_close_never_reuses_a_leased_descriptor(tmp_path):
    graph = LocalContextGraph("leased", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    ready, resume = threading.Event(), threading.Event()
    original_read = os.read
    originals = {graph._process.stdin.fileno(), graph._process.stdout.fileno()}
    replacement = None

    def paused_read(descriptor, size):
        ready.set()
        assert resume.wait(timeout=5)
        return original_read(descriptor, size)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool, patch.object(os, "read", side_effect=paused_read):
            future = pool.submit(graph.stats)
            try:
                assert ready.wait(timeout=5)
                graph.close()
                path = tmp_path / "host-owned-file"
                path.write_bytes(b"host-private")
                replacement = os.open(path, os.O_RDONLY)
                assert replacement in originals
            finally:
                resume.set()
            try:
                result = future.result(timeout=5)
            except LocalContextError as error:
                assert error.code == "Transport"
            else:
                # An already buffered, valid in-flight result may complete.
                assert result["documents"] == 0
            assert os.read(replacement, 100) == b"host-private"
    finally:
        resume.set()
        graph.close()
        if replacement is not None:
            os.close(replacement)
    assert graph.cleanup_complete


def test_interrupted_partial_raw_frame_closes_instead_of_reusing_stream():
    graph = LocalContextGraph("interrupted", worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    original_write = os.write

    def interrupt(descriptor, data):
        original_write(descriptor, data[:4])
        raise KeyboardInterrupt("test partial frame interrupted")

    with patch.object(os, "write", side_effect=interrupt):
        with pytest.raises(KeyboardInterrupt, match="test partial frame interrupted"):
            graph.stats()
    assert graph.cleanup_complete and graph._process.returncode is not None
    with pytest.raises(LocalContextError, match="Closed"):
        graph.stats()


def test_full_accepted_timeout_range_is_supported_by_poll():
    with LocalContextGraph(
        "large-timeout", timeout=threading.TIMEOUT_MAX, worker_path=os.environ.get("CIGAR_TEST_WORKER")
    ) as graph:
        assert graph.stats()["documents"] == 0
    assert graph.cleanup_complete


@pytest.mark.parametrize("excess", [0, 1])
def test_multichunk_valid_response_at_exact_limit_and_one_byte_over(tmp_path, excess):
    import json

    result = {"documents": 0, "padding": "x" * 131072}
    size = len(json.dumps({"id": 2, "ok": True, "result": result}).encode() + b"\n")
    with LocalContextGraph("boundary", worker_path=wire_worker(tmp_path, "boundary")) as graph:
        with patch.object(context, "_MAX_RESPONSE", size - excess):
            if excess:
                with pytest.raises(LocalContextError, match="Transport"):
                    graph.stats()
            else:
                assert graph.stats() == result
    assert graph.cleanup_complete
