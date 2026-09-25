"""Streaming integrity checks remain bounded and do not cache changed bytes."""

import hashlib
import io
import tracemalloc
from unittest.mock import patch

import pytest

from cigar_sdk.local_runtime import _sha256_file


def test_large_file_hash_uses_bounded_python_memory(tmp_path):
    path = tmp_path / "worker"
    block = b"a" * 1024 * 1024
    expected = hashlib.sha256()
    with path.open("wb") as stream:
        for _ in range(32):
            stream.write(block)
            expected.update(block)
    tracemalloc.start()
    try:
        assert _sha256_file(path) == expected.hexdigest()
        assert tracemalloc.get_traced_memory()[1] < 2 * 1024 * 1024
    finally:
        tracemalloc.stop()
    with path.open("ab") as stream:
        stream.write(b"changed")
    assert _sha256_file(path) != expected.hexdigest()


def test_hash_handles_short_reads_and_closes_on_error(tmp_path):
    class ShortReads(io.BytesIO):
        def readinto(self, buffer):
            return super().readinto(memoryview(buffer)[:3])

    stream = ShortReads(b"abcdefghijk")
    with patch("pathlib.Path.open", return_value=stream):
        assert _sha256_file(tmp_path / "worker") == hashlib.sha256(b"abcdefghijk").hexdigest()
    assert stream.closed

    class FailedRead(io.BytesIO):
        def readinto(self, buffer):
            raise OSError("read failed")

    stream = FailedRead()
    with patch("pathlib.Path.open", return_value=stream), pytest.raises(OSError):
        _sha256_file(tmp_path / "worker")
    assert stream.closed
