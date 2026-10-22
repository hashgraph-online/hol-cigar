"""Absolute deadlines through the real urllib/HTTP parser, without network access."""

from __future__ import annotations

import asyncio
import io
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_client import _UUID, FakeStream, FakeTransport, ok

from cigar_sdk import AsyncCigarClient, CallOptions, CigarClient, TypedOperationRequest, models
from cigar_sdk.errors import CigarTimeoutError
from cigar_sdk.transport import UrllibTransport


class Clock:
    now = 0.0

    def monotonic(self):
        return self.now


class WireSocket:
    """One byte per recv, with controllable elapsed time and real HTTP framing."""

    def __init__(self, wire, clock, slow_after, interval):
        self.wire = wire
        self.clock = clock
        self.slow_after = slow_after
        self.interval = interval
        self.offset = 0
        self.timeouts = []
        self.readers = []
        self.aborted = False

    def setsockopt(self, *_):
        pass

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, _):
        pass

    def close(self):
        pass  # A makefile reference owns the receive side, just like a real socket.

    def shutdown(self, _):
        self.aborted = True

    def makefile(self, mode, buffering=-1):
        assert mode == "rb"
        owner = self

        class Raw(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, target):
                if owner.offset >= len(owner.wire):
                    return 0
                if owner.offset >= owner.slow_after:
                    owner.clock.now += owner.interval
                target[0] = owner.wire[owner.offset]
                owner.offset += 1
                return 1

        raw = Raw()
        self.readers.append(raw)
        return raw if buffering == 0 else io.BufferedReader(raw)


@pytest.mark.parametrize("phase", ["headers", "body", "chunked", "problem", "events"])
@pytest.mark.parametrize("slow", [False, True])
def test_absolute_deadline_covers_each_http_read_phase(monkeypatch, phase, slow):
    clock = Clock()
    status = b"400 Bad Request" if phase == "problem" else b"200 OK"
    payload = b": heartbeat\n\n" * 8 if phase == "events" else b"x" * 40
    headers = b"Content-Type: text/event-stream\r\n" if phase == "events" else b""
    if phase == "chunked":
        headers += b"Transfer-Encoding: chunked\r\n"
        body = b"1\r\nx\r\n" * 40 + b"0\r\n\r\n"
    else:
        headers += b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        body = payload
    head = b"HTTP/1.1 " + status + b"\r\n" + headers + b"\r\n"
    wire = WireSocket(head + body, clock, 0 if phase == "headers" else len(head), 0.04 if slow else 0)
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: wire)
    transport = UrllibTransport()

    def consume():
        if phase == "events":
            response = transport.stream("GET", "http://127.0.0.1/", {}, 0.15)
            try:
                return b"".join(response)
            finally:
                response.close()
        return transport.request("GET", "http://127.0.0.1/", {}, None, 0.15).body

    if slow:
        with pytest.raises(CigarTimeoutError):
            consume()
        assert clock.now <= 0.20
        assert wire.offset < len(wire.wire)
        assert wire.timeouts[-1] < wire.timeouts[0]
    else:
        assert consume() == payload
    assert all(reader.closed for reader in wire.readers)


def test_custom_transport_cannot_return_success_after_deadline(monkeypatch):
    clock = Clock()
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    transport = FakeTransport()

    def late(*_):
        clock.now = 2.0
        return ok("getVersion")

    transport.request = late
    client = CigarClient(
        "https://fixture.invalid",
        bearer_token="fixture",
        transport=transport,
        trust_custom_transport=True,
        max_attempts=1,
    )
    with pytest.raises(CigarTimeoutError):
        client.get_version(TypedOperationRequest(models.EmptyRequest()), options=CallOptions(timeout=1))


@pytest.mark.parametrize("status", [200, 400])
def test_comment_and_problem_streams_share_the_total_deadline(monkeypatch, status):
    clock = Clock()
    monkeypatch.setattr("time.monotonic", clock.monotonic)

    class Drip(FakeStream):
        def __iter__(self):
            for _ in range(100):
                clock.now += 0.04
                yield b": keepalive\n\n"

    response = Drip([], status)
    transport = FakeTransport()
    transport.streams = [response]
    client = CigarClient(
        "https://fixture.invalid",
        bearer_token="fixture",
        transport=transport,
        trust_custom_transport=True,
        max_attempts=1,
    )
    with pytest.raises(CigarTimeoutError):
        list(
            client.subscribe_space_events(
                TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID)), options=CallOptions(timeout=0.15)
            )
        )
    assert response.closed and clock.now <= 0.20


def test_async_cancellation_closes_without_waiting_for_a_free_executor_thread():
    entered = threading.Event()
    released = threading.Event()

    class Blocking(FakeStream):
        def __iter__(self):
            entered.set()
            assert released.wait(2), "cancellation did not release the reader"
            return iter([])

        def close(self):
            super().close()
            released.set()

    async def run():
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
        transport = FakeTransport()
        response = Blocking([])
        transport.streams = [response]
        client = AsyncCigarClient(
            "https://fixture.invalid",
            bearer_token="fixture",
            transport=transport,
            trust_custom_transport=True,
            max_attempts=1,
        )
        stream = client.subscribe_space_events(TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID)))
        pending = asyncio.create_task(anext(stream))
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.005)
        assert entered.is_set()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert response.closed and released.is_set()
        await stream.aclose()

    try:
        asyncio.run(run())
    finally:
        released.set()
