from __future__ import annotations

import asyncio
import base64
import json
import time
import unittest
from collections.abc import Iterator, Mapping
from pathlib import Path

from cigar_sdk import (
    AsyncCigarClient,
    CallOptions,
    CigarApiError,
    CigarClient,
    OperationRequest,
    PathParameter,
    TransportError,
    TypedOperationRequest,
    ValidationError,
    models,
)
from cigar_sdk.digest import _deterministic_cbor
from cigar_sdk.transport import HttpResponse, StreamResponse

_PROBLEM = (Path(__file__).resolve().parents[2] / "fixtures/problem-index-unavailable-v1.json").read_bytes()


_UUID = "01900000-0000-7000-8000-000000000001"
_DIGEST = "1220" + "1" * 64
_EVENT_PAYLOAD = (
    base64.urlsafe_b64encode(
        _deterministic_cbor(
            {
                "space_id": _UUID,
                "project_id": _UUID,
                "event": {"event_id": _UUID, "kind": "context_committed", "payload_digest": _DIGEST},
            }
        )
    )
    .rstrip(b"=")
    .decode()
)
_EVENT_LINE = (
    f'data: {{"operation_id":"subscribeSpaceEvents","event_id":"event-1","payload_cbor":"{_EVENT_PAYLOAD}"}}\n'
).encode()


def ok(operation_id: str, cursor: str | None = None, payload: object | None = None) -> HttpResponse:
    encoded = base64.urlsafe_b64encode(_deterministic_cbor({} if payload is None else payload)).rstrip(b"=").decode()
    body = {"operation_id": operation_id, "payload_cbor": encoded}
    if cursor is not None:
        body["next_page_cursor"] = cursor
    return HttpResponse(
        200,
        {"content-type": "application/json", "x-cigar-api-version": "1"},
        json.dumps(body).encode(),
    )


def retryable() -> HttpResponse:
    return HttpResponse(
        503,
        {"content-type": "application/problem+json"},
        _PROBLEM,
    )


class FakeStream(StreamResponse):
    def __init__(self, lines: list[bytes], status: int = 200) -> None:
        self.status = status
        self.headers: Mapping[str, str] = {"content-type": "text/event-stream"}
        self.lines = lines
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        return iter(self.lines)

    def close(self) -> None:
        self.closed = True


class FailingStream(FakeStream):
    def __iter__(self) -> Iterator[bytes]:
        yield from self.lines
        raise TransportError("connection reset")


class FakeTransport:
    def __init__(self) -> None:
        self.responses: list[HttpResponse] = []
        self.streams: list[FakeStream] = []
        self.requests: list[tuple[str, str, Mapping[str, str], bytes | None]] = []
        self.stream_headers: list[Mapping[str, str]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        del timeout
        self.requests.append((method, url, dict(headers), body))
        return self.responses.pop(0)

    def stream(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> StreamResponse:
        del method, url, timeout
        self.stream_headers.append(dict(headers))
        return self.streams.pop(0)


class ClientTests(unittest.TestCase):
    def test_all_generated_methods_exist(self) -> None:
        with self.assertRaises(ValidationError):
            CigarClient("http://localhost", allow_insecure_loopback=True, transport=FakeTransport())
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=FakeTransport(), trust_custom_transport=True
        )
        for name in ("compile_context_bundle", "accept_handoff", "reconcile_effect", "run_observational_replay"):
            self.assertTrue(callable(getattr(client, name)))

        self.assertEqual(len(models.PAYLOAD_SCHEMAS), 70)
        for model_name in models.PAYLOAD_SCHEMAS:
            self.assertTrue(callable(getattr(models, model_name)))

    def test_malformed_nominal_response_is_rejected(self) -> None:
        transport = FakeTransport()
        transport.responses = [ok("getVersion", payload={"version": "missing-required-fields"})]
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        with self.assertRaises(ValidationError):
            client.get_version(TypedOperationRequest(models.EmptyRequest()))

    def test_retry_preserves_body_and_idempotency_key(self) -> None:
        transport = FakeTransport()
        transport.responses = [
            retryable(),
            ok(
                "ingestCatalog",
                payload={
                    "revision": 1,
                    "snapshot_id": _UUID,
                    "published_atoms": 1,
                    "tombstoned_atoms": 0,
                    "publication_digest": _DIGEST,
                },
            ),
        ]
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        result = client.ingest_catalog(
            TypedOperationRequest(
                models.IngestCatalogRequest(source_id=_UUID, plan_digest=_DIGEST),
                idempotency_key="fixed-key",
            )
        )
        self.assertEqual(result.payload.revision, 1)
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(transport.requests[0][2]["idempotency-key"], "fixed-key")
        self.assertEqual(transport.requests[0][2]["idempotency-key"], transport.requests[1][2]["idempotency-key"])
        self.assertEqual(transport.requests[0][3], transport.requests[1][3])

    def test_dispatch_is_never_retried(self) -> None:
        transport = FakeTransport()
        transport.responses = [retryable(), ok("dispatchEffect")]
        client = CigarClient(
            "http://localhost",
            allow_insecure_loopback=True,
            max_attempts=8,
            transport=transport,
            trust_custom_transport=True,
        )
        with self.assertRaises(CigarApiError):
            client.dispatch_effect(
                TypedOperationRequest(
                    models.EffectIdRequest(effect_id=_UUID),
                    idempotency_key="dispatch-key",
                    expected_revision="revision-1",
                )
            )
        self.assertEqual(len(transport.requests), 1)

    def test_pagination_and_stream_resume(self) -> None:
        transport = FakeTransport()
        transport.responses = [ok("getSpaceLog", "cursor-2"), ok("getSpaceLog")]
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        request = OperationRequest(path_parameters=(PathParameter("space_id", "space-1"),), page_size=10)
        self.assertEqual(len(list(client.paginate("getSpaceLog", request))), 2)
        self.assertIn("page_cursor=cursor-2", transport.requests[1][1])

        transport.streams = [
            FakeStream(
                [
                    b"id: event-1\n",
                    _EVENT_LINE,
                    b"\n",
                ]
            )
        ]
        with client.subscribe_space_events(
            TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID)),
            options=CallOptions(max_attempts=1, resume_from="event-0"),
        ) as stream:
            events = list(stream)
            self.assertEqual(events[0].event_id, "event-1")
            self.assertEqual(events[0].payload.space_id, _UUID)
            self.assertEqual(stream.last_event_id, "event-1")
            self.assertEqual(transport.stream_headers[0]["last-event-id"], "event-0")

    def test_stream_reconnect_deduplicates_and_never_moves_resume_backward(self) -> None:
        transport = FakeTransport()
        second = _EVENT_LINE.replace(b"event-1", b"event-2")
        transport.streams = [
            FailingStream([b"id: event-1\n", _EVENT_LINE, b"\n"]),
            FakeStream([b"id: event-1\n", _EVENT_LINE, b"\n", b"id: event-2\n", second, b"\n"]),
        ]
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        with client.subscribe_space_events(
            TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID)),
            options=CallOptions(max_attempts=2, resume_from="event-0"),
        ) as stream:
            self.assertEqual([event.event_id for event in stream], ["event-1", "event-2"])
            self.assertEqual(stream.last_event_id, "event-2")
        self.assertEqual([headers.get("last-event-id") for headers in transport.stream_headers], ["event-0", "event-1"])

    def test_missing_mutation_metadata_fails_before_network(self) -> None:
        transport = FakeTransport()
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        with self.assertRaises(ValidationError):
            client.fork_space(TypedOperationRequest(models.ForkSpaceRequest(space_id=_UUID, fork={})))
        self.assertEqual(transport.requests, [])

    def test_typed_handoff_reconciliation_and_replay_workflows(self) -> None:
        transport = FakeTransport()
        transport.responses = [
            ok(
                "acceptHandoff",
                payload={
                    "schema_version": "cigar.handoff-acceptance.v1",
                    "acceptance_id": _UUID,
                    "handoff_id": _UUID,
                    "recipient_id": _UUID,
                    "accepted_capabilities": ["read_context"],
                    "rejected_capabilities": [],
                    "unavailable_references": [],
                    "policy_digest": _DIGEST,
                    "bundle_id": _DIGEST,
                    "accepted_at": "2026-01-01T00:00:00Z",
                    "acknowledgement_digest": _DIGEST,
                },
            ),
            ok(
                "reconcileEffect",
                payload={
                    "effect_id": _UUID,
                    "state": "succeeded",
                    "effect_version": 2,
                    "intent_digest": _DIGEST,
                    "attempt_count": 1,
                    "reconciliation_count": 1,
                },
            ),
            ok(
                "runObservationalReplay",
                payload={
                    "schema_version": "cigar.replay-execution.v1",
                    "execution_id": _UUID,
                    "request_id": _UUID,
                    "mode": "observational",
                    "status": "complete",
                    "completeness": {"available": ["bundle"], "missing": []},
                    "egress_permitted": False,
                    "effect_dispatch_permitted": False,
                    "started_at": "2026-01-01T00:00:00Z",
                },
            ),
        ]
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        handoff = client.accept_handoff(
            TypedOperationRequest(
                models.AcceptHandoffRequest(handoff_id=_UUID, target_plan_id=_UUID),
                idempotency_key="accept-1",
                expected_revision="revision-1",
            )
        )
        effect = client.reconcile_effect(
            TypedOperationRequest(
                models.EffectIdRequest(effect_id=_UUID),
                idempotency_key="reconcile-1",
                expected_revision="revision-2",
            )
        )
        replay = client.run_observational_replay(
            TypedOperationRequest(models.ReplayIdRequest(replay_id=_UUID), idempotency_key="replay-1")
        )
        self.assertEqual(handoff.payload.accepted_capabilities, ("read_context",))
        self.assertEqual(effect.payload.state, "succeeded")
        self.assertEqual(replay.payload.mode, "observational")


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_facade_calls_and_streams(self) -> None:
        transport = FakeTransport()
        transport.responses = [
            ok(
                "getVersion",
                payload={
                    "version": "0.1.0",
                    "source_revision": "revision",
                    "protocol_min": "1",
                    "protocol_max": "1",
                    "build_profile": "test",
                    "enabled_features": [],
                },
            )
        ]
        client = AsyncCigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        response = await client.get_version(TypedOperationRequest(models.EmptyRequest()))
        self.assertEqual(response.operation_id, "getVersion")

        transport.streams = [
            FakeStream(
                [
                    b"id: event-1\n",
                    _EVENT_LINE,
                    b"\n",
                ]
            )
        ]
        async with client.subscribe_space_events(
            TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID)),
            options=CallOptions(max_attempts=1),
        ) as stream:
            event = await anext(stream)
            self.assertEqual(event.event_id, "event-1")

    async def test_transport_security_and_exact_problem_contract(self) -> None:
        with self.assertRaises(ValidationError):
            CigarClient("http://example.com")
        with self.assertRaises(ValidationError):
            CigarClient("https://example.com/prefix")

        missing_type = FakeTransport()
        missing_type.responses = [HttpResponse(200, {}, b'{"operation_id":"getVersion","payload_cbor":""}')]
        client = AsyncCigarClient(
            "http://localhost",
            allow_insecure_loopback=True,
            max_attempts=1,
            transport=missing_type,
            trust_custom_transport=True,
        )
        with self.assertRaises(TransportError):
            await client.get_version(TypedOperationRequest(models.EmptyRequest()))

        wrong_problem = json.loads(_PROBLEM)
        wrong_problem["retry"] = "never"
        mismatch = FakeTransport()
        mismatch.responses = [
            HttpResponse(
                503,
                {"content-type": "application/problem+json"},
                json.dumps(wrong_problem).encode(),
            )
        ]
        client = AsyncCigarClient(
            "http://localhost",
            allow_insecure_loopback=True,
            max_attempts=1,
            transport=mismatch,
            trust_custom_transport=True,
        )
        with self.assertRaises(TransportError):
            await client.get_version(TypedOperationRequest(models.EmptyRequest()))

        oversized = AsyncCigarClient(
            "http://localhost",
            allow_insecure_loopback=True,
            bearer_token="x" * 8193,
            transport=FakeTransport(),
            trust_custom_transport=True,
        )
        with self.assertRaises(ValidationError):
            await oversized.get_version(TypedOperationRequest(models.EmptyRequest()))

    async def test_async_call_cancellation_returns_promptly(self) -> None:
        transport = FakeTransport()
        transport.responses = [ok("getVersion", payload={})]

        original_request = transport.request

        def delayed_request(*args: object, **kwargs: object) -> HttpResponse:
            time.sleep(0.2)
            return original_request(*args, **kwargs)  # type: ignore[arg-type]

        transport.request = delayed_request  # type: ignore[method-assign]
        client = AsyncCigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        task = asyncio.create_task(client.get_version(TypedOperationRequest(models.EmptyRequest())))
        await asyncio.sleep(0.01)
        started = time.monotonic()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertLess(time.monotonic() - started, 0.1)


if __name__ == "__main__":
    unittest.main()
