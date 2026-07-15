from __future__ import annotations

import base64
import http.server
import threading
import time
import unittest
from collections.abc import Iterator, Mapping
from importlib import resources

from cigar_sdk import (
    CallOptions,
    CigarClient,
    CigarTimeoutError,
    TransportError,
    TypedOperationRequest,
    ValidationError,
    models,
)
from cigar_sdk.errors import CigarApiError, ProblemDetails
from cigar_sdk.models_runtime import decode_operation_payload, encode_operation_payload, payload_value
from cigar_sdk.transport import HttpResponse, StreamResponse

_UUID = "01900000-0000-7000-8000-000000000001"
_DIGEST = "1220" + "1" * 64
_PROBLEM = resources.files("cigar_sdk.fixtures").joinpath("problem-index-unavailable-v1.json").read_bytes()


class _FakeStream(StreamResponse):
    def __init__(self, lines: list[bytes]) -> None:
        self.status = 200
        self.headers: Mapping[str, str] = {"content-type": "text/event-stream"}
        self.lines = lines

    def __iter__(self) -> Iterator[bytes]:
        return iter(self.lines)

    def close(self) -> None:
        return None


class _Transport:
    def __init__(self, response: HttpResponse | None = None, delay: float = 0.0) -> None:
        self.response = response
        self.delay = delay
        self.calls = 0
        self.stream_response: StreamResponse | None = None

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        del method, url, headers, body, timeout
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        assert self.response is not None
        return self.response

    def stream(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> StreamResponse:
        del method, url, headers, timeout
        assert self.stream_response is not None
        return self.stream_response


class HardeningTests(unittest.TestCase):
    def test_schema_is_deeply_immutable_and_pattern_properties_work(self) -> None:
        schema = models.PAYLOAD_SCHEMAS["ContextBundle"]
        with self.assertRaises(TypeError):
            schema["properties"] = {}  # type: ignore[index]
        properties = schema["properties"]
        with self.assertRaises(TypeError):
            properties["bundle_id"] = {}  # type: ignore[index]

        bundle = models.ContextBundle(
            schema_version="cigar.context-bundle.v1",
            bundle_id=_DIGEST,
            contract_digest=_DIGEST,
            manifest_digest=_DIGEST,
            blocks=(),
            total_tokens=0,
            extensions={"valid.key": {"type": "integer", "value": -1}},
        )
        self.assertEqual(payload_value(bundle)["extensions"]["valid.key"]["value"], -1)
        invalid = models.ContextBundle(
            schema_version="cigar.context-bundle.v1",
            bundle_id=_DIGEST,
            contract_digest=_DIGEST,
            manifest_digest=_DIGEST,
            blocks=(),
            total_tokens=0,
            extensions={"INVALID KEY": {"type": "text", "value": "x"}},
        )
        with self.assertRaises(ValidationError):
            payload_value(invalid)

    def test_optional_none_is_omitted_and_encodable(self) -> None:
        request = models.AuthorizeEffectRequest(effect_id=_UUID)
        self.assertNotIn("approval", payload_value(request))
        self.assertTrue(encode_operation_payload(request))

    def test_problem_details_are_deeply_immutable(self) -> None:
        details: dict[str, object] = {"nested": [{"value": "before"}]}
        error = CigarApiError(
            503,
            ProblemDetails(
                schema_version="cigar.problem.v1",
                code="INDEX_UNAVAILABLE",
                numeric_code=1,
                http_status=503,
                retry="after_backoff",
                message="message",
                remediation="remediation",
                correlation_id=_UUID,
                details=details,
            ),
        )
        details["nested"] = [{"value": "after"}]
        nested = error.details["nested"]
        self.assertIsInstance(nested, tuple)
        item = nested[0]  # type: ignore[index]
        self.assertIsInstance(item, Mapping)
        self.assertEqual(item["value"], "before")
        with self.assertRaises(TypeError):
            item["value"] = "tampered"

    def test_deadline_and_injected_body_bounds(self) -> None:
        retry = _Transport(
            HttpResponse(503, {"content-type": "application/problem+json"}, _PROBLEM),
            delay=0.03,
        )
        client = CigarClient(
            "http://localhost",
            allow_insecure_loopback=True,
            max_attempts=8,
            transport=retry,
            trust_custom_transport=True,
        )
        started = time.monotonic()
        with self.assertRaises(CigarTimeoutError):
            client.get_version(TypedOperationRequest(models.EmptyRequest()), options=CallOptions(timeout=0.05))
        self.assertLess(time.monotonic() - started, 0.15)
        self.assertEqual(retry.calls, 1)

        oversized = _Transport(
            HttpResponse(
                200,
                {"content-type": "application/json", "content-length": "999999999"},
                b"{}",
            )
        )
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=oversized, trust_custom_transport=True
        )
        with self.assertRaises(TransportError):
            client.get_version(TypedOperationRequest(models.EmptyRequest()))

    def test_event_unknown_fields_and_codec_nesting_fail_closed(self) -> None:
        event_payload = (
            base64.urlsafe_b64encode(
                encode_operation_payload(
                    models.SpaceEventPayload(
                        space_id=_UUID,
                        project_id=_UUID,
                        event={"event_id": _UUID, "kind": "context_committed", "payload_digest": _DIGEST},
                    )
                )
            )
            .rstrip(b"=")
            .decode()
        )
        transport = _Transport()
        transport.stream_response = _FakeStream(
            [
                b"id: event-1\n",
                (
                    'data: {"operation_id":"subscribeSpaceEvents","event_id":"event-1",'
                    f'"payload_cbor":"{event_payload}","extra":true}}\n'
                ).encode(),
                b"\n",
            ]
        )
        client = CigarClient(
            "http://localhost", allow_insecure_loopback=True, transport=transport, trust_custom_transport=True
        )
        stream = client.subscribe_space_events(
            TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID)),
            options=CallOptions(max_attempts=1),
        )
        with self.assertRaises(TransportError):
            next(stream)

        nested: object = "leaf"
        for _ in range(66):
            nested = [nested]
        with self.assertRaises(ValidationError):
            encode_operation_payload(models.ForkSpaceRequest(space_id=_UUID, fork={"nested": nested}))
        with self.assertRaises(ValidationError):
            decode_operation_payload(bytes([0x9A, 0x00, 0x01, 0x86, 0xA1]))


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        del format, args


class RedirectTests(unittest.TestCase):
    def test_default_transport_does_not_follow_redirect_with_credentials(self) -> None:
        target_calls: list[str | None] = []

        class Target(_QuietHandler):
            def do_GET(self) -> None:
                target_calls.append(self.headers.get("authorization"))
                self.send_response(200)
                self.end_headers()

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()

        class Origin(_QuietHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("location", f"http://127.0.0.1:{target.server_port}/target")
                self.end_headers()

        origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
        origin_thread.start()
        try:
            client = CigarClient(
                f"http://127.0.0.1:{origin.server_port}",
                allow_insecure_loopback=True,
                bearer_token="secret",
                max_attempts=1,
            )
            with self.assertRaises(TransportError):
                client.get_version(TypedOperationRequest(models.EmptyRequest()))
            self.assertEqual(target_calls, [])
        finally:
            origin.shutdown()
            target.shutdown()
            origin.server_close()
            target.server_close()


if __name__ == "__main__":
    unittest.main()
