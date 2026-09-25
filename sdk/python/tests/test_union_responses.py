"""Shared response bytes must decode successfully in both public clients."""

from __future__ import annotations

import base64
import json
import unittest
from importlib import resources

from test_client import FakeTransport

from cigar_sdk import CigarClient, TypedOperationRequest, ValidationError, models
from cigar_sdk.digest import _deterministic_cbor
from cigar_sdk.models_runtime import construct_payload, decode_operation_payload, payload_value
from cigar_sdk.transport import HttpResponse

_FIXTURE = json.loads(
    resources.files("cigar_sdk.fixtures").joinpath("union-responses-v1.json").read_text(encoding="utf-8")
)


def payload_bytes(vector: dict) -> bytes:
    encoded = vector["payload_cbor"]
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


class UnionResponseTests(unittest.TestCase):
    def check_value(self, vector: dict, payload: object) -> None:
        value = payload_value(payload)
        self.assertEqual(_deterministic_cbor(value), payload_bytes(vector))
        for expected in vector.get("integers", []):
            actual = value
            for key in expected["path"]:
                actual = actual[key]
            self.assertIs(type(actual), int)
            self.assertEqual(str(actual), expected["decimal"])

    def test_valid_shared_response_variants(self) -> None:
        for vector in _FIXTURE["valid"]:
            with self.subTest(vector=vector["name"]):
                decoded = decode_operation_payload(payload_bytes(vector))
                payload = construct_payload(getattr(models, vector["response_type"]), decoded)
                self.check_value(vector, payload)

    def test_invalid_shared_response_variants(self) -> None:
        for vector in _FIXTURE["invalid"]:
            with self.subTest(vector=vector["name"]), self.assertRaises(ValidationError):
                construct_payload(
                    getattr(models, vector["response_type"]), decode_operation_payload(payload_bytes(vector))
                )

    def test_publish_space_response_variants_without_repeating_mutations(self) -> None:
        for accepted, vectors in [(True, _FIXTURE["valid"]), (False, _FIXTURE["invalid"])]:
            for vector in vectors:
                if vector["response_type"] != "SpacePublishResponse":
                    continue
                with self.subTest(vector=vector["name"]):
                    transport = FakeTransport()
                    transport.responses = [HttpResponse(
                        200, {"content-type": "application/json", "x-cigar-api-version": "1"},
                        json.dumps({"operation_id": "publishSpace", "payload_cbor": vector["payload_cbor"]}).encode(),
                    )]
                    client = CigarClient(
                        "http://localhost", allow_insecure_loopback=True,
                        transport=transport, trust_custom_transport=True,
                    )
                    request = TypedOperationRequest(
                        models.PublishSpaceRequest(
                            space_id=_FIXTURE["uuid"], overlay_id=_FIXTURE["uuid"],
                            purpose="Offline response decoding regression",
                        ),
                        idempotency_key="union-response-regression", expected_revision="revision-1",
                    )
                    if accepted:
                        response = client.publish_space(request)
                        self.assertEqual(response.payload_cbor, payload_bytes(vector))
                        self.check_value(vector, response.payload)
                    else:
                        with self.assertRaises(ValidationError):
                            client.publish_space(request)
                    self.assertEqual(len(transport.requests), 1)
                    self.assertEqual(transport.requests[0][0], "POST")
                    self.assertEqual(
                        transport.requests[0][1], f"http://localhost/v1/spaces/{_FIXTURE['uuid']}:publish"
                    )


if __name__ == "__main__":
    unittest.main()
