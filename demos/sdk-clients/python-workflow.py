#!/usr/bin/env python3
"""Exercise the public Python SDK against the shared recorded workflow."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Never
from urllib.parse import urlsplit

from cigar_sdk import (
    AsyncCigarClient,
    TypedOperationRequest,
    bundle_id,
    models,
    verify_bundle,
)
from cigar_sdk.digest import _deterministic_cbor, _normalize
from cigar_sdk.models_runtime import payload_value
from cigar_sdk.transport import HttpResponse

FIXTURE = Path(__file__).with_name("workflow-fixture-v1.json")
BASE_URL = "http://127.0.0.1:1"


def fail(message: str) -> Never:
    raise RuntimeError(message)


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("workflow fixture contains a duplicate JSON key")
        result[key] = value
    return result


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def manifest_id(value: Mapping[str, Any]) -> str:
    fields = dict(value)
    fields.pop("manifest_id", None)
    encoded = _deterministic_cbor([3, _normalize(fields)])
    return "1220" + hashlib.sha256(b"CIGAR-MANIFEST\0v1\0" + encoded).hexdigest()


class RecordedTransport:
    def __init__(self, fixture: Mapping[str, Any]) -> None:
        self._operations = list(fixture["operations"])
        self._position = 0

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        if not 0 < timeout <= 300:
            fail("SDK supplied an invalid bounded timeout")
        if self._position >= len(self._operations):
            fail("SDK issued an unexpected extra operation")
        operation = self._operations[self._position]
        self._position += 1
        operation_id = operation["operation_id"]
        if headers.get("x-cigar-operation-id") != operation_id:
            fail("SDK operation header differs from the recorded operation")
        path = urlsplit(url).path
        expected_paths = {
            "discoverSources": "/v1/sources:discover",
            "ingestCatalog": "/v1/catalog:ingest",
            "createContextPlan": "/v1/context/plans",
            "compileContextBundle": "/v1/context/bundles:compile",
        }
        if operation_id == "getContextBundleManifest":
            expected_path = f"/v1/context/bundles/{operation['path_parameters'][0]['value']}/manifest"
        else:
            expected_path = expected_paths[operation_id]
        expected_method = (
            "GET" if operation_id == "getContextBundleManifest" else "POST"
        )
        if method != expected_method or path != expected_path:
            fail("SDK method or bound operation path differs from the fixture")
        expected_key = operation["idempotency_key"]
        if headers.get("idempotency-key") != expected_key:
            fail("SDK idempotency key differs from the recorded request")
        if method == "GET":
            if body is not None:
                fail("SDK emitted a body for a GET operation")
        else:
            try:
                wire = json.loads(body or b"", object_pairs_hook=unique)
            except (json.JSONDecodeError, UnicodeError) as error:
                raise RuntimeError("SDK request wrapper is not strict JSON") from error
            if wire.get("operation_id") != operation_id:
                fail("SDK request wrapper operation differs from the fixture")
            if wire.get("payload_cbor") != operation["request_cbor_base64url"]:
                fail("SDK typed request CBOR differs from the recorded request")
            if wire.get("path_parameters") != operation["path_parameters"]:
                fail("SDK request path parameters differ from the fixture")
            if wire.get("idempotency_key") != expected_key:
                fail("SDK request idempotency field differs from the fixture")
        response = json.dumps(
            {
                "operation_id": operation_id,
                "payload_cbor": operation["response_cbor_base64url"],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return HttpResponse(
            status=200,
            headers={
                "content-type": "application/json",
                "content-length": str(len(response)),
                "x-cigar-api-version": "1",
            },
            body=response,
        )

    def stream(self, *args: object, **kwargs: object) -> Never:
        del args, kwargs
        fail("recorded workflow does not permit streaming operations")

    def assert_complete(self) -> None:
        if self._position != len(self._operations):
            fail("SDK did not execute every recorded workflow operation")


async def execute() -> str:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if fixture.get("schema_version") != "cigar.sdk-recorded-workflow.v1":
        fail("workflow fixture schema is unsupported")
    if [
        item.get("operation_id") for item in fixture.get("operations", [])
    ] != fixture.get("expected_operations"):
        fail("workflow fixture operation inventory is incomplete")
    for operation in fixture["operations"]:
        if (
            b64url(_deterministic_cbor(operation["request"]))
            != operation["request_cbor_base64url"]
            or b64url(_deterministic_cbor(operation["response"]))
            != operation["response_cbor_base64url"]
        ):
            fail("workflow fixture contains non-canonical operation CBOR")
    contract = next(
        item["request"]["contract"]
        for item in fixture["operations"]
        if item["operation_id"] == "createContextPlan"
    )
    contract_digest = (
        "1220"
        + hashlib.sha256(
            b"CIGAR-CONTEXT-CONTRACT\0v1\0" + _deterministic_cbor(_normalize(contract))
        ).hexdigest()
    )
    if contract_digest != fixture["expected_contract_digest"]:
        fail("workflow contract digest differs from its canonical request")
    transport = RecordedTransport(fixture)
    requests = {item["operation_id"]: item for item in fixture["operations"]}
    async with AsyncCigarClient(
        BASE_URL,
        transport=transport,
        trust_custom_transport=True,
        allow_insecure_loopback=True,
        max_attempts=1,
    ) as client:
        discovered = await client.discover_sources(
            TypedOperationRequest(
                models.DiscoverSourcesRequest(
                    source_id=requests["discoverSources"]["request"]["source_id"],
                    include_paths=tuple(
                        requests["discoverSources"]["request"]["include_paths"]
                    ),
                )
            )
        )
        ingested = await client.ingest_catalog(
            TypedOperationRequest(
                models.IngestCatalogRequest(**requests["ingestCatalog"]["request"]),
                idempotency_key=requests["ingestCatalog"]["idempotency_key"],
            )
        )
        planned = await client.create_context_plan(
            TypedOperationRequest(
                models.CreateContextPlanRequest(
                    **requests["createContextPlan"]["request"]
                ),
                idempotency_key=requests["createContextPlan"]["idempotency_key"],
            )
        )
        compiled = await client.compile_context_bundle(
            TypedOperationRequest(
                models.CompileContextBundleRequest(
                    **requests["compileContextBundle"]["request"]
                ),
                idempotency_key=requests["compileContextBundle"]["idempotency_key"],
            )
        )
        manifest = await client.get_context_bundle_manifest(
            TypedOperationRequest(
                models.BundleIdRequest(
                    **requests["getContextBundleManifest"]["request"]
                )
            )
        )
    transport.assert_complete()
    if discovered.payload.plan_digest != ingested.payload.publication_digest.replace(
        "c", "b"
    ):
        fail("discovery and ingestion fixture chain is inconsistent")
    if planned.payload.bundle_id != fixture["expected_bundle_id"]:
        fail("planned bundle identity differs from the workflow fixture")
    bundle = payload_value(compiled.payload)
    verify_bundle(bundle)
    if bundle_id(bundle) != fixture["expected_bundle_id"]:
        fail("compiled bundle identity verification failed")
    manifest_value = payload_value(manifest.payload)
    if manifest_id(manifest_value) != fixture["expected_manifest_id"]:
        fail("selection manifest identity verification failed")
    if (
        bundle["manifest_digest"] != manifest_value["manifest_id"]
        or bundle["contract_digest"] != manifest_value["contract_digest"]
        or bundle["contract_digest"] != fixture["expected_contract_digest"]
    ):
        fail("compiled bundle and manifest are not bound to the same contract")
    return fixture["expected_bundle_id"]


def main() -> None:
    print(asyncio.run(execute()))


if __name__ == "__main__":
    main()
