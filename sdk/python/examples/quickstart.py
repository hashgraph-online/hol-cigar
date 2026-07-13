"""Verify the shared identity and optionally execute the async daemon workflow."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from importlib import resources  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2

from cigar_sdk import AsyncCigarClient, CallOptions, TypedOperationRequest, bundle_id, create_idempotency_key, models
from cigar_sdk.digest import verify_bundle


async def main() -> None:
    source = resources.files("cigar_sdk.fixtures").joinpath("semantic-bundle-v1.json").read_text(encoding="utf-8")
    fixture = json.loads(source)
    verify_bundle(fixture["bundle"])
    identity = bundle_id(fixture["bundle"])
    if identity != fixture["expected_bundle_id"]:
        raise ValueError("shared semantic bundle identity differs")

    endpoint = os.environ.get("CIGAR_URL")
    if endpoint is not None:
        plan_id = os.environ.get("CIGAR_PLAN_ID")
        if plan_id is None:
            raise ValueError("CIGAR_PLAN_ID is required with CIGAR_URL")
        async with AsyncCigarClient(
            endpoint,
            bearer_token=os.environ.get("CIGAR_TOKEN"),
            allow_insecure_loopback=endpoint.startswith("http://"),
        ) as client:
            await client.negotiate(options=CallOptions(timeout=5.0))
            compiled = await client.compile_context_bundle(
                TypedOperationRequest(
                    models.CompileContextBundleRequest(plan_id=plan_id),
                    idempotency_key=create_idempotency_key("quickstart"),
                )
            )
            if compiled.payload.bundle_id != identity:
                raise ValueError("daemon bundle identity differs from the shared fixture")
            manifest = await client.get_context_bundle_manifest(
                TypedOperationRequest(models.BundleIdRequest(bundle_id=compiled.payload.bundle_id))
            )
            print(f"verified daemon manifest {manifest.payload.manifest_id}", file=sys.stderr)
    print(identity)


if __name__ == "__main__":
    asyncio.run(main())
