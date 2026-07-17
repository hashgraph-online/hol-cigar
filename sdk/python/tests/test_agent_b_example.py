from __future__ import annotations

import asyncio
from typing import cast

from cigar_sdk import AsyncCigarClient
from cigar_sdk.examples.agent_b_handoff import AgentBWork, execute
from cigar_sdk.generated import models
from cigar_sdk.types import TypedOperationRequest, TypedOperationResponse


class FakeClient:
    def __init__(self) -> None:
        self.requests: list[TypedOperationRequest[object]] = []

    async def accept_handoff(
        self, request: TypedOperationRequest[object], **_kwargs: object
    ) -> TypedOperationResponse[models.HandoffAcceptance]:
        self.requests.append(request)
        return TypedOperationResponse(
            operation_id="acceptHandoff",
            payload=models.HandoffAcceptance(
                schema_version="cigar.handoff-acceptance.v1",
                acceptance_id="11111111-1111-7111-8111-111111111111",
                handoff_id="22222222-2222-7222-8222-222222222222",
                recipient_id="33333333-3333-7333-8333-333333333333",
                accepted_capabilities=("read_context",),
                rejected_capabilities=(),
                unavailable_references=(),
                policy_digest="1220" + "a" * 64,
                bundle_id="1220" + "b" * 64,
                accepted_at="2026-07-14T00:00:00Z",
                acknowledgement_digest="1220" + "c" * 64,
            ),
            payload_cbor=b"acceptance",
        )

    async def record_handoff_result(
        self, request: TypedOperationRequest[object], **_kwargs: object
    ) -> TypedOperationResponse[models.HandoffResultReceipt]:
        self.requests.append(request)
        return TypedOperationResponse(
            operation_id="recordHandoffResult",
            payload=models.HandoffResultReceipt(
                delta_id="44444444-4444-7444-8444-444444444444",
                handoff_id="22222222-2222-7222-8222-222222222222",
                result_digest="1220" + "d" * 64,
                revision=8,
            ),
            payload_cbor=b"result",
        )


def test_agent_b_uses_two_idempotent_mutations_and_requests_no_new_authority() -> None:
    client = FakeClient()
    summary = asyncio.run(
        execute(
            cast(AsyncCigarClient, client),
            AgentBWork(
                handoff_id="22222222-2222-7222-8222-222222222222",
                target_plan_id="55555555-5555-7555-8555-555555555555",
                base_commit_id="1220" + "e" * 64,
                expected_revision=7,
                claim="The requested invariant holds.",
                evidence=("1220" + "f" * 64,),
                accept_idempotency_key="agent-b-accept-fixture",
                result_idempotency_key="agent-b-result-fixture",
            ),
        )
    )
    assert summary["revision"] == 8
    assert len(client.requests) == 2
    acceptance, result = client.requests
    assert acceptance.idempotency_key == "agent-b-accept-fixture"
    assert result.idempotency_key == "agent-b-result-fixture"
    assert result.expected_revision == "7"
    assert isinstance(result.payload, models.RecordHandoffResultRequest)
    assert result.payload.requested_followup_capabilities == ()
