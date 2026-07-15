"""Accept a Honey handoff as Agent B and return one typed, evidence-backed result."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import dataclass

from cigar_sdk import AsyncCigarClient, CallOptions, TypedOperationRequest, models, validate_idempotency_key


@dataclass(frozen=True, slots=True)
class AgentBWork:
    """Inputs already issued to the recipient through the governed handoff workflow."""

    handoff_id: str
    target_plan_id: str
    base_commit_id: str
    expected_revision: int
    claim: str
    evidence: tuple[str, ...]
    accept_idempotency_key: str
    result_idempotency_key: str


async def execute(client: AsyncCigarClient, work: AgentBWork) -> dict[str, object]:
    """Accept and record a result without requesting additional capabilities."""

    acceptance = await client.accept_handoff(
        TypedOperationRequest(
            models.AcceptHandoffRequest(
                handoff_id=work.handoff_id,
                target_plan_id=work.target_plan_id,
            ),
            idempotency_key=validate_idempotency_key(work.accept_idempotency_key),
        ),
        options=CallOptions(timeout=30.0, max_attempts=3),
    )
    if acceptance.payload.handoff_id != work.handoff_id:
        raise ValueError("daemon returned an acceptance for a different handoff")

    result = await client.record_handoff_result(
        TypedOperationRequest(
            models.RecordHandoffResultRequest(
                handoff_id=work.handoff_id,
                base_commit_id=work.base_commit_id,
                claims=({"claim": work.claim, "evidence": work.evidence},),
                decisions=(),
                artifacts=(),
                source_changes=(),
                verifier_receipts=work.evidence,
                unresolved_questions=(),
                blockers=(),
                effect_references=(),
                requested_followup_capabilities=(),
            ),
            idempotency_key=validate_idempotency_key(work.result_idempotency_key),
            expected_revision=str(work.expected_revision),
        ),
        options=CallOptions(timeout=30.0, max_attempts=3),
    )
    if result.payload.handoff_id != work.handoff_id:
        raise ValueError("daemon returned a result receipt for a different handoff")
    return {
        "handoff_id": result.payload.handoff_id,
        "acceptance_id": acceptance.payload.acceptance_id,
        "accepted_capabilities": acceptance.payload.accepted_capabilities,
        "unavailable_reference_count": len(acceptance.payload.unavailable_references),
        "delta_id": result.payload.delta_id,
        "result_digest": result.payload.result_digest,
        "revision": result.payload.revision,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("CIGAR_URL"))
    parser.add_argument("--handoff-id", required=True)
    parser.add_argument("--target-plan-id", required=True)
    parser.add_argument("--base-commit-id", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--evidence", required=True, action="append")
    parser.add_argument("--accept-idempotency-key", required=True)
    parser.add_argument("--result-idempotency-key", required=True)
    return parser


async def _main(arguments: argparse.Namespace) -> None:
    if not isinstance(arguments.url, str) or not arguments.url:
        raise ValueError("--url or CIGAR_URL is required")
    if arguments.expected_revision < 0:
        raise ValueError("--expected-revision must be non-negative")
    token = os.environ.get("CIGAR_AGENT_B_TOKEN")
    if token is None or not token:
        raise ValueError("CIGAR_AGENT_B_TOKEN is required")
    async with AsyncCigarClient(
        arguments.url,
        bearer_token=token,
        allow_insecure_loopback=arguments.url.startswith("http://"),
    ) as client:
        await client.negotiate(options=CallOptions(timeout=5.0))
        summary = await execute(
            client,
            AgentBWork(
                handoff_id=arguments.handoff_id,
                target_plan_id=arguments.target_plan_id,
                base_commit_id=arguments.base_commit_id,
                expected_revision=arguments.expected_revision,
                claim=arguments.claim,
                evidence=tuple(sorted(set(arguments.evidence))),
                accept_idempotency_key=arguments.accept_idempotency_key,
                result_idempotency_key=arguments.result_idempotency_key,
            ),
        )
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))


def main() -> None:
    """Console-script entry point."""

    asyncio.run(_main(_parser().parse_args()))


if __name__ == "__main__":
    main()
