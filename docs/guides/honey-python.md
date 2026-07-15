# Honey Python SDK

Honey ships `cigar_sdk-0.9.0.dev1-py3-none-any.whl` and
`cigar_sdk-0.9.0.dev1.tar.gz`. Install an exact GitHub attachment into a new virtual environment;
Honey does not publish to PyPI.

## Offline installation

Verify the artifact against release `SHA256SUMS`. A wheel install needs no build tool. An sdist may
need build dependencies supplied in a local wheelhouse; disabling the index prevents an accidental
registry fallback.

<!-- docs-check: illustrative -->
```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index ./cigar_sdk-0.9.0.dev1-py3-none-any.whl
python -c 'import cigar_sdk; print(cigar_sdk.__version__)'
```

## Client contract

Use `AsyncCigarClient` or `CigarClient` with an explicit loopback daemon endpoint, bounded deadline,
and authorization source. Generated models reject unknown fields. Retried mutations must reuse a
stable idempotency key only for the same canonical request. Structured errors retain CIGAR problem
codes; do not branch on human message text.

```python
from cigar_sdk import AsyncCigarClient, TypedOperationRequest, models

async def compile_plan(endpoint: str, plan_id: str):
    async with AsyncCigarClient(
        endpoint,
        allow_insecure_loopback=True,
        max_attempts=1,
    ) as client:
        response = await client.compile_context_bundle(
            TypedOperationRequest(
                models.CompileContextBundleRequest(plan_id=plan_id),
                idempotency_key="python-compile-1",
            )
        )
        return response.payload
```

`allow_insecure_loopback` is for the local Honey daemon only. Remote cleartext endpoints are not a
supported Honey deployment.

## Agent B result

Agent B accepts a handoff through its own authenticated client, verifies the accepted recipient
bundle, and returns a `RecordHandoffResultRequest`. Claims reference immutable evidence; artifacts and
verifier receipts are multihashes. `requested_followup_capabilities` is a request for later review,
not implicit authority.

```python
from cigar_sdk import TypedOperationRequest, models

request = models.RecordHandoffResultRequest(
    handoff_id=handoff_id,
    base_commit_id=base_commit_id,
    claims=({"claim": "tests pass", "evidence": [test_receipt_id]},),
    decisions=(),
    artifacts=(patch_artifact_id,),
    source_changes=(),
    verifier_receipts=(test_receipt_id,),
    unresolved_questions=(),
    blockers=(),
    effect_references=(),
    requested_followup_capabilities=(),
)
receipt = client.record_handoff_result(
    TypedOperationRequest(
        request,
        idempotency_key="agent-b-result-1",
        expected_revision=handoff_revision,
    )
)
```

The wheel installs the `cigar-agent-b-handoff` example command. Run
`cigar-agent-b-handoff --help` after installation, then supply only explicit local endpoint,
authorization, handoff, base, and result inputs. Its recorded transport qualification is a
credential-free contract test, not evidence of a remote production service. See [two-agent
coordination](honey-two-agent.md).
