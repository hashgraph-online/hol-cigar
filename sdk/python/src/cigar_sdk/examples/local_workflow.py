"""Complete offline local workflow with a separately authored fixture reviewer.

Run ``python -m cigar_sdk.examples.local_workflow`` after installation.
This reviewer checks known example facts; it does not judge arbitrary documents.
"""

from __future__ import annotations

import json
from pathlib import Path

from cigar_sdk.context import LocalContextError, LocalContextGraph
from cigar_sdk.context_types import LocalAnswerDraft, LocalClaimReview, LocalContextRequest

INITIAL_POLICY = "Retry at most three times and preserve the operation ID."
UPDATED_POLICY = "Retry at most once and preserve the operation ID."
POLICY_ID = "retry.policy"


def _review_fixture(graph: LocalContextGraph, draft: LocalAnswerDraft, known_policy: str) -> list[LocalClaimReview]:
    """Replace with an authenticated semantic reviewer for real documents.

    Keep reviewer verdicts, authorization and policy outside generator control.
    """
    reviews: list[LocalClaimReview] = []
    for claim, key in zip(draft["claims"], graph.review_keys(draft), strict=True):
        verdict: LocalClaimReview = {"claim_key": key, "verdict": "unknown"}
        if claim["citations"] == [POLICY_ID]:
            if claim["text"] == known_policy:
                verdict["verdict"] = "supported"
            elif claim["text"] == "Retry thirty times.":
                verdict["verdict"] = "contradicted"
        reviews.append(verdict)
    return reviews


def run_local_workflow(*, worker_path: str | Path | None = None) -> dict[str, object]:
    """Keep the graph alive across requests in a real application/privacy domain."""
    if not __debug__:
        raise RuntimeError("Run the self-checking workflow without Python -O.")
    with LocalContextGraph("local-workflow-example", worker_path=worker_path) as graph:
        # The host reads approved files and supplies text; source locators are not opened.
        graph.replace_source(
            "src/retry.ts",
            [
                {
                    "id": "retry.impl",
                    "source": "src/retry.ts",
                    "text": "export const retryLimit = 3; // Preserve the operation ID.",
                }
            ],
        )
        graph.replace_source("docs/retry.md", [{"id": POLICY_ID, "source": "docs/retry.md", "text": INITIAL_POLICY}])
        graph.link("retry.impl", POLICY_ID, "requires")
        request: LocalContextRequest = {
            "query": "retry",
            "required": ["retry.impl"],
            "allowed": ["retry.impl", POLICY_ID],
            "policy_revision": "example-access-v1",
            "max_tokens": 1024,
            "reserve_tokens": 128,
        }
        compiled = graph.compile(request)
        assert compiled["snapshot"]["stats"]["rendered_tokens"] <= 896
        assert graph.verify(compiled["snapshot"]) == compiled
        hits = graph.stats()["cache"]["hits"]
        assert graph.compile(request) == compiled
        assert graph.stats()["cache"]["hits"] > hits
        prompt = graph.prompt_view(compiled["snapshot"], 896)
        graph.verify_prompt(prompt, compiled["snapshot"])
        handle = next(key for key, refs in prompt["citations"].items() if any(c["node_id"] == POLICY_ID for c in refs))
        citations = graph.resolve_citation(handle, prompt, compiled["snapshot"])
        node_ids = sorted({citation["node_id"] for citation in citations})

        # A real generator consumes prompt["rendered"] as data. This demo authors its draft.
        draft: LocalAnswerDraft = {
            "snapshot_id": compiled["snapshot"]["id"],
            "claims": [{"text": INITIAL_POLICY, "citations": node_ids, "confidence_bps": 9900}],
        }
        reviews = _review_fixture(graph, draft, INITIAL_POLICY)
        assessment = graph.check_answer(request, draft, reviews)
        assert assessment["decision"] == "release"
        # Display only assessed claims after release, never extra unreviewed prose.
        released = [claim["text"] for claim in draft["claims"]] if assessment["decision"] == "release" else []
        assert graph.check_answer(request, draft, [])["decision"] == "abstain"
        wrong: LocalAnswerDraft = {
            "snapshot_id": compiled["snapshot"]["id"],
            "claims": [{"text": "Retry thirty times.", "citations": node_ids, "confidence_bps": 9900}],
        }
        assert (
            graph.check_answer(request, wrong, _review_fixture(graph, wrong, INITIAL_POLICY))["decision"] == "abstain"
        )

        graph.replace_source("docs/retry.md", [{"id": POLICY_ID, "source": "docs/retry.md", "text": UPDATED_POLICY}])
        graph.replace_source(
            "src/retry.ts",
            [
                {
                    "id": "retry.impl",
                    "source": "src/retry.ts",
                    "text": "export const retryLimit = 1; // Preserve the operation ID.",
                }
            ],
        )
        try:
            graph.check_answer(request, draft, reviews)
        except LocalContextError as error:
            assert error.code == "BaseMismatch"
        else:
            raise AssertionError("stale review was accepted")
        refreshed = graph.compile(request)
        delta = graph.delta(compiled["snapshot"], refreshed["snapshot"])
        assert graph.apply_delta(compiled["snapshot"], delta) == refreshed
        fresh_draft: LocalAnswerDraft = {
            "snapshot_id": refreshed["snapshot"]["id"],
            "claims": [{"text": UPDATED_POLICY, "citations": [POLICY_ID], "confidence_bps": 9900}],
        }
        assert (
            graph.check_answer(request, fresh_draft, _review_fixture(graph, fresh_draft, UPDATED_POLICY))["decision"]
            == "release"
        )
        try:
            graph.compile(request | {"allowed": ["retry.impl"]})
        except LocalContextError as error:
            assert error.code == "RequiredUnavailable"
        else:
            raise AssertionError("unauthorized hard dependency was accepted")
        return {
            "schema": "cigar.local-workflow-example.v1",
            "status": "passed",
            "reviewer": "scripted-fixture",
            "requires_hol_services": False,
            "selected_sources": compiled["snapshot"]["stats"]["selected_sources"],
            "rendered_tokens": compiled["snapshot"]["stats"]["rendered_tokens"],
            "prompt_tokens": prompt["rendered_tokens"],
            "released_claims": released,
            "refreshed_claims": [claim["text"] for claim in fresh_draft["claims"]],
            "checks": [
                "authorized-dependencies",
                "exact-budget",
                "snapshot-integrity",
                "cache-reuse",
                "compact-citations",
                "supported-release",
                "missing-review-abstention",
                "confident-error-abstention",
                "stale-review-rejection",
                "source-refresh",
                "delta-roundtrip",
                "fresh-review",
                "authorization-rejection",
            ],
        }


if __name__ == "__main__":
    print(json.dumps(run_local_workflow(), indent=2))
