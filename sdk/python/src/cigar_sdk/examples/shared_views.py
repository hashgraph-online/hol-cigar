"""Five concurrent, scripted agents using one local worker. No model or network calls."""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cigar_sdk import LocalContextGraph, LocalContextView
from cigar_sdk.context_types import LocalAnswerDraft, LocalClaimReview


def run_shared_views(*, worker_path: str | Path | None = None, rounds: int = 10) -> dict[str, object]:
    """The host retains root authority and independently checks this example's known facts."""
    if not __debug__ or not 1 <= rounds <= 1000:
        raise ValueError("Use normal Python execution and 1..1000 rounds.")
    with LocalContextGraph("five-agent-example", worker_path=worker_path) as graph:
        graph.upsert({"id": "policy", "source": "shared", "text": "Release only independently reviewed claims."})
        views: list[LocalContextView] = []
        for index in range(5):
            name = f"agent-{index}"
            graph.upsert({"id": name, "source": name, "text": f"{name} completed revision 0."})
            graph.link(name, "policy", "requires")
            views.append(
                graph.create_view(
                    {
                        "id": name,
                        "allowed_sources": [name, "shared"],
                        "writable_sources": [name],
                        "policy_revision": "host-policy-1",
                    }
                )
            )

        def agent(index: int) -> int:
            name, view = f"agent-{index}", views[index]
            for revision in range(1, rounds + 1):
                known_fact = f"{name} completed revision {revision}."
                view.replace_source(name, [{"id": name, "source": name, "text": known_fact}])
                result = view.compile({"required": [name], "max_tokens": 512})
                context = result["context"]
                citations = {c["node_id"] for b in context["snapshot"]["blocks"] for c in b["citations"]}
                assert citations == {name, "policy"}
                assert known_fact in result["rendered"]
                assert context["snapshot"]["stats"]["rendered_tokens"] <= 512
                # A real generator consumes rendered DATA and returns claims. This one is scripted.
                draft: LocalAnswerDraft = {
                    "snapshot_id": context["snapshot"]["id"],
                    "claims": [{"text": known_fact, "citations": [name], "confidence_bps": 9900}],
                }
                # Host-side fixture oracle, not a generator-supplied verdict or general truth judge.
                reviews: list[LocalClaimReview] = [
                    {"claim_key": key, "verdict": "supported" if claim["text"] == known_fact else "unknown"}
                    for claim, key in zip(draft["claims"], view.review_keys(draft), strict=True)
                ]
                assert view.check_answer(context, draft, reviews)["assessment"]["decision"] == "release"
                assert view.check_answer(context, draft, [])["assessment"]["decision"] == "abstain"
            return rounds

        with ThreadPoolExecutor(max_workers=5) as pool:
            released = sum(pool.map(agent, range(5)))
        assert graph.stats()["documents"] == 6
    assert graph.cleanup_complete
    return {
        "schema": "cigar.shared-views-example.v1",
        "status": "passed",
        "agents": 5,
        "workers": 1,
        "indexed_documents": 6,
        "released": released,
        "missing_review_abstentions": released,
        "reviewer": "scripted-fixture",
        "requires_hol_services": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--rounds", type=int, default=10)
    args = parser.parse_args()
    print(json.dumps(run_shared_views(worker_path=args.worker, rounds=args.rounds), indent=2))
