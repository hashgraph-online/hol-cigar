"""Paired application replay: citation hosts versus adoption of native review."""
import copy
import json
from pathlib import Path
import sys

import fixtures
from worker import Worker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "benches/answer-quality"))
import metrics  # noqa: E402


def citation_host(current, draft):
    """A declared reference host; this is not a v0.10.0 answer-release API."""
    if not current["ok"]:
        return current["error"]
    snapshot = current["result"]["snapshot"]
    if snapshot["id"] != draft["snapshot_id"]:
        return "BaseMismatch"
    if draft["abstain"] or not draft["claims"]:
        return "abstain"
    selected = {citation["node_id"] for block in snapshot["blocks"] for citation in block["citations"]}
    if any(not claim["citations"] or not set(claim["citations"]) <= selected for claim in draft["claims"]):
        return "invalid_citation"
    return "release"


def fully_supported_cited(row):
    return metrics.correct_answer(row) and all(
        c["citation_labels"] and all(label == "supported" for label in c["citation_labels"])
        for c in row["claims"])


def replay(episode, review_inputs, treatment, build, output):
    worker = Worker(build["binary"], build["version"], output / f"{episode['id']}-{treatment}.jsonl.gz", domain=f"tracking/{episode['id']}")
    elapsed, tokens, history, displayed = 0.0, 0, [], []
    try:
        for document in episode["documents"]:
            worker.ok({"op": "upsert", "document": document})
        request = {"query": "fixture workflow facts", "required": [d["id"] for d in episode["documents"]], "max_tokens": 4096}
        for index, attempt in enumerate(episode["attempts"]):
            worker.tag = f"attempt-{index + 1}"
            result, spent = worker.ok({"op": "compile", "request": request})
            elapsed += spent
            snapshot = result["snapshot"]
            tokens += snapshot["stats"]["rendered_tokens"]
            draft = {"snapshot_id": snapshot["id"], "abstain": attempt["abstain"],
                     "claims": [{"text": fixtures.text(c["fact"], c["value"]), "citations": c["citations"], "confidence_bps": c["confidence_bps"]} for c in attempt["claims"]]}
            reviewed = treatment == "v11_reviewed_host"
            if reviewed:
                keys, spent = worker.ok({"op": "review_keys", "draft": draft})
                elapsed += spent
                reviews = [{"claim_key": key, "verdict": verdict, "reviewed_counterevidence": []}
                           for key, verdict in zip(keys, review_inputs[index], strict=True) if verdict is not None]
            if index == 0:
                for mutation in episode["mutations_after_first_draft"]:
                    worker.ok(mutation)
                request = request | episode["request_after"]
            if reviewed:
                response, spent = worker.call({"op": "check_answer", "request": request, "draft": draft, "reviews": reviews, "policy": episode["policy"]})
                disposition = response["result"]["decision"] if response["ok"] else response["error"]
            else:
                response, spent = worker.call({"op": "compile", "request": request})
                disposition = citation_host(response, draft)
            elapsed += spent
            history.append({"attempt": index + 1, "snapshot_id": snapshot["id"], "decision": disposition,
                            "draft": draft, "response": response, "scripted_review": review_inputs[index] if reviewed else None})
            if disposition == "release":
                displayed = attempt["claims"]
                break
            if attempt["abstain"]:
                break
    finally:
        resources = worker.close()
    return {"episode_id": episode["id"], "treatment": treatment, "stratum": episode["stratum"],
            "answerable": episode["answerable"], "abstained": not displayed, "gold_facts": episode["gold_facts"],
            "claims": fixtures.annotations(episode, displayed), "context_tokens": tokens, "latency_ms": elapsed,
            "attempts": len(history), "history": history, "resources": resources,
            "initially_valid_control": episode["initially_valid_control"], "repairable": episode["repairable"]}


def run(builds, output, episodes, review_inputs):
    output.mkdir()
    fixtures.validate(episodes, review_inputs)
    rows = []
    treatments = {"v10_citation_host": builds["baseline"], "v11_citation_host": builds["candidate"], "v11_reviewed_host": builds["candidate"]}
    for episode in episodes:
        for treatment, build in treatments.items():
            rows.append(replay(copy.deepcopy(episode), review_inputs[episode["id"]], treatment, build, output))
    (output / "episodes.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    summary = {"all_episodes": metrics.evaluate(rows), "honest_review": metrics.evaluate([r for r in rows if r["stratum"] == "honest_review"]), "application_kpis": {}}
    for treatment in treatments:
        selected = [r for r in rows if r["treatment"] == treatment and r["stratum"] == "honest_review"]
        answerable = [r for r in selected if r["answerable"]]
        controls = [r for r in selected if r["initially_valid_control"]]
        repairable = [r for r in selected if r["repairable"]]
        summary["application_kpis"][treatment] = {
            "honest_episodes": len(selected), "answerable_episodes": len(answerable),
            "fully_supported_cited_answers": sum(fully_supported_cited(r) for r in answerable),
            "supported_cited_answerable_yield": sum(fully_supported_cited(r) for r in answerable) / len(answerable),
            "initially_valid_controls": len(controls), "initially_valid_controls_preserved": sum(fully_supported_cited(r) for r in controls),
            "repairable_episodes": len(repairable), "repairable_episodes_completed": sum(fully_supported_cited(r) for r in repairable),
            "total_attempts": sum(r["attempts"] for r in selected),
        }
    by_treatment = {name: {r["episode_id"]: r for r in rows if r["treatment"] == name} for name in treatments}
    comparable = ("abstained", "claims", "context_tokens", "attempts")
    control_differences = [key for key, old in by_treatment["v10_citation_host"].items()
                           if any(old[field] != by_treatment["v11_citation_host"][key][field] for field in comparable)]
    candidate = summary["application_kpis"]["v11_reviewed_host"]
    honest = summary["honest_review"]["treatments"]["v11_reviewed_host"]
    diagnostic = by_treatment["v11_reviewed_host"]
    checks = {
        "unchanged_host_version_parity": not control_differences,
        "honest_review_zero_erroneous_releases": honest["unsupported_or_contradicted_claims"] == 0,
        "initially_valid_controls_preserved": candidate["initially_valid_controls"] == candidate["initially_valid_controls_preserved"],
        "repairable_episodes_finish": candidate["repairable_episodes"] == candidate["repairable_episodes_completed"],
        "false_positive_review_exposes_error": diagnostic["reviewer-false-positive"]["claims"][0]["label"] == "contradicted",
        "false_negative_review_exposes_refusal": diagnostic["reviewer-false-negative"]["abstained"],
        "incomplete_supported_answer_fails_task_yield": not fully_supported_cited(diagnostic["supported-but-incomplete"]),
        "approved_unknown_stays_unknown": diagnostic["reviewer-approves-unresolved"]["claims"][0]["label"] == "unknown",
    }
    summary.update({"checks": checks, "citation_host_differences": control_differences,
                    "scope": "Authored scripted application-adoption replay. Reviews are provided fixtures; gold uses typed propositions, never gate verdicts. This is not real-model factuality or calibration.",
                    "timing_scope": "Compile + current-state display check RPCs (plus review-key RPC when adopted); no generation/reviewer cost, ingestion or worker startup. Tokens count snapshots delivered to the scripted generator, including blocked attempts."})
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if not all(checks.values()):
        raise AssertionError(checks)
    return summary
