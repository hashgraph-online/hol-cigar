"""Five synthetic agents share a real worker; no model provider or network is required."""

import copy
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from cigar_sdk import LocalContextError, LocalContextGraph
from cigar_sdk.examples.shared_views import run_shared_views


def test_packaged_five_agent_example():
    report = run_shared_views(worker_path=os.environ.get("CIGAR_TEST_WORKER"), rounds=3)
    assert report["status"] == "passed"
    assert report["workers"] == 1
    assert report["released"] == report["missing_review_abstentions"] == 15


@pytest.fixture
def workspace():
    with LocalContextGraph("five-agent-alpha", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
        graph.upsert({"id": "policy", "source": "shared", "text": "Only release independently reviewed claims."})
        views = []
        for i in range(5):
            agent = f"agent-{i}"
            graph.upsert({"id": agent, "source": agent, "text": f"{agent} task revision 0."})
            graph.link(agent, "policy", "requires")
            views.append(
                graph.create_view(
                    {
                        "id": agent,
                        "allowed_sources": [agent, "shared"],
                        "writable_sources": [agent],
                        "policy_revision": "host-policy-1",
                    }
                )
            )
        yield graph, views
    assert graph.cleanup_complete


def draft_and_reviews(view, context, agent, text="A task is assigned."):
    draft = {
        "snapshot_id": context["snapshot"]["id"],
        "claims": [{"text": text, "citations": [agent], "confidence_bps": 9999}],
    }
    reviews = [{"claim_key": key, "verdict": "supported"} for key in view.review_keys(draft)]
    return draft, reviews


def test_five_agents_share_one_worker_and_index_during_writes(workspace):
    graph, views = workspace

    def run(i):
        agent = f"agent-{i}"
        view = views[i]
        results = []
        for revision in range(25):
            text = f"{agent} task revision {revision}."
            view.replace_source(agent, [{"id": agent, "source": agent, "text": text}])
            result = view.compile({"query": "task", "required": [agent], "max_tokens": 1024})
            context = result["context"]
            ids = {c["node_id"] for b in context["snapshot"]["blocks"] for c in b["citations"]}
            assert ids == {agent, "policy"}
            assert text in result["rendered"]
            assert context["snapshot"]["stats"]["documents"] == 2
            assert context["snapshot"]["stats"]["rendered_tokens"] <= 1024
            draft, reviews = draft_and_reviews(view, context, agent, text)
            checked = view.check_answer(context, draft, reviews)
            assert checked["assessment"]["decision"] == "release"
            assert checked["context_id"] == context["id"]
            assert graph.verify(context["snapshot"])["rendered"] == result["rendered"]
            results.append(checked)
        return results

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(run, range(5)))
    assert sum(map(len, results)) == 125
    assert graph.stats()["documents"] == 6
    assert len({id(view._graph) for view in views}) == 1


def test_unrelated_write_keeps_view_review_but_legacy_still_rejects(workspace):
    graph, views = workspace
    result = views[0].compile({"required": ["agent-0"]})
    context = result["context"]
    draft, reviews = draft_and_reviews(views[0], context, "agent-0")
    legacy_request = {"required": ["agent-0"], "allowed": ["agent-0", "policy"]}
    legacy = graph.compile(legacy_request)
    legacy_draft = {"snapshot_id": legacy["snapshot"]["id"], "claims": [], "abstain": True}
    views[4].replace_source("agent-4", [{"id": "agent-4", "source": "agent-4", "text": "Changed other work."}])
    assert views[0].check_answer(context, draft, reviews)["assessment"]["decision"] == "release"
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        graph.check_answer(legacy_request, legacy_draft, [])


def test_scope_cannot_be_widened_and_denied_writes_are_atomic(workspace):
    graph, views = workspace
    before = graph.stats()["revision"]
    for request in [
        {"required": ["agent-4"]},
        {"required": ["agent-4"], "allowed": ["agent-4"]},
        {"required": ["agent-0"], "allowed": []},
    ]:
        with pytest.raises(LocalContextError, match="RequiredUnavailable"):
            views[0].compile(request)
    with pytest.raises(LocalContextError, match="RequiredUnavailable"):
        views[0].replace_source("agent-4", [])
    with pytest.raises(LocalContextError, match="RequiredUnavailable"):
        views[0].replace_source("agent-0", [{"id": "policy", "source": "agent-0", "text": "Steal shared source"}])
    assert graph.stats()["revision"] == before
    with pytest.raises(LocalContextError, match="BudgetUnsatisfiable"):
        views[0].compile({"required": ["agent-0"], "max_tokens": 1})


def test_shared_evidence_change_and_revocation_invalidate(workspace):
    graph, views = workspace
    context = views[0].compile({"required": ["agent-0"]})["context"]
    draft, reviews = draft_and_reviews(views[0], context, "agent-0")
    graph.upsert({"id": "unselected", "source": "shared", "text": "New authorized evidence."})
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        views[0].check_answer(context, draft, reviews)
    assert graph.revoke_view("agent-0")
    with pytest.raises(LocalContextError, match="RequiredUnavailable"):
        views[0].compile({"required": ["agent-0"]})
    replacement = graph.create_view(
        {"id": "agent-0", "allowed_sources": ["agent-0", "shared"], "policy_revision": "host-policy-2"}
    )
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        replacement.check_answer(context, draft, reviews)


def test_tampering_and_confident_unsupported_claims_fail(workspace):
    _, views = workspace
    context = views[0].compile({"required": ["agent-0"]})["context"]
    draft, reviews = draft_and_reviews(views[0], context, "agent-0")
    for field in ["id", "scope_id"]:
        changed = copy.deepcopy(context)
        changed[field] = "0" * 64
        with pytest.raises(LocalContextError, match="Integrity"):
            views[0].check_answer(changed, draft, reviews)
    assert views[0].check_answer(context, draft, [])["assessment"]["decision"] == "abstain"
    reviews[0]["verdict"] = "contradicted"
    checked = views[0].check_answer(context, draft, reviews)
    assert checked["assessment"]["decision"] == "abstain"
    assert checked["assessment"]["confident_failures"] == 1
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        views[1].check_answer(context, draft, reviews)


def test_worker_failure_closes_every_view_without_restart(workspace):
    graph, views = workspace
    graph._process.kill()
    graph._process.wait(timeout=5)
    with pytest.raises(LocalContextError, match="Transport"):
        views[0].compile({"required": ["agent-0"]})
    for view in views[1:]:
        with pytest.raises(LocalContextError, match="Closed"):
            view.compile({"query": "task"})


def test_capability_absence_fails_before_view_dispatch(workspace):
    graph, _ = workspace
    graph._supports_views = False
    with pytest.raises(LocalContextError, match="IncompatibleWorker"):
        graph.create_view({"id": "unsupported", "allowed_sources": [], "policy_revision": "1"})
    assert graph.stats()["documents"] == 6
