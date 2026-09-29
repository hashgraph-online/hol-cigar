"""Check independent scoring, review-fault sensitivity and paired measurement units."""
import copy
import unittest

import answers
import fixtures
import performance
import verify_results


class TrackingTests(unittest.TestCase):
    def test_review_approval_does_not_change_independent_gold(self):
        episode = next(e for e in fixtures.episodes() if e["id"] == "reviewer-false-positive")
        self.assertEqual(fixtures.reviews()[episode["id"]], [["supported"]])
        self.assertEqual(fixtures.annotations(episode, episode["attempts"][0]["claims"])[0]["label"], "contradicted")

    def test_actual_truth_does_not_make_an_irrelevant_citation_supportive(self):
        episode = next(e for e in fixtures.episodes() if e["id"] == "irrelevant-real-citation")
        result = fixtures.annotations(episode, episode["attempts"][0]["claims"])[0]
        self.assertEqual(result["label"], "supported")
        self.assertEqual(result["citation_labels"], ["unsupported"])

    def test_boolean_false_is_not_numeric_zero(self):
        self.assertEqual(fixtures.label(fixtures.claim("target_executed", 0), fixtures.LEDGER), "contradicted")
        self.assertEqual(fixtures.label(fixtures.claim("target_executed", False), fixtures.LEDGER), "supported")

    def test_unresolved_remains_unknown_despite_review(self):
        episode = next(e for e in fixtures.episodes() if e["id"] == "reviewer-approves-unresolved")
        self.assertEqual(fixtures.annotations(episode, episode["attempts"][0]["claims"])[0]["label"], "unknown")

    def test_refusing_everything_does_not_earn_task_success(self):
        row = {"episode_id": "refusal", "treatment": "test", "stratum": "test", "answerable": True,
               "abstained": True, "gold_facts": ["queue_limit"], "claims": [], "context_tokens": 7, "latency_ms": 1}
        summary = answers.metrics.evaluate([row])["treatments"]["test"]
        self.assertEqual(summary["correct_answer_yield"], 0)
        self.assertEqual(summary["answerable_refusal_rate"], 1)
        self.assertIsNone(summary["factual_precision"])
        self.assertFalse(answers.fully_supported_cited(row))

    def test_partial_true_answer_does_not_earn_complete_yield(self):
        episode = next(e for e in fixtures.episodes() if e["id"] == "supported-but-incomplete")
        row = {"answerable": True, "abstained": False, "gold_facts": episode["gold_facts"],
               "claims": fixtures.annotations(episode, episode["attempts"][0]["claims"])}
        self.assertFalse(answers.fully_supported_cited(row))

    def test_duplicate_episode_and_misaligned_review_rejected(self):
        episodes, reviews = fixtures.episodes(), fixtures.reviews()
        fixtures.validate(episodes, reviews)
        with self.assertRaises(AssertionError):
            fixtures.validate(episodes + [episodes[0]], reviews)
        reviews = copy.deepcopy(reviews)
        reviews[episodes[0]["id"]][0].append("supported")
        with self.assertRaises(AssertionError):
            fixtures.validate(episodes, reviews)

    def test_reference_host_rechecks_current_snapshot_and_citations(self):
        current = {"ok": True, "result": {"snapshot": {"id": "new", "blocks": [{"citations": [{"node_id": "a"}]}]}}}
        draft = {"snapshot_id": "old", "abstain": False, "claims": [{"citations": ["a"]}]}
        self.assertEqual(answers.citation_host(current, draft), "BaseMismatch")
        draft["snapshot_id"] = "new"
        self.assertEqual(answers.citation_host(current, draft), "release")
        draft["claims"][0]["citations"] = ["fabricated"]
        self.assertEqual(answers.citation_host(current, draft), "invalid_citation")

    def test_paired_intervals_use_sessions_and_declared_threshold(self):
        result = performance.paired_interval([(100, 80)] * 8)
        self.assertEqual(result["paired_sessions"], 8)
        self.assertAlmostEqual(result["paired_median_reduction_percent"], 20)
        self.assertTrue(result["improvement_threshold_met"])
        self.assertFalse(performance.paired_interval([(100, 99)] * 8)["improvement_threshold_met"])
        self.assertFalse(performance.paired_interval([(100, 100)] * 8)["improvement_threshold_met"])

    def test_valid_citation_cannot_hide_missing_required_body(self):
        records = [
            {"request": {"command": {"op": "upsert", "document": {"id": "a", "source": "fixture", "text": "limit is 3"}}}, "reply": {"ok": True, "result": True}},
            {"request": {"command": {"op": "compile", "request": {"required": ["a"], "max_tokens": 100}}},
             "reply": {"ok": True, "result": {"snapshot": {"stats": {"rendered_tokens": 10}, "blocks": [{"text": "limit is 30", "citations": [{"node_id": "a"}]}]}}}},
        ]
        with self.assertRaisesRegex(AssertionError, "required source body missing"):
            verify_results.audit_trace(records)

    def test_capacity_workload_declares_all_distinct_required_documents(self):
        docs, requests = performance.corpus({"documents": 1536, "documents_per_query": 1, "max_tokens": 8192, "query_mode": "required_only"})
        self.assertEqual(len(requests), 1536)
        self.assertEqual({r["required"][0] for r in requests}, {d["id"] for d in docs})
        self.assertTrue(all(r["query"] == "unmatchedmarker" and r["max_blocks"] == 1 for r in requests))


if __name__ == "__main__":
    unittest.main()
