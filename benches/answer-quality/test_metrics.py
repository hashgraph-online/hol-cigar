"""Hand-calculated examples and adversarial denominator/label checks."""
import copy
import unittest
from metrics import evaluate, paired_interval
from qualify import evidence_cases


def row():
    return {"episode_id": "q1", "treatment": "baseline", "stratum": "answerable", "answerable": True,
            "abstained": False, "gold_facts": ["f1"], "context_tokens": 100, "latency_ms": 2,
            "claims": [{"id": "c1", "fact_id": "f1", "label": "supported", "confidence": .9, "citation_labels": ["supported"]},
                       {"id": "c2", "fact_id": None, "label": "unsupported", "confidence": .8, "citation_labels": ["unsupported"]}]}


class MetricsTests(unittest.TestCase):
    def test_unanswerable_source_fixture_has_no_impossible_gold_fact(self):
        fixture = next(c for c in evidence_cases() if c["name"] == "no-relevant-evidence")
        self.assertFalse(fixture["answerable"])
        self.assertEqual(fixture["facts"], [])

    def test_known_values(self):
        result = evaluate([row()])["treatments"]["baseline"]
        self.assertEqual(result["factual_precision"], .5)
        self.assertEqual(result["confident_error_rate_confident_claims"], .5)
        self.assertEqual(result["confident_error_episode_rate"], 1)
        self.assertAlmostEqual(result["brier"], .325)
        self.assertAlmostEqual(result["ece_10"], .45)
        self.assertEqual(result["citation_precision"], .5)
        self.assertEqual(result["useful_fact_recall"], 1)
        self.assertEqual(result["correct_answer_yield"], 0)

    def test_refuse_everything_never_gets_perfect_accuracy(self):
        value = row() | {"abstained": True, "claims": []}
        result = evaluate([value])["treatments"]["baseline"]
        for key in ["factual_precision", "brier", "ece_10", "citation_precision", "context_tokens_per_supported_useful_fact"]:
            self.assertIsNone(result[key])
        self.assertEqual(result["answerable_refusal_rate"], 1)
        self.assertEqual(result["correct_answer_yield"], 0)

    def test_missing_confidence_and_unknown_truth_are_not_imputed(self):
        value = row()
        value["claims"][0]["confidence"] = None
        value["claims"][1]["label"] = "unknown"
        result = evaluate([value])["treatments"]["baseline"]
        self.assertEqual(result["confidence_coverage"], .5)
        self.assertEqual(result["annotation_coverage"], .5)
        self.assertEqual(result["confident_unknown_claims"], 1)
        self.assertIsNone(result["brier"])

    def test_duplicate_useful_facts_cannot_inflate_recall(self):
        value = row()
        value["claims"][1] = value["claims"][0] | {"id": "c2"}
        result = evaluate([value])["treatments"]["baseline"]
        self.assertEqual(result["supported_useful_facts"], 1)
        self.assertEqual(result["useful_fact_recall"], 1)

    def test_reject_ambiguous_data(self):
        for confidence in [-.1, 1.1, float("nan"), float("inf"), True, "0.9"]:
            value = row()
            value["claims"][0]["confidence"] = confidence
            with self.assertRaises(ValueError):
                evaluate([value])
        for field in ["confidence", "label", "citation_labels"]:
            value = row()
            del value["claims"][0][field]
            with self.assertRaises(ValueError):
                evaluate([value])
        with self.assertRaises(ValueError):
            evaluate([row(), row()])
        with self.assertRaises(ValueError):
            evaluate([row() | {"abstained": True}])
        with self.assertRaises(ValueError):
            evaluate([])

    def test_paired_bootstrap_requires_same_questions_and_gold(self):
        base = row()
        candidate = copy.deepcopy(base) | {"treatment": "candidate"}
        candidate["claims"].pop()
        result = paired_interval([base, candidate], "baseline", "candidate", draws=100)
        self.assertEqual(result["delta"], 1)
        self.assertEqual(result["ci95_percentile"], [1, 1])
        self.assertEqual(result["confident_error_episode_rate"]["ci95_percentile"], [-1, -1])
        candidate["gold_facts"] = ["different"]
        with self.assertRaises(ValueError):
            paired_interval([base, candidate], "baseline", "candidate")


if __name__ == "__main__":
    unittest.main()
