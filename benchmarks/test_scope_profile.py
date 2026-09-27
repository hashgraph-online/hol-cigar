"""Diagnostic reductions must retain failures, actual process pairs and output equivalence."""

from __future__ import annotations

import copy
import unittest

from scope_profile import MODES, summarize


def fixture():
    return [
        {
            "cohort": cohort,
            "mode": mode,
            "documents": 100,
            "status": "ok",
            "raw_ms": [2 if mode == "root" else 4] * (1 if cohort == 0 else 100),
            "rendered_sha256": "same-output",
            "corpus_sha256": "same-corpus",
            "rss_samples": [{"total": 10000}],
        }
        for cohort in range(8)
        for mode in MODES
    ]


class ScopeProfileTests(unittest.TestCase):
    def test_equal_process_pairing_ignores_unequal_repetition_counts(self):
        rows = fixture()
        rows[1]["raw_ms"] = [20]
        report = summarize(rows, [100], 8)["100"]
        comparison = report["paired_vs_root"]["view-one"]
        self.assertEqual(comparison["cohorts"], 8)
        self.assertEqual(comparison["mean_difference"], (18 + 7 * 2) / 8)
        self.assertIsNotNone(comparison["difference_ci95"])
        self.assertEqual(report["treatments"]["root"]["process_median_ms"]["p50"], 2)

    def test_missing_failed_and_duplicate_processes_do_not_form_a_clean_comparison(
        self,
    ):
        rows = fixture()
        rows[0] = {key: rows[0][key] for key in ("mode", "cohort", "documents")}
        rows[0]["status"] = "failed"
        self.assertEqual(summarize(rows, [100], 8)["100"], {"status": "incomplete"})
        for invalid in (rows[:-1], rows + [rows[-1]]):
            with self.assertRaises(ValueError):
                summarize(invalid, [100], 8)

    def test_changed_corpus_or_rendering_invalidates_the_study(self):
        rows = fixture()
        for key in ("rendered_sha256", "corpus_sha256"):
            changed = copy.deepcopy(rows)
            changed[0][key] = "changed"
            with self.assertRaises(ValueError):
                summarize(changed, [100], 8)


if __name__ == "__main__":
    unittest.main()
