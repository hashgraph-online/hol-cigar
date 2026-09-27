"""A native speedup must retain exact complete results and independent pairs."""

from __future__ import annotations

import copy
import unittest

from scope_compare import MODES, compare


def fixture():
    return [
        {
            "cohort": cohort,
            "worker": worker,
            "mode": mode,
            "documents": 100,
            "status": "ok",
            "raw_ms": [2 if worker == "baseline" else 1] * (1 if cohort == 0 else 100),
            "rendered_sha256": "same-rendering",
            "result_sha256": f"exact-{mode}",
            "corpus_sha256": "same-corpus",
            "sdk_source_sha256": "same-sdk",
            "rss_samples": [{"total": 10000}],
        }
        for cohort in range(8)
        for mode in MODES
        for worker in ("baseline", "candidate")
    ]


class ScopeComparisonTests(unittest.TestCase):
    def test_complete_results_must_match_even_when_rendering_does(self):
        for key in ("result_sha256", "sdk_source_sha256", "corpus_sha256"):
            with self.subTest(key=key):
                rows = fixture()
                rows[1][key] = "changed"
                with self.assertRaises(ValueError):
                    compare(rows, [100], 8)

    def test_failed_missing_and_duplicated_cohorts_never_pass(self):
        rows = fixture()
        rows[0] = {
            key: rows[0][key] for key in ("worker", "mode", "cohort", "documents")
        }
        rows[0]["status"] = "failed"
        self.assertEqual(
            compare(rows, [100], 8)["100"]["root"], {"status": "incomplete"}
        )
        for invalid in (rows[:-1], rows + [rows[-1]]):
            with self.assertRaises(ValueError):
                compare(invalid, [100], 8)
        duplicated_pair = copy.deepcopy(fixture())
        duplicated_pair[-1]["cohort"] = 6
        with self.assertRaises(ValueError):
            compare(duplicated_pair, [100], 8)

    def test_pair_weight_uses_processes_instead_of_individual_calls(self):
        rows = fixture()
        rows[1]["raw_ms"] = [10]
        report = compare(rows, [100], 8)["100"]["root"]
        self.assertEqual(report["latency_paired"]["cohorts"], 8)
        self.assertEqual(report["latency_paired"]["mean_difference"], (8 - 7) / 8)
        self.assertEqual(report["workers"]["candidate"]["process_median_ms"]["p50"], 1)
        self.assertEqual(report["rss_paired"]["mean_difference"], 0)
        self.assertEqual(report["exact_result_sha256"], "exact-root")


if __name__ == "__main__":
    unittest.main()
