"""Prevent process-call pseudoreplication and failure dropping in storage probes."""

import unittest

from broker_storage import corpus, paired, summarize
from broker_storage_compare import summarize_comparison


def row(cohort, mode, times):
    return {
        "cohort": cohort,
        "mode": mode,
        "documents": 100,
        "status": "ok",
        "raw_ms": {"replace": times, "compile": times},
        "rendered_sha256": "same",
        "rss_samples": [{"total": 100}],
        "cpu": {"host_ms": 1, "worker_ms": 2},
        "disk_samples_bytes": [0],
        "checkpoint_bytes": 10,
        "resume_ms": 1,
    }


class StorageStudyTests(unittest.TestCase):
    def test_repeated_calls_do_not_overweight_one_process(self):
        rows = [
            row(0, "memory", [1] * 100),
            row(0, "sqlite", [2] * 100),
            row(1, "memory", [100]),
            row(1, "sqlite", [100]),
        ]
        result = summarize(rows, [100], 2)["100"]
        self.assertEqual(result["timing"]["memory"]["replace"]["p50"], 50.5)
        self.assertEqual(result["paired"]["replace"]["mean_difference"], 0.5)
        self.assertIsNone(result["paired"]["replace"]["difference_ci95"])

    def test_failed_and_missing_treatments_have_no_paired_success(self):
        rows = [row(0, "memory", [1]), row(0, "sqlite", [2])]
        self.assertEqual(summarize(rows, [100], 2)["100"]["status"], "incomplete")
        rows.append(
            {"cohort": 1, "mode": "sqlite", "documents": 100, "status": "failed"}
        )
        rows.append(row(1, "memory", [1]))
        self.assertEqual(
            summarize(rows, [100], 2)["100"], {"status": "incomplete", "paired": None}
        )

    def test_changed_context_cannot_pass_as_a_speed_improvement(self):
        rows = [row(0, "memory", [2]), row(0, "sqlite", [1])]
        rows[1]["rendered_sha256"] = "different"
        with self.assertRaisesRegex(ValueError, "different context"):
            summarize(rows, [100], 1)

    def test_intervals_require_eight_process_pairs_and_zero_baselines_are_not_ratios(
        self,
    ):
        self.assertIsNone(paired([(1, 2)] * 7)["difference_ci95"])
        self.assertEqual(paired([(1, 2)] * 8)["difference_ci95"], [1, 1])
        self.assertIsNone(paired([(0, 1)] * 8)["mean_relative_change"])

    def test_corpora_are_exactly_bounded_and_distinct(self):
        documents = corpus(100, 1024)
        self.assertEqual(len({d["id"] for d in documents}), 100)
        self.assertTrue(all(len(d["text"].encode()) == 1024 for d in documents))

    def test_worker_comparison_pairs_processes_and_rejects_duplicate_or_missing_variants(
        self,
    ):
        rows = [
            {**row(cohort, mode, times), "variant": variant}
            for cohort in range(2)
            for mode in ("memory", "sqlite")
            for variant, times in (
                ("reference", [1] * 100 if cohort == 0 else [100]),
                ("candidate", [2] * 100 if cohort == 0 else [100]),
            )
        ]
        result = summarize_comparison(rows, [100], 2)["100"]
        self.assertEqual(
            result["paired"]["sqlite"]["replace_median_ms"]["mean_difference"], 0.5
        )
        self.assertEqual(
            summarize_comparison(rows[:-1], [100], 2)["100"]["status"], "incomplete"
        )
        self.assertEqual(
            summarize_comparison(rows + [rows[0]], [100], 2)["100"]["status"],
            "incomplete",
        )
        rows[0]["status"] = "failed"
        self.assertEqual(
            summarize_comparison(rows, [100], 2)["100"]["status"], "incomplete"
        )
        rows[0]["status"] = "ok"
        rows[0]["rendered_sha256"] = "different"
        with self.assertRaisesRegex(ValueError, "different context"):
            summarize_comparison(rows, [100], 2)


if __name__ == "__main__":
    unittest.main()
