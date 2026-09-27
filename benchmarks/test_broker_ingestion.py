"""Guard result interpretation: a rejected frame cannot count as a faster ingestion."""

import copy
import unittest

from broker_ingestion import summarize


def rows(size=1, cohorts=2):
    return [
        {
            "status": "ok",
            "mode": mode,
            "storage": storage,
            "mib": size,
            "cohort": cohort,
            "outcome": "rejected_before_dispatch"
            if size > 32 and mode == "whole"
            else "committed",
            "rendered_sha256": "old"
            if size > 32 and mode == "whole"
            else "complete-evidence",
            "corpus_sha256": "fixed",
            "input_to_ack_ms": (cohort + 1) * (2 if mode == "batches" else 1),
            "rss_samples": [{"host": 100, "worker": 200, "total": 300}],
        }
        for cohort in range(cohorts)
        for storage in ("memory", "sqlite")
        for mode in ("whole", "batches")
    ]


class IngestionReductionTests(unittest.TestCase):
    def test_whole_process_pairs_are_the_units_and_small_cohorts_have_no_interval(self):
        result = summarize(rows(), [1], 2)["1MiB/memory"]
        self.assertEqual(result["status"], "comparable")
        latency = result["metrics"]["input_to_ack_ms"]
        self.assertEqual(latency["whole"]["p50"], 1.5)
        self.assertEqual(latency["batches"]["p50"], 3)
        self.assertEqual(latency["paired"]["cohorts"], 2)
        self.assertIsNone(latency["paired"]["difference_ci95"])
        self.assertIsNotNone(
            summarize(rows(cohorts=8), [1], 8)["1MiB/memory"]["metrics"][
                "input_to_ack_ms"
            ]["paired"]["difference_ci95"]
        )

    def test_large_rejection_is_not_a_speed_or_memory_comparison(self):
        for result in summarize(rows(34), [34], 2).values():
            self.assertEqual(result["status"], "frame_boundary_demonstrated")
            for metric in result["metrics"].values():
                self.assertIsNone(metric["paired"])
        broken = rows(34)
        broken[0]["outcome"] = "committed"
        with self.assertRaisesRegex(ValueError, "outcome"):
            summarize(broken, [34], 2)

    def test_missing_duplicate_or_failed_processes_never_disappear_from_the_denominator(
        self,
    ):
        original = rows()
        for broken in (
            original[:-1],
            original + [original[-1]],
            original[:-1] + [original[0]],
        ):
            with self.assertRaisesRegex(ValueError, "cohort"):
                summarize(broken, [1], 2)
        failed = copy.deepcopy(original)
        failed[0] = {
            key: failed[0][key]
            for key in ("status", "mib", "storage", "mode", "cohort")
        }
        failed[0]["status"] = "failed"
        result = summarize(failed, [1], 2)
        self.assertEqual(
            result["1MiB/memory"], {"status": "incomplete", "paired": None}
        )
        self.assertEqual(result["1MiB/sqlite"]["status"], "comparable")

    def test_input_or_rendering_changes_cannot_be_hidden_in_performance_results(self):
        for field in ("corpus_sha256", "rendered_sha256"):
            changed = rows()
            changed[0][field] = "changed"
            with self.assertRaises(ValueError):
                summarize(changed, [1], 2)
        # Deterministic within each mode still fails if the modes select different evidence.
        changed = rows()
        for row in changed:
            if row["mode"] == "whole":
                row["rendered_sha256"] = "other"
        with self.assertRaisesRegex(ValueError, "compiled different"):
            summarize(changed, [1], 2)


if __name__ == "__main__":
    unittest.main()
