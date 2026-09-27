"""Reporting keeps process pairs, failed cells and semantic parity explicit."""

import copy
from pathlib import Path
import tempfile
import unittest

from broker_load_report import read, relative, summarize


def plan(cohorts=8):
    return {
        "cohorts": cohorts,
        "cells": {
            "agents": [1],
            "runtimes": ["python"],
            "storage": ["memory"],
            "parallelism": [1, 4],
        },
    }


def rows(cohorts=8):
    result = []
    for cohort in range(cohorts):
        for parallelism in (1, 4):
            value = cohort + 1
            result.append(
                {
                    "cohort": cohort,
                    "agents": 1,
                    "runtime": "python",
                    "storage": "memory",
                    "parallelism": parallelism,
                    "observations": [{"samples": [{"rendered_sha256": "a" * 64}]}],
                    "rss_samples": [
                        {"host": 10, "worker": 20, "actors": [30], "total": 60}
                    ],
                    "result": {
                        "status": "passed",
                        "agents": [
                            {
                                "compile_ms": {
                                    "p50": value * parallelism,
                                    "p95": value * parallelism,
                                    "p99": value * parallelism,
                                },
                                "cycles_per_second": value * parallelism,
                                "attempted": 1000 * value,
                                "completed": 1000 * value,
                            }
                        ],
                        "fairness": {"python": {"min_max_ratio": 1, "jain": 1}},
                    },
                }
            )
    return result


class LoadReportTests(unittest.TestCase):
    def test_only_whole_process_cohorts_count_as_repetitions(self):
        report = summarize(rows(), plan())
        self.assertEqual(
            report["groups"]["1/python/memory/1"]["metrics"]["compile_median_ms"][
                "cohorts"
            ],
            8,
        )
        compared = report["one_to_four_inflight_tradeoffs"]["1/python/memory"][
            "paired"
        ]["compile_median_ms"]
        self.assertEqual(compared["cohorts"], 8)
        self.assertEqual(compared["mean_difference"], 13.5)
        self.assertEqual(compared["mean_relative_change"], 3)
        self.assertIsNotNone(compared["difference_ci95"])
        smoke = summarize(rows(1), plan(1))
        self.assertIsNone(
            smoke["one_to_four_inflight_tradeoffs"]["1/python/memory"]["paired"][
                "compile_median_ms"
            ]["difference_ci95"]
        )

    def test_failed_process_removes_comparison_not_denominator(self):
        values = rows()
        values[0]["result"] = {
            "status": "failed",
            "violations": ["unexpected operation failure"],
        }
        report = summarize(values, plan())
        self.assertEqual(
            report["groups"]["1/python/memory/1"],
            {
                "status": "incomplete",
                "failed_or_missing_observation_cohorts": [0],
                "metrics": None,
            },
        )
        self.assertEqual(report["groups"]["1/python/memory/4"]["status"], "passed")
        self.assertEqual(
            report["one_to_four_inflight_tradeoffs"]["1/python/memory"],
            {"status": "incomplete", "paired": None},
        )

    def test_duplicate_missing_foreign_and_changed_context_cells_fail(self):
        original = rows()
        for values in (
            original[:-1],
            original + [original[-1]],
            original[:-1] + [original[0]],
        ):
            with self.assertRaisesRegex(ValueError, "cohort"):
                summarize(values, plan())
        changed = copy.deepcopy(original)
        changed[0]["observations"][0]["samples"][0]["rendered_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "different context"):
            summarize(changed, plan())

    def test_json_and_member_path_ambiguity_are_rejected_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, value in enumerate(
                (b'{"status":1,"status":2}', b'{"number":NaN}')
            ):
                path = root / f"case-{index}.json"
                path.write_bytes(value)
                with self.assertRaises(ValueError):
                    read(path)
            for name in ("/outside.json", "../outside.json", "dir/../../outside.json"):
                with self.assertRaises(ValueError):
                    relative(root, name)
            self.assertEqual(
                relative(root, "nested/result.json"), root / "nested/result.json"
            )


if __name__ == "__main__":
    unittest.main()
