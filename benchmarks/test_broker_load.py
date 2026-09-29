"""A reported improvement cannot hide failed, missing or unfair work."""

import copy
import hashlib
import json
from types import SimpleNamespace
import unittest

from broker_load import (
    CONFIG,
    cleanup,
    fixture,
    no_credentials,
    reduce_cell,
    validate_dimensions,
    verify_load_cell,
)
from broker_faults import Transcript, ScheduleFailure
from broker_storage import encoded


CONFIGURATION = json.loads(CONFIG.read_text())


def observation(runtime="python", cycles=30):
    operation = {
        "status": "ok",
        "elapsed_ms": 2,
        "timing": {"queue_us": 500, "service_us": 1000}
        if runtime == "python"
        else None,
    }
    return {
        "status": "ok",
        "kind": "measure",
        "runtime": runtime,
        "native_timing": "validated-reply" if runtime == "python" else "unavailable",
        "duration_ms": 3000,
        "actual_start_ms": 10001,
        "finish_ms": 13001,
        "monotonic_window_ms": 3001,
        "capped": False,
        "attempted": cycles,
        "samples": [
            {
                "sequence": index,
                "lane": index % 4,
                "compile": copy.deepcopy(operation),
                "forget": copy.deepcopy(operation),
                "rendered_sha256": "a" * 64,
            }
            for index in range(cycles)
        ],
    }


def reduce(observations, expected=None):
    return reduce_cell(
        observations,
        CONFIGURATION,
        10000,
        3000,
        4,
        expected or [row["runtime"] for row in observations],
    )


class LoadReductionTests(unittest.TestCase):
    def test_wall_clock_adjustment_cannot_change_elapsed_window_evidence(self):
        row = observation()
        row["finish_ms"] = (
            12990  # Wall clock steps/slews; monotonic duration is complete.
        )
        self.assertEqual(reduce([row])["status"], "passed")
        row["monotonic_window_ms"] = 2990
        row["finish_ms"] = (
            14000  # A long wall interval cannot hide an early monotonic exit.
        )
        self.assertEqual(reduce([row])["status"], "failed")
        for value in (None, True, float("nan"), float("inf"), -1):
            row["monotonic_window_ms"] = value
            with self.assertRaises(ValueError):
                reduce([row])

    def test_cell_binds_workload_recomputes_metrics_and_requires_complete_rss(self):
        row = {
            "schema": "cigar.broker-load-cell.v1",
            "agents": 1,
            "runtime": "python",
            "storage": "memory",
            "parallelism": 4,
            "duration_ms": 3000,
            "start_at_ms": 10000,
            "fixture_sha256": hashlib.sha256(
                encoded(fixture(CONFIGURATION, 1))
            ).hexdigest(),
            "observations": [observation()],
            "rss_samples": [
                {"host": 100, "worker": 200, "actors": [300], "total": 600}
            ],
        }
        row["result"] = reduce(row["observations"])
        verify_load_cell(row, CONFIGURATION, 1, "python", "memory", 4, 3000)
        for change in (
            lambda value: value.update(agents=5),
            lambda value: value.update(fixture_sha256="b" * 64),
            lambda value: value["result"].update(status="invented"),
            lambda value: value.update(rss_samples=[]),
            lambda value: value["rss_samples"][0].update(total=1),
            lambda value: value["rss_samples"][0].update(actors=[True, 1]),
        ):
            invalid = copy.deepcopy(row)
            change(invalid)
            with self.assertRaises(ValueError):
                verify_load_cell(invalid, CONFIGURATION, 1, "python", "memory", 4, 3000)

    def test_runtime_groups_are_separate_and_absent_timing_is_explicit(self):
        result = reduce([observation("python"), observation("node", 100)])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["agents"][0]["compile_ms"]["p99"], 2)
        self.assertEqual(result["agents"][0]["native_queue_us"]["p50"], 500)
        self.assertIsNone(result["agents"][1]["native_service_us"])
        self.assertEqual(result["fairness"]["python"]["min_max_ratio"], 1)

    def test_one_failed_forget_or_compile_is_never_dropped(self):
        for operation in ("compile", "forget"):
            row = observation()
            sample = row["samples"][3]
            sample[operation] = {
                "status": "error",
                "code": "Timeout",
                "dispatched": None,
                "elapsed_ms": 5000,
                "timing": None,
            }
            if operation == "compile":
                sample["forget"] = sample["rendered_sha256"] = None
            result = reduce([row])
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["agents"][0]["attempted"], 30)
            self.assertEqual(result["agents"][0]["completed"], 29)
            self.assertEqual(len(result["agents"][0]["failures"]), 1)
            self.assertIsNone(
                result["agents"][0]["failures"][0][operation]["dispatched"]
            )

    def test_missing_duplicate_reordered_foreign_or_unreported_samples_fail(self):
        for transform in (
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[-1])),
            lambda rows: rows.reverse(),
            lambda rows: rows[0].update(lane=4),
            lambda rows: rows[0].update(sequence=True),
            lambda rows: rows.__setitem__(0, None),
        ):
            row = observation()
            transform(row["samples"])
            with self.assertRaises(ValueError):
                reduce([row])

    def test_missing_actor_or_substituted_runtime_fails(self):
        with self.assertRaises(ValueError):
            reduce([observation()], ["python", "node"])
        with self.assertRaises(ValueError):
            reduce([observation()], ["node"])

    def test_bool_nonfinite_and_invalid_clocks_are_not_measurements(self):
        for value in (True, -1, float("nan"), float("inf"), "3"):
            row = observation()
            row["samples"][0]["compile"]["elapsed_ms"] = value
            with self.assertRaises(ValueError):
                reduce([row])
            row = observation()
            row["actual_start_ms"] = value
            with self.assertRaises(ValueError):
                reduce([row])

    def test_unknown_dispatch_is_preserved_but_missing_dispatch_is_invalid(self):
        for update in ({}, {"dispatched": 0}):
            row = observation()
            row["samples"][0].update(
                compile={
                    "status": "error",
                    "code": "Quota",
                    "elapsed_ms": 1,
                    "timing": None,
                    **update,
                },
                forget=None,
                rendered_sha256=None,
            )
            with self.assertRaises(ValueError):
                reduce([row])

    def test_capped_early_skewed_slow_or_unfair_cells_cannot_pass(self):
        for updates in (
            {"capped": True},
            {"monotonic_window_ms": 2999},
            {"actual_start_ms": 10200},
        ):
            row = observation()
            row.update(updates)
            self.assertEqual(reduce([row])["status"], "failed")
        slow = observation()
        slow["samples"][0]["compile"]["elapsed_ms"] = 1000
        self.assertEqual(reduce([slow])["status"], "failed")
        self.assertEqual(
            reduce([observation(), observation(cycles=20)])["status"], "failed"
        )
        self.assertEqual(reduce([observation(cycles=14)])["status"], "failed")

    def test_changed_context_or_missing_native_timing_cannot_pass(self):
        row = observation()
        row["samples"][0]["rendered_sha256"] = "b" * 64
        self.assertEqual(reduce([row])["status"], "failed")
        for runtime, timing in (
            ("python", None),
            ("node", {"queue_us": 1, "service_us": 2}),
        ):
            row = observation(runtime)
            row["samples"][0]["compile"]["timing"] = timing
            with self.assertRaises(ValueError):
                reduce([row])

    def test_credentials_never_enter_retained_data(self):
        for field in ("secret", "connection", "private_ticket"):
            with self.assertRaises(ValueError):
                no_credentials({"nested": [{field: "redacted-fixture"}]})
            row = observation()
            row[field] = "redacted-fixture"
            with self.assertRaises(ValueError):
                reduce([row])

    def test_matrix_duplicates_are_rejected_before_creating_output_files(self):
        options = SimpleNamespace(
            agent_counts=[1, 5, 12],
            runtimes=["python", "node", "mixed"],
            storage_modes=["memory", "sqlite"],
            in_flight=[1, 4],
        )
        validate_dimensions(options)
        for name in vars(options):
            invalid = copy.deepcopy(options)
            getattr(invalid, name).append(getattr(invalid, name)[0])
            with self.assertRaises(ValueError):
                validate_dimensions(invalid)


class CleanupAndFaultTests(unittest.TestCase):
    def test_all_owned_resources_are_attempted_and_primary_failure_is_preserved(self):
        calls = []

        class Resource:
            cleanup_complete = True

            def __init__(self, name, fail=False):
                self.name, self.fail = name, fail

            def close(self):
                calls.append(self.name)
                if self.fail:
                    raise RuntimeError("fixture cleanup failure")

        actors = [Resource("first", True), Resource("second")]
        owner = Resource("owner")
        with self.assertRaisesRegex(ValueError, "primary") as caught:
            try:
                raise ValueError("primary")
            finally:
                cleanup(actors, owner)
        self.assertEqual(calls, ["first", "second", "owner"])
        self.assertTrue(caught.exception.__notes__)
        calls.clear()
        with self.assertRaisesRegex(RuntimeError, "cleanup"):
            cleanup(actors, owner)
        self.assertEqual(calls, ["first", "second", "owner"])

    def test_fault_mismatch_is_retained_and_aborts_the_dependent_schedule(self):
        transcript = Transcript()
        with self.assertRaises(ScheduleFailure):
            transcript.check(
                "old-ticket",
                {"status": "ok"},
                {"status": "error", "code": "AccessDenied"},
            )
        self.assertFalse(transcript.events[0]["passed"])
        with self.assertRaises(ValueError):
            transcript.check(
                "private-leak", {"status": "ok", "private_ticket": "secret"}
            )
        with self.assertRaises(ScheduleFailure):
            transcript.auth_denied(
                "bad-auth", {"status": "error", "code": "Transport", "dispatched": None}
            )


if __name__ == "__main__":
    unittest.main()
