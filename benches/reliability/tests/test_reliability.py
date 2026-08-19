from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def load(name: str):
    path = ROOT / "benches" / "reliability" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = load("reliability.py")
verifier = load("verify.py")
compile_runner = load("compile_load.py")
compile_verifier = load("verify_compile_load.py")
allocation_runner = load("packing_allocation.py")
allocation_verifier = load("verify_packing_allocation.py")
fault_runner = load("fault_matrix.py")
fault_verifier = load("verify_fault_matrix.py")
soak_runner = load("installed_soak.py")
soak_verifier = load("verify_installed_soak.py")


class ReliabilityTests(unittest.TestCase):
    @staticmethod
    def packing_allocation_raw(*, v4_peak: int = 500) -> dict[str, object]:
        configuration = allocation_runner.load_configuration()
        cells = []
        for candidate_count in configuration["candidate_counts"]:
            scale = candidate_count // 128
            pairs = []
            for pair in range(configuration["measured_pairs_per_count"]):
                pairs.append(
                    {
                        "pair": pair,
                        "order": (
                            ["balanced_v3", "balanced_v4"]
                            if pair % 2 == 0
                            else ["balanced_v4", "balanced_v3"]
                        ),
                        "balanced_v3": {
                            "peak_live_bytes": 1_000 * scale,
                            "allocated_bytes": 2_000 * scale,
                            "allocation_count": 200 * scale,
                            "selected_items": candidate_count,
                            "bundle_id": "1220" + "31" * 32,
                        },
                        "balanced_v4": {
                            "peak_live_bytes": v4_peak * scale,
                            "allocated_bytes": 1_000 * scale,
                            "allocation_count": 100 * scale,
                            "selected_items": min(candidate_count, 64),
                            "bundle_id": "1220" + "41" * 32,
                        },
                    }
                )
            cells.append({"candidate_count": candidate_count, "pairs": pairs})
        return {
            "schema_version": "cigar.h094-packing-allocation-raw.v1",
            "measurement_method": configuration["measurement_method"],
            "candidate_counts": configuration["candidate_counts"],
            "warmups_per_treatment_per_count": configuration[
                "warmups_per_treatment_per_count"
            ],
            "measured_pairs_per_count": configuration["measured_pairs_per_count"],
            "profiles": configuration["profiles"],
            "cells": cells,
        }

    def test_configuration_is_exact_and_content_free(self) -> None:
        configuration = runner.load_configuration()
        self.assertEqual(configuration["retained_record_counts"], verifier.COUNTS)
        self.assertEqual(configuration["compile_concurrency"], [1, 2, 4, 8, 16])
        self.assertEqual(configuration["soak_duration_seconds"], 86_400)
        self.assertEqual(configuration["memory_slope_maximum_bytes_per_hour"], 0)
        soak_configuration = soak_runner.load_object(soak_runner.CONFIGURATION)
        self.assertEqual(
            soak_configuration["profiles"]["soak-smoke"][
                "maximum_coordinator_rss_slope_bytes_per_hour"
            ],
            1_048_576,
        )
        self.assertEqual(
            soak_configuration["profiles"]["soak-rc-24h"][
                "maximum_coordinator_rss_slope_bytes_per_hour"
            ],
            0,
        )

    def test_every_scale_profile_is_bounded_and_exact(self) -> None:
        for count in verifier.COUNTS:
            profile = runner.profile(count)
            self.assertEqual(profile["atoms"], count)
            self.assertEqual(profile["edges"], count)
            self.assertLessEqual(profile["atom_batch_size"], 1_000)
            self.assertLessEqual(profile["edge_batch_size"], 10_000)
            self.assertEqual(
                profile["capacity_profile"],
                "large_local" if count == 1_000_000 else "standard",
            )
            self.assertEqual(
                profile["maximum_database_bytes"],
                68_719_476_736 if count == 1_000_000 else 4_294_967_296,
            )
        with self.assertRaises(runner.ReliabilityError):
            runner.profile(9)

    def test_driver_receipt_tampering_fails_closed(self) -> None:
        receipt = {
            "schema_version": "cigar.local-scale-result.v1",
            "result": "fixture-passed",
            "release_scale_qualified": False,
            "targets": {"atoms": 8},
            "observed": {"atoms": 8},
            "lifecycle": {name: 1 for name in verifier.LIFECYCLE},
            "roots": {
                "semantic_before_reopen": "same",
                "semantic_after_reopen": "same",
                "semantic_after_restore": "same",
            },
        }
        receipt["receipt_id"] = "1220" + verifier.hashlib.sha256(
            verifier.rust_struct_json(receipt)
        ).hexdigest()
        verifier.verify_driver_receipt(receipt, 8)
        receipt["lifecycle"]["restart_nanoseconds"] = 0
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_driver_receipt(receipt, 8)

    def test_create_new_publication_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            runner.write_new(path, {"value": 1}, 0o400)
            self.assertEqual(json.loads(path.read_text()), {"value": 1})
            with self.assertRaises(runner.ReliabilityError):
                runner.write_new(path, {"value": 2}, 0o400)

    def test_compile_load_cells_require_exact_registered_matrix(self) -> None:
        configuration = runner.load_configuration()
        cells = []
        for operation in ("full_bundle", "delta"):
            for concurrency in configuration["compile_concurrency"]:
                cells.append(
                    {
                        "operation": operation,
                        "concurrency": concurrency,
                        "queue_capacity": configuration["compile_queue_capacity"],
                        "iterations": configuration["compile_iterations_per_cell"],
                        "wall_nanoseconds": 10,
                        "operation_nanoseconds_p50": 5,
                        "operation_nanoseconds_p95": 9,
                        "maximum_queue_depth": min(concurrency, 32),
                        "rejected": 0,
                        "completed": configuration["compile_iterations_per_cell"],
                        "deterministic": True,
                    }
                )
        raw = {
            "schema_version": "cigar.h094-compile-load-result.v1",
            "compiler_profile": "cigar.compiler-profile.balanced.v4",
            "candidate_count": 128,
            "requirement_count": 4,
            "queue_capacity": configuration["compile_queue_capacity"],
            "iterations_per_cell": configuration["compile_iterations_per_cell"],
            "concurrency": configuration["compile_concurrency"],
            "allocation_probe": {
                "warmup_iterations": 128,
                "measurement_iterations": 2_000,
                "operations_per_iteration": 2,
                "live_bytes_before": 100,
                "live_bytes_after": 100,
                "live_allocations_before": 2,
                "live_allocations_after": 2,
                "peak_live_bytes": 200,
                "zero_monotonic_growth": True,
            },
            "cells": cells,
        }
        compile_runner.validate_raw(raw, configuration)
        raw["cells"][0]["deterministic"] = False
        with self.assertRaises(compile_runner.CompileLoadError):
            compile_runner.validate_raw(raw, configuration)

    def test_compile_report_identity_tampering_fails_closed(self) -> None:
        body = {
            "schema_version": "cigar.h094-bound-compile-load-result.v1",
            "status": "passed",
            "source_revision": "a" * 40,
            "configuration": {},
            "driver": {},
            "candidate": {},
            "raw": {},
            "queue_capacity_fixed": True,
            "all_cells_deterministic": True,
            "allocation_probe": {},
            "cells": [],
        }
        report = {
            **body,
            "report_id": compile_runner.hashlib.sha256(compile_runner.canonical(body)).hexdigest(),
        }
        report["cells"].append({"untrusted": True})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_bytes(compile_runner.canonical(report))
            with self.assertRaises(compile_verifier.compile_load.CompileLoadError):
                compile_verifier.verify(path)

    def test_packing_allocation_matrix_and_confidence_gate_are_exact(self) -> None:
        configuration = allocation_runner.load_configuration()
        raw = self.packing_allocation_raw()
        allocation_runner.validate_raw(raw, configuration)
        evaluation = allocation_runner.evaluate(raw, configuration)
        self.assertEqual(evaluation["status"], "passed")
        self.assertEqual(
            [cell["candidate_count"] for cell in evaluation["cells"]], [128, 512]
        )
        for cell in evaluation["cells"]:
            self.assertEqual(
                cell["comparison"]["peak_live_reduction_millionths"], 500_000
            )
            self.assertEqual(
                cell["comparison"][
                    "peak_live_reduction_95pct_bootstrap_interval_millionths"
                ],
                [500_000, 500_000],
            )
            self.assertTrue(all(cell["gates"].values()))

        weak = self.packing_allocation_raw(v4_peak=700)
        self.assertEqual(
            allocation_runner.evaluate(weak, configuration)["status"], "failed"
        )
        reordered = self.packing_allocation_raw()
        reordered["cells"][0]["pairs"][0]["order"].reverse()
        with self.assertRaises(allocation_runner.PackingAllocationError):
            allocation_runner.validate_raw(reordered, configuration)

    def test_packing_allocation_verifier_rejects_symlink_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            evidence = parent / "evidence"
            evidence.mkdir()
            (evidence / allocation_runner.RAW_NAME).write_text("{}", encoding="utf-8")
            (evidence / allocation_runner.REPORT_NAME).write_text("{}", encoding="utf-8")
            raw_path, report_path, raw_binding = allocation_verifier.evidence_paths(
                evidence
            )
            self.assertEqual(raw_path.name, allocation_runner.RAW_NAME)
            self.assertEqual(report_path.name, allocation_runner.REPORT_NAME)
            self.assertEqual(raw_binding["bytes"], 2)
            alias = parent / "alias"
            alias.symlink_to(evidence, target_is_directory=True)
            with self.assertRaises(allocation_runner.PackingAllocationError):
                allocation_verifier.verify(alias, parent / "missing-driver")

    def test_fault_manifest_covers_registered_matrix_exactly_once(self) -> None:
        configuration = fault_runner.load_object(fault_runner.CONFIGURATION)
        manifest = fault_runner.load_object(fault_runner.MANIFEST)
        cases = fault_runner.validate_manifest(manifest, configuration)
        observed = [fault for case in cases for fault in case["faults"]]
        self.assertCountEqual(observed, configuration["required_faults"])
        self.assertEqual(len(observed), len(set(observed)))

    def test_fault_report_tampering_fails_before_file_reads(self) -> None:
        body = {
            "schema_version": "cigar.h094-fault-matrix-result.v1",
            "status": "passed",
            "source": {},
            "configuration": {},
            "manifest": {},
            "runner": {},
            "cargo": {},
            "required_fault_count": 25,
            "case_count": 18,
            "all_cases_passed": True,
            "results": [],
        }
        report = {
            **body,
            "report_id": fault_runner.sha256(fault_runner.canonical(body)),
        }
        report["status"] = "failed"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fault-report.json"
            path.write_bytes(fault_runner.canonical(report))
            with self.assertRaises(fault_verifier.VerificationError):
                fault_verifier.verify(path)

    def test_installed_soak_profiles_are_exact_and_release_is_24_hours(self) -> None:
        configuration = soak_runner.load_object(soak_runner.CONFIGURATION)
        release = configuration["profiles"]["soak-rc-24h"]
        self.assertEqual(release["duration_seconds"], 86_400)
        self.assertEqual(release["sample_interval_seconds"], 10)
        self.assertEqual(release["warmup_seconds"], 3_600)
        self.assertEqual(release["maximum_sample_gap_seconds"], 30)
        self.assertEqual(
            sorted(configuration["required_operations"]),
            sorted(set(configuration["required_operations"])),
        )

    def test_independent_soak_slope_detects_growth(self) -> None:
        flat = [(0, 100), (1_800_000_000_000, 100), (3_600_000_000_000, 100)]
        growth = [(0, 100), (1_800_000_000_000, 200), (3_600_000_000_000, 300)]
        self.assertEqual(soak_verifier.slope_bytes_per_hour(flat), 0)
        self.assertGreater(soak_verifier.slope_bytes_per_hour(growth), 0)

    @staticmethod
    def _soak_sample(
        sequence: int,
        elapsed_seconds: int,
        operations: dict[str, int],
        completed: dict[str, int],
    ) -> dict[str, object]:
        return {
            "schema_version": "cigar.h094-installed-soak-sample.v1",
            "sequence": sequence,
            "elapsed_nanoseconds": elapsed_seconds * 1_000_000_000,
            "unix_seconds": 1_800_000_000 + elapsed_seconds,
            "coordinator_rss_bytes": 1_048_576,
            "active_process_group_rss_bytes": 0,
            "disk_available_bytes": 1_073_741_824,
            "active_job": None,
            "completed_cycles": completed,
            "operation_counts": operations,
        }

    def _verify_sample_series(
        self,
        elapsed_seconds: list[int],
        final_operations: dict[str, int] | None = None,
        final_completed: dict[str, int] | None = None,
    ) -> tuple[int, int, int, int]:
        operations = {"compile": 1}
        completed = {kind: 1 for kind in soak_verifier.KINDS}
        samples = []
        for sequence, elapsed in enumerate(elapsed_seconds):
            is_final = sequence == len(elapsed_seconds) - 1
            observed_operations = (
                final_operations
                if is_final and final_operations is not None
                else ({"compile": 1} if is_final else {"compile": 0})
            )
            observed_completed = (
                final_completed
                if is_final and final_completed is not None
                else (
                    completed
                    if is_final
                    else {kind: 0 for kind in soak_verifier.KINDS}
                )
            )
            samples.append(
                self._soak_sample(
                    sequence,
                    elapsed,
                    observed_operations,
                    observed_completed,
                )
            )
        profile = {
            "duration_seconds": 120,
            "sample_interval_seconds": 5,
            "warmup_seconds": 20,
            "maximum_sample_gap_seconds": 15,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "samples.jsonl"
            path.write_text(
                "".join(
                    json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n"
                    for sample in samples
                ),
                encoding="utf-8",
            )
            return soak_verifier.verify_samples(path, profile, operations, completed, set())

    def test_independent_soak_samples_cover_the_registered_window(self) -> None:
        result = self._verify_sample_series(list(range(0, 121, 15)))
        self.assertEqual(result[:2], (9, 2))

        with self.assertRaises(soak_verifier.VerificationError):
            self._verify_sample_series(list(range(15, 121, 15)))

    def test_independent_soak_samples_end_with_exact_cycle_counters(self) -> None:
        with self.assertRaises(soak_verifier.VerificationError):
            self._verify_sample_series(
                list(range(0, 121, 15)),
                final_operations={"compile": 0},
            )
        with self.assertRaises(soak_verifier.VerificationError):
            self._verify_sample_series(
                list(range(0, 121, 15)),
                final_completed={kind: 0 for kind in soak_verifier.KINDS},
            )

    def test_soak_json_inputs_reject_duplicate_and_nonfinite_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text('{"status":"passed","status":"failed"}\n')
            nonfinite = Path(temporary) / "nonfinite.json"
            nonfinite.write_text('{"rss":NaN}\n')
            for path in (duplicate, nonfinite):
                with self.assertRaises(soak_runner.SoakRunError):
                    soak_runner.load_object(path)
                with self.assertRaises(soak_verifier.VerificationError):
                    soak_verifier.load(path)

    def test_soak_cycle_verifier_rejects_symlinked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cycles"
            target = Path(temporary) / "target"
            root.mkdir(mode=0o700)
            target.mkdir(mode=0o700)
            (root / "00000001-installed").symlink_to(target, target_is_directory=True)
            with self.assertRaises(soak_verifier.VerificationError):
                soak_verifier.verify_cycles(root)

    def test_installed_soak_schema_preserves_profile_specific_rss_gates(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "packaging"
                / "honey"
                / "schemas"
                / "honey-installed-soak-report.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        conditional = schema["allOf"][0]
        self.assertEqual(
            conditional["then"]["properties"]["coordinator_rss_slope_bytes_per_hour"]["maximum"],
            1_048_576,
        )
        self.assertEqual(
            conditional["else"]["properties"]["coordinator_rss_slope_bytes_per_hour"]["maximum"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
