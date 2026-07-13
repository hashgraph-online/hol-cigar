from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "benches" / "cigarbench" / "performance.py"
SPEC = importlib.util.spec_from_file_location("cigar_performance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
performance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = performance
SPEC.loader.exec_module(performance)


MetricMutator = Callable[[dict[str, Any], dict[str, Any], str, int], None]


def multihash(label: str) -> str:
    return performance.sha256_multihash(label.encode("utf-8"))


def base_load() -> dict[str, Any]:
    return {
        "atoms": 1_000_000,
        "edges": 10_000_000,
        "candidates": 10,
        "referenced_blob_bytes": 100 * 1024**3,
        "clients": 32,
        "cache_state": "warm",
        "index_state": "current",
        "retrieval_modes": ["exact", "graph", "lexical", "vector"],
        "consistency": "strong",
        "store": "local",
        "bundle_tokens": 6_000,
        "generative_transform": False,
        "embedding": "none",
        "durability_profile": "sqlite",
        "region": "local",
        "memory_mapped_indexes_excluded": True,
        "generated_materializations": 1_000_000,
    }


def make_case(
    case_id: str,
    operation: str,
    *,
    work_unit: str = "operations",
    changes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    load = base_load()
    load.update(changes or {})
    case = {
        "case_id": case_id,
        "operation": operation,
        "work_unit": work_unit,
        "load": load,
    }
    return {
        **case,
        "case_digest": performance.sha256_multihash(performance.canonical_bytes(case)),
    }


def complete_cases() -> list[dict[str, Any]]:
    cases = [
        make_case("warm-cache", "warm_semantic_bundle_cache_hit"),
        make_case("delta", "delta_compile"),
        make_case("full", "full_deterministic_compile"),
        make_case("prompt-hook", "claude_prompt_hook"),
        make_case("mcp", "mcp_summary_retrieval"),
        make_case("ready", "daemon_ready"),
        make_case("journal", "durable_journal_prepare"),
        make_case("local-event", "local_event_propagation"),
        make_case(
            "shared-event",
            "same_region_shared_event",
            changes={
                "store": "shared",
                "region": "same_region",
                "durability_profile": "postgresql_object",
            },
        ),
        make_case("reindex", "one_file_incremental_reindex"),
        make_case(
            "ingestion",
            "ingestion",
            work_unit="atoms",
            changes={"atoms": 1_000},
        ),
        make_case(
            "active-sessions",
            "local_active_sessions",
            work_unit="sessions",
        ),
        make_case("local-scale", "local_scale"),
        make_case("idle", "idle_daemon"),
        make_case("hard-budget", "hard_budget", work_unit="materializations"),
    ]
    curve = [
        (1_000, 10, 1024**3, 1, "cold", "bounded_stale"),
        (10_000, 10_000, 100 * 1024**3, 8, "warm", "strong"),
        (100_000, 10, 100 * 1024**3, 32, "warm", "strong"),
        (1_000_000, 10, 100 * 1024**3, 64, "warm", "strong"),
        (10_000_000, 10, 100 * 1024**3, 128, "warm", "strong"),
    ]
    for atoms, candidates, blobs, clients, cache, consistency in curve:
        cases.append(
            make_case(
                f"shared-scale-{atoms}",
                "shared_scale",
                changes={
                    "atoms": atoms,
                    "candidates": candidates,
                    "referenced_blob_bytes": blobs,
                    "clients": clients,
                    "cache_state": cache,
                    "consistency": consistency,
                    "store": "shared",
                    "region": "same_region",
                    "durability_profile": "postgresql_object",
                },
            )
        )
    return cases


def make_manifest(
    run_id: str,
    *,
    evidence_class: str = "qualification",
    post_warm: int = 30,
    calibration: list[float] | None = None,
    dataset: str = "dataset-v1",
    build: str | None = None,
) -> dict[str, Any]:
    environment = {
        "cpu": "test-cpu",
        "physical_cores": 8,
        "logical_cores": 16,
        "memory_bytes": 64 * 1024**3,
        "os": "test-os",
        "kernel": "test-kernel",
        "filesystem": "test-fs",
        "storage": "test-nvme",
        "power_mode": "performance",
        "compiler_flags": ["--release"],
        "background_load": "none",
        "runner_id": "pinned-runner-1",
        "dedicated_pinned_runner": True,
    }
    return {
        "schema_version": performance.RUN_SCHEMA,
        "run_id": run_id,
        "evidence_class": evidence_class,
        "bindings": {
            "build_digest": multihash(build or run_id),
            "dataset_digest": multihash(dataset),
        },
        "environment": environment,
        "environment_digest": performance.sha256_multihash(
            performance.canonical_bytes(environment)
        ),
        "daemon": {
            "kind": "installed_cigard",
            "artifact_digest": multihash(f"artifact-{run_id}"),
            "installation_receipt_digest": multihash(f"receipt-{run_id}"),
            "version": "1.0.0-test",
        },
        "configuration": {
            "tokenizer": "pinned-tokenizer-v1",
            "policy": "pinned-policy-v1",
        },
        "collection": {
            "clock": "monotonic",
            "warmup_samples_per_case": 1,
            "post_warm_samples_per_case": post_warm,
            "host_calibration_ms": calibration or [10.0] * 30,
        },
        "cases": complete_cases(),
    }


def metrics_for(case: dict[str, Any]) -> dict[str, Any]:
    operation = case["operation"]
    work_units = 100.0
    if operation == "ingestion":
        work_units = 1_000.0
    elif operation == "local_active_sessions":
        work_units = 32.0
    elif operation == "hard_budget":
        work_units = 1_000_000.0
    return {
        "latency_ms": 10.0,
        "elapsed_ms": 100.0,
        "work_units": work_units,
        "allocations_count": 100,
        "allocation_bytes": 4_096,
        "cpu_percent": 0.5 if operation == "idle_daemon" else 10.0,
        "rss_bytes": 100 * 1024**2,
        "disk_amplification": 1.0,
        "database_bytes": 1_000_000,
        "index_bytes": 2_000_000,
        "lock_time_ms": 0.1,
        "queue_depth": 0.0,
        "cache_hit_rate": 1.0,
        "invalidation_lag_ms": 0.1,
        "failed_operations": 0,
        "total_operations": 100,
        "critical_recall": 1.0,
        "leakage_count": 0,
        "correctness_loss": False,
        "correctness_degradation": False,
        "materializations_attempted": (1_000_000 if operation == "hard_budget" else 0),
        "materializations_within_budget": (
            1_000_000 if operation == "hard_budget" else 0
        ),
        "external_latency_ms": {
            "model": 0.0,
            "embedding": 0.0,
            "network_source": 0.0,
            "connector": 0.0,
        },
    }


class PerformanceHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.temp = Path(self.directory.name)
        self.attestation_key = b"independently-held-performance-key-0001"
        self.attestation_key_path = self.temp / "performance-attestation.key"
        self.attestation_key_path.write_bytes(self.attestation_key)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write_evidence(
        self,
        name: str,
        manifest: dict[str, Any],
        mutator: MetricMutator | None = None,
    ) -> tuple[Path, Path]:
        manifest_path = self.temp / f"{name}.manifest.json"
        samples_path = self.temp / f"{name}.samples.jsonl"
        performance.write_json(manifest_path, manifest)
        run_digest = performance.manifest_digest(manifest)
        sequence = 0
        previous: str | None = None
        samples: list[dict[str, Any]] = []
        warmup_count = manifest["collection"]["warmup_samples_per_case"]
        post_count = manifest["collection"]["post_warm_samples_per_case"]
        for case in manifest["cases"]:
            for phase, count in (("warmup", warmup_count), ("post_warm", post_count)):
                for index in range(count):
                    metrics = metrics_for(case)
                    if mutator is not None:
                        mutator(metrics, case, phase, index)
                    sample = performance.sample_with_id(
                        {
                            "schema_version": performance.SAMPLE_SCHEMA,
                            "sequence": sequence,
                            "previous_sample_id": previous,
                            "run_id": manifest["run_id"],
                            "manifest_digest": run_digest,
                            "environment_digest": manifest["environment_digest"],
                            "build_digest": manifest["bindings"]["build_digest"],
                            "dataset_digest": manifest["bindings"]["dataset_digest"],
                            "daemon_artifact_digest": manifest["daemon"][
                                "artifact_digest"
                            ],
                            "case_id": case["case_id"],
                            "case_digest": case["case_digest"],
                            "sample_index": index,
                            "phase": phase,
                            "metrics": metrics,
                        }
                    )
                    samples.append(sample)
                    previous = sample["sample_id"]
                    sequence += 1
        samples_path.write_bytes(
            b"".join(performance.canonical_bytes(sample) + b"\n" for sample in samples)
        )
        return manifest_path, samples_path

    def load_evidence(
        self, manifest_path: Path, samples_path: Path
    ) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
        return performance.load_evidence(manifest_path, samples_path)

    def attest_evidence(
        self,
        name: str,
        evidence: tuple[dict[str, Any], list[dict[str, Any]], str],
    ) -> tuple[dict[str, Any], Path]:
        manifest, samples, samples_digest = evidence
        value = performance.create_attestation(
            manifest,
            samples,
            samples_digest,
            "performance-evaluator-2026q3",
            self.attestation_key,
        )
        path = self.temp / f"{name}.attestation.json"
        performance.write_json(path, value)
        verified = performance.verify_attestation(
            value,
            manifest,
            samples,
            samples_digest,
            self.attestation_key,
        )
        return verified, path

    def test_complete_release_shaped_comparison_passes_and_replays(self) -> None:
        baseline_paths = self.write_evidence("baseline", make_manifest("baseline"))
        candidate_paths = self.write_evidence("candidate", make_manifest("candidate"))
        baseline = self.load_evidence(*baseline_paths)
        candidate = self.load_evidence(*candidate_paths)
        baseline_attestation, baseline_attestation_path = self.attest_evidence(
            "baseline", baseline
        )
        candidate_attestation, candidate_attestation_path = self.attest_evidence(
            "candidate", candidate
        )
        report = performance.comparison_report(
            candidate[0],
            candidate[1],
            candidate[2],
            baseline[0],
            baseline[1],
            baseline[2],
            10_000,
            candidate_attestation,
            baseline_attestation,
        )
        self.assertEqual(report["decision"], "pass")
        self.assertTrue(report["candidate"]["load_matrix"]["complete"])
        for case in report["candidate"]["case_results"]:
            self.assertEqual(
                set(case["distributions"]), set(performance.REQUIRED_DISTRIBUTIONS)
            )
            self.assertEqual(case["post_warm_samples"], 30)

        report_path = self.temp / "comparison-report.json"
        performance.write_json(report_path, report)
        performance.command_replay(
            SimpleNamespace(
                report=report_path,
                candidate_manifest=candidate_paths[0],
                candidate_samples=candidate_paths[1],
                candidate_attestation=candidate_attestation_path,
                candidate_attestation_key_file=self.attestation_key_path,
                baseline_manifest=baseline_paths[0],
                baseline_samples=baseline_paths[1],
                baseline_attestation=baseline_attestation_path,
                baseline_attestation_key_file=self.attestation_key_path,
            )
        )

        # A self-consistent report rewrite is still rejected by source replay.
        rewritten = copy.deepcopy(report)
        rewritten["reasons"] = ["fabricated-success-reason"]
        rewritten = performance.with_report_id(rewritten)
        performance.write_json(report_path, rewritten)
        with self.assertRaisesRegex(performance.PerformanceError, "reproduce"):
            performance.command_replay(
                SimpleNamespace(
                    report=report_path,
                    candidate_manifest=candidate_paths[0],
                    candidate_samples=candidate_paths[1],
                    candidate_attestation=candidate_attestation_path,
                    candidate_attestation_key_file=self.attestation_key_path,
                    baseline_manifest=baseline_paths[0],
                    baseline_samples=baseline_paths[1],
                    baseline_attestation=baseline_attestation_path,
                    baseline_attestation_key_file=self.attestation_key_path,
                )
            )

    def test_unattested_or_forged_qualification_cannot_pass(self) -> None:
        paths = self.write_evidence("unattested", make_manifest("unattested"))
        manifest, samples, sample_digest = self.load_evidence(*paths)
        report = performance.validation_report(manifest, samples, sample_digest)
        self.assertEqual(report["decision"], "insufficient_evidence")
        self.assertIn(
            "missing_or_unverified_independent_attestation", report["reasons"]
        )

        forged = performance.create_attestation(
            manifest,
            samples,
            sample_digest,
            "attacker-controlled-key",
            b"attacker-controlled-key-material-0001",
        )
        with self.assertRaisesRegex(performance.PerformanceError, "authentication"):
            performance.verify_attestation(
                forged,
                manifest,
                samples,
                sample_digest,
                self.attestation_key,
            )

    def test_full_smoke_data_never_qualifies(self) -> None:
        paths = self.write_evidence(
            "smoke", make_manifest("smoke", evidence_class="harness_smoke")
        )
        manifest, samples, sample_digest = self.load_evidence(*paths)
        report = performance.validation_report(manifest, samples, sample_digest)
        self.assertEqual(report["decision"], "insufficient_evidence")
        self.assertIn("smoke_evidence_never_qualifies", report["reasons"])

    def test_sample_content_binding_and_hash_chain_detect_tampering(self) -> None:
        manifest_path, samples_path = self.write_evidence(
            "tamper", make_manifest("tamper")
        )
        lines = samples_path.read_text().splitlines()
        changed = json.loads(lines[0])
        changed["metrics"]["latency_ms"] = 0.01
        lines[0] = json.dumps(changed, sort_keys=True, separators=(",", ":"))
        samples_path.write_text("\n".join(lines) + "\n")
        manifest = performance.validate_manifest(performance.load_json(manifest_path))
        with self.assertRaisesRegex(performance.PerformanceError, "identity"):
            performance.load_samples(samples_path, manifest)

        # Recomputing the changed event id cannot repair the following chain link.
        changed = performance.sample_with_id(changed)
        lines[0] = performance.canonical_bytes(changed).decode("utf-8")
        samples_path.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(performance.PerformanceError, "hash chain"):
            performance.load_samples(samples_path, manifest)

    def test_missing_resource_metric_and_digest_substitution_fail_closed(self) -> None:
        manifest_path, samples_path = self.write_evidence(
            "strict", make_manifest("strict")
        )
        manifest = performance.validate_manifest(performance.load_json(manifest_path))
        lines = samples_path.read_text().splitlines()
        sample = json.loads(lines[0])
        del sample["metrics"]["queue_depth"]
        sample = performance.sample_with_id(sample)
        lines[0] = performance.canonical_bytes(sample).decode("utf-8")
        samples_path.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(performance.PerformanceError, "metrics"):
            performance.load_samples(samples_path, manifest)

        binding_manifest_path, binding_samples_path = self.write_evidence(
            "binding", make_manifest("binding")
        )
        binding_manifest = performance.validate_manifest(
            performance.load_json(binding_manifest_path)
        )
        lines = binding_samples_path.read_text().splitlines()
        sample = json.loads(lines[0])
        sample["dataset_digest"] = multihash("substituted-dataset")
        sample = performance.sample_with_id(sample)
        lines[0] = performance.canonical_bytes(sample).decode("utf-8")
        binding_samples_path.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(performance.PerformanceError, "binding"):
            performance.load_samples(binding_samples_path, binding_manifest)

    def test_29_samples_and_five_percent_host_variance_cannot_pass(self) -> None:
        deviation = 0.5 * math.sqrt(29.0 / 30.0)
        calibration = [10.0 - deviation] * 15 + [10.0 + deviation] * 15
        paths = self.write_evidence(
            "underpowered",
            make_manifest("underpowered", post_warm=29, calibration=calibration),
        )
        manifest, samples, sample_digest = self.load_evidence(*paths)
        report = performance.validation_report(manifest, samples, sample_digest)
        self.assertEqual(report["decision"], "insufficient_evidence")
        self.assertIn("fewer_than_30_post_warm_samples_per_case", report["reasons"])
        self.assertIn("host_variance_is_not_below_5_percent", report["reasons"])
        self.assertEqual(report["candidate"]["host_variance"]["value_percent"], 5.0)

    def test_slo_breach_is_a_failure_even_for_smoke(self) -> None:
        def breach(
            metrics: dict[str, Any], case: dict[str, Any], phase: str, _: int
        ) -> None:
            if (
                case["operation"] == "warm_semantic_bundle_cache_hit"
                and phase == "post_warm"
            ):
                metrics["latency_ms"] = 16.0

        paths = self.write_evidence(
            "slow-smoke",
            make_manifest("slow-smoke", evidence_class="harness_smoke"),
            breach,
        )
        manifest, samples, sample_digest = self.load_evidence(*paths)
        report = performance.validation_report(manifest, samples, sample_digest)
        self.assertEqual(report["decision"], "fail")
        self.assertIn("slo_failure:warm-cache", report["reasons"])

    def test_relative_regression_and_quality_false_passes_are_blocked(self) -> None:
        baseline_paths = self.write_evidence(
            "regression-baseline", make_manifest("regression-baseline")
        )

        def regress(
            metrics: dict[str, Any], case: dict[str, Any], phase: str, _: int
        ) -> None:
            if case["case_id"] == "local-scale" and phase == "post_warm":
                metrics["latency_ms"] = 12.0
                metrics["elapsed_ms"] = 120.0
                metrics["rss_bytes"] = 120 * 1024**2
                metrics["critical_recall"] = 0.9
                metrics["leakage_count"] = 1

        candidate_paths = self.write_evidence(
            "regression-candidate", make_manifest("regression-candidate"), regress
        )
        baseline = self.load_evidence(*baseline_paths)
        candidate = self.load_evidence(*candidate_paths)
        report = performance.comparison_report(
            candidate[0],
            candidate[1],
            candidate[2],
            baseline[0],
            baseline[1],
            baseline[2],
            200,
        )
        self.assertEqual(report["decision"], "fail")
        local = next(
            value
            for value in report["comparisons"]["cases"]
            if value["case_id"] == "local-scale"
        )
        self.assertEqual(local["p95_latency"]["status"], "fail")
        self.assertEqual(local["throughput"]["status"], "fail")
        self.assertEqual(local["rss"]["status"], "fail")
        failed_quality = {
            check["metric"]
            for check in report["comparisons"]["quality"]
            if check["status"] == "fail"
        }
        self.assertIn("minimum_critical_recall", failed_quality)
        self.assertIn("leakage_count", failed_quality)

    def test_changed_dataset_cannot_be_compared_as_a_faster_build(self) -> None:
        baseline_paths = self.write_evidence(
            "dataset-baseline", make_manifest("dataset-baseline")
        )
        candidate_paths = self.write_evidence(
            "dataset-candidate",
            make_manifest("dataset-candidate", dataset="easier-dataset"),
        )
        baseline = self.load_evidence(*baseline_paths)
        candidate = self.load_evidence(*candidate_paths)
        with self.assertRaisesRegex(performance.PerformanceError, "dataset"):
            performance.comparison_report(
                candidate[0],
                candidate[1],
                candidate[2],
                baseline[0],
                baseline[1],
                baseline[2],
                200,
            )

    def test_comparison_rejects_unbounded_bootstrap_work(self) -> None:
        manifest = make_manifest("bounded-bootstrap")
        baseline_paths = self.write_evidence("bounded-baseline", manifest)
        candidate_paths = self.write_evidence("bounded-candidate", manifest)
        baseline = self.load_evidence(*baseline_paths)
        candidate = self.load_evidence(*candidate_paths)
        with self.assertRaisesRegex(performance.PerformanceError, "bounded evaluator"):
            performance.comparison_report(
                candidate[0],
                candidate[1],
                candidate[2],
                baseline[0],
                baseline[1],
                baseline[2],
                performance.MAX_BOOTSTRAP_REPETITIONS + 1,
            )

    def test_cli_os_error_is_content_free(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(
            performance,
            "command_validate",
            side_effect=OSError("/sensitive-path-component/private-evidence"),
        ):
            with contextlib.redirect_stderr(stderr):
                status = performance.main(
                    [
                        "validate",
                        "--manifest",
                        "manifest.json",
                        "--samples",
                        "samples.jsonl",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(status, 2)
        self.assertIn("operating system operation failed", stderr.getvalue())
        self.assertNotIn("sensitive-path-component", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
