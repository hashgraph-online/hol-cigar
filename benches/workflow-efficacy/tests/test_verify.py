from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "benches/workflow-efficacy/verify.py"
CONFIGURATION_PATH = ROOT / "benches/workflow-efficacy/configuration.v1.json"
SPEC = importlib.util.spec_from_file_location("workflow_evidence_verify", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(evidence.canonical(value))
    path.chmod(0o600)


class WorkflowEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cigar-workflow-evidence-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.configuration = json.loads(CONFIGURATION_PATH.read_bytes())
        self.configuration["bootstrap"]["resamples"] = 32
        write_json(self.directory / "configuration.json", self.configuration)
        self.environment = {
            "schema_version": evidence.ENVIRONMENT_SCHEMA,
            "observed_at": datetime.now(UTC).isoformat(),
            "host": {
                "machine": "test-arm64",
                "platform": "test",
                "release": "1",
            },
            "toolchain": {
                "cargo": "cargo 1.92.0",
                "protoc": "libprotoc 33.2",
                "python": "3.12",
                "rustc": "rustc 1.92.0",
            },
            "power": {"source": "test", "thermal": "nominal"},
        }
        write_json(self.directory / "environment-receipt.json", self.environment)
        self.raw = self.make_raw()
        write_json(self.directory / "raw-observations.json", self.raw)

    def metric_values(self, treatment: str, trial: int) -> dict[str, object]:
        treatment_ordinal = evidence.TREATMENT_IDS.index(treatment)
        values: dict[str, object] = {}
        for metric in self.configuration["metrics"]:
            if metric in {
                "completed",
                "blocking_requirement_coverage",
                "gold_source_coverage",
                "citation_resolvability_rate",
            }:
                values[metric] = True if metric == "completed" else 1.0
            elif metric == "useful_selection_precision":
                values[metric] = (0.30, 0.50, 0.65)[treatment_ordinal]
            elif metric == "semantic_duplicate_rate":
                values[metric] = (0.45, 0.0, 0.0)[treatment_ordinal]
            elif metric in {"estimated_tokens", "exact_tokens"}:
                values[metric] = (2000, 1200, 1000)[treatment_ordinal] + trial
            elif metric == "materialized_tokens":
                values[metric] = (8000, 5000, 4300)[treatment_ordinal] + trial
            elif metric == "context_cycles":
                values[metric] = 3
            elif metric == "delta_count":
                values[metric] = 2
            elif metric == "delta_reuse_rate":
                values[metric] = (0.70, 0.75, 0.85)[treatment_ordinal]
            elif metric == "materialization_count":
                values[metric] = 3
            elif metric == "revalidation_count":
                values[metric] = 1
            elif metric == "effect_count":
                values[metric] = 1
            elif metric == "checkpoint_count":
                values[metric] = 3
            elif metric == "replay_verified" or metric == "fail_closed":
                values[metric] = True
            elif metric == "negative_cases_passed":
                values[metric] = 9
            elif metric == "embedded_mode_exercised":
                values[metric] = trial % 2 == 0
            elif metric == "sidecar_mode_exercised":
                values[metric] = trial % 2 == 1
            elif metric == "cigar_supplied_tokens":
                values[metric] = (6000, 3600, 3000)[treatment_ordinal] + trial
            elif metric in {"provider_input_tokens", "provider_output_tokens"}:
                values[metric] = 100
            elif metric == "provider_latency_ns":
                values[metric] = 50_000
            elif metric == "cigar_pipeline_latency_ns":
                values[metric] = (300_000, 200_000, 130_000)[treatment_ordinal] + trial
            elif metric.startswith("selected_") or metric == "selected_items":
                values[metric] = (20, 12, 10)[treatment_ordinal]
            elif "latency" in metric or metric == "wall_time_ns":
                values[metric] = (300000, 200000, 130000)[treatment_ordinal] + trial
            elif "allocations" in metric:
                values[metric] = (30000, 20000, 12000)[treatment_ordinal] + trial
            else:
                self.fail(f"unhandled metric {metric}")
        return values

    def make_raw(self) -> dict[str, object]:
        configuration_path = self.directory / "configuration.json"
        environment_path = self.directory / "environment-receipt.json"
        config_digest = evidence.file_digest(configuration_path)
        environment_digest = evidence.file_digest(environment_path)
        host_digest = evidence.digest_bytes(
            evidence.canonical(self.environment["host"])
        )
        toolchain_digest = evidence.digest_bytes(
            evidence.canonical(self.environment["toolchain"])
        )
        fixture_digest = evidence.digest_bytes(
            evidence.canonical(
                {
                    "scenario": self.configuration["scenario"],
                    "workflows": self.configuration["workflows"],
                }
            )
        )
        source_commits = (
            evidence.BASELINE_COMMITS[evidence.TREATMENT_IDS[0]],
            evidence.BASELINE_COMMITS[evidence.TREATMENT_IDS[1]],
            "c" * 40,
        )
        treatments = []
        for index, configured in enumerate(self.configuration["treatments"]):
            files = [{"path": "Cargo.lock", "bytes": 1, "sha256": f"{index + 1}" * 64}]
            treatments.append(
                {
                    "id": configured["id"],
                    "product_version": configured["product_version"],
                    "retrieval_profile": configured["retrieval_profile"],
                    "compiler_profile": configured["compiler_profile"],
                    "source": {
                        "root": f"/external/source/{configured['id']}",
                        "commit": source_commits[index],
                        "tree": f"{index + 4}" * 40,
                        "product_version": configured["product_version"],
                        "context_abi": "cigar.context.v1",
                        "worktree_dirty": False,
                        "source_set_sha256": evidence.digest_bytes(
                            evidence.canonical(files)
                        ),
                        "source_files": files,
                    },
                    "runner": {
                        "binary_sha256": "a" * 64,
                        "generated_manifest_sha256": "b" * 64,
                        "lockfile_sha256": "c" * 64,
                        "runner_source_sha256": "d" * 64,
                        "manifest_template_sha256": "e" * 64,
                        "harness_sha256": "f" * 64,
                        "fixture_sha256": fixture_digest,
                        "source_set_sha256": evidence.digest_bytes(
                            evidence.canonical(files)
                        ),
                        "environment_receipt_sha256": environment_digest,
                        "host_sha256": host_digest,
                        "toolchain_sha256": toolchain_digest,
                        "configuration_sha256": config_digest,
                        "build_profile": "release-locked-offline",
                    },
                }
            )
        seed = "1" * 64
        blocks = []
        observations = []
        for phase, pairing in evidence.expected_blocks(
            self.configuration, "historical", seed
        ):
            order = evidence.latin_row(self.configuration, "historical", seed, pairing)
            blocks.append({"phase": phase, "pairing": pairing, "order": order})
            if phase == "measured":
                for position, treatment in enumerate(order):
                    observations.append(
                        {
                            "pairing": pairing,
                            "treatment_id": treatment,
                            "order_position": position,
                            "metrics": self.metric_values(treatment, pairing["trial"]),
                        }
                    )
        return {
            "schema_version": evidence.RAW_SCHEMA,
            "configuration_sha256": config_digest,
            "cohort": "historical",
            "seed_commitment": seed,
            "treatments": treatments,
            "order_blocks": blocks,
            "observations": observations,
        }

    def build_and_verify(self) -> dict[str, object]:
        manifest = evidence.build(self.directory)
        self.assertEqual(evidence.verify(self.directory), manifest)
        return manifest

    def rewrite_attachment(self, name: str, value: dict[str, object]) -> None:
        manifest_path = self.directory / "evidence-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        file_name = manifest["attachments"][name]["file"]
        path = self.directory / file_name
        write_json(path, value)
        manifest["attachments"][name] = evidence.attachment(path)
        manifest["evidence_id"] = evidence.digest_bytes(
            evidence.canonical(manifest["attachments"])
        )
        write_json(manifest_path, manifest)

    def test_build_and_independent_verification(self) -> None:
        manifest = self.build_and_verify()
        self.assertEqual(manifest["cohort"], "historical")
        report = json.loads((self.directory / "aggregate-report.json").read_bytes())
        self.assertEqual(
            report["overall"]["treatments"][evidence.TREATMENT_IDS[2]][
                "observation_count"
            ],
            100,
        )
        comparison = report["overall"]["comparisons"][
            f"{evidence.TREATMENT_IDS[2]}__vs__{evidence.TREATMENT_IDS[1]}"
        ]
        self.assertIn(
            "paired_mean_delta_95pct_bootstrap_ci",
            comparison["metrics"]["exact_tokens"],
        )

    def test_registered_configuration_and_manifest_schema_are_valid(self) -> None:
        configured, _digest = evidence.configuration(CONFIGURATION_PATH)
        self.assertEqual(
            configured["bootstrap"]["resamples"],
            10_000,
        )
        self.assertEqual(
            configured["cohorts"]["historical"]["measured_trials_per_workflow"],
            20,
        )
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is unavailable")
        schema = json.loads(
            (
                ROOT / "packaging/honey/schemas/honey-three-way-context.v1.schema.json"
            ).read_bytes()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.build_and_verify(), schema)

    def test_pair_identity_does_not_collapse_across_workflows(self) -> None:
        changed = copy.deepcopy(self.raw)
        target = next(
            item
            for item in changed["observations"]
            if item["pairing"]["workflow"] == "consensus-node"
            and item["pairing"]["trial"] == 0
        )
        target["pairing"] = dict(target["pairing"], workflow="solo")
        write_json(self.directory / "raw-observations.json", changed)
        with self.assertRaises(evidence.EvidenceError):
            evidence.build(self.directory)

    def test_corrupt_aggregate_or_interval_is_rejected_after_digest_rebinding(
        self,
    ) -> None:
        self.build_and_verify()
        report = json.loads((self.directory / "aggregate-report.json").read_bytes())
        report["overall"]["treatments"][evidence.TREATMENT_IDS[2]]["metrics"][
            "exact_tokens"
        ]["mean"] += 1
        self.rewrite_attachment("aggregate_report", report)
        with self.assertRaises(evidence.EvidenceError):
            evidence.verify(self.directory)

    def test_corrupt_raw_observation_is_rejected_after_digest_rebinding(self) -> None:
        self.build_and_verify()
        raw = json.loads((self.directory / "raw-observations.json").read_bytes())
        raw["observations"][0]["metrics"]["exact_tokens"] += 1
        self.rewrite_attachment("raw_observations", raw)
        with self.assertRaises(evidence.EvidenceError):
            evidence.verify(self.directory)

    def test_dirty_source_and_profile_mismatch_are_rejected(self) -> None:
        dirty = copy.deepcopy(self.raw)
        dirty["treatments"][0]["source"]["worktree_dirty"] = True
        write_json(self.directory / "raw-observations.json", dirty)
        with self.assertRaises(evidence.EvidenceError):
            evidence.build(self.directory)

        write_json(self.directory / "raw-observations.json", self.raw)
        mismatch = copy.deepcopy(self.raw)
        mismatch["treatments"][1]["compiler_profile"] = (
            "cigar.compiler-profile.balanced.v1"
        )
        write_json(self.directory / "raw-observations.json", mismatch)
        with self.assertRaises(evidence.EvidenceError):
            evidence.build(self.directory)

    def test_missing_treatment_and_unregistered_metric_are_rejected(self) -> None:
        missing = copy.deepcopy(self.raw)
        missing["observations"].pop()
        write_json(self.directory / "raw-observations.json", missing)
        with self.assertRaises(evidence.EvidenceError):
            evidence.build(self.directory)

        extra = copy.deepcopy(self.raw)
        extra["observations"][0]["metrics"]["prompt"] = 1
        write_json(self.directory / "raw-observations.json", extra)
        with self.assertRaises(evidence.EvidenceError):
            evidence.build(self.directory)

    def test_build_never_overwrites_derived_evidence(self) -> None:
        self.build_and_verify()
        with self.assertRaises(evidence.EvidenceError):
            evidence.build(self.directory)


if __name__ == "__main__":
    unittest.main()
