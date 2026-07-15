from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "mutation_campaign", ROOT / "tools" / "quality" / "mutation_campaign.py"
)
assert SPEC is not None and SPEC.loader is not None
mutation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mutation)


class MutationCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = mutation.load_policy(ROOT)
        metadata = json.loads(
            subprocess.run(
                [
                    "cargo",
                    "metadata",
                    "--format-version",
                    "1",
                    "--no-deps",
                    "--locked",
                    "--offline",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        cls.inventory = mutation.workspace_package_inventory(ROOT, metadata, cls.policy)
        cls.source_files = []
        for package in cls.policy["production_packages"]:
            package_root = cls.inventory[package]
            candidates = sorted(package_root.rglob("*.rs"))
            selected = next(
                path
                for path in candidates
                if not mutation._source_is_excluded(
                    path.relative_to(ROOT).as_posix(), cls.policy
                )
            )
            cls.source_files.append(
                {"package": package, "path": selected.relative_to(ROOT).as_posix()}
            )

    def mutant(self, index: int, *, package: str = "cigar-dashboard") -> dict[str, Any]:
        source = next(
            entry["path"] for entry in self.source_files if entry["package"] == package
        )
        return {
            "name": f"{source}:1:1: replace candidate {index}",
            "package": package,
            "file": source,
            "function": None,
            "span": {
                "start": {"line": 1, "column": 1},
                "end": {"line": 1, "column": 2},
            },
            "replacement": "false",
            "genre": "FnValue",
        }

    def fixture(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        mutants = [
            self.mutant(index, package=package)
            for index, package in enumerate(self.policy["production_packages"])
        ]
        mutants.extend(self.mutant(index) for index in range(24, 30))
        discovered = [
            {**mutant, "diff": f"diff-{index}"} for index, mutant in enumerate(mutants)
        ]
        outcomes = [
            {
                "scenario": "Baseline",
                "summary": "Success",
                "log_path": "log/baseline.log",
                "diff_path": None,
                "phase_results": [
                    {
                        "phase": "Test",
                        "duration": 1.0,
                        "process_status": "Success",
                        "argv": ["cargo", "nextest", "run"],
                    }
                ],
            }
        ]
        for index, mutant in enumerate(mutants):
            outcomes.append(
                {
                    "scenario": {"Mutant": mutant},
                    "summary": "MissedMutant" if index >= 27 else "CaughtMutant",
                    "log_path": f"log/{index}.log",
                    "diff_path": f"diff/{index}.diff",
                    "phase_results": [
                        {
                            "phase": "Test",
                            "duration": 1.0,
                            "process_status": "Success"
                            if index >= 27
                            else {"Failure": 1},
                            "argv": ["cargo", "nextest", "run"],
                        }
                    ],
                }
            )
        document = {
            "outcomes": outcomes,
            "total_mutants": 30,
            "missed": 3,
            "caught": 27,
            "timeout": 0,
            "unviable": 0,
            "success": 0,
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T04:00:00Z",
            "cargo_mutants_version": "27.1.0",
        }
        return document, discovered

    def validate(
        self,
        outcomes: dict[str, Any],
        discovered: list[dict[str, Any]],
        *,
        source_files: list[dict[str, str]] | None = None,
        duration: float = 14_400,
    ) -> tuple[dict[str, int | float], dict[str, Any]]:
        return mutation.validate_campaign_documents(
            outcomes=outcomes,
            discovered_mutants=discovered,
            source_files=self.source_files if source_files is None else source_files,
            inventory=self.inventory,
            policy=self.policy,
            observed_duration_seconds=duration,
        )

    def test_policy_covers_every_workspace_package_with_exact_exclusions(self) -> None:
        self.assertEqual(len(self.policy["production_packages"]), 24)
        self.assertEqual(
            set(self.inventory),
            set(self.policy["production_packages"])
            | set(self.policy["excluded_package_names"]),
        )
        self.assertEqual(
            tuple(self.policy["excluded_source_globs"]),
            mutation.EXPECTED_EXCLUDED_SOURCE_GLOBS,
        )
        self.assertNotIn("**/build.rs", self.policy["excluded_source_globs"])
        self.assertFalse(
            mutation._source_is_excluded("crates/cigar-catalog/build.rs", self.policy)
        )
        self.assertTrue(
            {
                "cigar-catalog",
                "cigar-compiler",
                "cigar-protocol",
                "cigar-replay",
                "cigar-retrieval",
                "cigar-space",
            }.issubset(self.policy["critical_packages"])
        )

    def test_policy_weakening_is_rejected(self) -> None:
        policy = json.loads((ROOT / mutation.POLICY_PATH).read_text(encoding="utf-8"))
        requirements = json.loads(
            (ROOT / mutation.REQUIREMENTS_PATH).read_text(encoding="utf-8")
        )
        weakened_policies = []
        missing_critical_package = deepcopy(policy)
        missing_critical_package["critical_packages"].remove("cigar-compiler")
        weakened_policies.append(missing_critical_package)
        missing_critical_source = deepcopy(policy)
        missing_critical_source["critical_source_globs"].pop()
        weakened_policies.append(missing_critical_source)
        hidden_build_script = deepcopy(policy)
        hidden_build_script["excluded_source_globs"].insert(1, "**/build.rs")
        weakened_policies.append(hidden_build_script)
        for weakened in weakened_policies:
            with (
                self.subTest(policy=weakened),
                mock.patch.object(
                    mutation,
                    "load_json",
                    side_effect=[weakened, requirements],
                ),
                self.assertRaises(mutation.MutationCampaignError),
            ):
                mutation.load_policy(ROOT)

    def test_full_command_has_no_representative_file_or_package_omission(self) -> None:
        command = mutation.campaign_command(self.policy, Path("/private/tmp/mutations"))
        self.assertIn("--workspace", command)
        self.assertNotIn("--file", command)
        self.assertNotIn("--re", command)
        selected = [
            command[index + 1]
            for index, item in enumerate(command)
            if item == "--package"
        ]
        excluded = [
            command[index + 1]
            for index, item in enumerate(command)
            if item == "--exclude"
        ]
        self.assertEqual(selected, self.policy["production_packages"])
        self.assertEqual(excluded, self.policy["excluded_source_globs"])
        self.assertIn("--cargo-arg=--locked", command)
        self.assertIn("--cargo-arg=--offline", command)
        self.assertIn("nextest", command)

    def test_raw_outcomes_recompute_all_release_metrics(self) -> None:
        outcomes, discovered = self.fixture()
        metrics, details = self.validate(outcomes, discovered)
        self.assertEqual(
            metrics,
            {
                "mutation.score_percent": 90.0,
                "mutation.duration_seconds": 14_400,
                "mutation.production_package_fraction": 1.0,
                "mutation.timeout_count": 0,
                "mutation.critical_viable_survivor_count": 0,
            },
        )
        self.assertEqual(details["viable_denominator"], 30)
        self.assertEqual(len(details["source_files"]), len(self.source_files))

    def test_representative_scope_missing_package_and_generated_source_fail(
        self,
    ) -> None:
        outcomes, discovered = self.fixture()
        with self.assertRaisesRegex(mutation.MutationCampaignError, "omits packages"):
            self.validate(outcomes, discovered, source_files=self.source_files[:-1])
        generated = deepcopy(self.source_files)
        generated[0] = {
            "package": "cigar-api",
            "path": "crates/cigar-api/src/generated/operations.rs",
        }
        with self.assertRaisesRegex(mutation.MutationCampaignError, "excluded path"):
            self.validate(outcomes, discovered, source_files=generated)

    def test_under_duration_timeout_and_stale_tool_fail(self) -> None:
        outcomes, discovered = self.fixture()
        under = deepcopy(outcomes)
        under["end_time"] = "2026-01-01T03:59:59Z"
        with self.assertRaisesRegex(
            mutation.MutationCampaignError, "thresholds: duration"
        ):
            self.validate(under, discovered, duration=14_399)

        timed_out = deepcopy(outcomes)
        timed_out["outcomes"][-1]["summary"] = "Timeout"
        timed_out["outcomes"][-1]["phase_results"][-1]["process_status"] = "Timeout"
        timed_out["missed"] = 2
        timed_out["timeout"] = 1
        with self.assertRaisesRegex(mutation.MutationCampaignError, "timeouts"):
            self.validate(timed_out, discovered)

        stale = deepcopy(outcomes)
        stale["cargo_mutants_version"] = "27.0.0"
        with self.assertRaisesRegex(mutation.MutationCampaignError, "version"):
            self.validate(stale, discovered)

    def test_critical_survivor_malformed_denominator_and_missing_outcome_fail(
        self,
    ) -> None:
        outcomes, discovered = self.fixture()
        critical = deepcopy(outcomes)
        critical_mutant = critical["outcomes"][-1]["scenario"]["Mutant"]
        critical_source = next(
            entry["path"]
            for entry in self.source_files
            if entry["package"] == "cigar-canon"
        )
        critical_mutant["package"] = "cigar-canon"
        critical_mutant["file"] = critical_source
        critical_mutant["name"] = f"{critical_source}:1:1: critical survivor"
        discovered[-1] = {**critical_mutant, "diff": "critical-diff"}
        with self.assertRaisesRegex(
            mutation.MutationCampaignError, "critical-survivors"
        ):
            self.validate(critical, discovered)

        malformed, malformed_discovered = self.fixture()
        for outcome in malformed["outcomes"][1:]:
            outcome["summary"] = "Unviable"
            outcome["phase_results"][0]["phase"] = "Build"
            outcome["phase_results"][0]["process_status"] = {"Failure": 1}
        malformed["caught"] = 0
        malformed["missed"] = 0
        malformed["unviable"] = 30
        with self.assertRaisesRegex(mutation.MutationCampaignError, "denominator"):
            self.validate(malformed, malformed_discovered)

        missing, missing_discovered = self.fixture()
        missing["outcomes"].pop()
        missing["total_mutants"] = 29
        missing["missed"] = 2
        with self.assertRaisesRegex(mutation.MutationCampaignError, "omit"):
            self.validate(missing, missing_discovered)

    def test_count_tamper_and_duplicate_discovery_fail(self) -> None:
        outcomes, discovered = self.fixture()
        outcomes["caught"] = 26
        with self.assertRaisesRegex(mutation.MutationCampaignError, "caught count"):
            self.validate(outcomes, discovered)

        outcomes, discovered = self.fixture()
        discovered[-1] = deepcopy(discovered[0])
        with self.assertRaisesRegex(mutation.MutationCampaignError, "duplicate mutant"):
            self.validate(outcomes, discovered)


if __name__ == "__main__":
    unittest.main()
