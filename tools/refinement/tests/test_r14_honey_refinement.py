from __future__ import annotations

# ruff: noqa: E402

import sys
import tempfile
import unittest
import hashlib
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import canonical_bytes, identity, multihash_bytes
from tools.refinement.honey_refinement import (
    COHORT_SCHEMA,
    EXPECTED_LANES,
    EXPECTED_PROFILE_ID,
    EXPECTED_SCENARIOS,
    EXPECTED_SOURCES,
    EXPECTED_THRESHOLDS,
    EXPECTED_WORKFLOWS,
    HoneyRefinementError,
    create_plan,
    load_authority,
    validate,
)
from tools.refinement.schema import SchemaError, SchemaRegistry
from tools.refinement.source_build import (
    SourceBuildError,
    _adapter_manifest,
    _tool,
    load_source_consumers,
)


class HoneyRefinementAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = SchemaRegistry(ROOT / "schemas/refinement")
        self.profile, self.cohort = load_authority(ROOT)

    def test_profile_and_cohort_are_closed_bound_and_self_identifying(self) -> None:
        self.assertEqual(self.profile["profile_id"], EXPECTED_PROFILE_ID)
        self.registry.validate(COHORT_SCHEMA, self.cohort)
        unsigned = dict(self.cohort)
        claimed = unsigned.pop("cohort_id")
        self.assertEqual(identity(unsigned), claimed)
        self.assertEqual(
            tuple(self.cohort["execution_matrix"]["source_roles"]),
            EXPECTED_SOURCES,
        )
        self.assertEqual(
            tuple(self.cohort["execution_matrix"]["lanes"]),
            EXPECTED_LANES,
        )

    def test_profile_freezes_thresholds_cycles_and_public_authority(self) -> None:
        thresholds = {
            row["id"]: (row["operator"], row["value"], row["unit"], row["scope"])
            for row in self.profile["promotion_thresholds"]
        }
        self.assertEqual(thresholds, EXPECTED_THRESHOLDS)
        self.assertEqual(
            [row["allowed_change_class"] for row in self.profile["cycles"]],
            [
                "measurement-harness-only",
                "targeted-product-improvement",
                "resilience-and-regression-only",
            ],
        )
        self.assertEqual(self.profile["cycles"][1]["maximum_product_hypotheses"], 3)
        self.assertTrue(self.profile["authority"]["create_private_draft_pull_request"])
        self.assertTrue(self.profile["authority"]["merge"])
        self.assertFalse(self.profile["authority"]["release"])
        self.assertFalse(self.profile["authority"]["push_public"])

    def test_cohort_covers_six_workflows_and_all_required_scenarios(self) -> None:
        self.assertEqual(
            tuple(self.cohort["downstream"]["workflows"]), EXPECTED_WORKFLOWS
        )
        self.assertEqual(
            tuple(row["id"] for row in self.cohort["scenario_classes"]),
            EXPECTED_SCENARIOS,
        )
        covered_strata = {
            stratum
            for row in self.cohort["scenario_classes"]
            for stratum in row["kernel_strata"]
        }
        self.assertEqual(covered_strata, set(self.cohort["kernel"]["protected_strata"]))
        self.assertTrue(self.cohort["measurement_rules"]["identical_assignments"])
        self.assertTrue(self.cohort["measurement_rules"]["cold_and_warm_runs"])

    def test_unknown_profile_or_cohort_fields_fail_closed(self) -> None:
        profile = dict(self.profile)
        profile["unexpected"] = True
        with self.assertRaises(SchemaError):
            self.registry.validate("honey-refinement-profile-v1.schema.json", profile)
        cohort = dict(self.cohort)
        cohort["unexpected"] = True
        with self.assertRaises(SchemaError):
            self.registry.validate(COHORT_SCHEMA, cohort)

    def test_local_validation_binds_champion_main_and_disabled_public_push(
        self,
    ) -> None:
        profile, cohort = validate(repository_root=ROOT)
        self.assertEqual(
            profile["frozen_sources"]["champion"]["source"]["revision"],
            "b864d4e142de434790ec11f470dfe2eeb51f9099",
        )
        self.assertEqual(cohort["cohort_id"], self.cohort["cohort_id"])

    def _planned(self, changed_path: str) -> dict[str, object]:
        champion = self.profile["frozen_sources"]["champion"]["source"]
        candidate = {"revision": "c" * 40, "tree": "d" * 40}

        def git_text(_root: Path, *arguments: str) -> str:
            if arguments[:2] == ("status", "--porcelain=v1"):
                return ""
            if arguments == ("branch", "--show-current"):
                return "refine/honey-0.9.2-cycle-a"
            if arguments[:2] == ("diff", "--name-only"):
                return changed_path
            raise AssertionError(arguments)

        def source(_root: Path, revision: str) -> dict[str, str]:
            if revision in {"HEAD", candidate["revision"]}:
                return candidate
            if revision == champion["revision"]:
                return champion
            raise AssertionError(revision)

        with (
            mock.patch(
                "tools.refinement.honey_refinement.validate",
                return_value=(self.profile, self.cohort),
            ),
            mock.patch(
                "tools.refinement.honey_refinement._git_text", side_effect=git_text
            ),
            mock.patch("tools.refinement.honey_refinement._source", side_effect=source),
            mock.patch(
                "tools.refinement.honey_refinement._git",
                return_value=CompletedProcess(
                    args=[], returncode=0, stdout=b"", stderr=b""
                ),
            ),
        ):
            return create_plan(
                repository_root=ROOT,
                core_root=ROOT,
                cedar_root=ROOT,
                candidate_revision=candidate["revision"],
                cycle="cycle-a",
            )

    def test_cycle_a_plan_has_exact_three_by_five_matrix_and_no_mutation_authority(
        self,
    ) -> None:
        plan = self._planned("tools/refinement/honey_refinement.py")
        self.registry.validate("honey-evaluation-plan-v1.schema.json", plan)
        self.assertEqual(len(plan["cells"]), 15)
        self.assertEqual(len({row["cell_id"] for row in plan["cells"]}), 15)
        self.assertEqual(
            plan["plan_id"],
            identity({key: value for key, value in plan.items() if key != "plan_id"}),
        )
        self.assertFalse(plan["authority"]["edit_product"])
        self.assertFalse(plan["authority"]["create_pull_request"])
        self.assertFalse(plan["authority"]["push_public"])

    def test_cycle_a_rejects_product_changes(self) -> None:
        with self.assertRaisesRegex(HoneyRefinementError, "product or unscoped"):
            self._planned("crates/cigar-compiler/src/compiler.rs")

    def test_cycle_b_plan_binds_h1_release_sources_profiles_and_no_public_authority(
        self,
    ) -> None:
        champion = {
            "revision": "b864d4e142de434790ec11f470dfe2eeb51f9099",
            "tree": "ef62fcf807bac088239d6e29c64f64ce595414cf",
        }
        candidate = {"revision": "c" * 40, "tree": "d" * 40}
        external = {
            "HUMIDOR": {"revision": "e" * 40, "tree": "f" * 40},
            "CEDAR": {"revision": "1" * 40, "tree": "2" * 40},
        }

        def git_text(_root: Path, *arguments: str) -> str:
            if arguments[:2] == ("status", "--porcelain=v1"):
                return ""
            if arguments == ("branch", "--show-current"):
                return "release/honey-0.9.2-h1"
            raise AssertionError(arguments)

        def source(_root: Path, revision: str) -> dict[str, str]:
            if revision in {"HEAD", candidate["revision"]}:
                return candidate
            if revision in {champion["revision"], "refs/heads/main"}:
                return champion
            raise AssertionError(revision)

        with (
            mock.patch(
                "tools.refinement.honey_refinement.validate",
                return_value=(self.profile, self.cohort),
            ),
            mock.patch(
                "tools.refinement.honey_refinement._git_text", side_effect=git_text
            ),
            mock.patch("tools.refinement.honey_refinement._source", side_effect=source),
            mock.patch(
                "tools.refinement.honey_refinement._current_clean_descendant_source",
                side_effect=lambda _root, _frozen, label: external[label],
            ),
            mock.patch(
                "tools.refinement.honey_refinement._git",
                return_value=CompletedProcess(
                    args=[], returncode=0, stdout=b"", stderr=b""
                ),
            ),
        ):
            plan = create_plan(
                repository_root=ROOT,
                core_root=ROOT,
                cedar_root=ROOT,
                candidate_revision=candidate["revision"],
                cycle="cycle-b",
                champion_revision=champion["revision"],
                hypothesis_id="h1-release-equivalence",
                champion_profile="balanced.v2-candidate.1",
                candidate_profile="balanced.v2-candidate.1",
            )
        self.registry.validate("honey-evaluation-plan-v1.schema.json", plan)
        self.assertEqual(plan["product_sources"]["champion"], champion)
        self.assertEqual(plan["product_sources"]["candidate"], candidate)
        self.assertEqual(plan["harness_source"], champion)
        self.assertEqual(plan["external_sources"]["humidor"], external["HUMIDOR"])
        self.assertEqual(plan["external_sources"]["cedar"], external["CEDAR"])
        self.assertEqual(
            plan["intelligence_profiles"],
            {
                "honey": "balanced.v1",
                "champion": "balanced.v2-candidate.1",
                "candidate": "balanced.v2-candidate.1",
            },
        )
        self.assertFalse(plan["authority"]["create_pull_request"])
        self.assertFalse(plan["authority"]["push_public"])

    def test_source_adapter_is_relative_stable_and_balanced_v1_only(self) -> None:
        manifest = _adapter_manifest("published-honey")
        self.assertNotIn(str(ROOT).encode(), manifest)
        self.assertIn(
            b'path = "../../sources/candidate/benches/cigarbench/consumer/src/main.rs"',
            manifest,
        )
        self.assertIn(b'default = ["honey-0-9-1-compat"]', manifest)
        self.assertIn(
            b'cigar-daemon = { path = "../../sources/published-honey/crates/cigar-daemon" }',
            manifest,
        )
        self.assertIn(b"default = []", _adapter_manifest("champion"))
        h1 = _adapter_manifest("champion", "balanced.v2-candidate.1")
        self.assertIn(b'default = ["experimental-profiles"]', h1)
        self.assertIn(
            b'path = "../../sources/candidate/benches/cigarbench/consumer/src/main.rs"',
            h1,
        )
        self.assertIn(
            b'cigar-retrieval = { path = "../../sources/champion/crates/cigar-retrieval", features = ["experimental-profiles"] }',
            h1,
        )
        v3 = _adapter_manifest("candidate", "balanced.v3")
        self.assertIn(b'default = ["experimental-profiles"]', v3)
        frozen = _adapter_manifest("published-honey", harness_role="champion")
        self.assertIn(
            b'path = "../../sources/champion/benches/cigarbench/consumer/src/main.rs"',
            frozen,
        )

    def test_source_adapter_rejects_unknown_treatment(self) -> None:
        with self.assertRaisesRegex(SourceBuildError, "unknown source role"):
            _adapter_manifest("honey-proxy")
        with self.assertRaisesRegex(SourceBuildError, "unknown harness source role"):
            _adapter_manifest("published-honey", harness_role="unbound")

    def test_source_build_preserves_tool_proxy_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proxy = Path(temporary) / "proxy-tool"
            proxy.symlink_to(Path(sys.executable).resolve(strict=True))
            invocation, digest = _tool("proxy-tool", {"PATH": temporary})
        self.assertEqual(invocation, str(proxy))
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_source_build_custody_binds_three_profiles_and_rejects_byte_drift(
        self,
    ) -> None:
        plan = self._planned("tools/refinement/honey_refinement.py")
        plan["cycle"] = "cycle-b"
        plan["hypothesis_id"] = "h1-release-equivalence"
        plan["harness_source"] = plan["product_sources"]["champion"]
        plan["intelligence_profiles"] = {
            "honey": "balanced.v1",
            "champion": "balanced.v2-candidate.1",
            "candidate": "balanced.v2-candidate.1",
        }
        plan.pop("plan_id")
        plan["plan_id"] = identity(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            plan_path = root / "plan.json"
            plan_path.write_bytes(canonical_bytes(plan))
            build_root = root / "build"
            build_root.mkdir()
            builds = []
            for role, treatment, source_key in (
                ("published-honey", "honey", "published_honey"),
                ("champion", "champion", "champion"),
                ("candidate", "candidate", "candidate"),
            ):
                executable = build_root / "targets" / role / "release" / "consumer"
                executable.parent.mkdir(parents=True)
                executable.write_bytes(f"exact-{role}".encode())
                sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
                profile = plan["intelligence_profiles"][treatment]
                builds.append(
                    {
                        "source_role": role,
                        "product_source": plan["product_sources"][source_key],
                        "harness_source": plan["harness_source"],
                        "intelligence_profile": profile,
                        "adapter_manifest_digest": multihash_bytes(role.encode()),
                        "cargo_lock_digest": multihash_bytes(treatment.encode()),
                        "executable_digest": "1220" + sha256,
                        "executable_sha256": sha256,
                        "executable_bytes": executable.stat().st_size,
                        "executable_path": executable.relative_to(
                            build_root
                        ).as_posix(),
                        "source_clean_after_build": True,
                        "status": "built",
                    }
                )
            body = {
                "schema_version": "cigar.source-consumer-build-set.v1",
                "plan_id": plan["plan_id"],
                "profile_id": plan["profile_id"],
                "harness_source": plan["harness_source"],
                "build_profile": "release",
                "toolchain": {
                    "platform": "darwin",
                    "architecture": "aarch64",
                    "cargo_executable_sha256": "1" * 64,
                    "cargo_version_digest": "1220" + "2" * 64,
                    "rustc_executable_sha256": "3" * 64,
                    "rustc_version_digest": "1220" + "4" * 64,
                },
                "builds": builds,
            }
            receipt = {**body, "build_set_id": identity(body)}
            (build_root / "build-set.v1.json").write_bytes(canonical_bytes(receipt))
            loaded_plan, loaded_receipt, executables = load_source_consumers(
                repository_root=ROOT,
                plan_path=plan_path,
                build_root=build_root,
            )
            self.assertEqual(loaded_plan["plan_id"], plan["plan_id"])
            self.assertEqual(loaded_receipt["build_set_id"], receipt["build_set_id"])
            self.assertEqual(set(executables), {"honey", "champion", "candidate"})
            executables["candidate"].write_bytes(b"drift")
            with self.assertRaisesRegex(SourceBuildError, "drifted"):
                load_source_consumers(
                    repository_root=ROOT,
                    plan_path=plan_path,
                    build_root=build_root,
                )


if __name__ == "__main__":
    unittest.main()
