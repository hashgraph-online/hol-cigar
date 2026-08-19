from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "baselines/cigarbench/verify_honey_094_baselines.py"
SPEC = importlib.util.spec_from_file_location("honey_094_baselines", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
baseline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = baseline
SPEC.loader.exec_module(baseline)


class Honey094BaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(baseline.MANIFEST_PATH.read_bytes())
        self.old_id = "honey-0.9.2-balanced-v1"
        self.new_id = "honey-0.9.3-balanced-v3"

    def assert_rejected(self, document: dict[str, object]) -> None:
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_manifest(document, repository_root=ROOT)

    def test_repository_manifest_is_exact_and_schema_bound(self) -> None:
        baseline.validate_manifest(self.document, repository_root=ROOT)
        self.assertEqual(set(self.document["treatments"]), {self.old_id, self.new_id})
        self.assertEqual(
            self.document["candidate_policy"]["candidate_source_state"],
            "unbound-until-candidate-freeze",
        )

    def test_dirty_or_moving_source_is_rejected(self) -> None:
        dirty = copy.deepcopy(self.document)
        dirty["treatments"][self.old_id]["source"]["worktree_dirty"] = True
        self.assert_rejected(dirty)

        moving = copy.deepcopy(self.document)
        moving["treatments"][self.old_id]["source"]["commit"] = (
            "refs/heads/release/honey-0.9.2"
        )
        self.assert_rejected(moving)

    def test_absent_artifact_digest_is_rejected(self) -> None:
        missing = copy.deepcopy(self.document)
        del missing["treatments"][self.old_id]["artifacts"]["cigar"]["sha256"]
        self.assert_rejected(missing)

    def test_duplicate_treatment_id_is_rejected(self) -> None:
        duplicate = copy.deepcopy(self.document)
        duplicate["treatments"][self.new_id]["treatment_id"] = self.old_id
        duplicate["treatments"][self.new_id]["source"]["treatment_id"] = self.old_id
        self.assert_rejected(duplicate)

    def test_profile_mismatch_is_rejected(self) -> None:
        mismatch = copy.deepcopy(self.document)
        mismatch["treatments"][self.new_id]["source"]["profile"][
            "selection_profile_id"
        ] = "balanced_v1"
        self.assert_rejected(mismatch)

    def test_candidate_may_not_reuse_comparator_source(self) -> None:
        source = self.document["treatments"][self.old_id]["source"]
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_manifest(
                self.document,
                repository_root=ROOT,
                candidate_source={"commit": source["commit"], "tree": "f" * 40},
            )
        with self.assertRaises(baseline.BaselineError):
            baseline.validate_manifest(
                self.document,
                repository_root=ROOT,
                candidate_source={"commit": "f" * 40, "tree": source["tree"]},
            )

    def test_source_and_installed_set_digests_are_fail_closed(self) -> None:
        source_drift = copy.deepcopy(self.document)
        source_drift["treatments"][self.old_id]["source"]["source_files"][0][
            "sha256"
        ] = "f" * 64
        self.assert_rejected(source_drift)

        binary_drift = copy.deepcopy(self.document)
        binary_drift["treatments"][self.new_id]["installed_binaries"]["cigar"][
            "sha256"
        ] = "f" * 64
        self.assert_rejected(binary_drift)


if __name__ == "__main__":
    unittest.main()
