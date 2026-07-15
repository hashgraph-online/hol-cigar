from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPTS = ROOT / "scripts" / "release"
sys.path.insert(0, str(RELEASE_SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "development_macos_profile", RELEASE_SCRIPTS / "development_macos_profile.py"
)
assert SPEC is not None and SPEC.loader is not None
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


class DevelopmentMacosProfileTests(unittest.TestCase):
    def staged_root(self, base: Path) -> Path:
        root = base / "repository"
        for relative in (
            profile.SCHEMA_PATH,
            profile.PRODUCT_VERSION_PATH,
            profile.ARTIFACT_MATRIX_PATH,
        ):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        profile.generate(root)
        return root

    def write_canonical(self, path: Path, document: object) -> None:
        path.write_bytes(profile.canonical_json_bytes(document))

    def test_repository_projection_is_exact_and_nonclaiming(self) -> None:
        profile.validate(ROOT)
        document = json.loads((ROOT / profile.PROFILE_PATH).read_text())
        selected = document["selected_artifacts"]
        deferred = document["deferred_artifacts"]
        missing = document["missing_artifacts"]
        self.assertEqual((len(selected), len(deferred), len(missing)), (17, 5, 0))
        self.assertTrue(all(item["status"] == "planned" for item in selected))
        self.assertTrue(all(not item["built"] for item in selected))
        self.assertTrue(all(not item["qualified"] for item in selected))
        self.assertFalse(document["published"])
        self.assertFalse(document["supported"])
        self.assertFalse(document["observed_host"]["minimum_support_claim"])
        self.assertEqual(missing, [])
        for obligation in ("fuzz_accumulation", "soak"):
            self.assertEqual(
                document["qualification_obligations"][obligation]["current_run"],
                "deferred",
            )
        for obligation in ("signing", "notarization"):
            self.assertEqual(
                document["qualification_obligations"][obligation]["evidence_status"],
                "not-evidenced",
            )

    def test_generator_is_deterministic_and_checker_accepts_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / profile.PROFILE_PATH
            before = path.read_bytes()
            profile.generate(root)
            self.assertEqual(path.read_bytes(), before)
            profile.validate(root)

    def test_partition_claim_platform_and_status_inflation_fail_closed(self) -> None:
        mutations = (
            "drop-selected",
            "move-deferred",
            "built",
            "qualified",
            "published",
            "supported",
            "target",
            "deployment",
            "host-claim",
            "skip-fuzz",
            "signing-evidenced",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / profile.PROFILE_PATH
                document = json.loads(path.read_text())
                if mutation == "drop-selected":
                    document["selected_artifacts"].pop()
                elif mutation == "move-deferred":
                    document["deferred_artifacts"][0] = copy.deepcopy(
                        document["selected_artifacts"][0]
                    )
                elif mutation == "built":
                    document["selected_artifacts"][0]["built"] = True
                elif mutation == "qualified":
                    document["selected_artifacts"][0]["qualified"] = True
                elif mutation == "published":
                    document["published"] = True
                elif mutation == "supported":
                    document["supported"] = True
                elif mutation == "target":
                    document["target"]["target_triple"] = "x86_64-apple-darwin"
                elif mutation == "deployment":
                    document["deployment_modes"].append("shared")
                elif mutation == "host-claim":
                    document["observed_host"]["minimum_support_claim"] = True
                elif mutation == "skip-fuzz":
                    document["qualification_obligations"]["fuzz_accumulation"][
                        "requirement"
                    ] = "waived"
                else:
                    document["qualification_obligations"]["signing"][
                        "evidence_status"
                    ] = "passed"
                self.write_canonical(path, document)
                with self.assertRaises(profile.ReleaseError):
                    profile.validate(root)

    def test_version_matrix_schema_and_canonical_digest_drift_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / profile.PRODUCT_VERSION_PATH
            document = json.loads(path.read_text())
            document["version"] = "1.0.0"
            path.write_text(json.dumps(document, indent=2) + "\n")
            with self.assertRaisesRegex(profile.ReleaseError, "product-version digest"):
                profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / profile.ARTIFACT_MATRIX_PATH
            document = json.loads(path.read_text())
            document["artifacts"].pop()
            path.write_text(json.dumps(document, indent=2) + "\n")
            with self.assertRaisesRegex(profile.ReleaseError, "artifact ID inventory"):
                profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / profile.SCHEMA_PATH
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(profile.ReleaseError, "schema digest"):
                profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / profile.PROFILE_PATH
            document = json.loads(path.read_text())
            path.write_text(json.dumps(document, indent=2) + "\n")
            with self.assertRaisesRegex(profile.ReleaseError, "canonical JSON"):
                profile.validate(root)

    @unittest.skipUnless(hasattr(os, "link"), "hard-link regression requires os.link")
    def test_hard_linked_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / profile.PROFILE_PATH
            source = root / "profile-link-source.json"
            path.replace(source)
            os.link(source, path)
            with self.assertRaisesRegex(profile.ReleaseError, "hard-linked"):
                profile.validate(root)

    @unittest.skipUnless(
        hasattr(os, "symlink"), "symlink regression requires os.symlink"
    )
    def test_symlinked_profile_is_rejected_by_check_and_generate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / profile.PROFILE_PATH
            source = root / "profile-link-source.json"
            path.replace(source)
            os.symlink(source, path)
            with self.assertRaisesRegex(profile.ReleaseError, "regular file"):
                profile.validate(root)
            with self.assertRaisesRegex(profile.ReleaseError, "regular file"):
                profile.generate(root)


if __name__ == "__main__":
    unittest.main()
