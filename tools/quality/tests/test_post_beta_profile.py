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
    "post_beta_profile", RELEASE_SCRIPTS / "post_beta_profile.py"
)
assert SPEC is not None and SPEC.loader is not None
post_beta_profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(post_beta_profile)


class PostBetaProfileTests(unittest.TestCase):
    def staged_root(self, base: Path) -> Path:
        root = base / "repository"
        beta_destination = root / "packaging" / "beta"
        beta_destination.parent.mkdir(parents=True)
        shutil.copytree(ROOT / "packaging" / "beta", beta_destination)
        schema_destination = root / post_beta_profile.SCHEMA_PATH
        schema_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / post_beta_profile.SCHEMA_PATH, schema_destination)
        ownership_schema = root / post_beta_profile.OWNERSHIP_SCHEMA_PATH
        ownership_schema.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            ROOT / post_beta_profile.OWNERSHIP_SCHEMA_PATH, ownership_schema
        )
        matrix = root / post_beta_profile.ARTIFACT_MATRIX_PATH
        matrix.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / post_beta_profile.ARTIFACT_MATRIX_PATH, matrix)
        inventory_paths = {
            path
            for entry in post_beta_profile.expected_ownership_registry()["capabilities"]
            for field in ("test_inventory", "operations_docs")
            for path in entry[field]
        }
        for relative in inventory_paths:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        shutil.copyfile(ROOT / "rust-toolchain.toml", root / "rust-toolchain.toml")
        post_beta_profile.generate(root)
        return root

    def write_canonical(self, path: Path, document: object) -> None:
        path.write_bytes(post_beta_profile.canonical_json_bytes(document))

    def test_repository_profile_is_exact_and_beta_policy_is_unchanged(self) -> None:
        before = (ROOT / post_beta_profile.BETA_POLICY_PATH).read_bytes()
        post_beta_profile.validate(ROOT)
        after = (ROOT / post_beta_profile.BETA_POLICY_PATH).read_bytes()
        self.assertEqual(after, before)

        profile = json.loads((ROOT / post_beta_profile.PROFILE_PATH).read_text())
        self.assertEqual(len(profile["capabilities"]), 29)
        self.assertEqual(
            profile["platform_scope"]["target_triple"], "aarch64-apple-darwin"
        )
        self.assertFalse(any(item["supported"] for item in profile["capabilities"]))
        ownership = json.loads((ROOT / post_beta_profile.OWNERSHIP_PATH).read_text())
        self.assertEqual(len(ownership["capabilities"]), 29)
        self.assertFalse(ownership["release_claimed"])
        self.assertFalse(ownership["support_claimed"])
        by_id = {entry["id"]: entry for entry in ownership["capabilities"]}
        self.assertEqual(
            by_id["installers"]["artifact_set"],
            [
                {"id": "macos-homebrew-formula-arm64", "status": "planned"},
                {"id": "macos-installer-arm64", "status": "planned"},
            ],
        )
        self.assertEqual(
            by_id["mcp"]["artifact_set"],
            [{"id": "cli-daemon-macos-aarch64", "status": "planned"}],
        )
        self.assertEqual(
            by_id["windows"]["profile_scope"]["disposition"],
            "deferred-separate-profile",
        )
        self.assertEqual(
            by_id["oci"]["profile_scope"]["disposition"],
            "deferred-separate-profile",
        )
        self.assertEqual(
            post_beta_profile.sha256_file(ROOT / post_beta_profile.OWNERSHIP_PATH),
            post_beta_profile.OWNERSHIP_REGISTRY_SHA256,
        )
        schema = json.loads(
            (ROOT / post_beta_profile.OWNERSHIP_SCHEMA_PATH).read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(len(schema["properties"]["capabilities"]["prefixItems"]), 29)

    def test_generator_is_deterministic_and_cannot_modify_beta_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            profile_path = root / post_beta_profile.PROFILE_PATH
            ownership_path = root / post_beta_profile.OWNERSHIP_PATH
            policy_path = root / post_beta_profile.BETA_POLICY_PATH
            before_profile = profile_path.read_bytes()
            before_ownership = ownership_path.read_bytes()
            before_policy = policy_path.read_bytes()
            post_beta_profile.generate(root)
            self.assertEqual(profile_path.read_bytes(), before_profile)
            self.assertEqual(ownership_path.read_bytes(), before_ownership)
            self.assertEqual(policy_path.read_bytes(), before_policy)
            post_beta_profile.validate(root)

    def test_ownership_ids_fields_paths_and_artifacts_fail_closed(self) -> None:
        mutations = (
            "reordered",
            "unknown-field",
            "missing-path",
            "unbound-planned-artifact",
            "matrix-present-missing-artifact",
            "broadened-scope",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / post_beta_profile.OWNERSHIP_PATH
                document = json.loads(path.read_text())
                capabilities = document["capabilities"]
                if mutation == "reordered":
                    capabilities[0], capabilities[1] = capabilities[1], capabilities[0]
                elif mutation == "unknown-field":
                    capabilities[0]["waiver"] = "not-allowed"
                elif mutation == "missing-path":
                    capabilities[0]["test_inventory"] = ["tests/not-present.rs"]
                elif mutation == "unbound-planned-artifact":
                    capabilities[0]["artifact_set"] = [
                        {"id": "not-in-matrix", "status": "planned"}
                    ]
                elif mutation == "matrix-present-missing-artifact":
                    capabilities[0]["artifact_set"] = [
                        {"id": "source", "status": "missing"}
                    ]
                else:
                    capabilities[0]["profile_scope"] = {
                        "disposition": "selected",
                        "profile_id": "cigar.post-beta.macos-arm64.v1",
                        "target_triple": "x86_64-apple-darwin",
                    }
                self.write_canonical(path, document)
                with self.assertRaises(post_beta_profile.ReleaseError):
                    post_beta_profile.validate(root)

    def test_homebrew_and_mcp_artifacts_must_remain_explicit(self) -> None:
        expected_errors = {
            "installers": "planned macOS Homebrew artifacts are not explicit",
            "mcp": "packaged cigar-mcp runtime ownership is not explicit",
        }
        for identifier, expected_error in expected_errors.items():
            with (
                self.subTest(identifier=identifier),
                tempfile.TemporaryDirectory() as raw,
            ):
                root = self.staged_root(Path(raw))
                path = root / post_beta_profile.OWNERSHIP_PATH
                document = json.loads(path.read_text())
                entry = next(
                    item
                    for item in document["capabilities"]
                    if item["id"] == identifier
                )
                entry["artifact_set"] = [{"id": "source", "status": "planned"}]
                self.write_canonical(path, document)
                with self.assertRaisesRegex(
                    post_beta_profile.ReleaseError, expected_error
                ):
                    post_beta_profile.validate(root)

    def test_missing_extra_duplicate_and_reordered_ids_fail_closed(self) -> None:
        mutations = ("missing", "extra", "duplicate", "reordered")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / post_beta_profile.PROFILE_PATH
                document = json.loads(path.read_text())
                capabilities = document["capabilities"]
                if mutation == "missing":
                    capabilities.pop()
                elif mutation == "extra":
                    capabilities.append(copy.deepcopy(capabilities[-1]))
                elif mutation == "duplicate":
                    capabilities[1]["id"] = capabilities[0]["id"]
                else:
                    capabilities[0], capabilities[1] = capabilities[1], capabilities[0]
                self.write_canonical(path, document)
                with self.assertRaises(post_beta_profile.ReleaseError):
                    post_beta_profile.validate(root)

    def test_unknown_fields_and_non_boolean_states_fail_closed(self) -> None:
        invalid_values: tuple[object, ...] = ("unknown", "skipped", "waived", None, 0)
        for value in invalid_values:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / post_beta_profile.PROFILE_PATH
                document = json.loads(path.read_text())
                document["capabilities"][0]["integrated"] = value
                self.write_canonical(path, document)
                with self.assertRaisesRegex(
                    post_beta_profile.ReleaseError, "must be Boolean"
                ):
                    post_beta_profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / post_beta_profile.PROFILE_PATH
            document = json.loads(path.read_text())
            document["capabilities"][0]["waiver"] = True
            self.write_canonical(path, document)
            with self.assertRaisesRegex(
                post_beta_profile.ReleaseError, "missing or unexpected fields"
            ):
                post_beta_profile.validate(root)

    def test_every_monotonicity_hole_fails(self) -> None:
        for state_index in range(1, len(post_beta_profile.STATE_ORDER)):
            with self.subTest(state=post_beta_profile.STATE_ORDER[state_index]):
                document = copy.deepcopy(post_beta_profile.expected_profile())
                capability = document["capabilities"][12]
                for state in post_beta_profile.STATE_ORDER:
                    capability[state] = False
                capability[post_beta_profile.STATE_ORDER[state_index]] = True
                with self.assertRaisesRegex(
                    post_beta_profile.ReleaseError, "non-monotonic"
                ):
                    post_beta_profile._validate_document(document)

    def test_transition_allows_advancement_and_rejects_regression(self) -> None:
        previous = post_beta_profile.expected_profile()
        advanced = copy.deepcopy(previous)
        vector = next(
            item for item in advanced["capabilities"] if item["id"] == "vector"
        )
        vector["integrated"] = True
        post_beta_profile.validate_transition(previous, advanced)

        regressed = copy.deepcopy(previous)
        catalog = next(
            item
            for item in regressed["capabilities"]
            if item["id"] == "catalog-discovery"
        )
        catalog["implemented_source"] = False
        with self.assertRaisesRegex(post_beta_profile.ReleaseError, "regressed"):
            post_beta_profile.validate_transition(previous, regressed)

    def test_scope_policy_and_fail_closed_drift_are_rejected(self) -> None:
        mutations = (
            ("profile_id", "cigar.post-beta.linux.v1"),
            ("fail_closed", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                document = copy.deepcopy(post_beta_profile.expected_profile())
                document[field] = value
                with self.assertRaises(post_beta_profile.ReleaseError):
                    post_beta_profile._validate_document(document)

        for field, value in (
            ("host_os", "linux"),
            ("host_arch", "x86_64"),
            ("target_triple", "x86_64-apple-darwin"),
        ):
            with self.subTest(platform_field=field):
                document = copy.deepcopy(post_beta_profile.expected_profile())
                document["platform_scope"][field] = value
                with self.assertRaisesRegex(
                    post_beta_profile.ReleaseError, "not macOS arm64"
                ):
                    post_beta_profile._validate_document(document)

        document = copy.deepcopy(post_beta_profile.expected_profile())
        document["source_capability_policy"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(post_beta_profile.ReleaseError, "different beta"):
            post_beta_profile._validate_document(document)

    def test_schema_weakening_and_noncanonical_profile_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            schema_path = root / post_beta_profile.SCHEMA_PATH
            schema_path.write_bytes(schema_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                post_beta_profile.ReleaseError, "schema digest mismatch"
            ):
                post_beta_profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            profile_path = root / post_beta_profile.PROFILE_PATH
            document = json.loads(profile_path.read_text())
            profile_path.write_text(json.dumps(document, indent=2) + "\n")
            with self.assertRaisesRegex(
                post_beta_profile.ReleaseError, "not canonical JSON"
            ):
                post_beta_profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            schema_path = root / post_beta_profile.OWNERSHIP_SCHEMA_PATH
            schema_path.write_bytes(schema_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                post_beta_profile.ReleaseError, "ownership schema digest mismatch"
            ):
                post_beta_profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            ownership_path = root / post_beta_profile.OWNERSHIP_PATH
            document = json.loads(ownership_path.read_text())
            ownership_path.write_text(json.dumps(document, indent=2) + "\n")
            with self.assertRaisesRegex(
                post_beta_profile.ReleaseError, "not canonical JSON"
            ):
                post_beta_profile.validate(root)

    @unittest.skipUnless(hasattr(os, "link"), "hard-link regression requires os.link")
    def test_hard_linked_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            profile_path = root / post_beta_profile.PROFILE_PATH
            link_source = root / "profile-link-source.json"
            profile_path.replace(link_source)
            os.link(link_source, profile_path)
            with self.assertRaisesRegex(post_beta_profile.ReleaseError, "hard-linked"):
                post_beta_profile.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            ownership_path = root / post_beta_profile.OWNERSHIP_PATH
            link_source = root / "ownership-link-source.json"
            ownership_path.replace(link_source)
            os.link(link_source, ownership_path)
            with self.assertRaisesRegex(post_beta_profile.ReleaseError, "hard-linked"):
                post_beta_profile.validate(root)

    @unittest.skipUnless(
        hasattr(os, "symlink"), "symlink regression requires os.symlink"
    )
    def test_symlinked_profile_is_rejected_by_check_and_generate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            profile_path = root / post_beta_profile.PROFILE_PATH
            external = root / "external-profile.json"
            profile_path.replace(external)
            os.symlink(external, profile_path)
            with self.assertRaisesRegex(post_beta_profile.ReleaseError, "regular file"):
                post_beta_profile.validate(root)
            with self.assertRaisesRegex(post_beta_profile.ReleaseError, "regular file"):
                post_beta_profile.generate(root)


if __name__ == "__main__":
    unittest.main()
