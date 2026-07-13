from __future__ import annotations

import base64
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
    "beta_profile", RELEASE_SCRIPTS / "beta_profile.py"
)
assert SPEC is not None and SPEC.loader is not None
beta_profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(beta_profile)


class BetaProfileTests(unittest.TestCase):
    def staged_root(self, base: Path) -> Path:
        root = base / "repository"
        schema_source = ROOT / "packaging" / "beta" / "schemas"
        schema_destination = root / "packaging" / "beta" / "schemas"
        schema_destination.parent.mkdir(parents=True)
        shutil.copytree(schema_source, schema_destination)
        cargo_resolution = root / beta_profile.MANIFEST_PATHS["cargo_resolution"]
        cargo_resolution.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            ROOT / beta_profile.MANIFEST_PATHS["cargo_resolution"], cargo_resolution
        )
        shutil.copyfile(ROOT / "rust-toolchain.toml", root / "rust-toolchain.toml")
        beta_profile.generate(root)
        return root

    def write_canonical(self, path: Path, document: object) -> None:
        path.write_bytes(beta_profile.canonical_json_bytes(document))

    def test_repository_profile_is_exactly_the_reviewed_beta(self) -> None:
        beta_profile.validate(ROOT)
        product = json.loads(
            (ROOT / "packaging/beta/product-version.v1.json").read_text()
        )
        self.assertEqual(product["version"], "0.1.0-beta.1")
        self.assertEqual(product["tag"], "v0.1.0-beta.1")
        self.assertTrue(product["prerelease"])
        self.assertFalse(product["production_ready"])

    def test_generator_is_deterministic_and_checker_accepts_its_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            before = {
                relative: (root / relative).read_bytes()
                for relative in beta_profile.GENERATED_DOCUMENTS
            }
            beta_profile.generate(root)
            after = {
                relative: (root / relative).read_bytes()
                for relative in beta_profile.GENERATED_DOCUMENTS
            }
            self.assertEqual(after, before)
            beta_profile.validate(root)

    def test_added_artifact_or_removed_exclusion_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            matrix_path = root / "packaging/beta/artifact-matrix.v1.json"
            matrix = json.loads(matrix_path.read_text())
            matrix["artifacts"].append(copy.deepcopy(matrix["artifacts"][-1]))
            matrix["artifacts"][-1]["id"] = "cigard-linux-x86_64-gnu"
            matrix["artifacts"][-1]["executables"] = ["bin/cigard"]
            self.write_canonical(matrix_path, matrix)
            with self.assertRaisesRegex(beta_profile.ReleaseError, "pinned definition"):
                beta_profile.validate(root)

            beta_profile.generate(root)
            capability_path = root / "packaging/beta/capability-policy.v1.json"
            capability = json.loads(capability_path.read_text())
            capability["excluded"] = [
                entry for entry in capability["excluded"] if entry["id"] != "mcp"
            ]
            self.write_canonical(capability_path, capability)
            with self.assertRaisesRegex(beta_profile.ReleaseError, "pinned definition"):
                beta_profile.validate(root)

    def test_ga_evidence_and_signature_domains_are_rejected(self) -> None:
        beta_evidence = {
            "schema_version": beta_profile.BETA_EVIDENCE_SCHEMA,
            "release_profile": beta_profile.PROFILE_ID,
            "product_version": beta_profile.VERSION,
            "evidence_purpose": beta_profile.BETA_EVIDENCE_PURPOSE,
        }
        beta_profile.validate_beta_evidence_identity(beta_evidence)
        ga_evidence = dict(beta_evidence)
        ga_evidence["schema_version"] = "cigar.qualification-evidence.v1"
        with self.assertRaisesRegex(beta_profile.ReleaseError, "beta evidence"):
            beta_profile.validate_beta_evidence_identity(ga_evidence)

        beta_release_evidence = {
            "schema_version": beta_profile.BETA_RELEASE_EVIDENCE_SCHEMA,
            "release_profile": beta_profile.PROFILE_ID,
            "product_version": beta_profile.VERSION,
            "tag": beta_profile.TAG,
            "prerelease": True,
            "production_ready": False,
        }
        beta_profile.validate_beta_release_evidence_identity(beta_release_evidence)
        ga_release_evidence = dict(beta_release_evidence)
        ga_release_evidence["schema_version"] = "cigar.release-evidence.v1"
        with self.assertRaisesRegex(beta_profile.ReleaseError, "beta schema"):
            beta_profile.validate_beta_release_evidence_identity(ga_release_evidence)

        beta_signature = {
            "schema_version": "cigar.signature-envelope.v1",
            "algorithm": "Ed25519",
            "key_id": f"sha256:{'1' * 64}",
            "signer_principal": "release@example.invalid",
            "purpose": "cigar-beta-release-artifact-v1",
            "signed_at": 1_700_000_000,
            "payload": {
                "name": "artifact.tar.gz",
                "sha256": "2" * 64,
                "bytes": 123,
            },
            "signature_base64": base64.b64encode(b"\0" * 64).decode("ascii"),
        }
        beta_profile.validate_beta_signature_identity(beta_signature)
        with self.assertRaisesRegex(beta_profile.ReleaseError, "beta signature"):
            beta_profile.validate_beta_signature_identity(
                {**beta_signature, "purpose": "release-artifact"}
            )
        for mutation in (
            {**beta_signature, "algorithm": "ed25519"},
            {**beta_signature, "unexpected": True},
            {**beta_signature, "payload": {"path": "artifact.tar.gz"}},
            {**beta_signature, "signature_base64": "not-base64"},
            {**beta_signature, "expires_at": beta_signature["signed_at"]},
        ):
            with self.subTest(signature_mutation=mutation):
                with self.assertRaises(beta_profile.ReleaseError):
                    beta_profile.validate_beta_signature_identity(mutation)

    def test_schema_weakening_and_noncanonical_manifest_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            schema_path = root / (
                "packaging/beta/schemas/beta-signature-envelope.v1.schema.json"
            )
            schema_path.write_bytes(schema_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(beta_profile.ReleaseError, "schema digest"):
                beta_profile.validate(root)

            shutil.copyfile(
                ROOT / "packaging/beta/schemas/beta-signature-envelope.v1.schema.json",
                schema_path,
            )
            profile_path = root / "packaging/beta/release-profile.v1.json"
            profile = json.loads(profile_path.read_text())
            profile_path.write_text(json.dumps(profile, indent=2) + "\n")
            with self.assertRaisesRegex(beta_profile.ReleaseError, "canonical JSON"):
                beta_profile.validate(root)

    def test_cargo_resolution_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / beta_profile.MANIFEST_PATHS["cargo_resolution"]
            document = json.loads(path.read_text())
            document["vendor_packages"][0]["checksum"] = "0" * 64
            self.write_canonical(path, document)
            with self.assertRaisesRegex(
                beta_profile.ReleaseError, "exact reviewed pin"
            ):
                beta_profile.validate(root)

    @unittest.skipUnless(hasattr(os, "link"), "hard-link regression requires os.link")
    def test_hard_linked_contract_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            profile_path = root / "packaging/beta/release-profile.v1.json"
            link_source = root / "profile-link-source.json"
            profile_path.replace(link_source)
            os.link(link_source, profile_path)
            with self.assertRaisesRegex(beta_profile.ReleaseError, "hard-linked"):
                beta_profile.validate(root)

    @unittest.skipUnless(
        hasattr(os, "symlink"), "symlink regression requires os.symlink"
    )
    def test_generator_rejects_symlinked_output_parent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "repository"
            external = base / "external"
            root.mkdir()
            external.mkdir()
            os.symlink(external, root / "packaging")
            with self.assertRaisesRegex(beta_profile.ReleaseError, "real directory"):
                beta_profile.generate(root)
            self.assertEqual(list(external.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
