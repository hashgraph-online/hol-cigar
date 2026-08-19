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
    "development_protocol_baseline",
    RELEASE_SCRIPTS / "development_protocol_baseline.py",
)
assert SPEC is not None and SPEC.loader is not None
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


class DevelopmentProtocolBaselineTests(unittest.TestCase):
    def staged_root(self, base: Path) -> Path:
        root = base / "repository"
        relative_paths = (baseline.SCHEMA_PATH, *baseline._all_bound_paths())
        for relative in relative_paths:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        baseline.generate(root)
        return root

    def write_json(self, path: Path, document: object) -> None:
        path.write_bytes(baseline.canonical_json_bytes(document))

    def mutate_json(self, root: Path, relative: str, mutation: str) -> None:
        path = root / relative
        document = json.loads(path.read_text())
        if mutation == "operation-count":
            document["services"][0]["operations"].pop()
        elif mutation == "payload-count":
            name = next(iter(document["types"]))
            del document["types"][name]
            document["type_count"] = 69
        elif mutation == "sdk-duplicate":
            document["operations"].append(copy.deepcopy(document["operations"][0]))
        elif mutation == "sdk-payload-mapping":
            document["operations"][0]["request_type"] = document["operations"][1][
                "request_type"
            ]
        elif mutation == "openapi-parity":
            first_path = next(iter(document["paths"].values()))
            method = next(
                key
                for key in first_path
                if key in {"delete", "get", "patch", "post", "put"}
            )
            del first_path[method]
        elif mutation == "error-duplicate":
            document["errors"][1]["code"] = document["errors"][0]["code"]
        elif mutation == "canonical-duplicate":
            document["valid"][1]["id"] = document["valid"][0]["id"]
        elif mutation == "conformance-source":
            document["source_vector_sha256"] = "0" * 64
        elif mutation == "generator-inventory":
            document["wire_artifacts"].pop()
        else:
            self.fail(f"unsupported mutation: {mutation}")
        self.write_json(path, document)

    def test_repository_baseline_is_exact_nonclaiming_and_complete(self) -> None:
        baseline.validate(ROOT)
        document = json.loads((ROOT / baseline.BASELINE_PATH).read_text())
        self.assertEqual(document["binding_inventory"]["file_count"], 83)
        self.assertEqual(len(document["binding_inventory"]["groups"]), 9)
        projection_group = document["binding_inventory"]["groups"][4]
        self.assertEqual(projection_group["id"], "interface-projections")
        self.assertEqual(projection_group["file_count"], 6)
        self.assertEqual(
            [binding["path"] for binding in projection_group["files"]],
            list(baseline.INTERFACE_PROJECTIONS),
        )
        self.assertEqual(document["binding_inventory"]["total_bytes"], 2_573_821)
        self.assertEqual(
            document["binding_inventory"]["path_inventory_sha256"],
            "fc422b6870a8613ca44e4eb96c969b6584b8d10b2004532da7d4f071a8c28f1f",
        )
        self.assertFalse(document["lifecycle"]["release_claimed"])
        self.assertFalse(document["lifecycle"]["candidate_frozen"])
        self.assertFalse(
            document["execution_scope"]["cross_platform_qualification_claimed"]
        )
        semantic = document["semantic_contract"]
        self.assertEqual(
            (
                semantic["context_abi"],
                semantic["protocol_min"],
                semantic["protocol_max"],
            ),
            ("cigar.context.v1", "1.0", "1.x"),
        )
        self.assertEqual(semantic["operation_registry"]["count"], 45)
        self.assertEqual(semantic["nominal_payload_registry"]["count"], 70)
        self.assertEqual(semantic["error_registry"]["count"], 34)
        self.assertTrue(semantic["sdk_capability_registry"]["operation_parity"])
        self.assertTrue(semantic["sdk_capability_registry"]["nominal_payload_parity"])

    def test_generator_is_deterministic_and_checker_accepts_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / baseline.BASELINE_PATH
            before = path.read_bytes()
            baseline.generate(root)
            self.assertEqual(path.read_bytes(), before)
            baseline.validate(root)

    def test_registry_counts_duplicates_and_parity_fail_closed(self) -> None:
        mutations = (
            (
                "spec/api/operations-v1.json",
                "operation-count",
                "operation catalog",
            ),
            (
                "schemas/json/api-payload-types-v1.schema.json",
                "payload-count",
                "payload schema bundle",
            ),
            ("sdk/capabilities-v1.json", "sdk-duplicate", "SDK capability"),
            (
                "sdk/capabilities-v1.json",
                "sdk-payload-mapping",
                "nominal payload mapping",
            ),
            ("schemas/openapi/cigar-v1.json", "openapi-parity", "OpenAPI"),
            (
                "schemas/openapi/error-registry-v1.json",
                "error-duplicate",
                "error codes",
            ),
            (
                "schemas/vectors/canonical-v1.json",
                "canonical-duplicate",
                "canonical vector IDs",
            ),
            (
                "conformance/vectors/v1/core-v1.json",
                "conformance-source",
                "conformance vector",
            ),
            (
                "schemas/generated-manifest.json",
                "generator-inventory",
                "generated schema manifest",
            ),
        )
        for relative, mutation, message in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                self.mutate_json(root, relative, mutation)
                with self.assertRaisesRegex(baseline.ReleaseError, message):
                    baseline.validate(root)
                with self.assertRaisesRegex(baseline.ReleaseError, message):
                    baseline.generate(root)

    def test_context_abi_identity_cannot_be_rebaselined(self) -> None:
        mutations = (
            (
                "packaging/product-version.v1.json",
                '"context_abi": "cigar.context.v1"',
                '"context_abi": "cigar.context.v2"',
                "product Context ABI",
            ),
            (
                "schemas/proto/context_abi.proto",
                "package cigar.context.v1;",
                "package cigar.context.v2;",
                "Context ABI Proto package",
            ),
            (
                "crates/cigar-protocol/src/lib.rs",
                'pub const CONTEXT_ABI: &str = "cigar.context.v1";',
                'pub const CONTEXT_ABI: &str = "cigar.context.v2";',
                "Rust protocol identity",
            ),
        )
        for relative, before, after, message in mutations:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / relative
                source = path.read_text(encoding="utf-8")
                self.assertEqual(source.count(before), 1)
                path.write_text(source.replace(before, after, 1), encoding="utf-8")
                with self.assertRaisesRegex(baseline.ReleaseError, message):
                    baseline.validate(root)
                with self.assertRaisesRegex(baseline.ReleaseError, message):
                    baseline.generate(root)

    def test_generated_digest_and_runtime_proto_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / "sdk/typescript/src/generated/operations.ts"
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(baseline.ReleaseError, "projection changed"):
                baseline.validate(root)
            with self.assertRaisesRegex(baseline.ReleaseError, "projection changed"):
                baseline.generate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / "crates/cigar-api/proto/cigar_service.proto"
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(baseline.ReleaseError, "Proto files differ"):
                baseline.validate(root)

    def test_interface_projection_authority_and_generated_drift_fail_closed(
        self,
    ) -> None:
        for relative in (
            "spec/api/interface-projections-v1.json",
            "crates/cigar-dashboard/src/generated/protocol-catalog-v1.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / relative
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaisesRegex(
                    baseline.ReleaseError, "projection changed"
                ):
                    baseline.validate(root)

    def test_claim_inflation_duplicate_binding_and_unsafe_path_fail_closed(
        self,
    ) -> None:
        mutations = ("release", "frozen", "duplicate", "unsafe")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / baseline.BASELINE_PATH
                document = json.loads(path.read_text())
                if mutation == "release":
                    document["lifecycle"]["release_claimed"] = True
                elif mutation == "frozen":
                    document["lifecycle"]["candidate_frozen"] = True
                elif mutation == "duplicate":
                    first = document["binding_inventory"]["groups"][0]["files"][0]
                    document["binding_inventory"]["groups"][0]["files"][1] = (
                        copy.deepcopy(first)
                    )
                else:
                    document["binding_inventory"]["groups"][0]["files"][0]["path"] = (
                        "../escape"
                    )
                self.write_json(path, document)
                expected = (
                    "lifecycle claims"
                    if mutation in {"release", "frozen"}
                    else "duplicate file paths"
                    if mutation == "duplicate"
                    else "unsafe protocol-baseline path"
                )
                with self.assertRaisesRegex(baseline.ReleaseError, expected):
                    baseline.validate(root)

    def test_unsafe_inventory_path_forms_are_rejected(self) -> None:
        for value in (
            "",
            ".",
            "..",
            "../schema.json",
            "/tmp/schema.json",
            "schemas/./schema.json",
            "schemas/../schema.json",
            "schemas//schema.json",
            "schemas\\schema.json",
            "C:/schema.json",
            "--schema",
            "schemas/schema.json/",
            "schemas/\n/schema.json",
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    baseline.ReleaseError, "unsafe protocol-baseline path"
                ),
            ):
                baseline._validate_relative_path(value)

    def test_schema_manifest_canonical_duplicate_and_nonfinite_drift_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / baseline.SCHEMA_PATH
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(baseline.ReleaseError, "schema digest"):
                baseline.validate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / baseline.BASELINE_PATH
            document = json.loads(path.read_text())
            path.write_text(json.dumps(document, indent=2) + "\n")
            with self.assertRaisesRegex(baseline.ReleaseError, "not canonical"):
                baseline.validate(root)

        for payload, message in (
            (
                b'{"schema_version":"one","schema_version":"two"}\n',
                "duplicate JSON key",
            ),
            (b'{"schema_version":NaN}\n', "non-finite"),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                (root / baseline.BASELINE_PATH).write_bytes(payload)
                with self.assertRaisesRegex(baseline.ReleaseError, message):
                    baseline.validate(root)

    @unittest.skipUnless(hasattr(os, "link"), "hard-link regression requires os.link")
    def test_hard_linked_bound_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / "sdk/capabilities-v1.json"
            source = root / "capability-link-source.json"
            path.replace(source)
            os.link(source, path)
            with self.assertRaisesRegex(baseline.ReleaseError, "hard-linked"):
                baseline.validate(root)

    @unittest.skipUnless(
        hasattr(os, "symlink"), "symlink regression requires os.symlink"
    )
    def test_symlinked_manifest_and_bound_parent_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / baseline.BASELINE_PATH
            source = root / "baseline-link-source.json"
            path.replace(source)
            os.symlink(source, path)
            with self.assertRaisesRegex(baseline.ReleaseError, "regular file"):
                baseline.validate(root)
            with self.assertRaisesRegex(baseline.ReleaseError, "regular file"):
                baseline.generate(root)

        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            sdk = root / "sdk"
            moved = root / "sdk-real"
            sdk.replace(moved)
            os.symlink(moved, sdk)
            with self.assertRaisesRegex(baseline.ReleaseError, "real directory"):
                baseline.validate(root)


if __name__ == "__main__":
    unittest.main()
