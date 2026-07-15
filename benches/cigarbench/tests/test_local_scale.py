from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "benches" / "cigarbench" / "local_scale.py"
SPEC = importlib.util.spec_from_file_location("cigar_local_scale", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
local_scale = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = local_scale
SPEC.loader.exec_module(local_scale)


def measured_probe() -> dict[str, int | str]:
    return {
        "schema_version": local_scale.PROBE_SCHEMA_VERSION,
        "atom_cbor_bytes": 938,
        "edge_cbor_bytes": 373,
        "uuid_cbor_text_bytes": 38,
        "version_cbor_text_bytes": 70,
    }


def minimal_receipt() -> dict[str, object]:
    architecture = local_scale.architecture_evidence()
    model = local_scale.capacity_model(architecture, measured_probe())
    source = local_scale.source_file_snapshot()
    source["git"] = local_scale.git_state()
    source["source_descriptor_bound"] = True
    body: dict[str, object] = {
        "schema_version": local_scale.SCHEMA_VERSION,
        "result": "blocked",
        "release_scale_qualified": False,
        "started_at_unix_nanos": 1,
        "finished_at_unix_nanos": 2,
        "platform_scope": "aarch64-apple-darwin",
        "targets": {
            "atoms": 1_000_000,
            "edges": 10_000_000,
            "referenced_blob_bytes": 100 * 1024**3,
            "referenced_blob_unit": "logical bytes",
        },
        "observed": {
            "atoms": None,
            "edges": None,
            "referenced_blob_bytes": None,
        },
        "blockers": ["large_local_initial_free_space_below_requirement"],
        "architecture": architecture,
        "capacity_model": model,
        "source": source,
        "environment": {
            "system": "Darwin",
            "machine": "arm64",
            "release": "test-release",
            "python": "test-python",
            "rustc": "test-rustc",
            "cargo": "test-cargo",
            "logical_cpus": 1,
            "filesystem_path": "/private/tmp/cigar-scale-test",
            "filesystem_device": 1,
            "filesystem_inode": 1,
            "filesystem_total_bytes": 2,
            "filesystem_free_bytes": 1,
        },
        "checks": [
            {
                "id": "exact_fixture_cbor_probe",
                "status": "passed",
                "detail": "exact fixture probe passed",
            },
            {
                "id": "normalized_v4_authority",
                "status": "passed",
                "detail": "normalized authority is source-bound",
            },
            {
                "id": "large_local_target_bounds",
                "status": "passed",
                "detail": "target bounds are covered",
            },
            {
                "id": "large_local_initial_free_space",
                "status": "blocked",
                "detail": "host availability is below the activation requirement",
            },
            {
                "id": "physical_scale_execution",
                "status": "not-run",
                "detail": "physical execution was not started",
            },
        ],
        "claims": {
            "physical_scale_execution_attempted": False,
            "one_million_physical_atoms": False,
            "ten_million_physical_edges": False,
            "one_hundred_gib_referenced_blobs": False,
            "legacy_sql_tables_treated_as_production": False,
            "fuzz_executed": False,
            "soak_executed": False,
        },
        "required_remediation": local_scale.REQUIRED_REMEDIATION,
    }
    return local_scale.receipt_with_id(body)


class LocalScalePreflightTests(unittest.TestCase):
    def test_capacity_measurement_is_bound_to_exact_private_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cigar-local-scale-capacity-") as raw:
            capacity = Path(raw).resolve(strict=True)
            capacity.chmod(0o700)
            with (
                mock.patch.object(
                    local_scale.platform, "system", return_value="Darwin"
                ),
                mock.patch.object(
                    local_scale.platform, "machine", return_value="arm64"
                ),
                mock.patch.object(
                    local_scale, "_tool_version", return_value="test-tool"
                ),
                mock.patch.object(
                    local_scale.shutil,
                    "disk_usage",
                    wraps=local_scale.shutil.disk_usage,
                ) as disk_usage,
            ):
                environment = local_scale.host_environment(capacity)
            disk_usage.assert_called_once_with(capacity)
            metadata = capacity.lstat()
            self.assertEqual(environment["filesystem_path"], capacity.as_posix())
            self.assertEqual(environment["filesystem_device"], metadata.st_dev)
            self.assertEqual(environment["filesystem_inode"], metadata.st_ino)

            alias = capacity.parent / f"{capacity.name}-alias"
            alias.symlink_to(capacity, target_is_directory=True)
            self.addCleanup(alias.unlink)
            with (
                mock.patch.object(
                    local_scale.platform, "system", return_value="Darwin"
                ),
                mock.patch.object(
                    local_scale.platform, "machine", return_value="arm64"
                ),
                self.assertRaisesRegex(local_scale.LocalScaleError, "canonical"),
            ):
                local_scale.host_environment(alias)

    def test_normalized_payload_model_and_profile_quotas_cover_the_target(self) -> None:
        architecture = {
            "large_local_maximum_database_bytes": 68_719_476_736,
            "large_local_maximum_atoms": 1_250_000,
            "large_local_maximum_edges": 12_500_000,
            "large_local_maximum_referenced_blob_bytes": 137_438_953_472,
        }
        model = local_scale.capacity_model(architecture, measured_probe())
        self.assertEqual(model["per_atom_record_bytes"], 938)
        self.assertEqual(model["per_edge_record_bytes"], 373)
        self.assertEqual(model["modeled_atom_record_bytes"], 938_000_000)
        self.assertEqual(model["modeled_edge_record_bytes"], 3_730_000_000)
        self.assertEqual(model["modeled_catalog_record_bytes"], 4_668_000_000)
        self.assertEqual(
            model["capacity_headroom_before_excluded_overhead_bytes"],
            64_051_476_736,
        )
        self.assertTrue(model["record_payload_lower_bound_fits"])
        self.assertTrue(model["logical_targets_within_profile_quotas"])

    def test_rust_probe_measures_the_exact_valid_fixture_encodings(self) -> None:
        self.assertEqual(local_scale.run_record_probe(), measured_probe())

    def test_architecture_check_binds_normalized_v4_and_large_local_authority(
        self,
    ) -> None:
        architecture = local_scale.architecture_evidence()
        self.assertEqual(
            architecture["large_local_maximum_database_bytes"], 68_719_476_736
        )
        self.assertFalse(architecture["commit_rewrites_complete_catalog"])
        self.assertFalse(architecture["read_decodes_complete_catalog"])
        self.assertTrue(architecture["normalized_catalog_tables_are_authoritative"])
        self.assertFalse(architecture["legacy_sql_catalog_tables_are_authoritative"])
        self.assertEqual(architecture["normalized_edge_insert_occurrences"], 1)

    def test_receipt_identity_and_false_claims_fail_closed(self) -> None:
        receipt = minimal_receipt()
        local_scale.validate_receipt(receipt)

        tampered = json.loads(json.dumps(receipt))
        tampered["capacity_model"]["record_payload_lower_bound_fits"] = False
        with self.assertRaisesRegex(local_scale.LocalScaleError, "identity"):
            local_scale.validate_receipt(tampered)

        false_pass = json.loads(json.dumps(receipt))
        false_pass["claims"]["ten_million_physical_edges"] = True
        body = dict(false_pass)
        body.pop("receipt_id")
        false_pass = local_scale.receipt_with_id(body)
        with self.assertRaisesRegex(local_scale.LocalScaleError, "claims"):
            local_scale.validate_receipt(false_pass)

    def test_receipt_rejects_fabricated_binding_platform_checks_and_time(self) -> None:
        for mutate, expected in (
            (
                lambda receipt: receipt["source"].__setitem__(
                    "digest", "1220" + "0" * 64
                ),
                "source inventory digest",
            ),
            (
                lambda receipt: receipt.__setitem__("platform_scope", "x86_64-linux"),
                "platform scope",
            ),
            (
                lambda receipt: receipt["checks"][3].__setitem__("status", "passed"),
                "check is inconsistent",
            ),
            (
                lambda receipt: receipt.__setitem__("finished_at_unix_nanos", 0),
                "time interval",
            ),
        ):
            receipt = minimal_receipt()
            mutate(receipt)
            body = dict(receipt)
            body.pop("receipt_id")
            receipt = local_scale.receipt_with_id(body)
            with self.assertRaisesRegex(local_scale.LocalScaleError, expected):
                local_scale.validate_receipt(receipt)

    def test_external_publication_is_private_create_new_and_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cigar-local-scale-evidence-") as root:
            evidence = Path(root).resolve(strict=True)
            evidence.chmod(0o700)
            arguments = SimpleNamespace(
                evidence_dir=evidence,
                capacity_path=evidence,
                output="qualification/local-scale-preflight.json",
                require_clean_source=False,
            )
            with mock.patch.object(
                local_scale, "build_receipt", return_value=minimal_receipt()
            ):
                self.assertEqual(local_scale.command_preflight(arguments), 3)
                with self.assertRaises(local_scale.EvidenceWorkspaceError):
                    local_scale.command_preflight(arguments)
            receipt = evidence / arguments.output
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o400)
            self.assertEqual(local_scale.load_receipt(receipt)["result"], "blocked")

    def test_source_inventory_is_content_bound_and_stable(self) -> None:
        first = local_scale.source_file_snapshot()
        second = local_scale.source_file_snapshot()
        self.assertEqual(first["digest"], second["digest"])
        self.assertGreater(len(first["files"]), 10)
        paths = {entry["path"] for entry in first["files"]}
        self.assertIn(".cargo/config.toml", paths)
        self.assertIn("benches/cigarbench/local_scale.py", paths)
        self.assertIn("benches/cigarbench/local_scale_driver/src/main.rs", paths)
        self.assertIn("benches/cigarbench/profiles/large-local-v1.json", paths)
        self.assertIn(
            "benches/cigarbench/schemas/local-scale-result-v1.schema.json", paths
        )
        self.assertIn("crates/cigar-store/src/backup.rs", paths)
        self.assertIn("crates/cigar-store/src/blob.rs", paths)
        self.assertIn("crates/cigar-store/src/sqlite.rs", paths)
        self.assertIn("crates/cigar-store/src/postgres.rs", paths)
        self.assertIn("crates/cigar-store/migrations/sqlite/0001_initial.sql", paths)
        self.assertIn(
            "crates/cigar-store/migrations/sqlite/0004_normalized_authoritative_catalog.sql",
            paths,
        )
        self.assertIn(
            "crates/cigar-store/migrations/postgres/0004_gc_revision_guard.sql", paths
        )
        self.assertIn("crates/cigar-canon/src/lib.rs", paths)
        self.assertIn("crates/cigar-aws-creds/src/lib.rs", paths)
        self.assertIn("crates/cigar-rust-s3/src/lib.rs", paths)
        self.assertIn("crates/cigar-testkit/src/lib.rs", paths)
        self.assertIn("scripts/release/evidence_workspace.py", paths)

    def test_public_schema_closes_every_security_relevant_nested_binding(self) -> None:
        schema_path = (
            ROOT
            / "benches"
            / "cigarbench"
            / "schemas"
            / "local-scale-preflight-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        properties = schema["properties"]
        for name in ("architecture", "capacity_model", "source", "environment"):
            self.assertFalse(properties[name]["additionalProperties"])
            self.assertTrue(properties[name]["required"])
        self.assertFalse(
            properties["capacity_model"]["properties"]["record_probe"][
                "additionalProperties"
            ]
        )
        self.assertFalse(
            properties["source"]["properties"]["git"]["additionalProperties"]
        )
        self.assertFalse(properties["required_remediation"]["items"])

    def test_physical_driver_profile_and_schemas_are_exact_and_fail_closed(
        self,
    ) -> None:
        root = ROOT / "benches" / "cigarbench"
        profile = json.loads(
            (root / "profiles" / "large-local-v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            profile,
            {
                "schema_version": "cigar.local-scale-profile.v1",
                "id": "large_local",
                "platform": "aarch64-apple-darwin",
                "capacity_profile": "large_local",
                "atoms": 1_000_000,
                "edges": 10_000_000,
                "blob_objects": 1_600,
                "blob_bytes_each": 64 * 1024**2,
                "referenced_blob_bytes": 100 * 1024**3,
                "atom_batch_size": 1_000,
                "edge_batch_size": 10_000,
                "maximum_database_bytes": 64 * 1024**3,
                "minimum_initial_available_bytes": 300 * 1024**3,
                "minimum_runtime_reserve_bytes": 16 * 1024**3,
                "maximum_atoms": 1_250_000,
                "maximum_edges": 12_500_000,
                "maximum_referenced_blob_bytes": 128 * 1024**3,
            },
        )
        binding_schema = json.loads(
            (root / "schemas" / "local-scale-binding-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        result_schema = json.loads(
            (root / "schemas" / "local-scale-result-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(binding_schema["additionalProperties"])
        self.assertFalse(result_schema["additionalProperties"])
        self.assertEqual(
            set(binding_schema["required"]), set(binding_schema["properties"])
        )
        self.assertEqual(
            set(result_schema["required"]), set(result_schema["properties"])
        )
        qualification = result_schema["allOf"][0]["then"]["properties"]
        self.assertTrue(qualification["release_scale_qualified"]["const"])
        self.assertEqual(
            qualification["targets"]["properties"]["blob_objects"]["const"],
            1_600,
        )
        self.assertEqual(
            qualification["observed"]["properties"]["referenced_blob_bytes"]["const"],
            100 * 1024**3,
        )
        try:
            import jsonschema
        except ImportError:
            return
        jsonschema.Draft202012Validator.check_schema(binding_schema)
        jsonschema.Draft202012Validator.check_schema(result_schema)


if __name__ == "__main__":
    unittest.main()
