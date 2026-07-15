from __future__ import annotations

import copy
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "compatibility" / "protocol_compatibility.py"
SPEC = importlib.util.spec_from_file_location("protocol_compatibility", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
compat = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compat
SPEC.loader.exec_module(compat)


class ProtocolCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = compat.load_policy(ROOT)

    def stage(self, base: Path) -> Path:
        root = base / "candidate"
        paths = {
            compat.POLICY_PATH,
            compat.POLICY_SCHEMA_PATH,
            self.policy["domains"]["public_schemas"]["manifest_path"],
        }
        for domain_paths in compat.authority_paths(ROOT, self.policy).values():
            paths.update(domain_paths)
        for relative in sorted(paths):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        return root

    def read_json(self, root: Path, relative: str) -> object:
        return compat.load_json_bytes((root / relative).read_bytes(), relative)

    def write_json(self, root: Path, relative: str, document: object) -> None:
        (root / relative).write_bytes(compat.canonical_json_bytes(document))

    def rebind(
        self, root: Path, policy: dict[str, object] | None = None
    ) -> dict[str, object]:
        candidate = compat.refresh_bindings(root, policy or copy.deepcopy(self.policy))
        (root / compat.POLICY_PATH).write_bytes(
            compat.canonical_policy_bytes(candidate)
        )
        return candidate

    def compare(
        self, root: Path, policy: dict[str, object] | None = None
    ) -> compat.Comparison:
        candidate = self.rebind(root, policy)
        return compat.compare_repositories(ROOT, self.policy, root, candidate)

    def test_repository_policy_is_exact_bound_and_nonclaiming(self) -> None:
        compat.validate_repository(ROOT, self.policy)
        domains = self.policy["domains"]
        self.assertEqual(domains["public_schemas"]["binding"]["file_count"], 42)
        self.assertEqual(domains["operations"]["operation_count"], 45)
        self.assertEqual(domains["interface_projections"]["binding"]["file_count"], 6)
        self.assertEqual(domains["interface_projections"]["cli_mapping_count"], 34)
        self.assertEqual(domains["interface_projections"]["mcp_mapping_count"], 10)
        self.assertEqual(domains["errors"]["error_count"], 34)
        self.assertEqual(domains["payloads"]["payload_type_count"], 70)
        self.assertEqual(
            domains["cursor_stream"]["stream_operations"], ["subscribeSpaceEvents"]
        )
        self.assertEqual(domains["stored_records"]["sqlite_migration_count"], 4)
        self.assertEqual(domains["stored_records"]["postgres_migration_count"], 4)
        self.assertEqual(
            self.policy["claim_scope"],
            {
                "cross_platform_qualified": False,
                "development_source_only": True,
                "migration_qualified": False,
                "release_frozen": False,
            },
        )
        result = compat.compare_repositories(ROOT, self.policy, ROOT, self.policy)
        self.assertEqual(result.classification, "exact")
        self.assertEqual(result.backward_reader, "compatible")
        self.assertEqual(result.forward_reader, "compatible")

    def test_interface_projection_unknown_duplicate_and_mapping_change_fail_closed(
        self,
    ) -> None:
        relative = self.policy["domains"]["interface_projections"]["source_path"]
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            catalog = self.read_json(root, relative)
            catalog["cli"]["mappings"][0]["operation_id"] = "unsupportedOperation"
            self.write_json(root, relative, catalog)
            with self.assertRaisesRegex(
                compat.CompatibilityError, "operation mismatch"
            ):
                self.rebind(root)
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            catalog = self.read_json(root, relative)
            catalog["cli"]["mappings"][1]["exposed_name"] = catalog["cli"]["mappings"][
                0
            ]["exposed_name"]
            self.write_json(root, relative, catalog)
            with self.assertRaisesRegex(
                compat.CompatibilityError, "duplicate CLI projection"
            ):
                self.rebind(root)
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            catalog = self.read_json(root, relative)
            doctor = next(
                mapping
                for mapping in catalog["cli"]["mappings"]
                if mapping["exposed_name"] == "doctor"
            )
            doctor["operation_id"] = "getVersion"
            self.write_json(root, relative, catalog)
            result = self.compare(root)
            self.assertEqual(result.classification, "breaking-major")
            self.assertIn(
                "interface-mapping-changed", {issue.code for issue in result.issues}
            )

    def test_duplicate_unknown_noncanonical_and_unsafe_policy_data_fail_closed(
        self,
    ) -> None:
        with self.assertRaisesRegex(compat.CompatibilityError, "duplicate JSON key"):
            compat.load_json_bytes(b'{"value":1,"value":2}\n', "duplicate")
        with self.assertRaisesRegex(compat.CompatibilityError, "fields drifted"):
            changed = copy.deepcopy(self.policy)
            changed["unknown"] = True
            compat.validate_policy_document(changed)
        with self.assertRaisesRegex(
            compat.CompatibilityError, "not canonical policy JSON"
        ):
            with tempfile.TemporaryDirectory() as raw:
                root = self.stage(Path(raw))
                path = root / compat.POLICY_PATH
                path.write_bytes(path.read_bytes() + b"\n")
                compat.load_policy(root)
        with self.assertRaisesRegex(
            compat.CompatibilityError, "unsafe repository path"
        ):
            changed = copy.deepcopy(self.policy)
            changed["domains"]["errors"]["paths"] = ["../escape"]
            compat.validate_policy_document(changed)

    def test_symlink_and_hardlink_authorities_fail_closed(self) -> None:
        relative = self.policy["domains"]["claude_plugin"]["path"]
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as raw:
                root = self.stage(Path(raw))
                path = root / relative
                original = Path(raw) / "outside.json"
                shutil.copyfile(path, original)
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(original)
                else:
                    os.link(original, path)
                with self.assertRaisesRegex(
                    compat.CompatibilityError,
                    "cannot read authority|regular file|hard-linked",
                ):
                    compat.validate_repository(root, self.policy)

    def test_final_component_swap_to_symlink_is_blocked_by_descriptor_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = self.policy["domains"]["claude_plugin"]["path"]
            authority = root / relative
            external = Path(raw) / "external.json"
            external.write_bytes(authority.read_bytes())
            real_open = os.open
            swapped = False

            def racing_open(
                path: object, flags: int, *, dir_fd: int | None = None
            ) -> int:
                nonlocal swapped
                if path == authority.name and dir_fd is not None and not swapped:
                    swapped = True
                    authority.unlink()
                    authority.symlink_to(external)
                return real_open(path, flags, dir_fd=dir_fd)

            with (
                mock.patch.object(compat.os, "open", side_effect=racing_open),
                self.assertRaisesRegex(
                    compat.CompatibilityError, "cannot read authority"
                ),
            ):
                compat._read_bytes(root, relative)
            self.assertTrue(swapped)

    def test_optional_schema_addition_is_directional_minor(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = "schemas/json/health-report-v1.schema.json"
            schema = self.read_json(root, relative)
            schema["properties"]["diagnostic_hint"] = {
                "type": "string",
                "maxLength": 64,
            }
            self.write_json(root, relative, schema)
            result = self.compare(root)
            self.assertEqual(result.classification, "additive-minor")
            self.assertEqual(result.backward_reader, "compatible")
            self.assertEqual(result.forward_reader, "conditional")
            self.assertIn(
                "schema-optional-property-added",
                {issue.code for issue in result.issues},
            )

    def test_required_schema_addition_is_breaking_major(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = "schemas/json/health-report-v1.schema.json"
            schema = self.read_json(root, relative)
            schema["properties"]["mandatory_hint"] = {"type": "string"}
            schema["required"].append("mandatory_hint")
            self.write_json(root, relative, schema)
            result = self.compare(root)
            self.assertEqual(result.classification, "breaking-major")
            self.assertIn(
                "schema-required-added", {issue.code for issue in result.issues}
            )

    def test_invalid_schema_and_error_projection_drift_fail_before_comparison(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = "schemas/json/health-report-v1.schema.json"
            schema = self.read_json(root, relative)
            schema["required"].append(schema["required"][0])
            self.write_json(root, relative, schema)
            with self.assertRaisesRegex(
                compat.CompatibilityError, "invalid required array"
            ):
                self.rebind(root)
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = "schemas/openapi/error-registry-v1.json"
            registry = self.read_json(root, relative)
            registry["errors"][0]["http"] = 500
            self.write_json(root, relative, registry)
            with self.assertRaisesRegex(
                compat.CompatibilityError,
                "source catalog and generated registry differ",
            ):
                self.rebind(root)

    def test_operation_payload_cursor_and_wit_changes_require_major(self) -> None:
        mutations = (
            ("spec/api/operations-v1.json", "operation"),
            ("spec/api/operation-payloads-v1.json", "payload"),
            ("crates/cigar-api/src/cursor.rs", "cursor"),
            ("spec/context-abi/cigar-extension-world-v1.wit", "wit"),
        )
        for relative, mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.stage(Path(raw))
                path = root / relative
                if mutation == "operation":
                    document = self.read_json(root, relative)
                    document["services"][0]["operations"][0]["http_path"] = (
                        "/v1/sources:changed"
                    )
                    self.write_json(root, relative, document)
                elif mutation == "payload":
                    document = self.read_json(root, relative)
                    document["operations"][0]["request_max_bytes"] -= 1
                    self.write_json(root, relative, document)
                else:
                    path.write_bytes(
                        path.read_bytes() + b"\n// compatibility mutation\n"
                    )
                result = self.compare(root)
                self.assertEqual(result.classification, "breaking-major")

    def test_error_addition_and_existing_mapping_change_are_classified(self) -> None:
        before = {
            "OLD": {
                "code": 1000,
                "name": "OLD",
                "http": 400,
                "grpc": "INVALID_ARGUMENT",
                "retry": "never",
                "message": "old",
                "remediation": "fix",
                "disclose_identity": False,
            }
        }
        added = copy.deepcopy(before)
        added["NEW"] = {
            "code": 1001,
            "name": "NEW",
            "http": 400,
            "grpc": "INVALID_ARGUMENT",
            "retry": "never",
            "message": "new",
            "remediation": "fix",
            "disclose_identity": False,
        }
        collector = compat._Collector()
        compat._compare_errors(before, added, collector)
        self.assertEqual(collector.finish().classification, "additive-minor")
        changed = copy.deepcopy(before)
        changed["OLD"]["http"] = 500
        collector = compat._Collector()
        compat._compare_errors(before, changed, collector)
        self.assertEqual(collector.finish().classification, "breaking-major")

    def test_claude_window_widening_is_minor_but_platform_removal_breaks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = "adapters/claude-code/compatibility.json"
            record = self.read_json(root, relative)
            record["claude_code"]["maximum_exclusive"] = "2.1.209"
            self.write_json(root, relative, record)
            result = self.compare(root)
            self.assertEqual(result.classification, "additive-minor")
            self.assertIn(
                "claude-window-widened", {issue.code for issue in result.issues}
            )
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = "adapters/claude-code/compatibility.json"
            record = self.read_json(root, relative)
            record["platforms"].pop()
            self.write_json(root, relative, record)
            result = self.compare(root)
            self.assertEqual(result.classification, "breaking-major")

    def test_migration_rewrite_breaks_and_append_requires_manual_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            for relative in (
                "migrations/postgres/0004_gc_revision_guard.sql",
                "crates/cigar-store/migrations/postgres/0004_gc_revision_guard.sql",
            ):
                path = root / relative
                path.write_bytes(
                    path.read_bytes() + b"\n-- changed applied migration\n"
                )
            result = self.compare(root)
            self.assertEqual(result.classification, "breaking-major")

        migration = """-- CIGAR PostgreSQL schema v5. Append-only compatibility probe.
-- sequence/name: 5 / compatibility_probe
-- application compatibility: major 1 through major 2
-- classification/lock: online / new empty table only
-- data backfill: none
-- verification: compatibility_probe exists
-- rollback or restore: restore the mandatory pre-migration backup
CREATE TABLE IF NOT EXISTS compatibility_probe (id bigint PRIMARY KEY);
"""
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            policy = copy.deepcopy(self.policy)
            additions = (
                "crates/cigar-store/migrations/postgres/0005_compatibility_probe.sql",
                "migrations/postgres/0005_compatibility_probe.sql",
            )
            for relative in additions:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(migration, encoding="utf-8")
            stored = policy["domains"]["stored_records"]
            stored["migration_paths"] = sorted([*stored["migration_paths"], *additions])
            stored["postgres_migration_count"] = 5
            result = self.compare(root, policy)
            self.assertEqual(result.classification, "manual-review")
            self.assertEqual(result.backward_reader, "unproven")
            self.assertIn(
                "appended-migration-requires-evidence",
                {issue.code for issue in result.issues},
            )

    def test_unversioned_stored_codec_change_is_never_auto_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.stage(Path(raw))
            relative = self.policy["domains"]["stored_records"]["codec_paths"][0]
            path = root / relative
            path.write_bytes(
                path.read_bytes() + b"\n// persisted-codec review mutation\n"
            )
            result = self.compare(root)
            self.assertEqual(result.classification, "manual-review")
            self.assertIn(
                "stored-codec-source-changed", {issue.code for issue in result.issues}
            )


if __name__ == "__main__":
    unittest.main()
