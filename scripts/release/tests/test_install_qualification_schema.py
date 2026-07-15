from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "release"))

import qualify_install  # noqa: E402


SCHEMA_PATH = ROOT / "packaging/schemas/install-qualification.v1.schema.json"
OUTER_CHECKS = {"version", "help", "mcp-schema", "claude-hook-schema"}
SUPPORTED_RULES = {
    "$schema",
    "$id",
    "title",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "const",
    "pattern",
    "minimum",
}


class SchemaViolation(AssertionError):
    """The representative receipt violates the schema subset used by this file."""


def assert_supported_schema(rule: dict[str, Any], path: str = "$") -> None:
    unsupported = set(rule) - SUPPORTED_RULES
    if unsupported:
        raise SchemaViolation(f"{path}: unsupported schema keywords: {unsupported}")
    properties = rule.get("properties", {})
    if not isinstance(properties, dict):
        raise SchemaViolation(f"{path}: properties must be an object")
    for name, child in properties.items():
        if not isinstance(child, dict):
            raise SchemaViolation(f"{path}.{name}: property rule must be an object")
        assert_supported_schema(child, f"{path}.{name}")


def assert_matches_schema(value: Any, rule: dict[str, Any], path: str = "$") -> None:
    if "const" in rule and value != rule["const"]:
        raise SchemaViolation(f"{path}: value differs from const")
    expected_type = rule.get("type")
    if expected_type == "object" and not isinstance(value, dict):
        raise SchemaViolation(f"{path}: expected object")
    if expected_type == "string" and not isinstance(value, str):
        raise SchemaViolation(f"{path}: expected string")
    if expected_type == "integer" and (
        not isinstance(value, int) or isinstance(value, bool)
    ):
        raise SchemaViolation(f"{path}: expected integer")
    if "pattern" in rule and (
        not isinstance(value, str) or re.search(rule["pattern"], value) is None
    ):
        raise SchemaViolation(f"{path}: pattern mismatch")
    if "minimum" in rule and (
        not isinstance(value, int) or isinstance(value, bool) or value < rule["minimum"]
    ):
        raise SchemaViolation(f"{path}: below minimum")
    if isinstance(value, dict):
        required = set(rule.get("required", []))
        missing = required - set(value)
        if missing:
            raise SchemaViolation(f"{path}: missing properties: {missing}")
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False:
            unexpected = set(value) - set(properties)
            if unexpected:
                raise SchemaViolation(f"{path}: unexpected properties: {unexpected}")
        for name, child in properties.items():
            if name in value:
                assert_matches_schema(value[name], child, f"{path}.{name}")


def representative_receipt() -> dict[str, Any]:
    digest = "a" * 64
    revision = "b" * 40
    return {
        "schema_version": "cigar.install-qualification.v1",
        "status": "passed",
        "artifact_id": qualify_install.RUNTIME_ARTIFACT_ID,
        "artifact_sha256": digest,
        "artifact_bytes": 1,
        "package_contract_sha256": digest,
        "product_version": "1.0.0-dev.1",
        "context_abi": "cigar.context.v1",
        "source_revision": revision,
        "target": qualify_install.MACOS_TARGET,
        "runtime_build_receipt": {
            "schema_version": qualify_install.RUNTIME_BUILD_RECEIPT_SCHEMA,
            "status": "built-unqualified",
            "sha256": digest,
            "bytes": 1,
        },
        "qualification_tool": {
            "artifact_id": qualify_install.QUALIFICATION_TOOL_ARTIFACT_ID,
            "archive_sha256": digest,
            "archive_bytes": 1,
            "contract_id": qualify_install.QUALIFICATION_TOOL_CONTRACT_ID,
            "contract_sha256": digest,
            "source_revision": revision,
            "build_receipt_schema_version": (
                qualify_install.QUALIFICATION_TOOL_BUILD_RECEIPT_SCHEMA
            ),
            "build_receipt_status": "built-unqualified",
            "build_receipt_sha256": digest,
            "build_receipt_bytes": 1,
            "runner_path": "bin/cigar-conformance",
            "runner_sha256": digest,
            "driver_path": "bin/cigar-install-qualifier",
            "driver_sha256": digest,
        },
        "build_receipt_authentication": qualify_install.BUILD_RECEIPT_AUTHENTICATION,
        "driver_receipt_sha256": digest,
        "installed_binary_sha256": {
            "cigar": digest,
            "cigard": digest,
            "cigar-mcp": digest,
            "cigar-claude-hook": digest,
        },
        "installed_workflow": {
            "profile": qualify_install.INSTALLED_WORKFLOW_PROFILE,
            "full_surface_sha256": digest,
            "semantic_identity_sha256": digest,
            "cigar_sha256": digest,
            "cigard_sha256": digest,
            "binding_sha256": digest,
            "no_egress_enforcement": qualify_install.MACOS_NO_EGRESS_ENFORCEMENT,
        },
        "unprivileged": True,
        "non_admin": True,
        "no_compiler_path": True,
        "no_egress": True,
        "no_egress_enforcement": qualify_install.MACOS_NO_EGRESS_ENFORCEMENT,
        "process_enforcement": qualify_install.MACOS_PROCESS_ENFORCEMENT,
        "path_cases": [
            "spaces",
            "unicode",
            "long",
            "read-only-parent",
            "non-admin",
        ],
        "checks": sorted(qualify_install.REQUIRED_DRIVER_CHECKS | OUTER_CHECKS),
        "uninstalled": True,
        "state_retained": True,
    }


class InstallQualificationSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def assert_rejected(self, receipt: dict[str, Any]) -> None:
        with self.assertRaises(SchemaViolation):
            assert_matches_schema(receipt, self.schema)

    def test_schema_exactly_matches_the_macos_receipt_surface(self) -> None:
        assert_supported_schema(self.schema)
        self.assertFalse(self.schema["additionalProperties"])
        self.assertEqual(set(self.schema["required"]), set(self.schema["properties"]))
        self.assertNotIn("qualification_driver", self.schema["properties"])
        self.assertEqual(
            self.schema["properties"]["artifact_id"]["const"],
            qualify_install.RUNTIME_ARTIFACT_ID,
        )
        self.assertEqual(
            self.schema["properties"]["target"]["const"],
            qualify_install.MACOS_TARGET,
        )
        self.assertEqual(
            self.schema["properties"]["no_egress_enforcement"]["const"],
            qualify_install.MACOS_NO_EGRESS_ENFORCEMENT,
        )
        self.assertEqual(
            self.schema["properties"]["process_enforcement"]["const"],
            qualify_install.MACOS_PROCESS_ENFORCEMENT,
        )
        self.assertEqual(
            self.schema["properties"]["checks"]["const"],
            sorted(qualify_install.REQUIRED_DRIVER_CHECKS | OUTER_CHECKS),
        )
        self.assertEqual(len(self.schema["properties"]["checks"]["const"]), 27)
        assert_matches_schema(representative_receipt(), self.schema)

    def test_raw_driver_external_attestation_and_non_macos_receipts_fail(self) -> None:
        raw_driver = representative_receipt()
        del raw_driver["qualification_tool"]
        raw_driver["qualification_driver"] = {
            "name": "synthetic-driver",
            "sha256": "a" * 64,
        }
        self.assert_rejected(raw_driver)

        for field, value in (
            ("artifact_id", "cli-daemon-linux-x86_64-gnu"),
            ("target", "x86_64-unknown-linux-gnu"),
            ("no_egress_enforcement", "external-runner-attestation-v1"),
            ("process_enforcement", "process-group-only-v1"),
            ("build_receipt_authentication", "authenticated"),
            ("non_admin", False),
        ):
            with self.subTest(field=field):
                receipt = representative_receipt()
                receipt[field] = value
                self.assert_rejected(receipt)

    def test_tool_binary_and_check_inventories_are_exact(self) -> None:
        tool_mutations = {
            "artifact_id": "synthetic-tool",
            "contract_id": "unreviewed-contract",
            "build_receipt_schema_version": "caller.receipt.v1",
            "build_receipt_status": "qualified",
            "runner_path": "bin/other-runner",
            "runner_sha256": "not-a-digest",
            "driver_path": "bin/other-driver",
            "driver_sha256": "not-a-digest",
        }
        for field, value in tool_mutations.items():
            with self.subTest(tool_field=field):
                receipt = representative_receipt()
                receipt["qualification_tool"][field] = value
                self.assert_rejected(receipt)

        extra_tool_field = representative_receipt()
        extra_tool_field["qualification_tool"]["verified"] = True
        self.assert_rejected(extra_tool_field)

        for field, value in (
            ("schema_version", "caller.receipt.v1"),
            ("status", "qualified"),
            ("sha256", "not-a-digest"),
            ("bytes", 0),
        ):
            with self.subTest(runtime_receipt_field=field):
                receipt = representative_receipt()
                receipt["runtime_build_receipt"][field] = value
                self.assert_rejected(receipt)

        for binary in ("cigar", "cigard", "cigar-mcp", "cigar-claude-hook"):
            with self.subTest(missing_binary=binary):
                receipt = representative_receipt()
                del receipt["installed_binary_sha256"][binary]
                self.assert_rejected(receipt)

        for field in (
            "profile",
            "full_surface_sha256",
            "semantic_identity_sha256",
            "cigar_sha256",
            "cigard_sha256",
            "binding_sha256",
            "no_egress_enforcement",
        ):
            with self.subTest(workflow_field=field):
                receipt = representative_receipt()
                del receipt["installed_workflow"][field]
                self.assert_rejected(receipt)

        for mutation in ("missing", "unexpected", "reordered"):
            with self.subTest(check_mutation=mutation):
                receipt = representative_receipt()
                if mutation == "missing":
                    receipt["checks"].pop()
                elif mutation == "unexpected":
                    receipt["checks"].append("synthetic-pass")
                else:
                    receipt["checks"].reverse()
                self.assert_rejected(receipt)


if __name__ == "__main__":
    unittest.main()
