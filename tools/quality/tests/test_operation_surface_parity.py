from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools" / "quality" / "operation_surface_parity.py"
SPEC = importlib.util.spec_from_file_location("operation_surface_parity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
parity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = parity
SPEC.loader.exec_module(parity)


class OperationSurfaceParityTests(unittest.TestCase):
    def staged_root(self, base: Path) -> Path:
        root = base / "repository"
        for relative in parity.SOURCE_FILES:
            source = ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return root

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )

    def test_repository_projection_is_exact_deterministic_and_non_release_eligible(
        self,
    ) -> None:
        first = parity.validate(ROOT)
        second = parity.validate(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["operation_count"], 45)
        self.assertEqual(first["service_count"], 7)
        self.assertEqual(first["error_count"], 34)
        self.assertFalse(first["release_eligible"])
        self.assertFalse(first["candidate_frozen"])
        self.assertEqual(
            first["source_binding"]["file_count"], len(parity.SOURCE_FILES)
        )
        self.assertEqual(
            first["surfaces"]["cli"],
            {"mapping_count": 34, "operation_count": 33, "mode": "closed-subset"},
        )
        self.assertEqual(
            first["surfaces"]["mcp"],
            {"mapping_count": 10, "operation_count": 10, "mode": "closed-subset"},
        )
        self.assertEqual(
            first["surfaces"]["metrics"]["mode"], "aggregate-no-operation-label"
        )
        self.assertEqual(
            first["surfaces"]["errors"],
            {
                "operation_count": 45,
                "error_count": 34,
                "mode": "shared-closed-catalog",
            },
        )

    def test_authority_identity_route_and_duplicate_key_drift_fail_closed(self) -> None:
        mutations = ("identity", "route", "duplicate-key", "nonfinite-number")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / "spec/api/operations-v1.json"
                if mutation in {"duplicate-key", "nonfinite-number"}:
                    source = path.read_text(encoding="utf-8")
                    if mutation == "duplicate-key":
                        source = source.replace(
                            '"schema_version": 1,',
                            '"schema_version": 1, "schema_version": 1,',
                            1,
                        )
                    else:
                        source = source.replace(
                            '"operation_count": 45', '"operation_count": NaN', 1
                        )
                    path.write_text(source, encoding="utf-8")
                else:
                    document = json.loads(path.read_text(encoding="utf-8"))
                    operation = document["services"][0]["operations"][0]
                    if mutation == "identity":
                        operation["operation_id"] = "discoverSourceAlias"
                    else:
                        operation["http_path"] = "/v1/sources:discover-alias"
                        document["services"][0]["operations"][1]["http_path"] = (
                            "/v1/sources:discover-alias"
                        )
                    self.write_json(path, document)
                with self.assertRaises(parity.ParityError):
                    parity.validate(root)

    def test_openapi_semantics_and_problem_shape_fail_closed(self) -> None:
        mutations = ("operation-id", "mutation", "problem-field", "problem-code")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                path = root / "schemas/openapi/cigar-v1.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                operation = document["paths"]["/v1/catalog:ingest"]["post"]
                if mutation == "operation-id":
                    operation["operationId"] = "queryCatalog"
                elif mutation == "mutation":
                    operation["x-cigar-mutation"] = False
                elif mutation == "problem-field":
                    document["components"]["schemas"]["Problem"]["required"].remove(
                        "correlation_id"
                    )
                else:
                    problem = document["components"]["schemas"]["Problem"]
                    one_of = problem["$defs"]["ErrorCode"]["oneOf"]
                    one_of[0]["const"] = "UNKNOWN_ALIAS"
                self.write_json(path, document)
                with self.assertRaises(parity.ParityError):
                    parity.validate(root)

    def test_cli_mcp_and_sdk_projection_drift_fail_closed(self) -> None:
        mutations = (
            "cli",
            "mcp",
            "sdk-capability",
            "typescript",
            "python",
            "go",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                if mutation == "sdk-capability":
                    path = root / "sdk/capabilities-v1.json"
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document["sdks"]["typescript"]["transport"] = ["grpc"]
                    self.write_json(path, document)
                    with self.assertRaises(parity.ParityError):
                        parity.validate(root)
                    continue
                paths = {
                    "cli": "crates/cigar-cli/src/generated/operation_mappings.rs",
                    "mcp": "crates/cigar-mcp/src/generated/operation_mappings.rs",
                    "typescript": "sdk/typescript/src/generated/operations.ts",
                    "python": "sdk/python/src/cigar_sdk/generated/operations.py",
                    "go": "sdk/go/operations_gen.go",
                }
                path = root / paths[mutation]
                source = path.read_text(encoding="utf-8")
                replacements = {
                    "cli": (
                        'operation_id: "discoverSources"',
                        'operation_id: "queryCatalog"',
                    ),
                    "mcp": (
                        'authority_lane: "context_read"',
                        'authority_lane: "effect_commit"',
                    ),
                    "typescript": (
                        '"responseType":"DiscoveryPlanResponse"',
                        '"responseType":"SourceStatusResponse"',
                    ),
                    "python": (
                        "'response_type': 'DiscoveryPlanResponse'",
                        "'response_type': 'SourceStatusResponse'",
                    ),
                    "go": (
                        'ResponseType: "DiscoveryPlanResponse"',
                        'ResponseType: "SourceStatusResponse"',
                    ),
                }
                before, after = replacements[mutation]
                self.assertIn(before, source)
                path.write_text(source.replace(before, after, 1), encoding="utf-8")
                with self.assertRaises(parity.ParityError):
                    parity.validate(root)

    def test_error_sdk_dashboard_log_and_metric_drift_fail_closed(self) -> None:
        mutations = ("error-sdk", "dashboard", "log", "metric-label", "metric-family")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = self.staged_root(Path(raw))
                if mutation == "error-sdk":
                    path = root / "sdk/typescript/src/generated/errors.ts"
                    before, after = '"numericCode":1000', '"numericCode":9999'
                elif mutation == "dashboard":
                    path = (
                        root
                        / "crates/cigar-dashboard/src/generated/protocol-catalog-v1.json"
                    )
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document["services"][0]["operations"][0]["auth"] = "anonymous"
                    self.write_json(path, document)
                    with self.assertRaises(parity.ParityError):
                        parity.validate(root)
                    continue
                elif mutation == "log":
                    path = root / "crates/cigar-api/src/context.rs"
                    before, after = (
                        '.field("operation", &self.operation)',
                        '.field("operation", &"unknown")',
                    )
                elif mutation == "metric-label":
                    path = root / "crates/cigar-observe/src/lib.rs"
                    before, after = (
                        'label("outcome", API_OUTCOMES)',
                        'label("operation", API_OUTCOMES)',
                    )
                else:
                    path = root / "crates/cigar-observe/src/lib.rs"
                    before, after = (
                        '"cigar_api_requests_total"',
                        '"cigar_api_request_total"',
                    )
                source = path.read_text(encoding="utf-8")
                self.assertIn(before, source)
                path.write_text(source.replace(before, after, 1), encoding="utf-8")
                with self.assertRaises(parity.ParityError):
                    parity.validate(root)

    def test_symlinked_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self.staged_root(Path(raw))
            path = root / "spec/api/operations-v1.json"
            target = root / "operations-copy.json"
            shutil.copy2(path, target)
            path.unlink()
            path.symlink_to(target)
            with self.assertRaisesRegex(parity.ParityError, "real regular file"):
                parity.validate(root)


if __name__ == "__main__":
    unittest.main()
