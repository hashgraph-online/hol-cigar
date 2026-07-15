from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "benches/cigarbench/generate_wp20_readiness.py"
SPEC = importlib.util.spec_from_file_location("generate_wp20_readiness", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def redigest(value: dict[str, object], field: str) -> None:
    unsigned = dict(value)
    unsigned.pop(field, None)
    value[field] = MODULE._sha256_multihash(MODULE._canonical(unsigned))


def validate_schema(
    value: object, schema: dict[str, object], root: dict[str, object]
) -> None:
    reference = schema.get("$ref")
    if reference is not None:
        assert isinstance(reference, str) and reference.startswith("#/$defs/")
        definitions = root["$defs"]
        assert isinstance(definitions, dict)
        target = definitions[reference.removeprefix("#/$defs/")]
        assert isinstance(target, dict)
        validate_schema(value, target, root)
        return
    all_of = schema.get("allOf", [])
    assert isinstance(all_of, list)
    for branch in all_of:
        assert isinstance(branch, dict)
        validate_schema(value, branch, root)
    one_of = schema.get("oneOf")
    if one_of is not None:
        assert isinstance(one_of, list)
        matches = 0
        for branch in one_of:
            assert isinstance(branch, dict)
            try:
                validate_schema(value, branch, root)
            except AssertionError:
                continue
            matches += 1
        assert matches == 1
    if "const" in schema:
        assert value == schema["const"]
    if "enum" in schema:
        assert value in schema["enum"]
    expected_type = schema.get("type")
    if expected_type == "object":
        assert isinstance(value, dict)
        required = schema.get("required", [])
        assert isinstance(required, list) and set(required).issubset(value)
        properties = schema.get("properties", {})
        assert isinstance(properties, dict)
        if schema.get("additionalProperties") is False:
            assert set(value).issubset(properties)
        for key, item in value.items():
            subschema = properties.get(key)
            if isinstance(subschema, dict):
                validate_schema(item, subschema, root)
    elif expected_type == "array":
        assert isinstance(value, list)
        assert len(value) >= schema.get("minItems", 0)
        if "maxItems" in schema:
            assert len(value) <= schema["maxItems"]
        if schema.get("uniqueItems") is True:
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            assert len(encoded) == len(set(encoded))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for item in value:
                validate_schema(item, item_schema, root)
    elif expected_type == "string":
        assert isinstance(value, str)
        assert len(value) >= schema.get("minLength", 0)
        if "maxLength" in schema:
            assert len(value) <= schema["maxLength"]
        if "pattern" in schema:
            assert re.search(schema["pattern"], value)
    elif expected_type == "integer":
        assert isinstance(value, int) and not isinstance(value, bool)
        assert value >= schema.get("minimum", value)
    elif expected_type == "boolean":
        assert isinstance(value, bool)
    elif expected_type == "null":
        assert value is None


class Wp20ReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        # macOS exposes /var as a symlink to /private/var. Resolve the test
        # harness root so positive-path fixtures contain no symlink component.
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        for relative in (
            "demos",
            "reports/demos",
            "reports/cigarbench/local-dry-run",
            "reports/cigarbench/local-matrix-dry-run-v1",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(ROOT / relative, destination)
        baseline = self.root / "baselines/cigarbench"
        baseline.mkdir(parents=True)
        shutil.copy2(
            ROOT / "baselines/cigarbench/manifest.json", baseline / "manifest.json"
        )
        # Qualification runs from a read-only candidate.  The adversarial
        # fixture tests intentionally mutate only this private temporary copy,
        # so normalize its inherited candidate modes without making the
        # candidate itself writable.
        for directory, _, filenames in os.walk(self.root):
            os.chmod(directory, 0o700)
            for filename in filenames:
                copied = Path(directory) / filename
                if copied.is_symlink():
                    raise AssertionError(
                        f"unexpected symlink in test fixture: {copied}"
                    )
                os.chmod(copied, 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def source(self) -> dict[str, object]:
        return {
            "clean": False,
            "committed": True,
            "committed_candidate": False,
            "dirty_path_count": 1,
            "evidence_source_bound": False,
            "git_tree": "2" * 40,
            "reason": "working_tree_not_clean_and_inputs_are_not_candidate_bound",
            "revision": "1" * 40,
        }

    def suites(self) -> list[dict[str, object]]:
        producer = {
            "executable": "/usr/bin/python3",
            "implementation": "CPython",
            "version": "3.14.0",
        }
        output = {
            "bytes": 0,
            "normalization": "unittest-duration-v1",
            "normalized_sha256": "0" * 64,
        }
        return [
            {
                "command_sha256": str(index) * 64,
                "id": identifier,
                "producer": producer,
                "status": "passed",
                "stderr": output,
                "stdout": output,
                "tests": index,
            }
            for index, identifier in enumerate(
                ("cigarbench", "comparator-matrix", "demos"), 1
            )
        ]

    def receipt(self) -> dict[str, object]:
        return MODULE.build_receipt(self.root, self.source(), self.suites())

    def test_current_assets_generate_deterministic_non_release_receipt(self) -> None:
        first = self.receipt()
        second = self.receipt()
        self.assertEqual(MODULE.canonical_json(first), MODULE.canonical_json(second))
        self.assertEqual(first["schema_version"], "cigar.wp20-local-readiness.v1")
        self.assertNotEqual(first["schema_version"], MODULE.DRY_RUN_SCHEMA_VERSION)
        self.assertEqual(first["status"], "passed-local-scope")
        self.assertFalse(first["wp20_exit_satisfied"])
        self.assertFalse(first["release_ready"])
        self.assertFalse(first["source_binding"]["committed_candidate"])
        self.assertFalse(first["source_binding"]["evidence_source_bound"])
        self.assertEqual(first["demo_evidence"]["qualified_records"], 7)
        self.assertEqual(
            first["benchmark_evidence"]["comparator_matrix_dry_run"][
                "attachment_count"
            ],
            36,
        )

    def test_forged_demo_driver_is_rejected_even_with_recomputed_record_digest(
        self,
    ) -> None:
        path = self.root / "reports/demos/offline-context-compiler.json"
        report = load_json(path)
        driver = report["scenario_driver"]
        assert isinstance(driver, dict)
        driver["driver_bundle_digest"] = "1220" + "f" * 64
        redigest(report, "record_digest")
        write_json(path, report)
        with self.assertRaisesRegex(MODULE.ReadinessError, "driver bundle"):
            self.receipt()

    def test_non_allowlisted_no_egress_marker_is_rejected_after_redigest(self) -> None:
        path = self.root / "reports/demos/offline-context-compiler.json"
        report = load_json(path)
        driver = report["scenario_driver"]
        assert isinstance(driver, dict)
        driver.pop("driver_bundle_digest")
        driver["no_egress_enforcement"] = "proxy-only"
        redigest(driver, "result_digest")
        manifest = load_json(self.root / "demos/quickstart/demo.json")
        driver["driver_bundle_digest"] = MODULE._sha256_multihash(
            MODULE._canonical(
                {
                    "driver": manifest["driver_digest"],
                    "support": manifest["driver_support_digest"],
                }
            )
        )
        redigest(report, "record_digest")
        write_json(path, report)
        with self.assertRaisesRegex(MODULE.ReadinessError, "no-egress"):
            self.receipt()

    def test_dry_run_schema_collision_is_rejected(self) -> None:
        path = self.root / "reports/cigarbench/local-dry-run/qualification.json"
        receipt = load_json(path)
        receipt["schema_version"] = MODULE.SCHEMA_VERSION
        write_json(path, receipt)
        with self.assertRaisesRegex(MODULE.ReadinessError, "schema"):
            self.receipt()

    def test_missing_attachment_is_rejected(self) -> None:
        (self.root / "reports/cigarbench/local-dry-run/events.jsonl").unlink()
        with self.assertRaisesRegex(MODULE.ReadinessError, "missing or extra"):
            self.receipt()

    def test_extra_physical_attachment_is_rejected(self) -> None:
        extra = self.root / "reports/cigarbench/local-dry-run/unreferenced.json"
        extra.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ReadinessError, "missing or extra"):
            self.receipt()

    def test_extra_matrix_evidence_record_is_rejected(self) -> None:
        path = (
            self.root / "reports/cigarbench/local-matrix-dry-run-v1/matrix-receipt.json"
        )
        receipt = load_json(path)
        evidence = receipt["evidence"]
        assert isinstance(evidence, dict)
        evidence["extra/events.jsonl"] = {"bytes": 1, "sha256": "0" * 64}
        write_json(path, receipt)
        with self.assertRaisesRegex(MODULE.ReadinessError, "inventory"):
            self.receipt()

    def test_final_symlink_attachment_is_rejected(self) -> None:
        path = self.root / "reports/cigarbench/local-dry-run/events.jsonl"
        target = self.base / "events-real.jsonl"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaisesRegex(MODULE.ReadinessError, "symlink"):
            self.receipt()

    def test_intermediate_symlink_attachment_is_rejected(self) -> None:
        path = self.root / "reports/cigarbench/local-dry-run"
        target = path.with_name("local-dry-run-real")
        path.rename(target)
        path.symlink_to(target.name, target_is_directory=True)
        with self.assertRaisesRegex(MODULE.ReadinessError, "symlink"):
            self.receipt()

    def test_boolean_attachment_byte_count_is_rejected(self) -> None:
        path = self.root / "reports/cigarbench/local-dry-run/qualification.json"
        receipt = load_json(path)
        evidence = receipt["evidence"]
        assert isinstance(evidence, dict) and isinstance(evidence["events"], dict)
        evidence["events"]["bytes"] = True
        write_json(path, receipt)
        with self.assertRaisesRegex(MODULE.ReadinessError, "bytes"):
            self.receipt()

    def test_non_string_attachment_digest_is_rejected(self) -> None:
        path = self.root / "reports/cigarbench/local-dry-run/qualification.json"
        receipt = load_json(path)
        evidence = receipt["evidence"]
        assert isinstance(evidence, dict) and isinstance(evidence["events"], dict)
        evidence["events"]["sha256"] = 7
        write_json(path, receipt)
        with self.assertRaisesRegex(MODULE.ReadinessError, "SHA-256"):
            self.receipt()

    def test_sdk_bundle_mismatch_is_rejected_after_redigest(self) -> None:
        path = self.root / "reports/demos/sdk-quickstarts.json"
        report = load_json(path)
        quickstarts = report["quickstarts"]
        assert isinstance(quickstarts, list) and isinstance(quickstarts[0], dict)
        quickstarts[0]["bundle_id"] = "1220" + "f" * 64
        redigest(report, "report_digest")
        write_json(path, report)
        with self.assertRaisesRegex(MODULE.ReadinessError, "identities disagree"):
            self.receipt()

    def test_sdk_mode_mismatch_is_rejected_after_redigest(self) -> None:
        path = self.root / "reports/demos/sdk-quickstarts.json"
        report = load_json(path)
        quickstarts = report["quickstarts"]
        assert isinstance(quickstarts, list) and isinstance(quickstarts[0], dict)
        quickstarts[0]["mode"] = "wrong-mode"
        redigest(report, "report_digest")
        write_json(path, report)
        with self.assertRaisesRegex(MODULE.ReadinessError, "mode/status"):
            self.receipt()

    def test_comparator_summary_mismatch_is_rejected(self) -> None:
        path = (
            self.root / "reports/cigarbench/local-matrix-dry-run-v1/matrix-receipt.json"
        )
        receipt = load_json(path)
        reports = receipt["reports"]
        assert isinstance(reports, dict) and isinstance(reports["fixed-window"], dict)
        reports["fixed-window"]["pair_count"] = 19
        write_json(path, receipt)
        with self.assertRaisesRegex(MODULE.ReadinessError, "summary"):
            self.receipt()

    def test_existing_output_is_rejected_without_overwrite(self) -> None:
        directory = self.base / "evidence"
        directory.mkdir(mode=0o700)
        output = directory / "receipt.json"
        output.write_text("preserve\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ReadinessError, "overwrite"):
            MODULE._open_output_target(self.root, output)
        self.assertEqual(output.read_text(encoding="utf-8"), "preserve\n")

    def test_symlink_output_is_rejected_without_touching_target(self) -> None:
        directory = self.base / "evidence"
        directory.mkdir(mode=0o700)
        target = self.base / "target"
        target.write_text("preserve\n", encoding="utf-8")
        output = directory / "receipt.json"
        output.symlink_to(target)
        with self.assertRaisesRegex(MODULE.ReadinessError, "overwrite"):
            MODULE._open_output_target(self.root, output)
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve\n")

    def test_in_repository_output_is_rejected(self) -> None:
        output = self.root / "receipt.json"
        with self.assertRaisesRegex(MODULE.ReadinessError, "outside"):
            MODULE._open_output_target(self.root, output)

    def test_descriptor_containment_rejects_a_lexically_missed_repository_parent(
        self,
    ) -> None:
        output = self.root / "receipt.json"
        with mock.patch.object(MODULE.os.path, "commonpath", return_value=str(output)):
            with self.assertRaisesRegex(MODULE.ReadinessError, "outside"):
                MODULE._open_output_target(self.root, output)
        self.assertFalse(output.exists())

    def test_dotdot_output_cannot_reenter_repository(self) -> None:
        external = self.base / "external-evidence"
        external.mkdir(mode=0o700)
        output = external / ".." / self.root.name / "receipt.json"
        with self.assertRaisesRegex(MODULE.ReadinessError, "navigation"):
            MODULE._open_output_target(self.root, output)
        self.assertFalse((self.root / "receipt.json").exists())

    def test_dotdot_output_is_rejected_even_when_normalized_target_stays_external(
        self,
    ) -> None:
        external = self.base / "external-evidence"
        external.mkdir(mode=0o700)
        nested = external / "nested"
        nested.mkdir(mode=0o700)
        output = nested / ".." / "receipt.json"
        with self.assertRaisesRegex(MODULE.ReadinessError, "navigation"):
            MODULE._open_output_target(self.root, output)
        self.assertFalse((external / "receipt.json").exists())

    def test_raw_dot_output_component_is_rejected_before_path_normalization(
        self,
    ) -> None:
        external = self.base / "external-evidence"
        external.mkdir(mode=0o700)
        output = f"{external}/./receipt.json"
        with self.assertRaisesRegex(MODULE.ReadinessError, "navigation"):
            MODULE._open_output_target(self.root, output)
        self.assertFalse((external / "receipt.json").exists())

    def test_unsafe_output_directory_mode_is_rejected(self) -> None:
        directory = self.base / "evidence"
        directory.mkdir(mode=0o755)
        os.chmod(directory, 0o755)
        with self.assertRaisesRegex(MODULE.ReadinessError, "0700"):
            MODULE._open_output_target(self.root, directory / "receipt.json")

    def test_intermediate_symlink_output_directory_is_rejected(self) -> None:
        real = self.base / "real-evidence"
        real.mkdir(mode=0o700)
        linked = self.base / "linked-evidence"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(MODULE.ReadinessError, "symlink"):
            MODULE._open_output_target(self.root, linked / "receipt.json")

    def test_create_new_receipt_is_mode_0600_and_durable_path_is_closed(self) -> None:
        directory = self.base / "evidence"
        directory.mkdir(mode=0o700)
        output = directory / "receipt.json"
        target = MODULE._open_output_target(self.root, output)
        try:
            MODULE._write_receipt(target, b"receipt\n")
        finally:
            target.close()
        self.assertEqual(output.read_bytes(), b"receipt\n")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_shared_external_workspace_is_private_create_new_and_unambiguous(
        self,
    ) -> None:
        evidence = self.base / "shared-evidence"
        receipt = {
            "schema_version": "test-only",
            "harness_test_evidence": {"total_tests": 3},
        }
        arguments = [
            "--root",
            str(self.root),
            "--out",
            "wp20/readiness.json",
            "--evidence-dir",
            str(evidence),
        ]
        with (
            mock.patch.object(MODULE, "run_harness_tests", return_value=[]),
            mock.patch.object(MODULE, "git_source_binding", return_value={}),
            mock.patch.object(MODULE, "build_receipt", return_value=receipt),
        ):
            self.assertEqual(MODULE.main(arguments), 0)
            with self.assertRaisesRegex(MODULE.ReadinessError, "unsafe"):
                MODULE.main(arguments)
        output = evidence / "wp20" / "readiness.json"
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
        self.assertEqual(load_json(output), receipt)

        other = self.base / "other-evidence"
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(other)}, clear=False
        ):
            with self.assertRaisesRegex(MODULE.ReadinessError, "conflicts"):
                MODULE.main(arguments)
        self.assertFalse(other.exists())

    def test_test_subprocess_environment_is_sanitized_and_metadata_is_recorded(
        self,
    ) -> None:
        root = self.base / "suite-root"
        tests = root / "tests"
        tests.mkdir(parents=True)
        (tests / "test_environment.py").write_text(
            "import os, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_clean(self): self.assertNotIn('CIGAR_TEST_SECRET', os.environ)\n",
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"CIGAR_TEST_SECRET": "must-not-leak"}):
            result = MODULE._run_test_suite(root, "cigarbench", "tests")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tests"], 1)
        self.assertTrue(Path(result["producer"]["executable"]).is_absolute())
        self.assertRegex(result["producer"]["version"], r"^\d+\.\d+\.\d+")
        self.assertRegex(result["stderr"]["normalized_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("logs", result)

    def test_noisy_child_is_killed_at_the_output_bound(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import os; os.write(1, b'x' * 65536); os.write(2, b'y' * 65536)",
        ]
        with self.assertRaisesRegex(MODULE.ReadinessError, "output exceeded"):
            MODULE._run_bounded(
                command,
                cwd=self.base,
                environment={"PATH": os.environ.get("PATH", "")},
                timeout=10,
                max_stdout=1024,
                max_stderr=1024,
                max_total=1024,
                label="noisy child",
            )

    def test_clean_child_without_descendants_completes_normally(self) -> None:
        result = MODULE._run_bounded(
            [sys.executable, "-c", "pass"],
            cwd=self.base,
            environment={"PATH": os.environ.get("PATH", "")},
            timeout=10,
            max_stdout=1024,
            max_stderr=1024,
            max_total=2048,
            label="clean child",
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process groups")
    def test_exited_parent_cannot_leave_a_pipe_holding_descendant(self) -> None:
        command = [
            sys.executable,
            "-c",
            (
                "import os,time; child=os.fork(); "
                "os._exit(0) if child else (time.sleep(30), os._exit(0))"
            ),
        ]
        started = time.monotonic()
        with self.assertRaisesRegex(MODULE.ReadinessError, "descendant processes"):
            MODULE._run_bounded(
                command,
                cwd=self.base,
                environment={"PATH": os.environ.get("PATH", "")},
                timeout=10,
                max_stdout=1024,
                max_stderr=1024,
                max_total=2048,
                label="pipe holder",
            )
        self.assertLess(time.monotonic() - started, 5)

    def test_sanitized_demo_suite_integration_passes(self) -> None:
        result = MODULE._run_test_suite(ROOT, "demos", "demos/tests")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tests"], 11)
        self.assertRegex(result["command_sha256"], r"^[0-9a-f]{64}$")

    def test_generated_receipt_validates_against_registered_schema(self) -> None:
        schema = json.loads(
            (ROOT / "packaging/schemas/wp20-local-readiness.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validate_schema(self.receipt(), schema, schema)
        try:
            import jsonschema
        except ImportError:
            return
        else:
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.validate(self.receipt(), schema)

    def test_cli_rejects_relative_output_before_running_suites(self) -> None:
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--out", "relative.json"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"absolute", result.stderr)
        self.assertFalse((ROOT / "relative.json").exists())


if __name__ == "__main__":
    unittest.main()
