from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "run_matrix", ROOT / "tools" / "quality" / "run_matrix.py"
)
assert SPEC is not None and SPEC.loader is not None
run_matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_matrix
SPEC.loader.exec_module(run_matrix)


def matrix(case: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "cigar.test-matrix.v1",
        "suite": "runner-self-test",
        "description": "Runner self test.",
        "cases": [case],
    }


def valid_case() -> dict[str, object]:
    return {
        "id": "SELF-001",
        "title": "A passing child.",
        "command": ["python3", "-c", "raise SystemExit(0)"],
        "timeout_seconds": 10,
        "profiles": ["local", "release"],
        "platforms": ["linux", "macos", "windows"],
        "requirements": ["VER-EVIDENCE-001"],
        "isolate_home": True,
    }


class MatrixRunnerTests(unittest.TestCase):
    def write_matrix(self, directory: Path, document: dict[str, object]) -> Path:
        path = directory / "matrix.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_valid_matrix_executes_and_emits_content_free_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            source = self.write_matrix(directory, matrix(valid_case()))
            loaded = run_matrix.load_matrix(source)
            result = run_matrix.run_case(
                ROOT,
                loaded.document["suite"],
                "local",
                loaded.document["cases"][0],
                None,
            )
            self.assertEqual(result["status"], "passed")
            self.assertNotIn("command", result)
            self.assertEqual(result["stdout"]["bytes"], 0)
            self.assertEqual(result["canary_scan"], "passed")

    def test_source_identity_fails_closed_without_a_git_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            identity = run_matrix.source_identity(Path(raw))
            self.assertEqual(identity["kind"], "workspace")
            self.assertIsNone(identity["revision"])
            self.assertFalse(identity["committed"])
            self.assertFalse(identity["clean"])

    def test_canary_output_is_a_hard_failure_without_serializing_it(self) -> None:
        case = valid_case()
        case["command"] = [
            "python3",
            "-c",
            "import os; print(os.environ['CIGAR_TEST_SECRET_CANARY'])",
        ]
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            source = self.write_matrix(directory, matrix(case))
            loaded = run_matrix.load_matrix(source)
            result = run_matrix.run_case(
                ROOT,
                loaded.document["suite"],
                "local",
                loaded.document["cases"][0],
                None,
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_kind"], "canary-leak")
            self.assertNotIn(run_matrix.SYNTHETIC_CANARY, json.dumps(result))

    def test_missing_required_environment_fails_closed(self) -> None:
        case = valid_case()
        case["required_environment"] = ["CIGAR_RUNNER_TEST_MISSING"]
        os.environ.pop("CIGAR_RUNNER_TEST_MISSING", None)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            source = self.write_matrix(directory, matrix(case))
            loaded = run_matrix.load_matrix(source)
            result = run_matrix.run_case(
                ROOT,
                loaded.document["suite"],
                "release",
                loaded.document["cases"][0],
                None,
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_kind"], "missing-required-environment")

    def test_child_environment_always_forces_cargo_offline(self) -> None:
        with mock.patch.dict(os.environ, {"CARGO_NET_OFFLINE": "false"}):
            environment = run_matrix.sanitized_environment(
                "runner-self-test", "local", isolated_home=None
            )
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")

    def test_offline_cargo_preflight_fails_once_without_disclosing_output(self) -> None:
        protected = b"private registry diagnostic and path"
        capture = run_matrix.CommandCapture(
            exit_code=102,
            stdout=b"",
            stderr=protected,
            timed_out=False,
        )
        case = valid_case()
        case["command"] = ["cargo", "nextest", "run", "--locked", "-p", "cigar-canon"]
        with mock.patch.object(
            run_matrix, "run_captured_command", return_value=capture
        ) as command:
            with self.assertRaises(run_matrix.MatrixError) as raised:
                run_matrix.preflight_offline_cargo(ROOT, [case])
        message = str(raised.exception)
        self.assertNotIn(protected.decode("utf-8"), message)
        self.assertIn(run_matrix.sha256_bytes(protected), message)
        invoked = command.call_args.args[0]
        self.assertEqual(invoked[:2], ["cargo", "metadata"])
        self.assertIn("--offline", invoked)
        self.assertEqual(
            command.call_args.kwargs["environment"]["CARGO_NET_OFFLINE"], "true"
        )

    def test_non_cargo_selection_skips_cargo_preflight(self) -> None:
        with mock.patch.object(run_matrix, "run_captured_command") as command:
            run_matrix.preflight_offline_cargo(ROOT, [valid_case()])
        command.assert_not_called()

    def test_cargo_cache_preparation_is_separate_and_content_free(self) -> None:
        protected = b"private fetch output"
        capture = run_matrix.CommandCapture(
            exit_code=1,
            stdout=protected,
            stderr=b"private fetch error",
            timed_out=False,
        )
        with mock.patch.object(
            run_matrix, "run_captured_command", return_value=capture
        ) as command:
            with self.assertRaises(run_matrix.MatrixError) as raised:
                run_matrix.prepare_cargo_cache(ROOT)
        message = str(raised.exception)
        self.assertNotIn(protected.decode("utf-8"), message)
        self.assertIn(run_matrix.sha256_bytes(protected), message)
        self.assertEqual(command.call_args.args[0], ["cargo", "fetch", "--locked"])

    def test_unsorted_duplicate_unknown_and_skip_contracts_are_rejected(self) -> None:
        bad_cases: list[dict[str, object]] = []
        unknown = valid_case()
        unknown["unexpected"] = True
        bad_cases.append(matrix(unknown))
        skipped = valid_case()
        skipped["command"] = ["cargo", "test", "--ignored"]
        bad_cases.append(matrix(skipped))
        empty_selection_prone = valid_case()
        empty_selection_prone["command"] = ["cargo", "test", "some_filter"]
        bad_cases.append(matrix(empty_selection_prone))
        duplicate = matrix(valid_case())
        duplicate["cases"] = [valid_case(), valid_case()]
        bad_cases.append(duplicate)
        unsorted = matrix(valid_case())
        second = valid_case()
        second["id"] = "AAA-001"
        unsorted["cases"] = [valid_case(), second]
        bad_cases.append(unsorted)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for index, document in enumerate(bad_cases):
                with self.subTest(index=index):
                    source = self.write_matrix(directory, document)
                    with self.assertRaises(run_matrix.MatrixError):
                        run_matrix.load_matrix(source)


if __name__ == "__main__":
    unittest.main()
