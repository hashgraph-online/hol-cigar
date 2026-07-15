from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "baselines" / "cigarbench" / "qualify_matrix.py"
SPEC = importlib.util.spec_from_file_location("cigarbench_matrix", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = matrix
SPEC.loader.exec_module(matrix)


class MatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        manifest = json.loads(
            (ROOT / "baselines" / "cigarbench" / "manifest.json").read_text()
        )
        self.inventory = {
            entry["baseline_id"] for entry in manifest["baselines"]
        } | set(manifest["ablations"])

    def report(self, comparator_id: str, index: int) -> dict[str, object]:
        def multihash(digit: str) -> str:
            return "1220" + digit * 64

        return {
            "comparison": {
                "comparator_id": comparator_id,
                "evidence_class": "qualification",
                "pins": {"shared": "pins"},
            },
            "decision": "pass",
            "qualification": {
                "eligible": True,
                "evaluator_attestation": {"verified": True},
            },
            "bootstrap_repetitions": 10_000,
            "input_manifests": {
                "plan": multihash(f"{index:x}"[-1]),
                "datasets": multihash("a"),
                "baselines": multihash("b"),
                "canaries": multihash("c"),
                "environment": multihash("d"),
            },
            "seed_commitment": multihash("e"),
            "input_digest": "1220" + f"{index:064x}",
            "report_digest": "1220" + f"{index + 100:064x}",
        }

    def test_complete_equally_pinned_matrix_passes(self) -> None:
        reports = {
            comparator_id: self.report(comparator_id, index + 1)
            for index, comparator_id in enumerate(sorted(self.inventory))
        }
        result = matrix.validate_matrix_reports(reports, self.inventory)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(set(result["comparators"]), self.inventory)

    def test_missing_or_reused_evidence_fails(self) -> None:
        reports = {
            comparator_id: self.report(comparator_id, index + 1)
            for index, comparator_id in enumerate(sorted(self.inventory))
        }
        reports.pop(next(iter(reports)))
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_matrix_reports(reports, self.inventory)
        reports = {
            comparator_id: self.report(comparator_id, index + 1)
            for index, comparator_id in enumerate(sorted(self.inventory))
        }
        for report in reports.values():
            report["input_digest"] = "1220" + "f" * 64
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_matrix_reports(reports, self.inventory)

    def test_cli_publishes_external_create_new_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary).resolve() / "evidence"

            def fake_qualify(arguments, analyzer):
                analyzer.write_json(arguments.output, {"status": "pass"})
                return 0

            arguments = [
                "--evidence-dir",
                str(evidence),
                "--evidence-root",
                "input",
                "--datasets",
                "datasets.json",
                "--baselines",
                "baselines.json",
                "--canaries",
                "canaries.json",
                "--environment",
                "environment.json",
                "--seed-file",
                "seed",
                "--attestation-key-file",
                "key",
                "--output",
                "matrix/report.json",
            ]
            with mock.patch.object(matrix, "qualify", side_effect=fake_qualify):
                self.assertEqual(matrix.main(arguments), 0)
                self.assertEqual(matrix.main(arguments), 2)
            output = evidence / "matrix" / "report.json"
            receipt = evidence / "matrix" / "report.json.receipt.json"
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o400)


if __name__ == "__main__":
    unittest.main()
