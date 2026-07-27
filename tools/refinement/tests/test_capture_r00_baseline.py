from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/refinement/capture_r00_baseline.py"
SPEC = importlib.util.spec_from_file_location("capture_r00_baseline", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
baseline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = baseline
SPEC.loader.exec_module(baseline)


class BaselineCaptureTests(unittest.TestCase):
    def test_canonical_identity_is_order_independent(self) -> None:
        left = {"b": [2, 1], "a": "value"}
        right = {"a": "value", "b": [2, 1]}
        self.assertEqual(baseline.canonical(left), baseline.canonical(right))
        self.assertRegex(baseline.multihash(baseline.canonical(left)), r"^1220[0-9a-f]{64}$")

    def test_test_counts_are_exact_and_fail_closed(self) -> None:
        self.assertEqual(
            baseline.test_count("demos", b"Ran 17 tests in 1.0s\nOK\n"), 17
        )
        self.assertEqual(
            baseline.test_count("python-sdk", b"22 passed in 2.0s\n"), 22
        )
        self.assertEqual(
            baseline.test_count(
                "focused-rust",
                (
                    b"test result: ok. 17 passed; 0 failed;\n"
                    b"test result: ok. 82 passed; 0 failed;\n"
                ),
            ),
            99,
        )
        with self.assertRaisesRegex(baseline.BaselineError, "ambiguous"):
            baseline.test_count("demos", b"no result")

    def test_probe_measurements_are_closed(self) -> None:
        expected = {
            "atom_cbor_bytes": 938,
            "edge_cbor_bytes": 373,
            "schema_version": "cigar.local-scale-record-probe.v1",
            "uuid_cbor_text_bytes": 38,
            "version_cbor_text_bytes": 70,
        }
        payload = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(baseline.test_count("local-scale-probe", payload), 1)
        changed = dict(expected)
        changed["atom_cbor_bytes"] = 939
        with self.assertRaisesRegex(baseline.BaselineError, "measurements changed"):
            baseline.test_count(
                "local-scale-probe",
                json.dumps(changed, sort_keys=True, separators=(",", ":")).encode(),
            )

    def test_source_identity_requires_a_clean_git_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(baseline.BaselineError):
                baseline.source_identity(Path(temporary))


if __name__ == "__main__":
    unittest.main()
