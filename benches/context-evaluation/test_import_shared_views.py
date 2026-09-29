"""The importer binds observed package code/worker bytes and uses raw samples."""

import copy
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from evaluation import EvaluationError, encoded, evaluate, file_digest
from import_shared_views import HARNESS, MODULE, import_study, wheel_identity


class SharedViewsImportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="context-study-import-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.wheels = []
        identities = []
        for version in ("0.12.0", "0.13.0a1"):
            wheel = self.root / f"{version}.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    f"hol_cigar-{version}.dist-info/METADATA",
                    f"Name: hol-cigar\nVersion: {version}\n",
                )
                archive.writestr(
                    "cigar_sdk/__init__.py", f'__version__ = "{version}"\n'
                )
                archive.writestr("cigar_sdk/py.typed", "")
                archive.writestr(
                    "cigar_sdk/_native/test/cigar-context-worker",
                    b"unit fixture; not an executable",
                )
            self.wheels.append(wheel)
            identities.append(wheel_identity(wheel))
        self.raw = {
            "schema": "cigar.shared-views-comparison.v1",
            "harness_sha256": file_digest(HARNESS),
            "agents": 12,
            "reviewer": "scripted-fixture",
            "cohorts": 2,
            "rounds_per_cohort": 1,
            "documents_per_source": 1,
            "host": "unit-test-only",
            "method": "unit-test-only",
            "summary": {"fictional-speedup": 1_000_000},
            "samples": [],
        }
        for cohort in range(2):
            for index, label in enumerate(("old-private", "new-views")):
                version, sources, workers = identities[index]
                self.raw["samples"].append(
                    {
                        "variant": label,
                        "cohort": cohort,
                        "version": version,
                        "sdk_source_sha256": sources,
                        "worker_sha256": next(iter(workers)),
                        "python": "3.14.7",
                        "protobuf": "6.33.5",
                        "mode": "private" if index == 0 else "views",
                        "raw_timing_ms": {
                            operation: [10, 15, 20]
                            for operation in ("compile", "verify", "review", "replace")
                        },
                        "raw_worker_rss_bytes": [50, 70],
                        "raw_host_and_worker_rss_bytes": [100, 120],
                        "startup_ms": 20,
                        "setup_ms": 30,
                    }
                )

    def run_import(self, raw=None):
        path = self.root / "raw.json"
        path.write_bytes(encoded(self.raw if raw is None else raw))
        return import_study(
            path,
            "old-private",
            "new-views",
            *self.wheels,
            "a" * 40,
            "b" * 40,
            self.root / "evidence",
        )

    def test_recomputes_raw_series_and_never_imports_summary_claims(self):
        result = self.run_import()
        self.assertEqual(result, evaluate(self.root / "evidence"))
        self.assertEqual(result["evidence_class"], "performance")
        self.assertEqual(
            result["metrics"]["compile-median"]["treatments"]["baseline"]["value"], 15
        )
        self.assertEqual(
            result["metrics"]["compile-p95"]["treatments"]["candidate"]["value"], 20
        )
        self.assertEqual(
            result["metrics"]["host-worker-rss-max"]["treatments"]["candidate"][
                "value"
            ],
            120,
        )
        self.assertEqual(
            result["metrics"]["compile-median"]["paired"]["mean_difference"], 0
        )
        self.assertIsNone(
            result["metrics"]["compile-median"]["paired"]["difference_ci95"]
        )
        self.assertNotIn("fictional", encoded(result).decode())

    def test_wrong_sdk_worker_version_or_harness_is_rejected(self):
        for field in ("sdk_source_sha256", "worker_sha256", "version"):
            raw = copy.deepcopy(self.raw)
            raw["samples"][0][field] = "mismatch"
            with self.subTest(field=field), self.assertRaises(EvaluationError):
                self.run_import(raw)
        raw = copy.deepcopy(self.raw)
        raw["harness_sha256"] = "0" * 64
        with self.assertRaisesRegex(EvaluationError, "harness"):
            self.run_import(raw)
        self.assertFalse((self.root / "evidence").exists())

    def test_summary_only_incomplete_or_mixed_runtime_studies_are_rejected(self):
        variants = []
        raw = copy.deepcopy(self.raw)
        raw["samples"][0].pop("raw_timing_ms")
        variants.append(raw)
        raw = copy.deepcopy(self.raw)
        raw["samples"].pop()
        variants.append(raw)
        raw = copy.deepcopy(self.raw)
        raw["samples"][0]["python"] = "different"
        variants.append(raw)
        for raw in variants:
            with self.subTest(raw=raw), self.assertRaises(EvaluationError):
                self.run_import(raw)
        self.assertFalse((self.root / "evidence").exists())

    def test_code_data_changes_affect_package_identity_and_bytecode_does_not(self):
        entries = [("a.py", b"code"), ("fixtures/a.json", b"data")]
        first = MODULE.package_source_identity(entries)
        self.assertEqual(first, MODULE.package_source_identity(list(reversed(entries))))
        self.assertNotEqual(
            first, MODULE.package_source_identity([*entries, ("new.py", b"code")])
        )
        self.assertNotEqual(
            first,
            MODULE.package_source_identity([(entries[0][0], b"changed"), entries[1]]),
        )
        self.assertEqual(
            first,
            MODULE.package_source_identity(
                [
                    *entries,
                    ("__pycache__/a.pyc", b"cache"),
                    ("_native/test/cigar-context-worker", b"worker"),
                ]
            ),
        )
        self.assertEqual(len(bytes.fromhex(first)), hashlib.sha256().digest_size)

    def test_existing_evidence_is_never_overwritten(self):
        first = self.run_import()
        with self.assertRaisesRegex(EvaluationError, "already exists"):
            self.run_import()
        self.assertEqual(first, evaluate(self.root / "evidence"))


if __name__ == "__main__":
    unittest.main()
