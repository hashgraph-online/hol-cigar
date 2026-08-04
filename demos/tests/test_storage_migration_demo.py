from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load():
    specification = importlib.util.spec_from_file_location(
        "cigar_storage_migration_demo_tests",
        ROOT / "demos" / "storage-migration" / "run.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


demo = load()


class StorageMigrationDemoTests(unittest.TestCase):
    @staticmethod
    def result(index: int, identity: str = "1220" + "a" * 64) -> dict[str, object]:
        return {
            "run": index,
            "status": "product_check_passed",
            "semantic_identity": identity,
            "workflow": {"source_retained": True},
        }

    def test_report_is_create_new_private_and_requires_repeat_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            root.chmod(0o700)
            output = root / "report.json"
            with mock.patch.object(
                demo, "run_once", side_effect=[self.result(1), self.result(2)]
            ):
                self.assertEqual(demo.main(["--output", str(output)]), 0)
            report = json.loads(output.read_bytes())
            self.assertEqual(report["status"], "source_product_demo_passed_twice")
            self.assertEqual(report["clean_runs"], 2)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
            with self.assertRaisesRegex(demo.DemoError, "new absolute path"):
                demo.publish(output, b"{}\n")

        with mock.patch.object(
            demo,
            "run_once",
            side_effect=[self.result(1), self.result(2, "1220" + "b" * 64)],
        ):
            with self.assertRaisesRegex(demo.DemoError, "different semantic"):
                demo.main([])

    def test_child_environment_is_offline_without_replacing_home(self) -> None:
        with mock.patch.dict(os.environ, {"HOME": "/fixture-home"}, clear=False):
            environment = demo.clean_environment()
        self.assertEqual(environment["HOME"], "/fixture-home")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["ALL_PROXY"], "http://127.0.0.1:9")


if __name__ == "__main__":
    unittest.main()
