from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_context_version as versions  # noqa: E402
import check_python_coverage as coverage  # noqa: E402


class PolicyTests(unittest.TestCase):
    def test_statement_and_branch_gates_are_independent(self):
        row = {
            "num_statements": 100,
            "covered_lines": 100,
            "num_branches": 100,
            "covered_branches": 100,
        }
        document = {
            "totals": row.copy(),
            "files": {
                "cigar_sdk/" + name: {"summary": row.copy()}
                for name in (
                    "digest.py",
                    "context.py",
                    "local_runtime.py",
                    "transport.py",
                )
            },
        }
        self.assertEqual(coverage.validate(document)["status"], "passed")
        for field, value in (
            ("covered_lines", 89),
            ("covered_branches", 84),
            ("num_branches", 0),
        ):
            changed = copy.deepcopy(document)
            changed["totals"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                coverage.validate(changed)
        del document["files"]["cigar_sdk/digest.py"]
        with self.assertRaises(ValueError):
            coverage.validate(document)

    def test_version_and_tool_drift_fail_before_native_build(self):
        self.assertEqual(versions.validate(expected="0.12.0")["status"], "passed")
        with self.assertRaises(AssertionError):
            versions.validate(expected="0.11.0")
        paths = [
            "sdk/local-context-release.v1.json",
            "sdk/python/pyproject.toml",
            "sdk/typescript/package.json",
            "crates/cigar-context/Cargo.toml",
            "Cargo.lock",
            "sdk/python/src/cigar_sdk/release.json",
            "sdk/typescript/release.json",
            "sdk/python/src/cigar_sdk/local_runtime.py",
            "sdk/typescript/src/local-runtime.ts",
            "docs/release/context-sdk-0.12.0-notes.md",
            "sdk/context-toolchain.v1.json",
            "scripts/release/containers/context-consumer.Dockerfile",
        ]
        paths += [
            str(path.relative_to(versions.ROOT))
            for path in (versions.ROOT / ".github/workflows").glob("*.yml")
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path in paths:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(versions.ROOT / path, target)
            self.assertEqual(versions.validate(root)["status"], "passed")
            for path, field in (
                ("sdk/typescript/package.json", "version"),
                ("sdk/context-toolchain.v1.json", "uv"),
            ):
                target = root / path
                original = target.read_bytes()
                value = json.loads(original)
                value[field] = "0.0.0"
                target.write_text(json.dumps(value))
                with self.subTest(path=path), self.assertRaises(AssertionError):
                    versions.validate(root)
                target.write_bytes(original)

    def test_wheel_without_native_requires_explicit_source_build_opt_in(self):
        # Load the actual hook with only Hatch's base interface replaced. The
        # native build pipeline separately exercises the real backend on archives.
        name = "hatchling.builders.hooks.plugin.interface"
        interface = ModuleType(name)
        interface.BuildHookInterface = object
        spec = importlib.util.spec_from_file_location(
            "tested_hatch_hook", versions.ROOT / "sdk/python/hatch_build.py"
        )
        module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {name: interface}):
            spec.loader.exec_module(module)
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            hook = SimpleNamespace(root=tmp, target_name="wheel")
            with self.assertRaisesRegex(ValueError, "CIGAR_ALLOW_PORTABLE_WHEEL"):
                module.CustomBuildHook.initialize(hook, "standard", {})
            with mock.patch.dict(os.environ, {"CIGAR_ALLOW_PORTABLE_WHEEL": "1"}):
                module.CustomBuildHook.initialize(hook, "standard", {})
            hook.target_name = "sdist"
            module.CustomBuildHook.initialize(hook, "standard", {})


if __name__ == "__main__":
    unittest.main()
