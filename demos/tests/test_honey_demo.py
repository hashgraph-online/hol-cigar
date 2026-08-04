from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


honey = load("cigar_honey_demo_tests", ROOT / "demos" / "run_honey.py")
claude_driver = load(
    "cigar_honey_claude_driver_tests", ROOT / "demos" / "claude-code" / "driver.py"
)


class HoneyDemoTests(unittest.TestCase):
    def test_two_agent_wrapper_is_bound_to_the_current_shared_driver(self) -> None:
        wrapper_path = ROOT / "demos" / "honey-two-agent" / "driver.py"
        shared_path = ROOT / "demos" / "agent-handoff" / "driver.py"
        module = ast.parse(wrapper_path.read_text(encoding="utf-8"))
        binding = next(
            node for node in module.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "SHARED_DRIVER_SHA256"
                for target in node.targets
            )
        )
        expected = ast.literal_eval(binding.value)
        self.assertEqual(expected, hashlib.sha256(shared_path.read_bytes()).hexdigest())

    def test_honey_environment_does_not_require_deferred_go_inputs(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                honey.demo_runner,
                "pinned_go_toolchain",
                side_effect=AssertionError("Honey must not load Go pins"),
            ),
        ):
            environment = honey.demo_runner.clean_environment(
                Path(temporary), include_go_toolchain=False
            )
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertNotIn("GOTOOLCHAIN", environment)

    def test_installed_claude_story_does_not_use_mutable_source_injection(self) -> None:
        plugin_root = ROOT / "adapters" / "claude-code"
        self.assertEqual(
            claude_driver.development_plugin_source_environment(
                plugin_root, installed_package=True
            ),
            {},
        )
        development = claude_driver.development_plugin_source_environment(
            plugin_root, installed_package=False
        )
        self.assertEqual(development["CIGAR_CLAUDE_PLUGIN_SOURCE"], str(plugin_root))
        self.assertEqual(development["CIGAR_TEST_PLUGIN_SOURCE"], str(plugin_root))

    def test_suite_is_exactly_four_stories_and_two_agent_fixture_has_one_worker(
        self,
    ) -> None:
        suite, stories = honey.load_suite(ROOT / "demos" / "honey-manifest.v1.json")
        self.assertEqual(suite["runs_per_scenario"], 2)
        self.assertEqual(
            set(stories),
            {"offline-context", "two-agent", "effect-recovery-replay", "claude-mcp"},
        )
        self.assertEqual(len(stories["offline-context"]), 2)
        self.assertEqual(len(stories["effect-recovery-replay"]), 2)
        fixture = honey.load_object(ROOT / "demos" / "honey-two-agent" / "fixture.json")
        self.assertEqual(len(fixture["children"]), 1)
        self.assertEqual(fixture["children"][0]["role"], "honey-worker-b")
        self.assertNotEqual(
            fixture["principals"]["agent_a"], fixture["principals"]["agent_b"]
        )
        self.assertIn("agent-a-resolves-typed-conflict", fixture["flow"])
        self.assertIn("final-evidence-root-correlates-workflow", fixture["flow"])

    def test_validation_report_is_content_bound_but_not_artifact_qualified(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "validation.json"
            self.assertEqual(
                honey.main(["--validate-only", "--output", str(output)]), 0
            )
            report = json.loads(output.read_bytes())
        self.assertEqual(report["status"], "validation_only")
        self.assertEqual(report["product_version"], honey.PRODUCT_VERSION)
        self.assertRegex(report["suite"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(report["installed_artifact_qualified"])
        self.assertRegex(report["report_digest"], r"^1220[0-9a-f]{64}$")

    def _runtime_archive(self, root: Path, *, extra: bool = False) -> Path:
        payloads = {
            relative: (
                (
                    b"#!/bin/sh\n"
                    b'printf \'%s\\n\' \'{"version":"0.9.2",'
                    b'"context_abi":"cigar.context.v1",'
                    b'"source_revision":"1111111111111111111111111111111111111111",'
                    b'"build_profile":"release"}\'\n'
                )
                if relative.startswith("bin/")
                else f"fixture {relative}\n".encode()
            )
            for relative in honey.RUNTIME_FILES
            if relative not in {"RELEASE-METADATA.json", "SHA256SUMS"}
        }
        metadata = {
            "schema_version": "cigar.release-metadata.v1",
            "artifact_id": "cli-daemon-macos-aarch64",
            "product_version": honey.PRODUCT_VERSION,
            "context_abi": honey.CONTEXT_ABI,
            "source_date_epoch": 1,
            "source": {
                "revision": "1" * 40,
                "tree_sha256": "2" * 64,
                "committed": True,
                "clean": True,
            },
        }
        payloads["RELEASE-METADATA.json"] = honey.canonical(metadata) + b"\n"
        checksum_paths = sorted(
            honey.RUNTIME_FILES - {"RELEASE-METADATA.json", "SHA256SUMS"},
            key=lambda value: value.encode("utf-8"),
        )
        payloads["SHA256SUMS"] = "".join(
            f"{honey.sha256_bytes(payloads[relative])}  {relative}\n"
            for relative in checksum_paths
        ).encode("ascii")
        if extra:
            payloads["unexpected"] = b"no\n"
        archive = root / "runtime.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            for relative, payload in sorted(payloads.items()):
                member = tarfile.TarInfo(relative)
                member.size = len(payload)
                member.mode = 0o755 if relative.startswith("bin/") else 0o644
                handle.addfile(member, io.BytesIO(payload))
        return archive

    def test_runtime_install_requires_exact_inventory_and_internal_checksums(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self._runtime_archive(root)
            identity = honey.sha256_bytes(archive.read_bytes())
            observed, binaries, metadata = honey.install_runtime(
                archive, identity, root / "installed"
            )
            self.assertEqual(observed["sha256"], identity)
            self.assertEqual(metadata["source"]["revision"], "1" * 40)
            self.assertEqual(set(binaries), {"cigar", "cigard", "hook", "mcp"})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self._runtime_archive(root, extra=True)
            with self.assertRaisesRegex(honey.HoneyDemoError, "exact Honey member"):
                honey.install_runtime(
                    archive,
                    honey.sha256_bytes(archive.read_bytes()),
                    root / "installed",
                )

    def test_story_requires_identical_semantic_identity_across_clean_runs(self) -> None:
        component = (
            ROOT / "demos" / "quickstart" / "demo.json",
            honey.demo_runner.load_json(ROOT / "demos" / "quickstart" / "demo.json"),
        )
        result = {
            "result_digest": "1220" + "a" * 64,
            "no_egress_enforcement": "darwin-loopback-only-v1",
            "assertions": [],
        }
        with mock.patch.object(honey, "run_component_once", return_value=result):
            report = honey.run_story("offline-context", [component], {}, {}, None, None)
        self.assertEqual(report["status"], "installed_story_passed_twice")

        changed = dict(result)
        changed["result_digest"] = "1220" + "b" * 64
        with (
            mock.patch.object(
                honey, "run_component_once", side_effect=[result, changed]
            ),
            self.assertRaisesRegex(honey.HoneyDemoError, "different semantic"),
        ):
            honey.run_story("offline-context", [component], {}, {}, None, None)


if __name__ == "__main__":
    unittest.main()
