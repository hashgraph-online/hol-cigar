from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "scripts" / "release"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


qualifier = load("cigar_qualify_honey_docs_tests", TOOLS / "qualify_honey_docs.py")


FAKE_RUNNER = r"""#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--manifest")
parser.add_argument("--scenario", required=True)
parser.add_argument("--runtime-archive")
parser.add_argument("--runtime-sha256", required=True)
parser.add_argument("--python-wheel")
parser.add_argument("--python-wheel-sha256")
parser.add_argument("--claude-plugin-archive")
parser.add_argument("--claude-plugin-sha256")
parser.add_argument("--output", required=True)
arguments = parser.parse_args()
support = {}
if arguments.python_wheel:
    support["python_wheel"] = {
        "sha256": arguments.python_wheel_sha256,
        "bytes": Path(arguments.python_wheel).stat().st_size,
    }
if arguments.claude_plugin_archive:
    support["claude_plugin"] = {
        "sha256": arguments.claude_plugin_sha256,
        "bytes": Path(arguments.claude_plugin_archive).stat().st_size,
    }
semantic = "1220" + "a" * 64
evidence = "1220" + "b" * 64
component_counts = {
    "offline-context": 2,
    "two-agent": 1,
    "effect-recovery-replay": 2,
    "claude-mcp": 1,
}
component = {
    "demo_id": "fixture-demo",
    "fixed_seed": 1,
    "manifest_digest": evidence,
    "fixture_digest": evidence,
    "driver_digest": evidence,
    "driver_support_digest": evidence,
    "status": "installed_component_passed_twice",
    "no_egress_enforcement": "darwin-loopback-only-v1",
    "semantic_identity": semantic,
    "repeated_semantic_identity": semantic,
    "assertions": [{
        "assertion_id": "fixture-assertion",
        "status": "product_observed",
        "evidence_digest": evidence,
    }],
}
report = {
    "schema_version": "cigar.honey-installed-demo-report.v1",
    "status": "installed_demo_passed",
    "product_version": "0.9.0-honey.1",
    "context_abi": "cigar.context.v1",
    "evidence_class": "cigar.honey-installed-demo.v1",
    "suite": {
        "manifest": "demos/honey-manifest.v1.json",
        "sha256": hashlib.sha256(Path(arguments.manifest).read_bytes()).hexdigest(),
    },
    "selected_scenarios": [arguments.scenario],
    "runtime": {
        "sha256": arguments.runtime_sha256,
        "bytes": Path(arguments.runtime_archive).stat().st_size,
    },
    "source": {
        "revision": "1" * 40,
        "tree_sha256": "2" * 64,
        "committed": True,
        "clean": True,
    },
    "supporting_artifacts": support,
    "scenarios": [{
        "scenario_id": arguments.scenario,
        "status": "installed_story_passed_twice",
        "semantic_identity": semantic,
        "components": [component] * component_counts[arguments.scenario],
    }],
    "installed_artifact_qualified": True,
}
unsigned = json.dumps(
    report,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
report["report_digest"] = "1220" + hashlib.sha256(unsigned).hexdigest()
Path(arguments.output).write_text(
    json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
"""


@unittest.skipUnless(os.name == "posix", "secure staging requires POSIX")
class HoneyDocumentationQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-honey-docs-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.demos = self.base / "demos.tar.gz"
        self._write_demo_archive(self.demos, FAKE_RUNNER)
        self.runtime = self._artifact("runtime.tar.gz", b"runtime-candidate\n")
        self.wheel = self._artifact("cigar_sdk.whl", b"python-wheel\n")
        self.plugin = self._artifact("claude-plugin.tar.gz", b"claude-plugin\n")

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _artifact(self, name: str, payload: bytes) -> Path:
        path = self.base / name
        path.write_bytes(payload)
        os.chmod(path, 0o400)
        return path

    @staticmethod
    def _write_demo_archive(path: Path, runner: str) -> None:
        if path.exists():
            path.unlink()
        members = {
            "demos/honey-manifest.v1.json": b"{}\n",
            "demos/run_honey.py": runner.encode("utf-8"),
        }
        with tarfile.open(path, "w:gz") as archive:
            for relative, payload in members.items():
                member = tarfile.TarInfo(relative)
                member.mode = 0o644
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        os.chmod(path, 0o400)

    def authority(self) -> dict[str, object]:
        return {
            "metadata": {
                "artifact_id": qualifier.DEMOS_ARTIFACT_ID,
                "contract": qualifier.DEMOS_CONTRACT_REFERENCE,
                "source": {
                    "revision": "1" * 40,
                    "tree_sha256": "3" * 64,
                    "committed": True,
                    "clean": True,
                },
            }
        }

    def arguments(self, flow: str, output: str) -> list[str]:
        arguments = [
            flow,
            "--demos-archive",
            str(self.demos),
            "--demos-sha256",
            self.digest(self.demos),
            "--runtime-archive",
            str(self.runtime),
            "--runtime-sha256",
            self.digest(self.runtime),
            "--evidence-dir",
            str(self.base / "evidence"),
            "--output",
            output,
        ]
        if flow == "handoff":
            arguments.extend(
                [
                    "--python-wheel",
                    str(self.wheel),
                    "--python-wheel-sha256",
                    self.digest(self.wheel),
                ]
            )
        if flow == "claude-plugin":
            arguments.extend(
                [
                    "--claude-plugin-archive",
                    str(self.plugin),
                    "--claude-plugin-sha256",
                    self.digest(self.plugin),
                ]
            )
        return arguments

    def test_all_four_flows_execute_the_packaged_runner_and_bind_exact_artifacts(
        self,
    ) -> None:
        with mock.patch.object(
            qualifier, "verify_package", return_value=self.authority()
        ) as verify:
            for flow, scenario in qualifier.FLOW_SCENARIOS.items():
                with self.subTest(flow=flow):
                    output = f"docs/{flow}.json"
                    self.assertEqual(qualifier.main(self.arguments(flow, output)), 0)
                    report = json.loads(
                        (self.base / "evidence" / output).read_text(encoding="utf-8")
                    )
                    self.assertEqual(report["status"], "passed")
                    self.assertEqual(report["flow"], flow)
                    self.assertEqual(report["scenario"], scenario)
                    self.assertTrue(report["offline"])
                    self.assertTrue(report["create_new"])
                    self.assertEqual(
                        report["artifacts"]["honey_demos"]["sha256"],
                        self.digest(self.demos),
                    )
                    self.assertEqual(
                        report["artifacts"]["runtime"]["sha256"],
                        self.digest(self.runtime),
                    )
                    self.assertEqual(
                        report["demo_report"]["selected_scenarios"], [scenario]
                    )
                    self.assertEqual(report["source"]["revision"], "1" * 40)
                    self.assertNotEqual(
                        report["source"]["demos"]["tree_sha256"],
                        report["source"]["runtime"]["tree_sha256"],
                    )
            self.assertEqual(verify.call_count, 4)

    def test_documentation_registry_uses_the_concrete_driver_and_exact_inputs(
        self,
    ) -> None:
        manifest = json.loads((ROOT / "docs/commands.v1.json").read_bytes())
        commands = {row["id"]: row for row in manifest["commands"]}
        flows = {
            "quickstart-source-compile": "quickstart",
            "handoff-flow": "handoff",
            "effect-replay-flow": "effect-replay",
            "claude-plugin-flow": "claude-plugin",
        }
        outputs: set[str] = set()
        for identifier, flow in flows.items():
            command = commands[identifier]
            self.assertEqual(command["mode"], "installed-candidate")
            self.assertEqual(command["cwd"], "${EMPTY_WORKSPACE}")
            self.assertEqual(
                command["argv"][:3],
                [
                    "python3",
                    "${CIGAR_SOURCE_ROOT}/scripts/release/qualify_honey_docs.py",
                    flow,
                ],
            )
            self.assertNotIn("${CIGAR_QUALIFICATION_DRIVER}", command["argv"])
            self.assertIn("--demos-archive", command["argv"])
            self.assertIn("--demos-sha256", command["argv"])
            self.assertIn("--runtime-archive", command["argv"])
            self.assertIn("--runtime-sha256", command["argv"])
            output = command["argv"][command["argv"].index("--output") + 1]
            self.assertNotIn(output, outputs)
            outputs.add(output)
        serialized = json.dumps(manifest)
        self.assertNotIn("CIGAR_QUALIFICATION_DRIVER", serialized)
        self.assertNotIn("QUALIFICATION_PROJECT", serialized)
        installed = [
            row for row in manifest["commands"] if row["mode"] == "installed-candidate"
        ]
        variables = {
            match
            for row in installed
            for value in [row["cwd"], *row.get("argv", [])]
            for match in re.findall(r"\$\{([A-Z0-9_]+)\}", value)
        }
        self.assertIn("HONEY_DEMOS_SHA256", variables)
        self.assertIn("HONEY_RUNTIME_SHA256", variables)
        self.assertIn("HONEY_PYTHON_WHEEL_SHA256", variables)
        self.assertIn("HONEY_CLAUDE_PLUGIN_SHA256", variables)

    def test_output_is_create_new_and_cannot_be_replaced(self) -> None:
        arguments = self.arguments("quickstart", "docs/quickstart.json")
        with mock.patch.object(
            qualifier, "verify_package", return_value=self.authority()
        ):
            self.assertEqual(qualifier.main(arguments), 0)
            with self.assertRaisesRegex(qualifier.EvidenceWorkspaceError, "overwrite"):
                qualifier.main(arguments)

    def test_required_support_set_and_independent_digests_fail_closed(self) -> None:
        missing_wheel = qualifier.parse_arguments(
            self.arguments("handoff", "docs/handoff.json")[:-4]
            + [
                "--evidence-dir",
                str(self.base / "other-evidence"),
                "--output",
                "docs/handoff.json",
            ]
        )
        with self.assertRaisesRegex(
            qualifier.HoneyDocsQualificationError, "exact supporting artifact set"
        ):
            qualifier._validate_selection(missing_wheel)

        mismatch = self.arguments("quickstart", "docs/mismatch.json")
        digest_index = mismatch.index("--runtime-sha256") + 1
        mismatch[digest_index] = "0" * 64
        with (
            mock.patch.object(
                qualifier, "verify_package", return_value=self.authority()
            ),
            self.assertRaisesRegex(
                qualifier.HoneyDocsQualificationError, "do not match"
            ),
        ):
            qualifier.main(mismatch)

    def test_secure_staging_rejects_symlink_and_archive_links(self) -> None:
        linked = self.base / "runtime-link.tar.gz"
        linked.symlink_to(self.runtime)
        with self.assertRaises(qualifier.HoneyDocsQualificationError):
            qualifier._stage_artifact(
                linked,
                self.base / "staged-runtime",
                self.digest(self.runtime),
                "runtime",
            )

        linked_archive = self.base / "linked-demos.tar.gz"
        with tarfile.open(linked_archive, "w:gz") as archive:
            member = tarfile.TarInfo("demos/run_honey.py")
            member.type = tarfile.SYMTYPE
            member.linkname = "../outside"
            archive.addfile(member)
        with self.assertRaisesRegex(
            qualifier.HoneyDocsQualificationError, "link or special"
        ):
            qualifier._extract_demos(linked_archive, self.base / "linked-output")

    def test_zero_exit_without_repeated_no_egress_evidence_is_rejected(self) -> None:
        broken = FAKE_RUNNER.replace('"darwin-loopback-only-v1"', '"unavailable"')
        self._write_demo_archive(self.demos, broken)
        with (
            mock.patch.object(
                qualifier, "verify_package", return_value=self.authority()
            ),
            self.assertRaisesRegex(
                qualifier.HoneyDocsQualificationError,
                "lacks repeated no-egress evidence",
            ),
        ):
            qualifier.main(self.arguments("quickstart", "docs/broken.json"))


if __name__ == "__main__":
    unittest.main()
