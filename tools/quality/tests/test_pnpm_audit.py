from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/quality/pnpm_audit.py"
SPEC = importlib.util.spec_from_file_location("pnpm_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pnpm_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pnpm_audit)


class PnpmAuditPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = pnpm_audit.load_policy()

    def successful_report(self) -> bytes:
        return (
            json.dumps(
                {
                    "advisories": {},
                    "metadata": {
                        "vulnerabilities": {
                            "info": 0,
                            "low": 0,
                            "moderate": 0,
                            "high": 0,
                            "critical": 0,
                        },
                        **self.policy["audit"]["expected_metadata"],
                    },
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8")

    def evaluate_mutated_report(self, report: dict[str, object]) -> dict[str, object]:
        payload = (json.dumps(report, indent=2) + "\n").encode("utf-8")
        policy = copy.deepcopy(self.policy)
        policy["audit"]["expected_report"] = {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        return pnpm_audit.evaluate_result(payload, policy)

    def valid_receipt_document(self) -> dict[str, object]:
        source = pnpm_audit.source_snapshot(ROOT)
        metadata = pnpm_audit.source_metadata(self.policy, ROOT)
        projected = pnpm_audit.project_metadata(self.policy, metadata)
        node = copy.deepcopy(self.policy["host"]["node"])
        distribution = copy.deepcopy(self.policy["auditor"]["distribution"])
        command = pnpm_audit.semantic_command(self.policy, node)
        policy_payload = pnpm_audit.POLICY_PATH.read_bytes()
        return {
            "schema_version": "cigar.pnpm-production-audit-receipt.v1",
            "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policy": {
                "schema_version": self.policy["schema_version"],
                "bytes": len(policy_payload),
                "sha256": hashlib.sha256(policy_payload).hexdigest(),
            },
            "source": source,
            "source_metadata": [
                {
                    "path": relative,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                for relative, payload in sorted(metadata.items())
            ],
            "host": pnpm_audit.verify_host(self.policy),
            "node": node,
            "auditor": {
                "name": self.policy["auditor"]["name"],
                "version": self.policy["auditor"]["version"],
                "corepack_hash": self.policy["auditor"]["corepack_hash"],
                "distribution": distribution,
            },
            "runtime": {
                "algorithm": "cigar.private-staged-pnpm-runtime.v1",
                "node": node,
                "auditor_distribution": distribution,
                "private_create_new": True,
                "source_revalidated": True,
                "staged_revalidated": True,
            },
            "projection": {
                "algorithm": "cigar.pnpm-audit-metadata-projection.v1",
                "files": [
                    {
                        "path": relative,
                        "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                    for relative, payload in sorted(projected.items())
                ],
                "root_package_manager_only": True,
            },
            "command": {
                **command,
                "sha256": hashlib.sha256(
                    pnpm_audit.canonical_json_bytes(command)
                ).hexdigest(),
            },
            "process": {
                "exit_code": 0,
                "duration_seconds": 0.5,
                "timed_out": False,
                "output_overflow": False,
                "descendant_cleanup_required": False,
                "stdout_bytes": self.policy["audit"]["expected_report"]["bytes"],
                "stdout_sha256": self.policy["audit"]["expected_report"]["sha256"],
                "stderr_bytes": 0,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            },
            "result": pnpm_audit.expected_result(self.policy),
            "claims": pnpm_audit.expected_claims(source),
        }

    def test_policy_separates_build_pnpm_from_pinned_auditor(self) -> None:
        self.assertEqual(
            self.policy["project"]["package_manager"],
            {"name": "pnpm", "version": "10.34.5"},
        )
        self.assertEqual(self.policy["auditor"]["version"], "11.13.0")
        self.assertEqual(
            self.policy["audit"]["arguments"],
            ["audit", "--prod", "--audit-level", "high", "--json"],
        )
        self.assertEqual(
            self.policy["audit"]["registry"], "https://registry.npmjs.org/"
        )
        self.assertNotIn("--ignore-registry-errors", self.policy["audit"]["arguments"])
        self.assertNotIn("--ignore", self.policy["audit"]["arguments"])
        self.assertEqual(
            self.policy["host"],
            {
                "architecture": "arm64",
                "node": {
                    "bytes": 117561248,
                    "code_signing": {
                        "candidate_cdhash_full_sha256": "e89ac81c24e645fa48a2c4ca49c10c58b9db488e4cd8229ee77d866b84882275",
                        "format": "Mach-O thin (arm64)",
                        "identifier": "node",
                        "leaf_authority": "Developer ID Application: Node.js Foundation (HX7739G8FX)",
                        "team_identifier": "HX7739G8FX",
                    },
                    "sha256": "9e759d34d97af8a71b75854d20af297794611155406997f06d796b5e0f6d573b",
                    "version": "24.10.0",
                },
                "operating_system": "Darwin",
            },
        )

    def test_policy_rejects_unpinned_or_suppressing_mutations(self) -> None:
        mutations = []
        changed = copy.deepcopy(self.policy)
        changed["auditor"]["version"] = "latest"
        mutations.append(changed)
        changed = copy.deepcopy(self.policy)
        changed["audit"]["arguments"].append("--ignore-registry-errors")
        mutations.append(changed)
        changed = copy.deepcopy(self.policy)
        changed["audit"]["registry"] = "https://example.invalid/"
        mutations.append(changed)
        changed = copy.deepcopy(self.policy)
        changed["project"]["metadata_files"].append("../package.json")
        mutations.append(changed)
        changed = copy.deepcopy(self.policy)
        changed["host"]["node"]["sha256"] = "0" * 64
        mutations.append(changed)
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw).resolve(strict=True)
            for index, mutation in enumerate(mutations):
                with self.subTest(index=index):
                    path = temporary / f"policy-{index}.json"
                    path.write_text(json.dumps(mutation), encoding="utf-8")
                    with self.assertRaises(pnpm_audit.PolicyError):
                        pnpm_audit.load_policy(path)

    def test_repository_metadata_is_closed_world_and_projection_is_minimal(
        self,
    ) -> None:
        source = pnpm_audit.source_snapshot(ROOT)
        self.assertEqual(
            source["package_manifests"],
            sorted(self.policy["project"]["package_manifests"]),
        )
        payloads = pnpm_audit.source_metadata(self.policy, ROOT)
        before = dict(payloads)
        projected = pnpm_audit.project_metadata(self.policy, payloads)
        self.assertEqual(payloads, before)
        for relative in payloads:
            if relative != "package.json":
                self.assertEqual(projected[relative], payloads[relative])
        original = pnpm_audit.strict_json_bytes(payloads["package.json"], "original")
        transformed = pnpm_audit.strict_json_bytes(
            projected["package.json"], "projection"
        )
        expected = copy.deepcopy(original)
        expected["packageManager"] = "pnpm@11.13.0"
        expected["engines"]["pnpm"] = "11.13.0"
        self.assertEqual(transformed, expected)

    def test_workspace_and_lockfile_parsers_reject_expansion_or_suppression(
        self,
    ) -> None:
        workspace = (ROOT / "pnpm-workspace.yaml").read_bytes()
        lockfile = (ROOT / "pnpm-lock.yaml").read_bytes()
        self.assertEqual(
            pnpm_audit._parse_workspace_packages(workspace),
            self.policy["project"]["workspace_packages"],
        )
        self.assertEqual(
            pnpm_audit._parse_lockfile_importers(lockfile),
            self.policy["project"]["importers"],
        )
        with self.assertRaisesRegex(pnpm_audit.PolicyError, "audit suppression"):
            pnpm_audit._parse_workspace_packages(
                workspace + b"auditConfig:\n  ignoreGhsas: [GHSA-test]\n"
            )
        expanded = pnpm_audit._parse_lockfile_importers(
            lockfile.replace(
                b"\npackages:\n", b"\n  extra/package: {}\n\npackages:\n", 1
            )
        )
        self.assertEqual(
            expanded, [*self.policy["project"]["importers"], "extra/package"]
        )

    def test_result_requires_exact_zero_advisories_and_dependency_counts(self) -> None:
        result = pnpm_audit.evaluate_result(self.successful_report(), self.policy)
        self.assertEqual(result["dependencies"], 1)
        self.assertEqual(result["totalDependencies"], 1)
        self.assertEqual(result["vulnerabilities"]["high"], 0)

        report = json.loads(self.successful_report())
        report["advisories"] = {"GHSA-redacted": {"severity": "high"}}
        with self.assertRaisesRegex(pnpm_audit.PolicyError, "advisories"):
            self.evaluate_mutated_report(report)

        report = json.loads(self.successful_report())
        report["metadata"]["vulnerabilities"]["low"] = 1
        with self.assertRaisesRegex(pnpm_audit.PolicyError, "counts"):
            self.evaluate_mutated_report(report)

        report = json.loads(self.successful_report())
        report["metadata"]["dependencies"] = 2
        report["metadata"]["totalDependencies"] = 2
        with self.assertRaisesRegex(pnpm_audit.PolicyError, "dependency counts"):
            self.evaluate_mutated_report(report)

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with self.assertRaisesRegex(pnpm_audit.PolicyError, "duplicate key"):
            pnpm_audit.strict_json_bytes(
                b'{"advisories":{},"advisories":{}}', "fixture"
            )
        with self.assertRaisesRegex(pnpm_audit.PolicyError, "non-finite"):
            pnpm_audit.strict_json_bytes(b'{"value":NaN}', "fixture")

    def test_secure_reader_rejects_symlinks_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(strict=True)
            (root / "real.json").write_text("{}\n", encoding="utf-8")
            (root / "link.json").symlink_to("real.json")
            with self.assertRaises(pnpm_audit.PolicyError):
                pnpm_audit.read_secure_file(root, "link.json")
            os.link(root / "real.json", root / "hard.json")
            with self.assertRaisesRegex(pnpm_audit.PolicyError, "single-link"):
                pnpm_audit.read_secure_file(root, "hard.json")
            with self.assertRaisesRegex(pnpm_audit.PolicyError, "canonical"):
                pnpm_audit.read_secure_file(root, "../escape.json")

    def test_projection_files_are_private_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(strict=True)
            records = pnpm_audit.write_projection(
                root,
                {"package.json": b"{}\n", "nested/lock.yaml": b"locked\n"},
            )
            self.assertEqual(
                [record["path"] for record in records],
                ["nested/lock.yaml", "package.json"],
            )
            self.assertEqual(
                stat.S_IMODE((root / "package.json").lstat().st_mode), 0o600
            )
            self.assertEqual(stat.S_IMODE((root / "nested").lstat().st_mode), 0o700)
            with self.assertRaises(pnpm_audit.PolicyError):
                pnpm_audit.write_projection(root, {"package.json": b"changed\n"})

    def test_auditor_distribution_is_closed_world_and_content_bound(self) -> None:
        policy = copy.deepcopy(self.policy)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(strict=True)
            (root / "dist").mkdir(mode=0o700)
            package = {
                "name": "pnpm",
                "version": "11.13.0",
                "engines": {"node": ">=22.13"},
                "bin": {
                    "pnpm": "bin/pnpm.mjs",
                    "pnpx": "bin/pnpx.mjs",
                    "pn": "bin/pnpm.mjs",
                    "pnx": "bin/pnpx.mjs",
                },
            }
            corepack = {
                "locator": {"name": "pnpm", "reference": "11.13.0"},
                "bin": {"pnpm": "./bin/pnpm.cjs", "pnpx": "./bin/pnpx.cjs"},
                "hash": policy["auditor"]["corepack_hash"],
            }
            (root / "package.json").write_bytes(
                pnpm_audit.canonical_json_bytes(package)
            )
            (root / ".corepack").write_bytes(pnpm_audit.canonical_json_bytes(corepack))
            entrypoint = b"export const fixture = true;\n"
            (root / "dist/pnpm.mjs").write_bytes(entrypoint)
            records = []
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                payload = path.read_bytes()
                records.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
            records.sort(key=lambda item: item["path"].encode("utf-8"))
            policy["auditor"]["distribution"] = {
                "files": len(records),
                "bytes": sum(record["bytes"] for record in records),
                "manifest_sha256": hashlib.sha256(
                    pnpm_audit.canonical_json_bytes(records)
                ).hexdigest(),
            }
            policy["auditor"]["entrypoint"] = {
                "path": "dist/pnpm.mjs",
                "bytes": len(entrypoint),
                "sha256": hashlib.sha256(entrypoint).hexdigest(),
            }
            self.assertEqual(
                pnpm_audit.auditor_distribution(policy, root),
                policy["auditor"]["distribution"],
            )
            (root / "dist/pnpm.mjs").write_bytes(entrypoint + b"// changed\n")
            with self.assertRaisesRegex(pnpm_audit.PolicyError, "distribution"):
                pnpm_audit.auditor_distribution(policy, root)

    def test_node_identity_rejects_any_unreviewed_executable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            executable = Path(raw).resolve(strict=True) / "node"
            executable.write_bytes(b"unreviewed-node-fixture")
            executable.chmod(0o500)
            with self.assertRaisesRegex(pnpm_audit.PolicyError, "reviewed authority"):
                pnpm_audit.node_identity(self.policy, executable)

    def test_staged_runtime_is_create_new_private_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(strict=True)
            runtime = root / "runtime"
            node, auditor = pnpm_audit.stage_runtime(
                runtime,
                b"reviewed-node-fixture",
                {
                    ".corepack": b"{}\n",
                    "dist/pnpm.mjs": b"export {};\n",
                    "package.json": b"{}\n",
                },
            )
            try:
                self.assertEqual(stat.S_IMODE(runtime.lstat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE(node.lstat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE(auditor.lstat().st_mode), 0o500)
                self.assertEqual(
                    stat.S_IMODE((auditor / "dist/pnpm.mjs").lstat().st_mode),
                    0o400,
                )
                self.assertEqual(node.read_bytes(), b"reviewed-node-fixture")
                with self.assertRaisesRegex(pnpm_audit.PolicyError, "create-new"):
                    pnpm_audit.stage_runtime(runtime, b"changed", {})
            finally:
                pnpm_audit._thaw_staged_runtime(runtime)

    def test_receipt_verifier_rejects_every_security_relevant_tamper(self) -> None:
        valid = self.valid_receipt_document()
        mutations: list[dict[str, object]] = []

        changed = copy.deepcopy(valid)
        changed["unexpected"] = True
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["process"]["exit_code"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["process"]["stdout_sha256"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["result"]["vulnerabilities"]["high"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["claims"]["zero_known_vulnerabilities"] = False
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["command"]["arguments"] = ["audit", "--json"]
        mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["projection"]["files"][0]["bytes"] += 1
        mutations.append(changed)

        distribution = copy.deepcopy(self.policy["auditor"]["distribution"])
        node = copy.deepcopy(self.policy["host"]["node"])
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(strict=True)
            os.chmod(parent, 0o700)
            with (
                mock.patch.object(
                    pnpm_audit,
                    "auditor_distribution",
                    return_value=distribution,
                ),
                mock.patch.object(
                    pnpm_audit,
                    "node_identity",
                    return_value=(Path("/private/tmp/reviewed-node"), node),
                ),
            ):
                valid_parent = parent / "valid"
                valid_parent.mkdir(mode=0o700)
                valid_receipt = valid_parent / "receipt.json"
                pnpm_audit.publish_receipt(valid_receipt, valid, ROOT)
                pnpm_audit.verify_receipt(
                    root=ROOT,
                    policy_path=pnpm_audit.POLICY_PATH,
                    node_executable=Path("/private/tmp/not-used-node"),
                    pnpm_root=Path("/private/tmp/not-used-pnpm"),
                    receipt=valid_receipt,
                )

                for index, mutation in enumerate(mutations):
                    with self.subTest(index=index):
                        case_parent = parent / f"tamper-{index}"
                        case_parent.mkdir(mode=0o700)
                        receipt = case_parent / "receipt.json"
                        pnpm_audit.publish_receipt(receipt, mutation, ROOT)
                        with self.assertRaises(pnpm_audit.PolicyError):
                            pnpm_audit.verify_receipt(
                                root=ROOT,
                                policy_path=pnpm_audit.POLICY_PATH,
                                node_executable=Path("/private/tmp/not-used-node"),
                                pnpm_root=Path("/private/tmp/not-used-pnpm"),
                                receipt=receipt,
                            )

    def test_audit_environment_drops_ambient_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            environment = pnpm_audit.audit_environment(Path(raw), self.policy)
        self.assertEqual(
            environment["NPM_CONFIG_REGISTRY"], "https://registry.npmjs.org/"
        )
        self.assertNotIn("NODE_OPTIONS", environment)
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("NPM_CONFIG_IGNORE_REGISTRY_ERRORS", environment)
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")

    def test_bounded_runner_separates_streams_and_rejects_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = pnpm_audit.run_bounded(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    "import sys; print('{}'); print('note', file=sys.stderr)",
                ],
                cwd=root,
                env={"PATH": "/usr/bin:/bin"},
                timeout_seconds=10,
                maximum_output_bytes=1024,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["stdout"], b"{}\n")
            self.assertEqual(result["stderr"], b"note\n")
            self.assertFalse(result["descendant_cleanup_required"])

            overflow = pnpm_audit.run_bounded(
                ["/usr/bin/python3", "-I", "-B", "-c", "print('x' * 2048)"],
                cwd=root,
                env={"PATH": "/usr/bin:/bin"},
                timeout_seconds=10,
                maximum_output_bytes=128,
            )
            self.assertTrue(overflow["output_overflow"])
            self.assertLessEqual(len(overflow["stdout"]), 128)

    def test_receipt_is_external_private_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(strict=True)
            os.chmod(parent, 0o700)
            receipt = parent / "receipt.json"
            pnpm_audit.publish_receipt(receipt, {"schema_version": "fixture"}, ROOT)
            self.assertEqual(stat.S_IMODE(receipt.lstat().st_mode), 0o400)
            self.assertEqual(receipt.read_bytes(), b'{"schema_version":"fixture"}\n')
            with self.assertRaisesRegex(pnpm_audit.PolicyError, "create-new"):
                pnpm_audit.publish_receipt(receipt, {"changed": True}, ROOT)

        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(strict=True)
            os.chmod(parent, 0o755)
            with self.assertRaisesRegex(pnpm_audit.PolicyError, "0700"):
                pnpm_audit.publish_receipt(parent / "receipt.json", {}, ROOT)


if __name__ == "__main__":
    unittest.main()
