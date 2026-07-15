from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
XTASK = ROOT / "crates" / "xtask"
if str(XTASK) not in sys.path:
    sys.path.insert(0, str(XTASK))

import command_plane_evidence as evidence  # noqa: E402


def source_binding(*, clean: bool = True) -> dict[str, object]:
    status = b"" if clean else b" M crates/example/src/lib.rs\0"
    return {
        "kind": "git",
        "revision": "1" * 40,
        "tree": "2" * 40,
        "committed": True,
        "clean": clean,
        "status_entry_count": 0 if clean else 1,
        "status_sha256": hashlib.sha256(status).hexdigest(),
    }


def coverage_feature_inventory() -> dict[str, dict[str, object]]:
    names = {
        str(collection["scope"])
        for collection in evidence.COVERAGE_COLLECTIONS
        if collection["scope"] != "workspace"
    } | set(evidence.COVERAGE_EXCLUDED_PACKAGES)
    inventory = {
        name: {"features": {}, "root": ROOT, "targets": [{"name": name}]}
        for name in names
    }
    inventory["cigar-cli"]["features"] = {
        "default": ["full"],
        "full": [],
        "beta-embedded": [],
    }
    inventory["cigar-sdk"]["features"] = {
        "default": ["embedded-daemon"],
        "embedded-daemon": [],
    }
    inventory["cigar-aws-creds"]["features"] = {
        "default": ["rustls-tls"],
        "http-credentials": [],
        "native-tls": ["http-credentials"],
        "native-tls-vendored": ["http-credentials"],
        "rustls-tls": ["http-credentials"],
    }
    inventory["cigar-rust-s3"]["features"] = {
        "default": ["sync-rustls-tls"],
        "blocking": [],
        "fail-on-err": [],
        "http-credentials": [],
        "sync": [],
        "sync-native-tls": ["sync"],
        "sync-native-tls-vendored": ["sync"],
        "sync-rustls-tls": ["sync"],
        "tags": [],
        "tokio-native-tls": ["with-tokio"],
        "tokio-rustls-tls": ["with-tokio"],
        "with-tokio": [],
    }
    inventory["cigar-store"]["features"] = {
        "migration-fault-injection": [],
        "projection-fault-injection": [],
    }
    return inventory


class CommandPlaneEvidenceTests(unittest.TestCase):
    @staticmethod
    def _native_host() -> dict[str, str]:
        return {
            "platform": "macos",
            "architecture": "arm64",
            "macos_version": "test",
        }

    def test_fixed_apple_python_39_imports_the_complete_xtask_helper_plane(
        self,
    ) -> None:
        script = """
import sys
from pathlib import Path

root = Path.cwd()
sys.path.insert(0, str(root / "crates" / "xtask"))
sys.path.insert(0, str(root / "scripts" / "release"))
sys.path.insert(0, str(root / "tools" / "quality"))
import command_plane_evidence
import native_macos_command_plane
import tool_authority
if sys.version_info[:2] != (3, 9):
    raise SystemExit(3)
print("python39-helper-plane-ok")
"""
        result = subprocess.run(
            ["/usr/bin/python3", "-B", "-c", script],
            cwd=ROOT,
            env={
                "HOME": "/var/empty",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
                "TMPDIR": "/private/tmp",
                "TZ": "UTC",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        summary = (
            f"exit={result.returncode}; stdout_bytes={len(result.stdout)}; "
            f"stdout_sha256={hashlib.sha256(result.stdout).hexdigest()}; "
            f"stderr_bytes={len(result.stderr)}; "
            f"stderr_sha256={hashlib.sha256(result.stderr).hexdigest()}"
        )
        self.assertEqual(result.returncode, 0, summary)
        self.assertEqual(result.stdout, b"python39-helper-plane-ok\n", summary)
        self.assertEqual(result.stderr, b"", summary)

    @staticmethod
    def _tool_authority(command_id: str) -> dict[str, object]:
        return {
            "command_id": command_id,
            "executions": [],
            "manifest": {"bytes": 123, "sha256": "a" * 64},
            "network_enforcement": "not-enforced",
            "review_status": "operator-reviewed",
            "tools": {name: "b" * 64 for name in evidence.ROUTE_TOOLS[command_id]},
        }

    def _publish_lint_fixture(self, parent: Path) -> tuple[dict[str, object], Path]:
        source = source_binding()
        root = parent / "evidence"
        with (
            mock.patch.object(evidence, "source_binding", return_value=source),
            mock.patch.object(
                evidence,
                "_require_native_macos_arm64",
                return_value=self._native_host(),
            ),
        ):
            evidence.publish_record(
                root=ROOT,
                evidence_directory=root,
                command_id="lint",
                expected_source=source,
                attachment_relative=None,
                started_unix_ms=time.time_ns() // 1_000_000,
                duration_ms=1,
                tool_authority=self._tool_authority("lint"),
            )
        return source, root

    def _verify_lint_fixture(
        self, source: dict[str, object], root: Path
    ) -> dict[str, object]:
        with (
            mock.patch.object(evidence, "source_binding", return_value=source),
            mock.patch.object(
                evidence,
                "_require_native_macos_arm64",
                return_value=self._native_host(),
            ),
        ):
            return evidence.verify_record(
                root=ROOT,
                evidence_directory=root,
                command_id="lint",
                expected_source=source,
                attachment_relative=None,
                tool_authority=self._tool_authority("lint"),
            )

    @staticmethod
    def _replace_read_only_json(path: Path, document: object) -> None:
        path.chmod(0o600)
        path.write_bytes(evidence.canonical_json_bytes(document))
        path.chmod(0o400)

    @staticmethod
    def _valid_native_micro_raw(
        source: dict[str, object], runtime: Path
    ) -> dict[str, object]:
        empty = hashlib.sha256(b"").hexdigest()
        version = "3.14.6"
        probe_output = f"Python {version}\n".encode()
        return {
            "schema_version": evidence.NATIVE_RAW_SCHEMA,
            "command_id": "bench-micro-verify",
            "source": source,
            "status": "passed",
            "exit_code": 0,
            "runtime": {
                "path": str(runtime),
                "bytes": runtime.stat().st_size,
                "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                "authority": "operator-reviewed-sha256",
                "limitation": "transitive-runtime-files-not-bound",
                "version": version,
                "version_probe": {
                    "exit_code": 0,
                    "stdout_bytes": len(probe_output),
                    "stdout_sha256": hashlib.sha256(probe_output).hexdigest(),
                    "stderr_bytes": 0,
                    "stderr_sha256": empty,
                    "version": version,
                },
            },
            "producer": {
                "closure": {
                    relative: {
                        "bytes": (ROOT / relative).stat().st_size,
                        "sha256": hashlib.sha256(
                            (ROOT / relative).read_bytes()
                        ).hexdigest(),
                    }
                    for relative in evidence.NATIVE_PRODUCER_CLOSURE
                }
            },
            "authority": {"bytes": 123, "sha256": "a" * 64},
            "executions": [
                {
                    "tool": "qualified performance replay",
                    "exit_code": 0,
                    "stdout": {"bytes": 0, "sha256": empty},
                    "stderr": {"bytes": 0, "sha256": empty},
                    "command_sha256": "b" * 64,
                }
            ],
            "outputs": [
                {
                    "role": "performance-comparison-report",
                    "bytes": 12,
                    "sha256": "c" * 64,
                }
            ],
            "details": {
                "platform_scope": ["macos-arm64"],
                "fuzz_executed": False,
                "soak_executed": False,
                "mutation_campaign_executed": False,
                "hundred_gib_scale_executed": False,
                "qualified_performance_replay": True,
                "physical_scale_receipt_verified": False,
            },
        }

    def test_native_raw_validator_rejects_forged_runtime_route_and_claims(self) -> None:
        source = source_binding()
        with tempfile.TemporaryDirectory(
            prefix="cigar-native-runtime-", dir="/private/tmp"
        ) as directory:
            root = Path(directory).resolve(strict=True)
            os.chmod(root, 0o700)
            runtime = root / "hostedtoolcache/python3"
            runtime.parent.mkdir(mode=0o700)
            runtime.write_bytes(b"protected runtime fixture")
            runtime.chmod(0o700)
            valid = self._valid_native_micro_raw(source, runtime)
            relative = "command-plane/bench-micro-verify.raw.json"
            evidence._validate_native_raw(valid, "bench-micro-verify", source, relative)
            mutations = [
                ("schema_version", "cigar.xtask-command-raw.v1"),
                ("status", "pass"),
                ("runtime.sha256", "d" * 64),
                ("executions.0.tool", "generic benchmark"),
                ("outputs.0.role", "unbound-report"),
                ("details.fuzz_executed", True),
            ]
            for selector, replacement in mutations:
                with self.subTest(selector=selector):
                    candidate = copy.deepcopy(valid)
                    target: object = candidate
                    parts = selector.split(".")
                    for part in parts[:-1]:
                        target = (
                            target[int(part)]
                            if isinstance(target, list)
                            else target[part]
                        )
                    if isinstance(target, list):
                        target[int(parts[-1])] = replacement
                    else:
                        target[parts[-1]] = replacement
                    with self.assertRaises(evidence.CommandPlaneError):
                        evidence._validate_native_raw(
                            candidate, "bench-micro-verify", source, relative
                        )

            extra = copy.deepcopy(valid)
            extra["unreviewed"] = True
            with self.assertRaises(evidence.CommandPlaneError):
                evidence._validate_native_raw(
                    extra, "bench-micro-verify", source, relative
                )

    def test_native_runtime_validator_rejects_named_replacement_during_hash(
        self,
    ) -> None:
        source = source_binding()
        with tempfile.TemporaryDirectory(
            prefix="cigar-native-runtime-race-", dir="/private/tmp"
        ) as directory:
            root = Path(directory).resolve(strict=True)
            os.chmod(root, 0o700)
            runtime = root / "python3"
            runtime.write_bytes(b"protected runtime fixture")
            runtime.chmod(0o700)
            raw = self._valid_native_micro_raw(source, runtime)
            replacement = root / "replacement"
            replacement.write_bytes(runtime.read_bytes())
            replacement.chmod(0o700)
            real_read = os.read
            swapped = False

            def replace_named_file(descriptor: int, maximum: int) -> bytes:
                nonlocal swapped
                payload = real_read(descriptor, maximum)
                if payload and not swapped:
                    os.replace(replacement, runtime)
                    swapped = True
                return payload

            with (
                mock.patch.object(evidence.os, "read", side_effect=replace_named_file),
                self.assertRaisesRegex(evidence.CommandPlaneError, "changed"),
            ):
                evidence._validate_native_runtime(raw["runtime"])

    def test_route_tool_binding_rejects_wrong_route_inventory_and_execution(
        self,
    ) -> None:
        valid = self._tool_authority("lint")
        self.assertEqual(evidence._reviewed_tool_authority(valid)["command_id"], "lint")

        omitted = copy.deepcopy(valid)
        omitted["tools"].pop(sorted(omitted["tools"])[0])
        with self.assertRaises(evidence.CommandPlaneError):
            evidence._reviewed_tool_authority(omitted)

        wrong_route = copy.deepcopy(valid)
        wrong_route["command_id"] = "format-check"
        with self.assertRaises(evidence.CommandPlaneError):
            evidence._reviewed_tool_authority(wrong_route)

        wrong_execution = copy.deepcopy(valid)
        wrong_execution["executions"] = [
            {
                "command_sha256": "c" * 64,
                "executable_sha256": "d" * 64,
                "exit_code": 0,
                "stderr_bytes": 0,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "stdout_bytes": 0,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "tool": "cargo",
            }
        ]
        with self.assertRaisesRegex(evidence.CommandPlaneError, "differs"):
            evidence._reviewed_tool_authority(wrong_execution)

    def test_hosted_ci_provides_distinct_external_workspaces_to_exact_routes(
        self,
    ) -> None:
        fast_ci = (ROOT / ".github/workflows/fast-ci.yml").read_text(encoding="utf-8")
        expected_fast_routes = {
            '"${evidence_parent}/fmt" fmt --check',
            '"${evidence_parent}/generate" generate --check',
            '"${evidence_parent}/test-vectors" test vectors',
            '"${evidence_parent}/lint" lint',
            '"${evidence_parent}/docs" docs --check',
        }
        for route in expected_fast_routes:
            self.assertEqual(fast_ci.count(route), 1)
        self.assertGreaterEqual(
            fast_ci.count("--evidence-dir"), len(expected_fast_routes)
        )
        self.assertIn('test ! -e "${evidence_parent}"', fast_ci)
        self.assertIn('mkdir -m 0700 "${evidence_parent}"', fast_ci)

        security = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        dependency_job = security.split("  static-security:", 1)[0]
        self.assertIn("runs-on: macos-15", dependency_job)
        self.assertIn(
            'cargo xtask --evidence-dir "${evidence_parent}/lint" lint',
            dependency_job,
        )
        self.assertIn('test ! -e "${evidence_parent}"', dependency_job)

    def test_coverage_totals_are_recomputed_from_counts(self) -> None:
        metrics = evidence._coverage_totals(
            {
                "data": [
                    {
                        "totals": {
                            "lines": {"count": 100, "covered": 85, "percent": 85.0},
                            "branches": {
                                "count": 80,
                                "covered": 60,
                                "percent": 75.0,
                            },
                            "functions": {
                                "count": 40,
                                "covered": 30,
                                "percent": 75.0,
                            },
                        }
                    }
                ]
            }
        )
        self.assertEqual(metrics["coverage.line_percent"], 85.0)
        self.assertEqual(metrics["coverage.branch_percent"], 75.0)

    def test_coverage_thresholds_come_from_release_policy(self) -> None:
        thresholds, digest = evidence._coverage_thresholds(ROOT)
        self.assertEqual(
            thresholds,
            {"line_percent": 80.0, "branch_percent": 70.0},
        )
        self.assertEqual(len(digest), 64)

    def test_coverage_plan_is_branch_enabled_offline_and_complete(self) -> None:
        commands = evidence._coverage_collection_commands(ROOT)
        identifiers = [identifier for identifier, _ in commands]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(identifiers[-1], "independent-properties")
        for identifier, command in commands:
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    command[:4],
                    [
                        "cargo",
                        f"+{evidence.COVERAGE_RUST_TOOLCHAIN}",
                        "llvm-cov",
                        "nextest",
                    ],
                )
                self.assertIn("--locked", command)
                self.assertIn("--offline", command)
                self.assertIn("--branch", command)
                self.assertIn("--no-report", command)
                self.assertIn("--all-targets", command)
                self.assertIn("-P", command)
                self.assertNotIn("--", command)
                self.assertNotIn("fuzz", command)
                self.assertNotIn("soak", command)
        workspace = dict(commands)["workspace-default"]
        exclusions = [
            workspace[index + 1]
            for index, value in enumerate(workspace)
            if value == "--exclude"
        ]
        self.assertEqual(exclusions, ["cigar-soak", "cigar-windows-ipc"])
        properties = dict(commands)["independent-properties"]
        self.assertEqual(
            properties[properties.index("--manifest-path") + 1],
            "tests/properties/Cargo.toml",
        )
        self.assertIn("--dep-coverage", properties)
        json_report = evidence._coverage_report_command(
            Path("/private/tmp/coverage.json"), "json"
        )
        lcov_report = evidence._coverage_report_command(
            Path("/private/tmp/lcov.info"), "lcov"
        )
        self.assertIn("--json", json_report)
        self.assertIn("--summary-only", json_report)
        self.assertIn("--lcov", lcov_report)

    def test_coverage_feature_plan_rejects_an_uncovered_feature(self) -> None:
        inventory = coverage_feature_inventory()
        evidence._validate_coverage_feature_plan(inventory)
        inventory["cigar-cli"]["features"]["new-shipped-feature"] = []
        with self.assertRaisesRegex(evidence.CommandPlaneError, "new-shipped-feature"):
            evidence._validate_coverage_feature_plan(inventory)

    def test_coverage_compositions_match_the_supported_lint_matrix(self) -> None:
        source = (ROOT / "crates/xtask/src/lib.rs").read_text(encoding="utf-8")
        block = source.split("const CLIPPY_PROFILES:", 1)[1].split("fn lint(", 1)[0]
        lint_profiles = set(re.findall(r'name: "([^"]+)"', block))
        coverage_profiles = {
            str(collection["id"])
            for collection in evidence.COVERAGE_COLLECTIONS
            if collection["id"] != "cigar-store-fault-injection"
        }
        self.assertEqual(coverage_profiles, lint_profiles)

    def test_coverage_environment_removes_external_execution_controls(self) -> None:
        injected = {
            name: "attacker-controlled"
            for name in evidence.COVERAGE_CONTROL_ENVIRONMENT
        }
        with mock.patch.dict(evidence.os.environ, injected, clear=False):
            environment = evidence._coverage_environment(Path("/private/tmp/coverage"))
        for name in evidence.COVERAGE_CONTROL_ENVIRONMENT:
            self.assertNotIn(name, environment)
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(
            environment["CARGO_LLVM_COV_TARGET_DIR"],
            "/private/tmp/coverage/target",
        )

    def test_mutation_environment_removes_external_execution_controls(self) -> None:
        injected = {
            name: "attacker-controlled"
            for name in evidence.MUTATION_CONTROL_ENVIRONMENT
        }
        with (
            tempfile.TemporaryDirectory(prefix="cigar-mutation-env-test-") as raw,
            mock.patch.dict(evidence.os.environ, injected, clear=False),
        ):
            temporary = Path(raw).resolve(strict=True)
            environment = evidence._mutation_environment(temporary)
            for name in evidence.MUTATION_CONTROL_ENVIRONMENT - {"CARGO_TARGET_DIR"}:
                self.assertNotIn(name, environment)
            self.assertEqual(environment["CARGO_TARGET_DIR"], str(temporary / "target"))
            self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")

    def test_security_workflow_runs_exact_native_coverage_gate(self) -> None:
        workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        coverage = workflow.split("  coverage:", 1)[1]
        self.assertIn("runs-on: macos-15", coverage)
        self.assertIn('test "$(uname -m)" = "arm64"', coverage)
        self.assertIn("cargo-nextest --version 0.9.140 --locked", coverage)
        self.assertIn("cargo-llvm-cov --version 0.8.7 --locked", coverage)
        self.assertIn("nightly-2026-07-13-aarch64-apple-darwin", coverage)
        self.assertIn("77cf889bc178ddb44d6a1c78e5a820b5abb31d8d", coverage)
        self.assertIn("59800466c5c41c444d264b1010b4d57e85a7117f", coverage)
        self.assertIn("tests/properties/Cargo.toml", coverage)
        self.assertIn("CIGAR_COVERAGE_REPORT_DIR", coverage)
        self.assertIn("test coverage --verify", coverage)
        self.assertNotIn("cargo llvm-cov --workspace --all-targets --lcov", coverage)

    def test_coverage_totals_reject_inconsistent_or_nonfinite_percentages(self) -> None:
        for percent in (84.0, float("nan"), float("inf")):
            with self.subTest(percent=percent):
                with self.assertRaises(evidence.CommandPlaneError):
                    evidence._coverage_totals(
                        {
                            "data": [
                                {
                                    "totals": {
                                        "lines": {
                                            "count": 100,
                                            "covered": 85,
                                            "percent": percent,
                                        },
                                        "branches": {
                                            "count": 10,
                                            "covered": 8,
                                            "percent": 80.0,
                                        },
                                        "functions": {
                                            "count": 10,
                                            "covered": 8,
                                            "percent": 80.0,
                                        },
                                    }
                                }
                            ]
                        }
                    )

    def test_coverage_totals_reject_zero_or_missing_branch_data(self) -> None:
        valid = {
            "data": [
                {
                    "totals": {
                        "lines": {"count": 10, "covered": 10, "percent": 100.0},
                        "branches": {"count": 1, "covered": 1, "percent": 100.0},
                        "functions": {
                            "count": 2,
                            "covered": 2,
                            "percent": 100.0,
                        },
                    }
                }
            ]
        }
        for branches in (
            None,
            {"count": 0, "covered": 0, "percent": 0.0},
        ):
            document = {"data": [{"totals": dict(valid["data"][0]["totals"])}]}
            if branches is None:
                document["data"][0]["totals"].pop("branches")
            else:
                document["data"][0]["totals"]["branches"] = branches
            with self.subTest(branches=branches):
                with self.assertRaises(evidence.CommandPlaneError):
                    evidence._coverage_totals(document)

    def test_lcov_must_have_real_branch_data_and_match_json(self) -> None:
        source = ROOT / "crates/cigar-canon/src/lib.rs"
        inventory = {
            "cigar-canon": {
                "root": ROOT / "crates/cigar-canon",
                "features": {},
                "targets": [],
            }
        }
        metrics = {
            "coverage.line_count": 1,
            "coverage.line_covered": 1,
            "coverage.branch_count": 2,
            "coverage.branch_covered": 1,
        }
        valid = (
            f"SF:{source}\n"
            "FNF:1\nFNH:1\n"
            "BRDA:1,0,0,1\nBRDA:1,0,1,-\n"
            "BRF:2\nBRH:1\nLF:1\nLH:1\nend_of_record\n"
        ).encode()
        self.assertEqual(
            evidence._validate_lcov(
                valid, root=ROOT, inventory=inventory, metrics=metrics
            )["branches"],
            2,
        )
        for invalid in (
            valid.replace(b"BRF:2\nBRH:1", b"BRF:0\nBRH:0"),
            valid.replace(b"BRF:2\nBRH:1\n", b""),
            b"",
        ):
            with self.subTest(invalid=invalid[:40]):
                with self.assertRaises(evidence.CommandPlaneError):
                    evidence._validate_lcov(
                        invalid, root=ROOT, inventory=inventory, metrics=metrics
                    )

    def test_validated_reports_publish_create_new_and_owner_read_only(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cigar-coverage-publish-test-"
        ) as parent:
            parent_path = Path(parent).resolve(strict=True)
            lcov = parent_path / "source.info"
            lcov.write_text("SF:/fixture\nBRF:1\nBRH:1\nLF:1\nLH:1\nend_of_record")
            report_directory = parent_path / "published"
            attachments = evidence._publish_coverage_reports(
                ROOT,
                report_directory,
                lcov,
                {
                    "schema_version": "cigar.coverage-report.v1",
                    "status": "passed",
                },
            )
            self.assertEqual(
                [attachment["path"] for attachment in attachments],
                ["lcov.info", "coverage-report.v1.json"],
            )
            self.assertEqual(stat.S_IMODE(report_directory.stat().st_mode), 0o700)
            for path in report_directory.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            with self.assertRaises(evidence.EvidenceWorkspaceError):
                evidence._publish_coverage_reports(
                    ROOT,
                    report_directory,
                    lcov,
                    {"schema_version": "fixture", "status": "passed"},
                )

    def test_package_threshold_is_not_hidden_by_aggregate_coverage(self) -> None:
        metrics = {"coverage.line_percent": 95.0, "coverage.branch_percent": 90.0}
        packages = [
            {
                "name": "under-tested",
                "metrics": {
                    "lines": {"percent": 79.0},
                    "branches": {"percent": 90.0},
                },
            }
        ]
        with self.assertRaisesRegex(evidence.CommandPlaneError, "under-tested lines"):
            evidence._enforce_coverage_thresholds(
                metrics,
                packages,
                {"line_percent": 80.0, "branch_percent": 70.0},
            )

    def test_source_binding_validation_rejects_dirty_count_or_digest_drift(
        self,
    ) -> None:
        clean = source_binding()
        self.assertEqual(evidence._validate_source_binding(clean), clean)
        for mutate in (
            lambda value: value.update(status_entry_count=1),
            lambda value: value.update(status_sha256="0" * 64),
            lambda value: value.update(revision="short"),
        ):
            invalid = dict(clean)
            mutate(invalid)
            with self.assertRaises(evidence.CommandPlaneError):
                evidence._validate_source_binding(invalid)

    def test_manifest_accepts_real_routes_and_rejects_unavailable_routes(self) -> None:
        coverage, digest = evidence._command_entry(ROOT, "test-coverage-verify")
        self.assertEqual(coverage["receipt"]["implemented"], True)
        self.assertEqual(len(digest), 64)
        mutation, mutation_digest = evidence._command_entry(
            ROOT, "test-mutations-verify"
        )
        self.assertEqual(mutation["receipt"]["implemented"], True)
        self.assertEqual(mutation_digest, digest)

    def test_mutation_metrics_require_full_threshold_shape(self) -> None:
        metrics = {
            "mutation.score_percent": 90.0,
            "mutation.duration_seconds": 14_400,
            "mutation.production_package_fraction": 1.0,
            "mutation.timeout_count": 0,
            "mutation.critical_viable_survivor_count": 0,
        }
        self.assertEqual(
            evidence._validate_command_metrics("test-mutations-verify", metrics),
            metrics,
        )
        for name, value in (
            ("mutation.score_percent", 89.999),
            ("mutation.duration_seconds", 14_399),
            ("mutation.production_package_fraction", 0.99),
            ("mutation.timeout_count", 1),
            ("mutation.critical_viable_survivor_count", 1),
        ):
            invalid = dict(metrics)
            invalid[name] = value
            with self.subTest(name=name), self.assertRaises(evidence.CommandPlaneError):
                evidence._validate_command_metrics("test-mutations-verify", invalid)

    def test_dirty_source_cannot_publish_a_command_receipt(self) -> None:
        dirty = source_binding(clean=False)
        with tempfile.TemporaryDirectory(prefix="cigar-xtask-dirty-test-") as parent:
            with mock.patch.object(evidence, "source_binding", return_value=dirty):
                with self.assertRaisesRegex(
                    evidence.CommandPlaneError, "fresh clean committed checkout"
                ):
                    evidence.publish_record(
                        root=ROOT,
                        evidence_directory=Path(parent).resolve(strict=True)
                        / "evidence",
                        command_id="lint",
                        expected_source=dirty,
                        attachment_relative=None,
                        started_unix_ms=time.time_ns() // 1_000_000,
                        duration_ms=1,
                        tool_authority=self._tool_authority("lint"),
                    )

    def test_protected_receipt_is_nonempty_source_bound_and_create_new(self) -> None:
        source = source_binding()
        with tempfile.TemporaryDirectory(prefix="cigar-xtask-evidence-test-") as parent:
            root = Path(parent).resolve(strict=True) / "evidence"
            with (
                mock.patch.object(evidence, "source_binding", return_value=source),
                mock.patch.object(
                    evidence,
                    "_require_native_macos_arm64",
                    return_value={
                        "platform": "macos",
                        "architecture": "arm64",
                        "macos_version": "test",
                    },
                ),
            ):
                receipt = evidence.publish_record(
                    root=ROOT,
                    evidence_directory=root,
                    command_id="lint",
                    expected_source=source,
                    attachment_relative=None,
                    started_unix_ms=time.time_ns() // 1_000_000,
                    duration_ms=1,
                    tool_authority=self._tool_authority("lint"),
                )
                self.assertEqual(receipt["status"], "passed")
                self.assertEqual(receipt["source"], source)
                self.assertFalse(receipt["release_eligible"])
                self.assertFalse(receipt["source_descriptor_bound"])
                paths = sorted(
                    path.relative_to(root).as_posix() for path in root.rglob("*.json")
                )
                self.assertEqual(
                    paths,
                    [
                        "command-plane/lint.raw.json",
                        "command-plane/lint.receipt.json",
                    ],
                )
                for path in root.rglob("*.json"):
                    self.assertGreater(path.stat().st_size, 0)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)

                with self.assertRaises(evidence.EvidenceWorkspaceError):
                    evidence.publish_record(
                        root=ROOT,
                        evidence_directory=root,
                        command_id="lint",
                        expected_source=source,
                        attachment_relative=None,
                        started_unix_ms=time.time_ns() // 1_000_000,
                        duration_ms=1,
                        tool_authority=self._tool_authority("lint"),
                    )

    def test_existing_attachment_must_be_the_only_nonempty_passing_result(self) -> None:
        source = source_binding()
        with tempfile.TemporaryDirectory(
            prefix="cigar-xtask-attachment-test-"
        ) as parent:
            root = Path(parent).resolve(strict=True) / "evidence"
            workspace = evidence.EvidenceWorkspace.create(root, repository_root=ROOT)
            try:
                workspace.write_json(
                    "quality/result.json",
                    {"schema_version": "fixture", "status": "failed", "source": source},
                )
            finally:
                workspace.close()
            with mock.patch.object(evidence, "source_binding", return_value=source):
                with self.assertRaises(evidence.CommandPlaneError):
                    evidence.publish_record(
                        root=ROOT,
                        evidence_directory=root,
                        command_id="test-compatibility",
                        expected_source=source,
                        attachment_relative="quality/result.json",
                        started_unix_ms=time.time_ns() // 1_000_000,
                        duration_ms=1,
                        tool_authority=self._tool_authority("test-compatibility"),
                    )
            self.assertFalse((root / "command-plane").exists())

    def test_existing_passing_attachment_is_bound_to_clean_revision(self) -> None:
        source = source_binding()
        with tempfile.TemporaryDirectory(prefix="cigar-xtask-bound-test-") as parent:
            root = Path(parent).resolve(strict=True) / "evidence"
            workspace = evidence.EvidenceWorkspace.create(root, repository_root=ROOT)
            try:
                workspace.write_json(
                    "quality/compatibility-matrix-result.v1.json",
                    {
                        "schema_version": "fixture",
                        "status": "passed",
                        "source": {
                            "revision": source["revision"],
                            "committed": True,
                            "clean": True,
                        },
                    },
                )
            finally:
                workspace.close()
            with (
                mock.patch.object(evidence, "source_binding", return_value=source),
                mock.patch.object(
                    evidence,
                    "_require_native_macos_arm64",
                    return_value={
                        "platform": "macos",
                        "architecture": "arm64",
                        "macos_version": "test",
                    },
                ),
            ):
                receipt = evidence.publish_record(
                    root=ROOT,
                    evidence_directory=root,
                    command_id="test-compatibility",
                    expected_source=source,
                    attachment_relative="quality/compatibility-matrix-result.v1.json",
                    started_unix_ms=time.time_ns() // 1_000_000,
                    duration_ms=1,
                    tool_authority=self._tool_authority("test-compatibility"),
                )
            self.assertEqual(
                receipt["attachments"][0]["path"],
                "quality/compatibility-matrix-result.v1.json",
            )
            self.assertTrue(
                (root / "command-plane/test-compatibility.receipt.json").is_file()
            )

    def test_post_publication_verifier_recomputes_exact_attachment_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="cigar-xtask-verify-test-") as parent:
            source, root = self._publish_lint_fixture(Path(parent).resolve(strict=True))
            receipt = self._verify_lint_fixture(source, root)
            self.assertEqual(receipt["command"]["id"], "lint")

        for mutation in ("missing", "mutable", "path-substitution"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(
                    prefix=f"cigar-xtask-{mutation}-test-"
                ) as parent,
            ):
                source, root = self._publish_lint_fixture(
                    Path(parent).resolve(strict=True)
                )
                raw_path = root / "command-plane/lint.raw.json"
                receipt_path = root / "command-plane/lint.receipt.json"
                if mutation == "missing":
                    raw_path.unlink()
                elif mutation == "mutable":
                    raw = evidence.load_json_bytes(raw_path.read_bytes(), "fixture")
                    raw["details"]["substituted"] = True
                    self._replace_read_only_json(raw_path, raw)
                else:
                    substitute = root / "command-plane/substitute.raw.json"
                    raw_path.rename(substitute)
                    receipt = evidence.load_json_bytes(
                        receipt_path.read_bytes(), "fixture"
                    )
                    payload = substitute.read_bytes()
                    receipt["attachments"] = [
                        {
                            "path": "command-plane/substitute.raw.json",
                            "bytes": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        }
                    ]
                    self._replace_read_only_json(receipt_path, receipt)
                with self.assertRaises(
                    (evidence.CommandPlaneError, evidence.EvidenceWorkspaceError)
                ):
                    self._verify_lint_fixture(source, root)

    def test_post_publication_verifier_rejects_stale_identity_status_and_metrics(
        self,
    ) -> None:
        for mutation in ("stale-sha", "prohibited-status", "synthetic-metric"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(
                    prefix=f"cigar-xtask-{mutation}-test-"
                ) as parent,
            ):
                source, root = self._publish_lint_fixture(
                    Path(parent).resolve(strict=True)
                )
                raw_path = root / "command-plane/lint.raw.json"
                receipt_path = root / "command-plane/lint.receipt.json"
                receipt = evidence.load_json_bytes(receipt_path.read_bytes(), "fixture")
                if mutation == "stale-sha":
                    receipt["source"]["revision"] = "9" * 40
                elif mutation == "prohibited-status":
                    receipt["status"] = "skipped"
                else:
                    raw = evidence.load_json_bytes(raw_path.read_bytes(), "fixture")
                    raw["metrics"] = {"synthetic.success": 1}
                    self._replace_read_only_json(raw_path, raw)
                    payload = raw_path.read_bytes()
                    receipt["metrics"] = {"synthetic.success": 1}
                    receipt["attachments"] = [
                        {
                            "path": "command-plane/lint.raw.json",
                            "bytes": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        }
                    ]
                self._replace_read_only_json(receipt_path, receipt)
                with self.assertRaises(evidence.CommandPlaneError):
                    self._verify_lint_fixture(source, root)

    def test_command_metric_verifier_rejects_nan_and_infinity(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    evidence.CommandPlaneError, "command metrics are invalid"
                ):
                    evidence._validate_command_metrics(
                        "lint", {"synthetic.success": value}
                    )

    def test_manifest_verifier_rejects_duplicate_command_id(self) -> None:
        manifest, _ = evidence._load_manifest(ROOT)
        duplicate = copy.deepcopy(manifest)
        duplicate["commands"].append(copy.deepcopy(duplicate["commands"][0]))
        duplicate["command_count"] += 1
        payload = evidence.canonical_json_bytes(duplicate)
        with mock.patch.object(Path, "read_bytes", return_value=payload):
            with self.assertRaisesRegex(
                evidence.CommandPlaneError, "duplicate command ID"
            ):
                evidence._load_manifest(ROOT)


if __name__ == "__main__":
    unittest.main()
