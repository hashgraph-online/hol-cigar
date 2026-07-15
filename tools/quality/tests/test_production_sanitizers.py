from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/quality/production_sanitizers.py"
SPEC = importlib.util.spec_from_file_location("production_sanitizers", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
production_sanitizers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production_sanitizers)


def descriptor(payload: bytes = b"") -> dict[str, object]:
    return {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def source_identity() -> dict[str, object]:
    return {
        "revision": "1" * 40,
        "inventory_count": 1,
        "tree_sha256": "2" * 64,
        "scope_clean": False,
        "scope_status": descriptor(b"scope"),
        "repository_clean": False,
        "repository_status": descriptor(b"repository"),
    }


def passing_receipt(manifest: dict[str, object]) -> dict[str, object]:
    case_results = []
    for case in manifest["cases"]:
        result = {
            key: copy.deepcopy(case[key])
            for key in (
                "id",
                "sanitizer",
                "surfaces",
                "package",
                "manifest_path",
                "test_target",
                "test_selector",
                "command",
                "environment",
                "timeout_seconds",
                "exclusions",
            )
        }
        result.update(
            {
                "status": "passed",
                "exit_code": 0,
                "timed_out": False,
                "duration_milliseconds": 1,
                "stdout": descriptor(),
                "stderr": descriptor(),
                "canary_observed": False,
                "sanitizer_diagnostic_observed": False,
                "test_harness": {
                    "selector": case["test_selector"],
                    "selected": 1,
                    "passed": 1,
                    "failed": 0,
                    "ignored": 0,
                    "measured": 0,
                    "filtered_out": 1,
                },
            }
        )
        case_results.append(result)
    source = source_identity()
    native_names = manifest["ub_equivalent"]["required_native_dependencies"]
    return {
        "schema_version": production_sanitizers.RECEIPT_SCHEMA,
        "manifest": production_sanitizers._manifest_reference(),
        "evidence_class": "development_diagnostic",
        "platform": copy.deepcopy(manifest["platform"]),
        "toolchain": {
            "cargo_configuration": {"baseline_home": "/private/tmp/cigar-test-home"}
        },
        "runtime_environment": {
            "HOME": "/private/tmp/cigar-test-home",
            "PATH": "/usr/bin:/bin",
        },
        "source_before": copy.deepcopy(source),
        "source_after": copy.deepcopy(source),
        "source_stable": True,
        "cases": case_results,
        "ub_equivalent": {
            "rust_ubsan_run": False,
            "rust_ubsan_status": "unsupported_by_rustc_on_selected_target",
            "workspace_unsafe_code_forbid": True,
            "first_party_macos_unsafe_findings": [],
            "native_c_and_ffi_asan_case_ids": copy.deepcopy(
                manifest["ub_equivalent"]["native_asan_case_ids"]
            ),
            "rust_ubsan_probe": {
                "command": [
                    "rustc",
                    f"+{production_sanitizers.RUSTUP_NAME}",
                    "-Zsanitizer=undefined",
                    "--crate-name",
                    "cigar_ubsan_capability_probe",
                    "--crate-type",
                    "bin",
                    "-o",
                    str(
                        production_sanitizers.SCRATCH_ROOT
                        / "rust-ubsan-capability-probe"
                    ),
                    "-",
                ],
                "exit_code": 1,
                "timed_out": False,
                "duration_milliseconds": 1,
                "stdin": descriptor(b"fn main() {}\n"),
                "stdout": descriptor(),
                "stderr": descriptor(b"unsupported"),
                "unsupported_diagnostic_observed": True,
            },
            "native_dependencies": [
                {"name": name, "version": "1.0.0", "source": "registry"}
                for name in native_names
            ],
            "platform_excluded_sources": [
                {
                    "path": item["path"],
                    "reason": item["reason"],
                    **descriptor((ROOT / item["path"]).read_bytes()),
                }
                for item in manifest["ub_equivalent"]["platform_excluded_sources"]
            ],
            "native_dependency_inventory_process": {
                "command": [
                    "cargo",
                    f"+{production_sanitizers.RUSTUP_NAME}",
                    "metadata",
                    "--locked",
                    "--offline",
                    "--filter-platform",
                    production_sanitizers.TARGET,
                    "--format-version",
                    "1",
                ],
                "environment": {
                    "CARGO_NET_OFFLINE": "true",
                    "CARGO_TERM_COLOR": "never",
                },
                "exit_code": 0,
                "timed_out": False,
                "duration_milliseconds": 1,
                "stdout": descriptor(b"metadata"),
                "stderr": descriptor(),
                "canary_observed": False,
            },
        },
        "claims": {
            "sanitizer_checks_passed": True,
            "release_eligible": False,
            "rust_ubsan_run": False,
            "fuzz_built_or_run": False,
            "soak_built_or_run": False,
            "test_exclusions": [],
        },
        "started_utc": "2026-07-14T00:00:00Z",
        "finished_utc": "2026-07-14T00:00:01Z",
    }


class ProductionSanitizerPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = production_sanitizers.load_manifest()

    def test_manifest_has_exact_cases_surfaces_and_no_hidden_exclusions(self) -> None:
        self.assertEqual(
            [case["id"] for case in self.manifest["cases"]],
            list(production_sanitizers.EXPECTED_CASE_IDS),
        )
        covered = {
            surface for case in self.manifest["cases"] for surface in case["surfaces"]
        }
        self.assertEqual(covered, production_sanitizers.REQUIRED_SURFACES)
        self.assertIn(".cargo/config.toml", self.manifest["source_scope"])
        self.assertEqual(self.manifest["test_exclusions"], [])
        for case in self.manifest["cases"]:
            self.assertEqual(case["exclusions"], [])
            self.assertEqual(
                case["command"][-5:],
                ["--exact", "-Z", "unstable-options", "--format", "json"],
            )
            command = "\0".join(case["command"]).lower()
            self.assertNotIn("fuzz", command)
            self.assertNotIn("soak", command)

    def test_manifest_rejects_toolchain_case_and_exclusion_substitution(self) -> None:
        mutations = []
        changed = copy.deepcopy(self.manifest)
        changed["toolchain"]["rustc_commit_hash"] = "0" * 40
        mutations.append(changed)
        changed = copy.deepcopy(self.manifest)
        changed["cases"][0]["exclusions"] = ["one-test"]
        mutations.append(changed)
        changed = copy.deepcopy(self.manifest)
        changed["cases"][0]["command"].remove("--exact")
        mutations.append(changed)
        changed = copy.deepcopy(self.manifest)
        changed["cases"][0]["command"].insert(3, "--exclude")
        mutations.append(changed)
        changed = copy.deepcopy(self.manifest)
        changed["cases"][0]["command"].insert(-5, "--skip=selected")
        mutations.append(changed)
        changed = copy.deepcopy(self.manifest)
        changed["cases"][0]["environment"]["RUSTC_BOOTSTRAP"] = "1"
        mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(production_sanitizers.QualificationError):
                production_sanitizers.validate_manifest(changed)

    def test_receipt_rejects_command_claim_source_and_ubsan_substitution(self) -> None:
        baseline = passing_receipt(self.manifest)
        production_sanitizers.validate_receipt_document(baseline, self.manifest)

        mutations = []
        changed = copy.deepcopy(baseline)
        changed["cases"][0]["command"].insert(3, "--release")
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["claims"]["fuzz_built_or_run"] = True
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["source_after"]["tree_sha256"] = "3" * 64
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["ub_equivalent"]["rust_ubsan_run"] = True
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["claims"]["release_eligible"] = True
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["cases"][0]["sanitizer_diagnostic_observed"] = True
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["cases"][0]["test_harness"]["selected"] = 0
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["ub_equivalent"]["rust_ubsan_probe"][
            "unsupported_diagnostic_observed"
        ] = False
        mutations.append(changed)
        changed = copy.deepcopy(baseline)
        changed["runtime_environment"]["HOME"] = "/private/tmp/substituted-home"
        mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(production_sanitizers.QualificationError):
                production_sanitizers.validate_receipt_document(changed, self.manifest)

    def test_exact_json_harness_rejects_zero_filtered_multiple_and_ambiguous(
        self,
    ) -> None:
        selector = "module::selected"

        def encoded(events: list[dict[str, object]]) -> bytes:
            return b"".join(
                json.dumps(event, separators=(",", ":")).encode("utf-8") + b"\n"
                for event in events
            )

        passing_events = [
            {"type": "suite", "event": "started", "test_count": 1},
            {"type": "test", "event": "started", "name": selector},
            {"type": "test", "event": "ok", "name": selector},
            {
                "type": "suite",
                "event": "ok",
                "passed": 1,
                "failed": 0,
                "ignored": 0,
                "measured": 0,
                "filtered_out": 27,
            },
        ]
        self.assertEqual(
            production_sanitizers.parse_exact_test_harness(
                encoded(passing_events), selector
            )["filtered_out"],
            27,
        )

        zero_selected = [
            {"type": "suite", "event": "started", "test_count": 0},
            {
                "type": "suite",
                "event": "ok",
                "passed": 0,
                "failed": 0,
                "ignored": 0,
                "measured": 0,
                "filtered_out": 28,
            },
        ]
        multiple_selected = copy.deepcopy(passing_events)
        multiple_selected[0]["test_count"] = 2
        ignored_selected = copy.deepcopy(passing_events)
        ignored_selected[2]["event"] = "ignored"
        ignored_selected[3]["passed"] = 0
        ignored_selected[3]["ignored"] = 1
        hostile_outputs = [
            encoded(zero_selected),
            encoded(multiple_selected),
            encoded(ignored_selected),
            encoded(passing_events) + b"not-json\n",
            encoded(passing_events).replace(
                b'"test_count":1', b'"test_count":1,"test_count":1', 1
            ),
        ]
        for output in hostile_outputs:
            with self.assertRaises(production_sanitizers.QualificationError):
                production_sanitizers.parse_exact_test_harness(output, selector)

    def test_sanitizer_diagnostics_are_rejected_independently_of_exit_status(
        self,
    ) -> None:
        for marker in (
            b"ERROR: AddressSanitizer: heap-buffer-overflow",
            b"WARNING: ThreadSanitizer: data race",
            b"SUMMARY: LeakSanitizer: detected memory leaks",
        ):
            self.assertTrue(
                production_sanitizers.sanitizer_diagnostic_observed(marker, b"")
            )
            self.assertTrue(
                production_sanitizers.sanitizer_diagnostic_observed(b"", marker)
            )
        self.assertFalse(
            production_sanitizers.sanitizer_diagnostic_observed(
                b"test result: ok", b"ordinary diagnostic"
            )
        )

    def test_development_receipt_stays_ineligible_even_for_clean_source(self) -> None:
        receipt = passing_receipt(self.manifest)
        for label in ("source_before", "source_after"):
            receipt[label]["repository_clean"] = True
            receipt[label]["repository_status"] = descriptor()
            receipt[label]["scope_clean"] = True
            receipt[label]["scope_status"] = descriptor()
        production_sanitizers.validate_receipt_document(receipt, self.manifest)
        receipt["claims"]["release_eligible"] = True
        with self.assertRaises(production_sanitizers.QualificationError):
            production_sanitizers.validate_receipt_document(receipt, self.manifest)

    def test_current_toolchain_digest_substitution_is_rejected(self) -> None:
        receipt = passing_receipt(self.manifest)
        receipt["toolchain"] = {
            "cargo_configuration": {"baseline_home": "/private/tmp/cigar-test-home"},
            "binaries": {
                "toolchain_rustc": {"path": "/pinned/rustc", **descriptor(b"rustc")}
            },
        }
        current = copy.deepcopy(receipt["toolchain"])
        production_sanitizers.validate_receipt_document(
            receipt, self.manifest, current_toolchain=current
        )
        receipt["toolchain"]["binaries"]["toolchain_rustc"]["sha256"] = "0" * 64
        with self.assertRaises(production_sanitizers.QualificationError):
            production_sanitizers.validate_receipt_document(
                receipt, self.manifest, current_toolchain=current
            )

    def test_trusted_file_reference_binds_content_and_rejects_writable_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cigar-sanitizer-file-", dir="/private/tmp"
        ) as temporary:
            path = Path(temporary) / "tool"
            path.write_bytes(b"one pinned executable")
            path.chmod(0o700)
            reference = production_sanitizers._trusted_file_reference(
                path, label="test tool", executable=True
            )
            self.assertEqual(
                reference["sha256"], hashlib.sha256(path.read_bytes()).hexdigest()
            )
            path.chmod(0o722)
            with self.assertRaises(production_sanitizers.QualificationError):
                production_sanitizers._trusted_file_reference(
                    path, label="test tool", executable=True
                )

    def test_cargo_configuration_rejects_a_second_lexical_alias(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cigar-sanitizer-cargo-", dir="/private/tmp"
        ) as temporary:
            root = Path(temporary) / "checkout"
            home = Path(temporary) / "home"
            cargo_directory = root / ".cargo"
            cargo_directory.mkdir(parents=True)
            (home / ".cargo").mkdir(parents=True)
            config = root / ".cargo/config.toml"
            config.write_text("[build]\nincremental = false\n", encoding="utf-8")
            with (
                mock.patch.object(production_sanitizers, "ROOT", root),
                mock.patch.dict(os.environ, {"HOME": str(home)}),
            ):
                authority = production_sanitizers._cargo_configuration()
                self.assertEqual(authority["baseline_home"], str(home))
                (root / ".cargo/config").symlink_to(config)
                with self.assertRaises(production_sanitizers.QualificationError):
                    production_sanitizers._cargo_configuration()
                (root / ".cargo/config").unlink()
                cargo_directory.chmod(0o777)
                with self.assertRaises(production_sanitizers.QualificationError):
                    production_sanitizers._cargo_configuration()
                cargo_directory.chmod(0o755)
                real_cargo_directory = root / "cargo-real"
                cargo_directory.rename(real_cargo_directory)
                cargo_directory.symlink_to(
                    real_cargo_directory, target_is_directory=True
                )
                with self.assertRaises(production_sanitizers.QualificationError):
                    production_sanitizers._cargo_configuration()

    def test_receipt_reader_requires_private_regular_single_link_file(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cigar-sanitizer-receipt-", dir="/private/tmp"
        ) as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            receipt = parent / "receipt.json"
            receipt.write_bytes(
                production_sanitizers.canonical_json_bytes({"ok": True})
            )
            receipt.chmod(0o600)
            self.assertEqual(
                production_sanitizers._load_receipt_document(receipt), {"ok": True}
            )
            receipt.chmod(0o644)
            with self.assertRaises(production_sanitizers.QualificationError):
                production_sanitizers._load_receipt_document(receipt)
            receipt.chmod(0o600)
            alias = parent / "alias.json"
            os.link(receipt, alias)
            with self.assertRaises(production_sanitizers.QualificationError):
                production_sanitizers._load_receipt_document(receipt)


if __name__ == "__main__":
    unittest.main()
