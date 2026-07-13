from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "fuzz_and_mutation", ROOT / "tools" / "quality" / "fuzz_and_mutation.py"
)
assert SPEC is not None and SPEC.loader is not None
fuzz_and_mutation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fuzz_and_mutation)
MANAGER_SPEC = importlib.util.spec_from_file_location(
    "corpus_manager_for_binding", ROOT / "tools" / "quality" / "corpus_manager.py"
)
assert MANAGER_SPEC is not None and MANAGER_SPEC.loader is not None
corpus_manager = importlib.util.module_from_spec(MANAGER_SPEC)
MANAGER_SPEC.loader.exec_module(corpus_manager)


class FuzzEvidenceTests(unittest.TestCase):
    def test_source_binding_matches_corpus_manager(self) -> None:
        self.assertEqual(
            fuzz_and_mutation.source_digest(),
            corpus_manager.qualification_source_state(),
        )
        self.assertEqual(
            fuzz_and_mutation.source_binding_identity(),
            corpus_manager.source_binding_document(),
        )

    def build_external_stage(self, base: Path) -> tuple[Path, list[str]]:
        campaign = json.loads(fuzz_and_mutation.CAMPAIGN.read_text())
        targets = campaign["targets"]
        policy = fuzz_and_mutation.load_corpus_policy(targets)
        output_root = base / "minimized"
        fuzz_and_mutation.private_mkdir(output_root, exist_ok=False)
        wrapper_directory = output_root / "cargo-wrapper"
        fuzz_and_mutation.private_mkdir(wrapper_directory, exist_ok=False)
        real_cargo = fuzz_and_mutation.shutil.which("cargo")
        self.assertIsNotNone(real_cargo)
        wrapper = wrapper_directory / "cargo"
        fuzz_and_mutation.write_private_executable(
            wrapper,
            fuzz_and_mutation.cargo_wrapper_source(
                real_cargo=real_cargo, python=fuzz_and_mutation.sys.executable
            ),
        )
        corpus_root = output_root / "corpus"
        equivalence_root = output_root / "equivalence"
        fuzz_and_mutation.private_mkdir(corpus_root, exist_ok=False)
        fuzz_and_mutation.private_mkdir(equivalence_root, exist_ok=False)
        states: dict[str, dict[str, object]] = {}
        target_reports = []
        enforcement = fuzz_and_mutation.execution_enforcement()
        preflight_directory = output_root / "preflight"
        fuzz_and_mutation.private_mkdir(preflight_directory, exist_ok=False)
        preflight_log = preflight_directory / "cargo-metadata.log"
        preflight_log.write_bytes(b"")
        preflight_log.chmod(0o600)
        for index, target in enumerate(targets):
            directory = corpus_root / target
            repeat_directory = equivalence_root / target
            fuzz_and_mutation.private_mkdir(directory, exist_ok=False)
            fuzz_and_mutation.private_mkdir(repeat_directory, exist_ok=False)
            for fixture in policy["targets"][target]["named_fixtures"]:
                source = ROOT / "fuzz" / "corpus" / target / fixture["name"]
                shutil.copyfile(source, directory / fixture["name"])
                shutil.copyfile(source, repeat_directory / fixture["name"])
            state = fuzz_and_mutation.corpus_state(directory)
            states[target] = state
            artifact_target = output_root / "artifacts" / target
            for run in ("primary", "repeat"):
                fuzz_and_mutation.private_mkdir(artifact_target / run, exist_ok=False)
            seed = policy["deterministic_minimization_seed_base"] + index
            engine = {
                "target": target,
                "exit_code": 0,
                "artifact_count": 0,
                "deterministic_seed": seed,
                "dependency_mode": "locked-offline-cargo-wrapper",
                "cargo_fuzz_invocation": fuzz_and_mutation.DIRECT_CARGO_FUZZ_MODE,
                "timed_out": False,
                "output_overflow": False,
                "descendant_cleanup_required": False,
                "execution_enforcement": enforcement,
            }
            target_reports.append(
                {
                    "target": target,
                    "output": state,
                    "repeat_output": state,
                    "engine": engine,
                    "repeat_engine": dict(engine),
                    "deterministic_equivalence_proved": True,
                }
            )
        source_binding = fuzz_and_mutation.source_binding_identity()
        report = {
            "schema_version": "cigar.fuzz-corpus-minimization.v1",
            "source_revision": source_binding["git_head"],
            "source_binding": source_binding,
            "source_working_corpus_unchanged": True,
            "all_fourteen_targets_snapshotted": True,
            "source_corpus_before": states,
            "source_corpus_after": states,
            "dependency_mode": "locked-offline-cargo-wrapper",
            "cargo_fuzz_execution": fuzz_and_mutation.cargo_fuzz_execution_record(
                wrapper, source_binding
            ),
            "execution_enforcement": enforcement,
            "metadata_preflight": {
                "exit_code": 0,
                "timed_out": False,
                "output_overflow": False,
                "descendant_cleanup_required": False,
                "execution_enforcement": enforcement,
                "private_log": {
                    "sha256": fuzz_and_mutation.sha256_file(preflight_log),
                    "size": 0,
                    "mode": "0600",
                },
            },
            "campaign": {
                "sha256": fuzz_and_mutation.sha256_file(fuzz_and_mutation.CAMPAIGN)
            },
            "policy": {
                "sha256": fuzz_and_mutation.sha256_file(fuzz_and_mutation.POLICY)
            },
            "targets": target_reports,
        }
        (output_root / "minimization-report.json").write_text(
            json.dumps(report), encoding="utf-8"
        )
        return corpus_root, targets

    def test_evidence_directory_is_required_and_must_be_external(self) -> None:
        previous = os.environ.pop("CIGAR_EVIDENCE_DIR", None)
        try:
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.evidence_dir(argparse.Namespace(evidence_dir=None))
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.evidence_dir(
                    argparse.Namespace(evidence_dir=str(ROOT / "artifacts"))
                )
        finally:
            if previous is not None:
                os.environ["CIGAR_EVIDENCE_DIR"] = previous

    def test_evidence_write_is_create_new_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            path = directory / "receipt.json"
            fuzz_and_mutation.write_evidence(path, {"status": "passed"})
            self.assertEqual(json.loads(path.read_text()), {"status": "passed"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.write_evidence(path, {"status": "replaced"})

    def test_evidence_directory_rejects_conflicting_sources(self) -> None:
        previous = os.environ.get("CIGAR_EVIDENCE_DIR")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            os.environ["CIGAR_EVIDENCE_DIR"] = str(base / "environment")
            try:
                with self.assertRaises(fuzz_and_mutation.GateFailure):
                    fuzz_and_mutation.evidence_dir(
                        argparse.Namespace(evidence_dir=str(base / "argument"))
                    )
            finally:
                if previous is None:
                    os.environ.pop("CIGAR_EVIDENCE_DIR", None)
                else:
                    os.environ["CIGAR_EVIDENCE_DIR"] = previous

    def test_private_directory_creation_and_symlink_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            nested = base / "one" / "two"
            fuzz_and_mutation.private_mkdir(nested, exist_ok=False)
            self.assertEqual((base / "one").stat().st_mode & 0o777, 0o700)
            self.assertEqual(nested.stat().st_mode & 0o777, 0o700)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.private_mkdir(link / "child", exist_ok=False)

    def test_corpus_state_rejects_nested_and_symlink_entries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            corpus = Path(raw).resolve() / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"seed")
            nested = corpus / "nested"
            nested.mkdir()
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.corpus_state(corpus)
            nested.rmdir()
            link = corpus / "link"
            link.symlink_to(corpus / "seed")
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.corpus_state(corpus)

    def test_artifact_state_rejects_deletion_and_detects_directory_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.artifact_state(base / "missing")
            artifacts = base / "artifacts"
            artifacts.mkdir(mode=0o700)
            before = fuzz_and_mutation.artifact_state(artifacts)
            artifacts.rename(base / "original-artifacts")
            artifacts.mkdir(mode=0o700)
            after = fuzz_and_mutation.artifact_state(artifacts)
            self.assertNotEqual(
                before["directory_identity"], after["directory_identity"]
            )

    def test_mutation_pass_requires_clean_process_exit(self) -> None:
        self.assertTrue(
            fuzz_and_mutation.mutation_campaign_passed({"exit_code": 0}, 100.0, 0, 0)
        )
        self.assertFalse(
            fuzz_and_mutation.mutation_campaign_passed({"exit_code": 2}, 100.0, 0, 0)
        )

    def test_combined_verifier_is_unconditionally_fail_closed(self) -> None:
        with mock.patch("builtins.print") as print_mock:
            with self.assertRaisesRegex(
                fuzz_and_mutation.GateFailure,
                "combined smoke/mutation verification is unavailable",
            ):
                fuzz_and_mutation.verify_evidence(
                    argparse.Namespace(evidence_dir="unused", corpus_dir=None)
                )
        print_mock.assert_not_called()

    def test_all_cli_is_unconditionally_fail_closed_before_execution(self) -> None:
        with mock.patch.object(
            fuzz_and_mutation.sys,
            "argv",
            [
                "fuzz_and_mutation.py",
                "all",
                "--evidence-dir",
                "/unused",
            ],
        ):
            args = fuzz_and_mutation.parse_args()
        self.assertIs(
            args.function, fuzz_and_mutation.combined_qualification_unavailable
        )
        with (
            mock.patch.object(fuzz_and_mutation, "smoke") as smoke_mock,
            mock.patch.object(fuzz_and_mutation, "mutation") as mutation_mock,
            self.assertRaisesRegex(
                fuzz_and_mutation.GateFailure,
                "combined smoke/mutation verification is unavailable",
            ),
        ):
            args.function(args)
        smoke_mock.assert_not_called()
        mutation_mock.assert_not_called()

    def test_mutation_survivor_receipt_hashes_source_text(self) -> None:
        sensitive = "replace secret_authorization_check with true"
        digests = fuzz_and_mutation.mutation_survivor_digests(
            [{"summary": "Missed", "scenario": sensitive}]
        )
        self.assertEqual(len(digests), 1)
        self.assertEqual(len(digests[0]), 64)
        self.assertNotIn(sensitive, json.dumps(digests))

    def test_actual_child_environment_does_not_inherit_secret_sentinel(self) -> None:
        sentinel = "CIGAR_TEST_SECRET_SENTINEL"
        previous = os.environ.get(sentinel)
        os.environ[sentinel] = "must-not-reach-child"
        try:
            with tempfile.TemporaryDirectory() as raw:
                base = Path(raw).resolve()
                home = base / "home"
                temporary = base / "tmp"
                home.mkdir(mode=0o700)
                temporary.mkdir(mode=0o700)
                environment = fuzz_and_mutation.sanitized_environment(
                    private_home=home,
                    private_tmp=temporary,
                )
                result = fuzz_and_mutation.run(
                    [
                        fuzz_and_mutation.sys.executable,
                        "-c",
                        f"import os; print('present' if {sentinel!r} in os.environ else 'absent')",
                    ],
                    log_path=base / "logs" / "environment.log",
                    timeout_seconds=5,
                    cwd=base,
                    env=environment,
                )
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["wall_timeout_seconds"], 5)
                self.assertEqual(result["_output"].strip(), "absent")
        finally:
            if previous is None:
                os.environ.pop(sentinel, None)
            else:
                os.environ[sentinel] = previous

    def test_external_seed_corpus_is_digest_bound_to_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            corpus_root, targets = self.build_external_stage(Path(raw).resolve())
            verification = {"targets": [{"target": target} for target in targets]}
            with mock.patch.object(
                fuzz_and_mutation,
                "verify_minimized_output",
                return_value=verification,
            ):
                path, descriptor = fuzz_and_mutation.seed_corpus_root(
                    argparse.Namespace(corpus_dir=str(corpus_root)), targets
                )
                self.assertEqual(path, corpus_root.resolve())
                self.assertEqual(descriptor["kind"], "external-minimized-corpus")
                policy = fuzz_and_mutation.load_corpus_policy(targets)
                fixture_name = policy["targets"][targets[0]]["named_fixtures"][0][
                    "name"
                ]
                substituted = corpus_root / targets[0] / fixture_name
                substituted.write_bytes(b"substituted")
                with self.assertRaises(fuzz_and_mutation.GateFailure):
                    fuzz_and_mutation.seed_corpus_root(
                        argparse.Namespace(corpus_dir=str(corpus_root)), targets
                    )

    def test_private_worker_policy_is_distinct_and_fail_closed(self) -> None:
        campaign = json.loads(fuzz_and_mutation.CAMPAIGN.read_text())
        targets = campaign["targets"]
        policy = json.loads(fuzz_and_mutation.POLICY.read_text())
        self.assertEqual(
            policy["limits"],
            {
                "maximum_files_per_target": 4096,
                "maximum_input_bytes": 1048576,
                "maximum_total_bytes_per_target": 16777216,
            },
        )
        self.assertEqual(
            policy["private_worker_limits"],
            {
                "maximum_files_per_target": 8192,
                "maximum_input_bytes": 1048576,
                "maximum_total_bytes_per_target": 33554432,
            },
        )
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            policy_path = base / "policy.json"

            def rejected(changed: dict[str, Any]) -> None:
                policy_path.write_text(json.dumps(changed), encoding="utf-8")
                with (
                    mock.patch.object(fuzz_and_mutation, "POLICY", policy_path),
                    self.assertRaises(fuzz_and_mutation.GateFailure),
                ):
                    fuzz_and_mutation.load_corpus_policy(targets)

            missing = copy.deepcopy(policy)
            missing.pop("private_worker_limits")
            rejected(missing)
            boolean = copy.deepcopy(policy)
            boolean["private_worker_limits"]["maximum_files_per_target"] = True
            rejected(boolean)
            too_small = copy.deepcopy(policy)
            too_small["private_worker_limits"]["maximum_files_per_target"] = 4095
            rejected(too_small)
            mismatched_input = copy.deepcopy(policy)
            mismatched_input["private_worker_limits"]["maximum_input_bytes"] = 1048577
            rejected(mismatched_input)

    def test_private_worker_measurement_enforces_all_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            worker = Path(raw).resolve() / "worker"
            worker.mkdir()
            (worker / "one").write_bytes(b"seed")
            limits = {
                "maximum_files_per_target": 1,
                "maximum_input_bytes": 4,
                "maximum_total_bytes_per_target": 4,
            }
            state, maximum = fuzz_and_mutation.private_worker_corpus_measurement(
                worker, limits, target="example"
            )
            self.assertEqual(state["file_count"], 1)
            self.assertEqual(maximum, 4)
            (worker / "two").write_bytes(b"")
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.private_worker_corpus_measurement(
                    worker, limits, target="example"
                )
            (worker / "two").unlink()
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.private_worker_corpus_measurement(
                    worker,
                    {**limits, "maximum_input_bytes": 3},
                    target="example",
                )
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.private_worker_corpus_measurement(
                    worker,
                    {**limits, "maximum_total_bytes_per_target": 3},
                    target="example",
                )

    def build_valid_smoke_evidence(
        self, base: Path
    ) -> tuple[Path, dict[str, Any], dict[str, Any]]:
        output = base / "evidence"
        fuzz_and_mutation.private_mkdir(output, exist_ok=False)
        log_root = output / "wp19-smoke-logs-abcdefgh"
        fuzz_and_mutation.private_mkdir(log_root, exist_ok=False)
        campaign = json.loads(fuzz_and_mutation.CAMPAIGN.read_text())
        targets = campaign["targets"]
        enforcement = {"mode": "test-no-network"}
        tracked_source = {
            "algorithm": "sha256-path-git-mode-oid-content-size-v1",
            "digest": "1" * 64,
            "file_count": 1,
            "total_bytes": 1,
        }
        candidate = {
            "schema_version": "cigar.read-only-candidate.v1",
            "git_head": "2" * 40,
            "git_tree": "3" * 40,
            "git_status": {
                "algorithm": "sha256-git-porcelain-v1-z",
                "digest": fuzz_and_mutation.sha256_bytes(b""),
                "entry_count": 0,
                "dirty": False,
            },
            "tracked_source": tracked_source,
            "root_mode": "0555",
            "tracked_files_read_only": True,
            "tracked_directories_read_only": True,
        }
        source_binding = {
            "git_head": "2" * 40,
            "qualification_source": {
                "algorithm": "sha256-path-and-content-v1",
                "digest": "4" * 64,
                "file_count": 1,
            },
        }
        seed_states = {
            target: {
                "algorithm": "sha256-path-and-content-v1",
                "digest": fuzz_and_mutation.sha256_bytes(target.encode()),
                "file_count": 2517 if target == "policy_parse_evaluate" else 1,
                "total_bytes": 2517 if target == "policy_parse_evaluate" else 1,
            }
            for target in targets
        }
        seed_descriptor = {
            "kind": "checked-in-corpus",
            "root_path_sha256": "5" * 64,
            "targets": seed_states,
        }

        def log_record(name: str, body: bytes) -> dict[str, Any]:
            path = log_root / name
            path.write_bytes(body)
            path.chmod(0o600)
            return {
                "name": name,
                "sha256": fuzz_and_mutation.sha256_bytes(body),
                "size": len(body),
                "mode": "0600",
            }

        def process_record(
            *, command: str, log_name: str, body: bytes, wall_timeout_seconds: int
        ) -> dict[str, Any]:
            return {
                "command": command,
                "started_at": "2026-01-01T00:00:10Z",
                "finished_at": "2026-01-01T00:01:10Z",
                "duration_seconds": 60.0,
                "wall_timeout_seconds": wall_timeout_seconds,
                "exit_code": 0,
                "timed_out": False,
                "output_overflow": False,
                "descendant_cleanup_required": False,
                "captured_output_bytes": len(body),
                "maximum_output_bytes": (
                    fuzz_and_mutation.MAXIMUM_SUBPROCESS_OUTPUT_BYTES
                ),
                "private_log": log_record(log_name, body),
                "execution_enforcement": enforcement,
            }

        checkout = {
            "command": "git checkout-index --all --prefix=<external-execution-source>",
            "exit_code": 0,
            "timed_out": False,
            "output_overflow": False,
            "descendant_cleanup_required": False,
            "captured_output_bytes": 0,
            "maximum_output_bytes": 1024 * 1024,
            "execution_enforcement": enforcement,
            "private_log": log_record("source-checkout.log", b""),
        }
        harness = {
            **process_record(
                command=fuzz_and_mutation.harness_check_command_record(),
                log_name="harness-check.log",
                body=b"cargo check completed\n",
                wall_timeout_seconds=900,
            ),
            "clean": True,
        }
        properties = {
            **process_record(
                command=fuzz_and_mutation.properties_command_record(),
                log_name="properties-and-loom.log",
                body=b"test result: ok. 15 passed; 0 failed\n",
                wall_timeout_seconds=1800,
            ),
            "passed_test_count": 15,
            "clean": True,
        }
        miri = {
            **process_record(
                command=fuzz_and_mutation.miri_command_record(),
                log_name="strict-miri.log",
                body=b"test result: ok. 1 passed; 0 failed\n",
                wall_timeout_seconds=1800,
            ),
            "passed_test_count": 1,
            "miri_flags": campaign["supplemental_memory_model"]["flags"],
            "clean": True,
        }
        fuzz_results = []
        for index, target in enumerate(targets):
            seed = fuzz_and_mutation.DEFAULT_SMOKE_SEED + index
            fuzz_body = (
                b"Done 123 runs in 60 seconds\nstat::number_of_executed_units: 123\n"
            )
            corpus_after = dict(seed_states[target])
            if target == "policy_parse_evaluate":
                corpus_after.update(file_count=4775, total_bytes=4775)
            fuzz_results.append(
                {
                    **process_record(
                        command=fuzz_and_mutation.fuzz_command_record(
                            target,
                            seed=seed,
                            seconds=campaign["smoke_seconds_per_target"],
                            campaign=campaign,
                        ),
                        log_name=f"fuzz-{target}.log",
                        body=fuzz_body,
                        wall_timeout_seconds=(
                            fuzz_and_mutation.smoke_fuzz_wall_timeout_seconds(
                                campaign["smoke_seconds_per_target"]
                            )
                        ),
                    ),
                    "target": target,
                    "sanitizer": "address",
                    "deterministic_seed": seed,
                    "qualification_mode": "time-threshold",
                    "requested_minimum_seconds": campaign["smoke_seconds_per_target"],
                    "requested_minimum_runs": None,
                    "observed_fuzzer_seconds": 60,
                    "observed_executed_units": 123,
                    "source_corpus": seed_states[target],
                    "corpus_before": seed_states[target],
                    "corpus_after": corpus_after,
                    "maximum_observed_input_bytes": 1,
                    "corpus_is_private_worker_copy": True,
                    "source_corpus_unchanged": True,
                    "crash_artifacts_before": 0,
                    "crash_artifacts_after": 0,
                    "artifact_directory_unchanged": True,
                    "clean": True,
                    "cargo_fuzz_invocation": fuzz_and_mutation.DIRECT_CARGO_FUZZ_MODE,
                }
            )

        build_basename = "wp19-smoke-build-abcdefgh"
        artifact_basename = "wp19-smoke-artifacts-abcdefgh"
        document = {
            "schema_version": "cigar.wp19-quality-smoke.v1",
            "content_policy": "metadata-only-no-corpus-no-subprocess-output",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:02:00Z",
            "source": source_binding["qualification_source"],
            "source_binding": source_binding,
            "campaign": {
                "path": "fuzz/campaign-v1.json",
                "sha256": fuzz_and_mutation.sha256_file(fuzz_and_mutation.CAMPAIGN),
                "target_count": len(targets),
                "smoke_seconds_per_target": campaign["smoke_seconds_per_target"],
                "minimum_clean_cpu_seconds_per_target": campaign[
                    "minimum_clean_cpu_seconds_per_target"
                ],
            },
            "seed_corpus": seed_descriptor,
            "dependency_execution": {
                "mode": "locked-offline-cargo-wrapper",
                "cargo_fuzz_execution": {},
                "source_checkout": checkout,
                "execution_source_before": (
                    fuzz_and_mutation.expected_execution_source_state(
                        tracked_source, set()
                    )
                ),
                "execution_source_after": (
                    fuzz_and_mutation.expected_execution_source_state(
                        tracked_source, set(targets)
                    )
                ),
                "read_only_candidate": candidate,
                "success_scratch_cleanup": {
                    "bindings": [
                        {
                            "kind": "tool-owned-external-smoke-build-scratch",
                            "basename": build_basename,
                            "path_sha256": fuzz_and_mutation.sha256_bytes(
                                str(output / build_basename).encode()
                            ),
                        },
                        {
                            "kind": "tool-owned-external-smoke-artifact-scratch",
                            "basename": artifact_basename,
                            "path_sha256": fuzz_and_mutation.sha256_bytes(
                                str(output / artifact_basename).encode()
                            ),
                        },
                    ],
                    "removed": True,
                },
                "build_outputs_external_to_repository": True,
                "private_directory_modes": True,
                "ambient_environment": "strict-reviewed-allowlist",
                "credentials_proxies_cloud_ci_variables_inherited": False,
                "network_enforcement": enforcement,
            },
            "toolchains": {
                "rustc": "tool",
                "cargo_nightly": "tool",
                "cargo_fuzz": "tool",
                "miri": "tool",
            },
            "platform": {
                "system": "test",
                "release": "1",
                "machine": "test",
                "python": "3",
            },
            "gates": {
                "harness_check": harness,
                "properties_and_loom": properties,
                "strict_miri": miri,
                "asan_libfuzzer": fuzz_results,
            },
            "outcome": {
                "viability_passed": True,
                "campaign_smoke_passed": True,
                "all_fourteen_targets_executed": True,
                "crash_count": 0,
                "sanitizer_failure_count": 0,
                "seven_day_equivalent_satisfied": False,
                "release_threshold_status": "not-satisfied-by-smoke",
                "required_clean_cpu_seconds_per_target": campaign[
                    "minimum_clean_cpu_seconds_per_target"
                ],
                "note": (
                    "The campaign smoke threshold is distinct from the release "
                    "accumulation. This evidence intentionally does not claim the "
                    "cumulative 604800 clean CPU-seconds required for each target."
                ),
            },
        }
        fuzz_and_mutation.write_evidence(
            output / fuzz_and_mutation.SMOKE_EVIDENCE_NAME, document
        )
        return (
            output,
            document,
            {
                "source_binding": source_binding,
                "seed_descriptor": seed_descriptor,
                "candidate": candidate,
                "enforcement": enforcement,
                "platform": document["platform"],
            },
        )

    def verify_smoke_fixture(self, output: Path, context: dict[str, Any]) -> None:
        with (
            mock.patch.object(fuzz_and_mutation, "evidence_dir", return_value=output),
            mock.patch.object(
                fuzz_and_mutation,
                "source_binding_identity",
                return_value=context["source_binding"],
            ),
            mock.patch.object(
                fuzz_and_mutation,
                "checked_in_corpus_descriptor",
                return_value=(output / "seed", context["seed_descriptor"]),
            ),
            mock.patch.object(
                fuzz_and_mutation, "tracked_index_entries", return_value=[{}]
            ),
            mock.patch.object(
                fuzz_and_mutation,
                "candidate_checkout_state",
                return_value=context["candidate"],
            ),
            mock.patch.object(
                fuzz_and_mutation,
                "recorded_cargo_fuzz_execution_is_valid",
                return_value=True,
            ),
            mock.patch.object(
                fuzz_and_mutation,
                "execution_enforcement",
                return_value=context["enforcement"],
            ),
            mock.patch.object(fuzz_and_mutation, "tool_version", return_value="tool"),
            mock.patch.object(
                fuzz_and_mutation,
                "platform_record",
                return_value=context["platform"],
            ),
            mock.patch.object(
                fuzz_and_mutation,
                "direct_cargo_fuzz_binary",
                return_value=Path("/tools/cargo-fuzz"),
            ),
        ):
            fuzz_and_mutation.verify_evidence(
                argparse.Namespace(corpus_dir=None), include_mutation=False
            )

    def rewrite_smoke_receipt(self, output: Path, document: dict[str, Any]) -> None:
        path = output / fuzz_and_mutation.SMOKE_EVIDENCE_NAME
        path.write_bytes(
            json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
        path.chmod(0o600)

    def test_smoke_verifier_accepts_bounded_private_worker_growth(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output, document, context = self.build_valid_smoke_evidence(
                Path(raw).resolve()
            )
            result = next(
                item
                for item in document["gates"]["asan_libfuzzer"]
                if item["target"] == "policy_parse_evaluate"
            )
            self.assertEqual(result["corpus_before"]["file_count"], 2517)
            self.assertEqual(result["corpus_after"]["file_count"], 4775)
            self.assertGreater(
                result["corpus_after"]["file_count"],
                json.loads(fuzz_and_mutation.POLICY.read_text())["limits"][
                    "maximum_files_per_target"
                ],
            )
            self.verify_smoke_fixture(output, context)

    def test_smoke_verifier_rejects_receipt_and_log_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output, original, context = self.build_valid_smoke_evidence(
                Path(raw).resolve()
            )
            self.verify_smoke_fixture(output, context)

            def extra_top(document: dict[str, Any]) -> None:
                document["unexpected"] = True

            def harness_exit(document: dict[str, Any]) -> None:
                document["gates"]["harness_check"]["exit_code"] = 1

            def harness_unclean(document: dict[str, Any]) -> None:
                document["gates"]["harness_check"]["clean"] = False

            def harness_extra_field(document: dict[str, Any]) -> None:
                document["gates"]["harness_check"]["unexpected"] = True

            def property_command(document: dict[str, Any]) -> None:
                document["gates"]["properties_and_loom"]["command"] = "forged"

            def miri_flags(document: dict[str, Any]) -> None:
                document["gates"]["strict_miri"]["miri_flags"] = []

            def fuzz_command(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["command"] = "forged"

            def fuzz_seed(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["deterministic_seed"] += 1

            def fuzz_seed_float(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["deterministic_seed"] = float(
                    document["gates"]["asan_libfuzzer"][0]["deterministic_seed"]
                )

            def fuzz_seconds(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["requested_minimum_seconds"] = 0

            def fuzz_seconds_float(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["requested_minimum_seconds"] = (
                    float(
                        document["gates"]["asan_libfuzzer"][0][
                            "requested_minimum_seconds"
                        ]
                    )
                )

            def fuzz_runs(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["requested_minimum_runs"] = 1

            def fuzz_wall_timeout(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["wall_timeout_seconds"] -= 1

            def fuzz_missing_field(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0].pop("sanitizer")

            def fuzz_corpus_after(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["corpus_after"] = {
                    "digest": "forged"
                }

            def worker_file_ceiling(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["corpus_after"]["file_count"] = (
                    8193
                )

            def worker_byte_ceiling(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["corpus_after"][
                    "total_bytes"
                ] = 33554433

            def worker_input_ceiling(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0][
                    "maximum_observed_input_bytes"
                ] = 1048577

            def worker_input_float(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0][
                    "maximum_observed_input_bytes"
                ] = 1.0

            def fuzz_metric(document: dict[str, Any]) -> None:
                document["gates"]["asan_libfuzzer"][0]["observed_executed_units"] = 124

            def campaign_count(document: dict[str, Any]) -> None:
                document["campaign"]["target_count"] = 13

            def campaign_count_float(document: dict[str, Any]) -> None:
                document["campaign"]["target_count"] = 14.0

            def outcome_viability(document: dict[str, Any]) -> None:
                document["outcome"]["viability_passed"] = False

            def reversed_time(document: dict[str, Any]) -> None:
                document["gates"]["harness_check"]["started_at"] = (
                    "2026-01-01T00:01:11Z"
                )

            def escaped_time(document: dict[str, Any]) -> None:
                document["gates"]["harness_check"]["started_at"] = (
                    "2025-12-31T23:59:59Z"
                )

            def noncanonical_time(document: dict[str, Any]) -> None:
                document["started_at"] = "2026-01-01 00:00:00Z"

            def excessive_duration(document: dict[str, Any]) -> None:
                document["gates"]["harness_check"]["duration_seconds"] = 901

            def bool_count(document: dict[str, Any]) -> None:
                document["outcome"]["crash_count"] = False

            def required_cpu_float(document: dict[str, Any]) -> None:
                document["outcome"]["required_clean_cpu_seconds_per_target"] = 604800.0

            def cleanup_hash(document: dict[str, Any]) -> None:
                document["dependency_execution"]["success_scratch_cleanup"]["bindings"][
                    0
                ]["path_sha256"] = "0" * 64

            mutations = [
                ("extra top field", extra_top),
                ("harness nonzero", harness_exit),
                ("harness unclean", harness_unclean),
                ("harness extra field", harness_extra_field),
                ("property command", property_command),
                ("Miri flags", miri_flags),
                ("fuzz command", fuzz_command),
                ("fuzz seed", fuzz_seed),
                ("fuzz seed float", fuzz_seed_float),
                ("fuzz seconds", fuzz_seconds),
                ("fuzz seconds float", fuzz_seconds_float),
                ("fuzz run mode", fuzz_runs),
                ("fuzz wall timeout", fuzz_wall_timeout),
                ("fuzz missing field", fuzz_missing_field),
                ("fuzz corpus after", fuzz_corpus_after),
                ("private worker file ceiling", worker_file_ceiling),
                ("private worker byte ceiling", worker_byte_ceiling),
                ("private worker input ceiling", worker_input_ceiling),
                ("private worker input float", worker_input_float),
                ("fuzz log metric", fuzz_metric),
                ("campaign count", campaign_count),
                ("campaign count float", campaign_count_float),
                ("outcome viability", outcome_viability),
                ("reversed process time", reversed_time),
                ("escaped process time", escaped_time),
                ("noncanonical receipt time", noncanonical_time),
                ("excessive duration", excessive_duration),
                ("bool counter", bool_count),
                ("required CPU float", required_cpu_float),
                ("cleanup binding", cleanup_hash),
            ]
            for label, mutate in mutations:
                with self.subTest(label=label):
                    changed = copy.deepcopy(original)
                    mutate(changed)
                    self.rewrite_smoke_receipt(output, changed)
                    with self.assertRaises(fuzz_and_mutation.GateFailure):
                        self.verify_smoke_fixture(output, context)

            self.rewrite_smoke_receipt(output, original)
            harness_log = output / "wp19-smoke-logs-abcdefgh" / "harness-check.log"
            harness_body = harness_log.read_bytes()
            harness_log.chmod(0o644)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                self.verify_smoke_fixture(output, context)
            harness_log.chmod(0o600)
            harness_log.write_bytes(harness_body + b"substituted")
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                self.verify_smoke_fixture(output, context)
            harness_log.write_bytes(harness_body)
            harness_log.chmod(0o600)
            extra_log = harness_log.parent / "extra.log"
            extra_log.write_bytes(b"")
            extra_log.chmod(0o600)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                self.verify_smoke_fixture(output, context)
            extra_log.unlink()
            backup = output.parent / "harness-backup.log"
            harness_log.rename(backup)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                self.verify_smoke_fixture(output, context)
            backup.rename(harness_log)
            harness_log.rename(backup)
            harness_log.symlink_to(backup)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                self.verify_smoke_fixture(output, context)
            harness_log.unlink()
            backup.rename(harness_log)
            self.verify_smoke_fixture(output, context)

    def test_smoke_fuzz_wall_timeout_includes_fixed_cold_build_allowance(self) -> None:
        self.assertEqual(
            fuzz_and_mutation.smoke_fuzz_wall_timeout_seconds(60),
            60 + fuzz_and_mutation.SMOKE_COLD_BUILD_ALLOWANCE_SECONDS,
        )
        self.assertEqual(fuzz_and_mutation.SMOKE_COLD_BUILD_ALLOWANCE_SECONDS, 900)
        for invalid in (0, -1, 1.0, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(fuzz_and_mutation.GateFailure):
                    fuzz_and_mutation.smoke_fuzz_wall_timeout_seconds(invalid)

    def test_private_evidence_loader_rejects_unsafe_documents(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            valid = base / "valid.json"
            fuzz_and_mutation.write_evidence(valid, {"value": 1})
            self.assertEqual(
                fuzz_and_mutation.load_private_evidence_document(valid, label="test"),
                {"value": 1},
            )
            valid.chmod(0o644)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.load_private_evidence_document(valid, label="test")
            valid.chmod(0o600)
            duplicate = base / "duplicate.json"
            duplicate.write_bytes(b'{"value":1,"value":2}\n')
            duplicate.chmod(0o600)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.load_private_evidence_document(
                    duplicate, label="test"
                )
            nonfinite = base / "nonfinite.json"
            nonfinite.write_bytes(b'{"value":NaN}\n')
            nonfinite.chmod(0o600)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.load_private_evidence_document(
                    nonfinite, label="test"
                )
            oversized = base / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(fuzz_and_mutation.MAXIMUM_EVIDENCE_DOCUMENT_BYTES + 1)
            oversized.chmod(0o600)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.load_private_evidence_document(
                    oversized, label="test"
                )
            symlink = base / "symlink.json"
            symlink.symlink_to(valid)
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.load_private_evidence_document(symlink, label="test")

    def test_cargo_fuzz_receipt_binds_deleted_wrapper_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            wrapper = base / "cargo"
            real_cargo = fuzz_and_mutation.shutil.which("cargo")
            self.assertIsNotNone(real_cargo)
            fuzz_and_mutation.write_private_executable(
                wrapper,
                fuzz_and_mutation.cargo_wrapper_source(
                    real_cargo=real_cargo,
                    python=fuzz_and_mutation.sys.executable,
                ),
            )
            binaries = {
                "cargo_fuzz": {"binding": "cargo-fuzz"},
                "nightly_cargo": {"binding": "nightly-cargo"},
                "nightly_rustc": {"binding": "nightly-rustc"},
            }
            source_binding = {"toolchain": {"binaries": binaries}}
            receipt = fuzz_and_mutation.cargo_fuzz_execution_record(
                wrapper, source_binding
            )
            self.assertTrue(
                fuzz_and_mutation.recorded_cargo_fuzz_execution_is_valid(
                    receipt,
                    source_binding,
                    expected_wrapper_path=wrapper,
                )
            )
            self.assertFalse(
                fuzz_and_mutation.recorded_cargo_fuzz_execution_is_valid(
                    receipt,
                    source_binding,
                    expected_wrapper_path=base / "substituted" / "cargo",
                )
            )


if __name__ == "__main__":
    unittest.main()
