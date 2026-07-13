from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path


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
                self.assertEqual(result["_output"].strip(), "absent")
        finally:
            if previous is None:
                os.environ.pop(sentinel, None)
            else:
                os.environ[sentinel] = previous

    def test_external_seed_corpus_is_digest_bound_to_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            corpus_root, targets = self.build_external_stage(Path(raw).resolve())
            path, descriptor = fuzz_and_mutation.seed_corpus_root(
                argparse.Namespace(corpus_dir=str(corpus_root)), targets
            )
            self.assertEqual(path, corpus_root.resolve())
            self.assertEqual(descriptor["kind"], "external-minimized-corpus")
            policy = fuzz_and_mutation.load_corpus_policy(targets)
            fixture_name = policy["targets"][targets[0]]["named_fixtures"][0]["name"]
            substituted = corpus_root / targets[0] / fixture_name
            substituted.write_bytes(b"substituted")
            with self.assertRaises(fuzz_and_mutation.GateFailure):
                fuzz_and_mutation.seed_corpus_root(
                    argparse.Namespace(corpus_dir=str(corpus_root)), targets
                )


if __name__ == "__main__":
    unittest.main()
