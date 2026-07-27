from __future__ import annotations

import copy
import math
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement import canonical, config
from tools.refinement.ledger import Ledger, LedgerError
from tools.refinement.schema import SchemaError, SchemaRegistry

SCHEMAS = ROOT / "schemas/refinement"
MH = "1220" + "1" * 64
MH2 = "1220" + "2" * 64
GIT = "a" * 40
TREE = "b" * 40


def source() -> dict[str, str]:
    return {"revision": GIT, "tree": TREE}


def task() -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-task.v1",
        "task_id": "task-1",
        "task_lineage_id": "lineage-1",
        "stratum": "Needle-and-Distractor",
        "sub_strata": ["symbol-lookup"],
        "source": {
            "repository_id": "repo-1",
            "immutable_revision": GIT,
            "archive_digest": MH,
            "license": "Apache-2.0",
            "setup_digest": MH2,
        },
        "contract": {
            "operation_class": "code-change",
            "purpose": "benchmark",
            "allowed_projects": ["project-a"],
            "prohibited_projects": ["project-b"],
            "target_profile": "balanced.v1",
            "token_budget": 10000,
            "output_budget": 2000,
        },
        "prompt_reference": "prompts/task-1.md",
        "oracle": {
            "critical_evidence": [
                {
                    "evidence_id": "evidence-1",
                    "version_or_span": "src/lib.rs:1",
                    "weight": 2,
                }
            ],
            "relevant_evidence": ["evidence-1"],
            "prohibited_evidence": ["secret-1"],
            "required_claims": [
                {
                    "claim_id": "claim-1",
                    "description": "The answer identifies the required symbol.",
                    "evidence_ids": ["evidence-1"],
                    "weight": 1,
                }
            ],
            "accepted_answers_or_properties": ["tests pass"],
            "expected_artifacts": ["src/lib.rs"],
            "deterministic_verifier": "verifiers/task-1.py",
            "allowed_abstention": False,
            "harm_conditions": ["Must not reveal project-b."],
        },
        "execution": {
            "permitted_tools": ["read", "test"],
            "network_policy": "none",
            "timeout_seconds": 600,
            "maximum_effects": 0,
        },
        "contamination": {
            "canary_ids": ["canary-1"],
            "public_visibility": "development",
        },
    }


def task_packet() -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-task-packet.v1",
        "packet_id": MH,
        "champion": source(),
        "architecture_summary": "Retrieval feeds the deterministic compiler.",
        "failure_cluster": "Exact symbols rank below distractors.",
        "hypothesis": "Populate authorized exact features.",
        "constraints": ["No denied content may affect scores."],
        "allowed_paths": ["crates/cigar-retrieval/src/index.rs"],
        "forbidden_paths": ["schemas/vectors/canonical-v1.json"],
        "budgets": {
            "files": 4,
            "lines": 300,
            "turns": 20,
            "input_tokens": 100000,
            "output_tokens": 20000,
            "wall_seconds": 1800,
            "cost_usd": 2.5,
        },
        "named_gates": ["retrieval-tests"],
        "public_examples": ["needle-1"],
        "prior_rejections": ["Boolean scoring did not improve precision."],
        "required_final_schema": "schemas/refinement/model-action-v1.schema.json",
    }


def model_action() -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-model-action.v1",
        "action_id": "action-1",
        "session_id": "session-1",
        "kind": "read",
        "query": None,
        "path": "crates/cigar-retrieval/src/index.rs",
        "start_line": 1,
        "max_lines": 200,
        "patch": None,
        "gate": None,
        "resource": None,
        "summary": None,
        "reason": None,
    }


def trial() -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-trial.v1",
        "trial_id": "trial-1",
        "iteration_id": "iteration-1",
        "status": "created",
        "champion": source(),
        "candidate": None,
        "hypothesis": "Populate authorized exact features.",
        "adapter": "recorded-proposal-v1",
        "model": "deterministic-recorded-v1",
        "prompt_digest": MH,
        "allowed_paths": ["crates/cigar-retrieval/src/index.rs"],
        "budgets": {
            "files": 4,
            "lines": 300,
            "turns": 20,
            "wall_seconds": 1800,
            "cost_usd": 2.5,
        },
        "patch_digest": None,
        "completed_gates": [],
        "evidence_class": "development",
        "decision_id": None,
    }


def observation() -> dict[str, object]:
    return {
        "schema_version": "cigar.benchmark-observation.v2",
        "observation_id": MH,
        "run_id": "run-1",
        "pair_id": "pair-1",
        "task_id": "task-1",
        "treatment": "candidate",
        "source": source(),
        "pins": {
            "catalog": MH,
            "graph": MH,
            "index": MH,
            "policy": MH,
            "planner": MH,
            "compiler": MH,
            "tokenizer": MH,
            "materializer": MH,
            "consumer": MH,
            "model": "deterministic-recorded-v1",
            "prompt": MH,
        },
        "selected_blocks": [
            {
                "block_id": "block-1",
                "lane": "evidence",
                "representation": "source",
                "provenance_ids": ["provenance-1"],
                "tokens": 50,
                "rank": 1,
            }
        ],
        "dispositions": [{"candidate_id": "candidate-1", "reason": "selected"}],
        "input_digest": MH,
        "output_digest": MH2,
        "tool_observations": [
            {
                "tool": "test",
                "request_digest": MH,
                "response_digest": MH2,
                "exit_code": 0,
            }
        ],
        "resources": {
            "physical_input_tokens": 50,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "output_tokens": 20,
            "latency_ms": 10.0,
            "cpu_ms": 8.0,
            "peak_rss_bytes": 1000000,
            "cost_usd": 0.01,
        },
        "effect_replay": {"effects": 0, "unsafe_retries": 0, "replay_dispatches": 0},
        "status": "completed",
    }


def evaluation() -> dict[str, object]:
    return {
        "schema_version": "cigar.benchmark-evaluation.v2",
        "evaluation_id": MH,
        "observation_id": MH2,
        "task_id": "task-1",
        "oracle_digest": MH,
        "evaluator_digest": MH2,
        "status": "valid",
        "metrics": [
            {
                "name": "verified_success",
                "numerator": 1,
                "denominator": 1,
                "value": 1,
                "unit": "boolean",
            }
        ],
        "violations": [],
        "attestation": {"key_id": "evaluator-1", "mac": "3" * 64},
    }


def comparison() -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-comparison.v1",
        "comparison_id": MH,
        "champion_source": source(),
        "candidate_source": source(),
        "dataset_epoch": MH,
        "policy_digest": MH2,
        "bootstrap_repetitions": 10000,
        "assignment_seeds": 2,
        "holm_correction": True,
        "metrics": [
            {
                "name": "verified_success",
                "champion": 0.8,
                "candidate": 0.9,
                "delta": 0.1,
                "lower": 0.02,
                "upper": 0.18,
                "confidence_percent": 99,
                "decision": "improved",
            }
        ],
        "protected_strata": [{"stratum": "PolicyBoundary", "status": "passed"}],
        "verdict": "eligible",
    }


def decision() -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-decision.v1",
        "decision_id": MH,
        "trial_id": "trial-1",
        "comparison_id": MH2,
        "champion_source": source(),
        "candidate_source": source(),
        "policy_digest": MH,
        "decision": "promote",
        "reasons": ["Meaningful paired improvement without regression."],
        "passed_gates": ["G0", "G1"],
        "failed_gates": [],
        "human_review": {
            "reviewer_id": "reviewer-1",
            "approval_digest": MH2,
        },
    }


def ledger_entry() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "cigar.refinement-ledger-entry.v1",
        "entry_id": "",
        "sequence": 0,
        "previous_entry_id": None,
        "event_type": "baseline_captured",
        "iteration_id": "iteration-0",
        "source_revision": GIT,
        "source_tree": TREE,
        "artifact_ids": [MH],
        "evidence_class": "diagnostic",
        "decision": None,
    }
    unsigned = dict(value)
    unsigned.pop("entry_id")
    value["entry_id"] = canonical.identity(unsigned)
    return value


SAMPLES = {
    "task-v1.schema.json": task,
    "task-packet-v1.schema.json": task_packet,
    "model-action-v1.schema.json": model_action,
    "trial-v1.schema.json": trial,
    "observation-v2.schema.json": observation,
    "evaluation-v2.schema.json": evaluation,
    "comparison-v1.schema.json": comparison,
    "decision-v1.schema.json": decision,
    "ledger-v1.schema.json": ledger_entry,
}


class SchemaContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = SchemaRegistry(SCHEMAS)

    def test_every_required_schema_accepts_a_complete_positive_record(self) -> None:
        self.assertEqual(len(SAMPLES), 9)
        for filename, factory in SAMPLES.items():
            with self.subTest(schema=filename):
                self.registry.validate(filename, factory())

    def test_every_positive_record_is_maximal_at_the_contract_boundary(self) -> None:
        for filename, factory in SAMPLES.items():
            with self.subTest(schema=filename):
                schema = self.registry.load(filename)
                self.assertEqual(set(factory()), set(schema["properties"]))

    def test_every_required_schema_rejects_deleted_and_unknown_fields(self) -> None:
        for filename, factory in SAMPLES.items():
            with self.subTest(schema=filename, mutation="deleted"):
                value = factory()
                value.pop("schema_version")
                with self.assertRaises(SchemaError):
                    self.registry.validate(filename, value)
            with self.subTest(schema=filename, mutation="unknown"):
                value = factory()
                value["unexpected"] = True
                with self.assertRaises(SchemaError):
                    self.registry.validate(filename, value)

    def test_every_required_schema_rejects_digest_or_identity_substitution(
        self,
    ) -> None:
        mutations = {
            "task-v1.schema.json": lambda value: value["source"].__setitem__(
                "archive_digest", "bad"
            ),
            "task-packet-v1.schema.json": lambda value: value.__setitem__(
                "packet_id", "bad"
            ),
            "model-action-v1.schema.json": lambda value: value.__setitem__(
                "action_id", "../bad"
            ),
            "trial-v1.schema.json": lambda value: value.__setitem__(
                "prompt_digest", "bad"
            ),
            "observation-v2.schema.json": lambda value: value.__setitem__(
                "observation_id", "bad"
            ),
            "evaluation-v2.schema.json": lambda value: value.__setitem__(
                "evaluation_id", "bad"
            ),
            "comparison-v1.schema.json": lambda value: value.__setitem__(
                "comparison_id", "bad"
            ),
            "decision-v1.schema.json": lambda value: value.__setitem__(
                "decision_id", "bad"
            ),
            "ledger-v1.schema.json": lambda value: value.__setitem__("entry_id", "bad"),
        }
        for filename, factory in SAMPLES.items():
            with self.subTest(schema=filename):
                value = factory()
                mutations[filename](value)
                with self.assertRaises(SchemaError):
                    self.registry.validate(filename, value)

    def test_schema_audit_rejects_open_objects_and_unbounded_values(self) -> None:
        with self.assertRaisesRegex(SchemaError, "open object"):
            self.registry.audit({"type": "object", "properties": {}})
        with self.assertRaisesRegex(SchemaError, "unbounded string"):
            self.registry.audit({"type": "string"})
        with self.assertRaisesRegex(SchemaError, "unbounded array"):
            self.registry.audit({"type": "array", "items": {"type": "null"}})

    def test_schema_path_formats_reject_traversal(self) -> None:
        value = task()
        value["prompt_reference"] = "../hidden.md"
        with self.assertRaisesRegex(SchemaError, "safe relative path"):
            self.registry.validate("task-v1.schema.json", value)


class CanonicalAndConfigTests(unittest.TestCase):
    def test_canonicalization_matches_cigarbench_and_is_order_independent(self) -> None:
        left = {"b": [2, 1], "a": "é"}
        right = {"a": "é", "b": [2, 1]}
        expected = b'{"a":"\xc3\xa9","b":[2,1]}'
        self.assertEqual(canonical.canonical_bytes(left), expected)
        self.assertEqual(canonical.canonical_bytes(right), expected)
        self.assertEqual(canonical.identity(left), canonical.identity(right))

    def test_strict_json_rejects_duplicates_nonfinite_and_oversize(self) -> None:
        with self.assertRaisesRegex(canonical.CanonicalError, "duplicate"):
            canonical.loads(b'{"a":1,"a":2}')
        for payload in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}'):
            with self.assertRaises(canonical.CanonicalError):
                canonical.loads(payload)
        with self.assertRaisesRegex(canonical.CanonicalError, "byte limit"):
            canonical.loads(b'"' + b"x" * 100 + b'"', maximum_bytes=16)
        with self.assertRaises(canonical.CanonicalError):
            canonical.canonical_bytes({"bad": math.nan})

    def test_safe_paths_reject_traversal_absolute_backslash_and_controls(self) -> None:
        self.assertEqual(canonical.safe_relative_path("a/b.json"), "a/b.json")
        for value in ("../a", "/a", "a\\b", "a/./b", "a/\x01"):
            with self.subTest(value=value), self.assertRaises(canonical.CanonicalError):
                canonical.safe_relative_path(value)

    def test_all_checked_in_configs_are_closed_and_bounded(self) -> None:
        for name in (
            "default-v1.toml",
            "fast-v1.toml",
            "shadow-v1.toml",
            "promotion-v1.toml",
        ):
            with self.subTest(config=name):
                loaded = config.load(ROOT / "refinement/config" / name)
                self.assertEqual(loaded["schema_version"], config.CONFIG_VERSION)

    def test_config_rejects_unknown_interpolation_unsafe_path_and_symlink(self) -> None:
        source_path = ROOT / "refinement/config/fast-v1.toml"
        payload = source_path.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = {
                "unknown.toml": payload + "\nunknown = true\n",
                "interpolation.toml": payload.replace(
                    'model = "deterministic-recorded-v1"',
                    'model = "${MODEL}"',
                ),
                "path.toml": payload.replace(
                    'development_manifest = "refinement/corpus/development-manifest-v1.json"',
                    'development_manifest = "../hidden.json"',
                ),
            }
            for name, changed in cases.items():
                path = root / name
                path.write_text(changed, encoding="utf-8")
                with self.subTest(case=name), self.assertRaises(config.ConfigError):
                    config.load(path)
            target = root / "target.toml"
            target.write_text(payload, encoding="utf-8")
            linked = root / "linked.toml"
            linked.symlink_to(target)
            with self.assertRaises(config.ConfigError):
                config.load(linked)

    def test_secret_handle_is_named_and_resolved_only_on_explicit_request(self) -> None:
        loaded = config.load(ROOT / "refinement/config/fast-v1.toml")
        handle = loaded["proposal"]["credential_handle"]
        self.assertEqual(handle, "CIGAR_PROPOSAL_API_KEY")
        previous = os.environ.get(handle)
        os.environ[handle] = "test-secret"
        try:
            self.assertEqual(config.resolve_secret_handle(loaded), "test-secret")
        finally:
            if previous is None:
                os.environ.pop(handle, None)
            else:
                os.environ[handle] = previous


class LedgerTests(unittest.TestCase):
    def create_ledger(self, base: Path) -> Ledger:
        base = base.resolve(strict=True)
        return Ledger(
            (base / "ledger").absolute(),
            repository_root=ROOT.absolute(),
            schema_root=SCHEMAS.absolute(),
        )

    def append_two(self, ledger: Ledger) -> list[dict[str, object]]:
        first = ledger.append(
            event_type="baseline_captured",
            iteration_id="iteration-0",
            source_revision=GIT,
            source_tree=TREE,
            artifact_ids=[MH],
            evidence_class="diagnostic",
        )
        second = ledger.append(
            event_type="trial_created",
            iteration_id="iteration-1",
            source_revision=GIT,
            source_tree=TREE,
            artifact_ids=[MH2],
            evidence_class="development",
        )
        return [first, second]

    def test_append_replay_is_exact_private_create_new_and_repository_external(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            ledger = self.create_ledger(base)
            expected = self.append_two(ledger)
            self.assertEqual(ledger.replay(), expected)
            for path in sorted((base / "ledger/entries").iterdir()):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                self.assertEqual(path.stat().st_nlink, 1)
            with self.assertRaises(LedgerError):
                Ledger(
                    (ROOT / "refinement/forbidden-ledger").absolute(),
                    repository_root=ROOT.absolute(),
                    schema_root=SCHEMAS.absolute(),
                ).replay()

    def test_replay_detects_single_field_mutation_and_chain_break(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            ledger = self.create_ledger(base)
            self.append_two(ledger)
            second_path = base / "ledger/entries/00000000000000000001.json"
            original = canonical.loads(second_path.read_bytes())
            for mutation in ("content", "chain"):
                value = copy.deepcopy(original)
                if mutation == "content":
                    value["iteration_id"] = "mutated"
                else:
                    value["previous_entry_id"] = MH
                    unsigned = dict(value)
                    unsigned.pop("entry_id")
                    value["entry_id"] = canonical.identity(unsigned)
                second_path.chmod(0o600)
                second_path.write_bytes(canonical.canonical_bytes(value))
                second_path.chmod(0o400)
                with self.subTest(mutation=mutation), self.assertRaises(LedgerError):
                    ledger.replay()
                second_path.chmod(0o600)
                second_path.write_bytes(canonical.canonical_bytes(original))
                second_path.chmod(0o400)

    def test_replay_detects_every_top_level_field_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            ledger = self.create_ledger(base)
            ledger.append(
                event_type="baseline_captured",
                iteration_id="iteration-0",
                source_revision=GIT,
                source_tree=TREE,
                artifact_ids=[MH],
                evidence_class="diagnostic",
            )
            path = base / "ledger/entries/00000000000000000000.json"
            original = canonical.loads(path.read_bytes())
            replacements = {
                "schema_version": "wrong",
                "entry_id": MH2,
                "sequence": 1,
                "previous_entry_id": MH2,
                "event_type": "trial_created",
                "iteration_id": "iteration-mutated",
                "source_revision": "c" * 40,
                "source_tree": "d" * 40,
                "artifact_ids": [MH2],
                "evidence_class": "development",
                "decision": "mutated",
            }
            self.assertEqual(set(replacements), set(original))
            for field, replacement in replacements.items():
                value = copy.deepcopy(original)
                value[field] = replacement
                path.chmod(0o600)
                path.write_bytes(canonical.canonical_bytes(value))
                path.chmod(0o400)
                with self.subTest(field=field), self.assertRaises(LedgerError):
                    ledger.replay()
                path.chmod(0o600)
                path.write_bytes(canonical.canonical_bytes(original))
                path.chmod(0o400)

    def test_replay_rejects_partial_publication_extra_file_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            ledger = self.create_ledger(base)
            ledger.append(
                event_type="baseline_captured",
                iteration_id="iteration-0",
                source_revision=GIT,
                source_tree=TREE,
                artifact_ids=[MH],
                evidence_class="diagnostic",
            )
            extra = base / "ledger/entries/partial.tmp"
            extra.write_text("partial", encoding="utf-8")
            extra.chmod(0o400)
            with self.assertRaises(LedgerError):
                ledger.replay()
            extra.unlink()
            target = base / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = base / "ledger/entries/00000000000000000001.json"
            link.symlink_to(target)
            with self.assertRaises(LedgerError):
                ledger.replay()

    def test_append_rejects_digest_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self.create_ledger(Path(temporary))
            with self.assertRaises(LedgerError):
                ledger.append(
                    event_type="baseline_captured",
                    iteration_id="iteration-0",
                    source_revision=GIT,
                    source_tree=TREE,
                    artifact_ids=["bad"],
                    evidence_class="diagnostic",
                )


if __name__ == "__main__":
    unittest.main()
