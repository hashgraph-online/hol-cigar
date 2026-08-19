from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "benches/workflow-efficacy/workflow_efficacy.py"
SPEC = importlib.util.spec_from_file_location("workflow_efficacy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
workflow = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = workflow
SPEC.loader.exec_module(workflow)


class WorkflowEfficacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture, self.digest = workflow.load_fixtures()

    def observation(
        self, trial: int = 0, workflow_id: str = "solo"
    ) -> dict[str, object]:
        definition = next(
            item for item in self.fixture["workflows"] if item["id"] == workflow_id
        )
        scheduled = next(
            item
            for item in workflow.schedule(self.fixture, trial + 1)
            if item.workflow == workflow_id and item.trial == trial
        )
        return {
            "workflow": workflow_id,
            "trial": trial,
            "mode": scheduled.mode,
            "restart_point": scheduled.restart_point,
            "mutation_axis": scheduled.mutation_axis,
            "terminal_outcome": definition["terminal"]["outcome"],
            "turn_count": 3,
            "context_cycles": 3,
            "delta_count": 2,
            "materialization_count": 3,
            "revalidation_count": 1,
            "effect_count": 1,
            "checkpoint_count": 3,
            "critical_evidence_coverage": 1.0,
            "citation_resolvability_rate": 1.0,
            "bundle_roots_verified": True,
            "replay_verified": True,
            "negative_cases_passed": 9,
            "cigar_supplied_tokens": 900,
            "provider_input_tokens": 900,
            "provider_output_tokens": 200,
            "cigar_latency_ns": 100,
            "provider_latency_ns": 50,
            "fail_closed": True,
        }

    def test_registered_fixture_is_complete_and_schema_valid(self) -> None:
        self.assertEqual(len(self.fixture["workflows"]), 5)
        self.assertEqual(tuple(self.fixture["negative_cases"]), workflow.NEGATIVE_CASES)
        self.assertEqual(tuple(self.fixture["mutation_axes"]), workflow.MUTATION_AXES)
        self.assertEqual(len(self.digest), 64)
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is unavailable")
        schema = json.loads(
            (
                ROOT / "packaging/honey/schemas/honey-workflow-efficacy.v1.schema.json"
            ).read_bytes()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.fixture, schema)

    def test_historical_and_rc_schedules_cover_modes_restarts_and_mutations(
        self,
    ) -> None:
        for trials in (20, 50):
            scheduled = workflow.schedule(self.fixture, trials)
            self.assertEqual(len(scheduled), 5 * trials)
            for workflow_id in workflow.WORKFLOW_IDS:
                cohort = [item for item in scheduled if item.workflow == workflow_id]
                self.assertEqual({item.mode for item in cohort}, set(workflow.MODES))
                self.assertEqual(
                    {item.mutation_axis for item in cohort},
                    set(workflow.MUTATION_AXES),
                )
                self.assertGreaterEqual(len({item.restart_point for item in cohort}), 3)

    def test_governed_hiero_sources_match_exact_bytes(self) -> None:
        hiero = ROOT.parents[1] / "hiero-pentest"
        observed = workflow.verify_governed_sources(self.fixture, hiero)
        self.assertEqual(set(observed), set(workflow.WORKFLOW_IDS))

    def test_complete_observation_passes(self) -> None:
        self.assertEqual(
            workflow.verify_observation(self.observation(), self.fixture)[
                "fail_closed"
            ],
            True,
        )

    def test_each_workflow_and_schedule_coordinate_passes(self) -> None:
        for workflow_id in workflow.WORKFLOW_IDS:
            for trial in range(10):
                workflow.verify_observation(
                    self.observation(trial, workflow_id), self.fixture
                )

    def test_missing_delta_replay_or_negative_case_fails_closed(self) -> None:
        for field, invalid in (
            ("delta_count", 1),
            ("replay_verified", False),
            ("negative_cases_passed", 8),
        ):
            with self.subTest(field=field):
                changed = self.observation()
                changed[field] = invalid
                with self.assertRaises(workflow.WorkflowQualificationError):
                    workflow.verify_observation(changed, self.fixture)

    def test_schedule_substitution_fails_closed(self) -> None:
        changed = self.observation(1)
        changed["mode"] = "embedded"
        with self.assertRaises(workflow.WorkflowQualificationError):
            workflow.verify_observation(changed, self.fixture)

    def test_fixture_duplicate_key_and_authority_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            path.write_text('{"schema_version":"a","schema_version":"b"}')
            with self.assertRaises(workflow.WorkflowQualificationError):
                workflow.load_fixtures(path)
        changed = copy.deepcopy(self.fixture)
        changed["negative_cases"].reverse()
        with self.assertRaises(workflow.WorkflowQualificationError):
            workflow.validate_fixtures(changed)

    def test_source_digest_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.fixture)
        changed["workflows"][0]["governed_source"]["sha256"] = "0" * 64
        with self.assertRaises(workflow.WorkflowQualificationError):
            workflow.verify_governed_sources(changed, ROOT.parents[1] / "hiero-pentest")


if __name__ == "__main__":
    unittest.main()
