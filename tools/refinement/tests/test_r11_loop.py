from __future__ import annotations

# ruff: noqa: E402

import errno
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.adapters import (
    OpenAICompatibleAdapter,
    OpenAIResponsesAdapter,
    ProviderFailure,
    RecordedAdapter,
)
from tools.refinement.canonical import canonical_bytes, identity, load_file, loads
from tools.refinement.commands import CommandRegistry, CommandSpec
from tools.refinement.custody_review import prepare as prepare_custody_review
from tools.refinement.development_promotion import (
    DevelopmentPromotionError,
    prepare_development_update,
)
from tools.refinement.experiment import make_signal
from tools.refinement.ledger import Ledger, LedgerError
from tools.refinement.loop import (
    GateOnlyEvaluator,
    LoopController,
    LoopError,
    LoopFault,
    _seal_evaluation,
    _usage_request,
)
from tools.refinement.loop_state import LoopState, LoopStateError
from tools.refinement.quota import QuotaLedger
from tools.refinement.schema import SchemaRegistry
from tools.refinement.soak import SoakJournal, run_soak
from tools.refinement.trials import TrialStore
from tools.refinement.workspace import repository_identity

LIMITS = ROOT / "refinement" / "operations" / "limits-v1.json"
PATCH = """diff --git a/src/value.txt b/src/value.txt
--- a/src/value.txt
+++ b/src/value.txt
@@ -1 +1 @@
-honey
+refined
"""


def replacement_patch(value: str) -> str:
    return PATCH.replace("+refined", f"+{value}")


def outside_patch(path: str, value: str) -> str:
    return f"""diff --git a/{path} b/{path}
new file mode 100644
--- /dev/null
+++ b/{path}
@@ -0,0 +1 @@
+{value}
"""


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def action(kind: str, action_id: str, **values: object) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": "cigar.refinement-model-action.v1",
        "action_id": action_id,
        "session_id": "replaced-at-start",
        "kind": kind,
        "query": None,
        "path": None,
        "start_line": None,
        "max_lines": None,
        "patch": None,
        "gate": None,
        "resource": None,
        "summary": None,
        "reason": None,
    }
    result.update(values)
    return result


class LoopFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.repository = self.root / "repository"
        self.repository.mkdir(mode=0o700)
        git(self.repository, "init", "-b", "main")
        git(self.repository, "config", "user.name", "CIGAR Test")
        git(self.repository, "config", "user.email", "cigar@example.invalid")
        shutil.copytree(ROOT / "schemas", self.repository / "schemas")
        (self.repository / "src").mkdir()
        (self.repository / "src/value.txt").write_text("honey\n", encoding="utf-8")
        (self.repository / "refinement").mkdir()
        families = """{
  "schema_version": "cigar.refinement-intervention-families.v1",
  "families": [{
    "schema_version": "cigar.refinement-intervention-family.v1",
    "family_id": "fixture-product",
    "trial_class": "product",
    "owner_hints": ["fixture-owner"],
    "source_kinds": ["test_failure"],
    "metrics": ["correctness", "correctness-00", "correctness-01", "correctness-02", "correctness-03", "correctness-04", "correctness-05", "correctness-06", "correctness-07", "correctness-08", "correctness-09", "correctness-10", "correctness-11", "correctness-12", "correctness-13", "correctness-14", "correctness-15", "correctness-16", "correctness-17", "correctness-18", "correctness-19"],
    "allowed_paths": ["src"],
    "forbidden_paths": ["refinement", "schemas/refinement", ".github", "scripts/release", "Cargo.lock"],
    "named_gates": ["fixture-pass"],
    "base_priority": 10,
    "budgets": {"files": 1, "lines": 4, "turns": 4, "input_tokens": 1000, "output_tokens": 1000, "wall_seconds": 30, "cost_usd": 0},
    "architecture_summary": "A deterministic loop qualification fixture.",
    "intervention_template": "Correct the fixture for metric {metric}."
  }]
}
"""
        (self.repository / "refinement/families.json").write_text(
            families, encoding="utf-8"
        )
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-m", "fixture champion")
        self.champion = repository_identity(self.repository, require_clean=True)
        self.worktrees = self.root / "worktrees"
        self.commands = self.root / "commands"
        self.worktrees.mkdir(mode=0o700)
        self.commands.mkdir(mode=0o700)
        self.loop_state_root = self.root / "loop-state"
        self.trial_state_root = self.root / "trial-state"
        self.ledger_root = self.root / "ledger"
        self.quota_root = self.root / "quota"
        self.loop_state_root.mkdir(mode=0o700)
        self.trial_state_root.mkdir(mode=0o700)
        self.config = {
            "schema_version": "cigar.refinement-config.v1",
            "profile_id": "fixture-v1",
            "mode": "pr",
            "evidence": {"class": "diagnostic"},
            "limits": {
                "max_iterations": 32,
                "max_wall_seconds": 3600,
                "max_cost_usd": 10.0,
                "max_input_tokens": 100000,
                "max_output_tokens": 100000,
                "max_files_changed": 4,
                "max_lines_changed": 20,
            },
            "proposal": {
                "adapter": "recorded-proposal-v1",
                "model": "fixture",
                "credential_handle": None,
                "maximum_turns": 4,
                "maximum_repairs": 0,
            },
            "consumer": {"matrix": "unused", "primary_profile": "unused"},
            "statistics": {
                "bootstrap_repetitions": 1000,
                "confidence_percent": 95,
                "assignment_seeds": 1,
                "holm_correction": True,
            },
            "paths": {
                "development_manifest": "unused",
                "proposal_profiles": "unused",
                "intervention_families": "refinement/families.json",
                "operations_policy": "unused",
            },
        }
        self.signal = make_signal(
            source_kind="test_failure",
            visibility="public",
            summary="The harmless loop fixture has not been refined.",
            source_commitment="1220" + "4" * 64,
            owner_hint="fixture-owner",
            metric="correctness",
            magnitude=1.0,
            estimated_cost=1.0,
            strata=[],
            reproducible=True,
        )
        self.registry = CommandRegistry(
            (
                CommandSpec(
                    "fixture-pass",
                    (sys.executable, "-c", "raise SystemExit(0)"),
                    10,
                ),
            )
        )

    def factory(self, _packet: dict[str, object]) -> RecordedAdapter:
        return RecordedAdapter(
            [
                action("apply_patch", "patch", patch=PATCH),
                action("finish", "finish", summary="Fixture refined."),
            ],
            maximum_turns=4,
        )

    def controller(
        self,
        *,
        run_id: str = "fixture-run",
        mode: str = "patch",
        adapter_factory: object | None = None,
        evaluator: object | None = None,
        signals: list[dict[str, object]] | None = None,
        fault_hook: object | None = None,
        state: LoopState | None = None,
        ledger: Ledger | None = None,
        quota: QuotaLedger | None = None,
    ) -> LoopController:
        return LoopController(
            repository=self.repository,
            loaded_config=self.config,
            run_id=run_id,
            state=(
                state
                or LoopState(
                    self.loop_state_root / run_id,
                    repository_root=self.repository,
                )
            ),
            trials=TrialStore(
                self.trial_state_root / run_id,
                repository_root=self.repository,
            ),
            worktree_root=self.worktrees,
            command_state_root=self.commands,
            ledger=(
                ledger or Ledger(self.ledger_root, repository_root=self.repository)
            ),
            quota=(
                quota
                or QuotaLedger(
                    self.quota_root,
                    repository_root=self.repository,
                    policy_path=LIMITS,
                )
            ),
            utc_day="2026-07-27",
            signals=(signals if signals is not None else [self.signal]),  # type: ignore[arg-type]
            history=[],
            trial_class="product",
            adapter_profile="recorded-proposal",
            adapter_factory=(adapter_factory or self.factory),  # type: ignore[arg-type]
            evaluator=(evaluator or GateOnlyEvaluator()),  # type: ignore[arg-type]
            mode=mode,
            maximum_iterations=1,
            maximum_estimated_cost=10,
            pause_file=self.root / "pause",
            no_promotion=True,
            registry=self.registry,
            fault_hook=fault_hook,  # type: ignore[arg-type]
        )

    def close(self) -> None:
        self.temporary.cleanup()


class LoopControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = LoopFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_offline_adapters_reserve_no_provider_cost(self) -> None:
        packet = {
            "budgets": {
                "input_tokens": 240_000,
                "output_tokens": 80_000,
                "wall_seconds": 4_200,
                "cost_usd": 30,
            }
        }
        hosted = _usage_request(packet, adapter_id="openai-responses-tools-v1")
        for adapter_id in ("patch-json-v1", "recorded-proposal-v1"):
            offline = _usage_request(packet, adapter_id=adapter_id)
            self.assertEqual(offline["cost_microusd"], 0)
            self.assertEqual(
                {
                    key: value
                    for key, value in offline.items()
                    if key != "cost_microusd"
                },
                {key: value for key, value in hosted.items() if key != "cost_microusd"},
            )
        self.assertEqual(hosted["cost_microusd"], 30_000_000)

    def test_one_real_iteration_commits_candidate_without_changing_champion(
        self,
    ) -> None:
        result = self.fixture.controller().run()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["last_decision"], "nominate")
        self.assertIsNotNone(result["candidate_revision"])
        self.assertEqual(
            repository_identity(self.fixture.repository, require_clean=True),
            self.fixture.champion,
        )
        entries = Ledger(
            self.fixture.ledger_root,
            repository_root=self.fixture.repository,
        ).replay()
        self.assertEqual(entries[-1]["event_type"], "trial_nominated")
        self.assertNotEqual(
            entries[-1]["source_revision"], self.fixture.champion["revision"]
        )
        resumed = self.fixture.controller().run()
        self.assertEqual(resumed["status"], "completed")
        self.assertEqual(resumed["event_id"], result["event_id"])

    def test_early_rejection_persists_measured_adapter_usage(self) -> None:
        def denied_factory(_packet: dict[str, object]) -> RecordedAdapter:
            return RecordedAdapter(
                [
                    action(
                        "read",
                        "forbidden-read",
                        path="refinement/families.json",
                        start_line=1,
                        max_lines=10,
                    )
                ],
                maximum_turns=4,
            )

        result = self.fixture.controller(
            run_id="measured-early-rejection",
            adapter_factory=denied_factory,
        ).run()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["last_decision"], "reject_invalid")
        state = LoopState(
            self.fixture.loop_state_root / "measured-early-rejection",
            repository_root=self.fixture.repository,
        )
        terminal = state.artifact(state.replay()[-1]["artifact_ids"][0])
        rejection = state.artifact(terminal["early_rejection_id"])
        self.assertEqual(
            rejection["adapter_usage"]["adapter"],
            "recorded-proposal-v1",
        )
        self.assertEqual(rejection["adapter_usage"]["turns"], 1)
        self.assertTrue(rejection["adapter_usage"]["terminal"])
        self.assertEqual(rejection["adapter_transcript"][0]["kind"], "read")
        self.assertNotIn(
            "refinement/families.json",
            canonical_bytes(rejection).decode(),
        )

    def test_pause_and_all_required_fault_boundaries_resume(self) -> None:
        pause_fixture = LoopFixture()
        try:
            pause = pause_fixture.root / "pause"
            pause.write_text("pause\n", encoding="utf-8")
            pause.chmod(0o600)
            first = pause_fixture.controller(run_id="pause-run").run()
            self.assertEqual(first["status"], "paused")
            pause.unlink()
            second = pause_fixture.controller(run_id="pause-run").run()
            self.assertEqual(second["status"], "completed")
        finally:
            pause_fixture.close()

        scenarios: list[tuple[str, str, object]] = [
            (
                "worker-kill",
                "worker_kill",
                lambda phase, _iteration, _trial: (
                    (_ for _ in ()).throw(LoopFault("worker_kill"))
                    if phase == "proposed"
                    else None
                ),
            ),
            (
                "disk-pressure",
                "disk_pressure",
                lambda phase, _iteration, _trial: (
                    (_ for _ in ()).throw(OSError(errno.ENOSPC, "injected"))
                    if phase == "gated"
                    else None
                ),
            ),
            (
                "evidence-interruption",
                "evidence_publication_interruption",
                lambda phase, _iteration, _trial: (
                    (_ for _ in ()).throw(
                        LoopFault("evidence_publication_interruption")
                    )
                    if phase == "before_terminal"
                    else None
                ),
            ),
        ]
        for run_id, category, hook in scenarios:
            fixture = LoopFixture()
            injected = {"done": False}

            def once(
                phase: str,
                iteration: int,
                trial_id: str | None,
                *,
                selected: object = hook,
            ) -> None:
                if injected["done"]:
                    return
                try:
                    selected(phase, iteration, trial_id)  # type: ignore[operator]
                except BaseException:
                    injected["done"] = True
                    raise

            try:
                interrupted = fixture.controller(run_id=run_id, fault_hook=once).run()
                self.assertEqual(interrupted["status"], "interrupted")
                self.assertEqual(interrupted["failure_category"], category)
                resumed = fixture.controller(run_id=run_id).run()
                self.assertEqual(resumed["status"], "completed")
                self.assertEqual(
                    repository_identity(fixture.repository, require_clean=True),
                    fixture.champion,
                )
            finally:
                fixture.close()

        provider_fixture = LoopFixture()
        attempts = {"count": 0}

        class TimeoutAdapter(RecordedAdapter):
            def next(
                self,
                session_id: str,
                tool_result: dict[str, object] | None = None,
            ) -> dict[str, object]:
                raise ProviderFailure("injected provider timeout")

        def provider_factory(_packet: dict[str, object]) -> RecordedAdapter:
            attempts["count"] += 1
            actions = [
                action("apply_patch", "patch", patch=PATCH),
                action("finish", "finish", summary="Fixture refined."),
            ]
            if attempts["count"] == 1:
                return TimeoutAdapter(actions, maximum_turns=4)
            return RecordedAdapter(actions, maximum_turns=4)

        try:
            first = provider_fixture.controller(
                run_id="provider-timeout",
                adapter_factory=provider_factory,
            ).run()
            self.assertEqual(first["failure_category"], "provider_outage")
            second = provider_fixture.controller(
                run_id="provider-timeout",
                adapter_factory=provider_factory,
            ).run()
            self.assertEqual(second["status"], "completed")
            self.assertEqual(attempts["count"], 2)
        finally:
            provider_fixture.close()

    def test_suggest_patch_and_pr_modes_never_promote_or_publish(self) -> None:
        for mode in ("suggest", "patch", "pr"):
            fixture = LoopFixture()
            try:
                result = fixture.controller(run_id=f"mode-{mode}", mode=mode).run()
                self.assertEqual(result["status"], "completed")
                events = LoopState(
                    fixture.loop_state_root / f"mode-{mode}",
                    repository_root=fixture.repository,
                ).replay()
                terminal_event = events[-1]
                terminal = LoopState(
                    fixture.loop_state_root / f"mode-{mode}",
                    repository_root=fixture.repository,
                ).artifact(terminal_event["artifact_ids"][0])
                self.assertTrue(terminal["no_promotion"])
                self.assertEqual(terminal["mode"], mode)
                if mode == "suggest":
                    self.assertIsNone(terminal["candidate"])
                    self.assertIsNone(terminal["review_payload"])
                elif mode == "patch":
                    self.assertIsNotNone(terminal["candidate"])
                    self.assertIsNone(terminal["review_payload"])
                else:
                    self.assertIsNotNone(terminal["candidate"])
                    self.assertFalse(terminal["review_payload"]["merge_authority"])
                    self.assertFalse(
                        terminal["review_payload"]["publication_authority"]
                    )
                entries = Ledger(
                    fixture.ledger_root,
                    repository_root=fixture.repository,
                ).replay()
                self.assertNotIn(
                    "trial_promoted", {entry["event_type"] for entry in entries}
                )
            finally:
                fixture.close()

    def test_controller_crash_after_materialization_resumes_exactly(self) -> None:
        injected = {"raised": False}

        def fault(phase: str, _iteration: int, _trial_id: str | None) -> None:
            if phase == "materialized" and not injected["raised"]:
                injected["raised"] = True
                raise LoopFault("controller_crash")

        first = self.fixture.controller(run_id="crash-run", fault_hook=fault).run()
        self.assertEqual(first["status"], "interrupted")
        self.assertEqual(first["resume_phase"], "materialized")
        second = self.fixture.controller(run_id="crash-run").run()
        self.assertEqual(second["status"], "completed")
        self.assertEqual(
            repository_identity(self.fixture.repository, require_clean=True),
            self.fixture.champion,
        )

    def test_resume_rebinds_contract_and_excludes_concurrent_controller(self) -> None:
        injected = {"raised": False}

        def fault(phase: str, _iteration: int, _trial_id: str | None) -> None:
            if phase == "scheduled" and not injected["raised"]:
                injected["raised"] = True
                raise LoopFault("controller_crash")

        first = self.fixture.controller(
            run_id="contract-run",
            mode="patch",
            fault_hook=fault,
        ).run()
        self.assertEqual(first["status"], "interrupted")
        with self.assertRaisesRegex(LoopError, "authority differs from its contract"):
            self.fixture.controller(
                run_id="contract-run",
                mode="suggest",
            ).run()
        resumed = self.fixture.controller(
            run_id="contract-run",
            mode="patch",
        ).run()
        self.assertEqual(resumed["status"], "completed")

        state = LoopState(
            self.fixture.loop_state_root / "leased-run",
            repository_root=self.fixture.repository,
        )
        with state.exclusive():
            with self.assertRaisesRegex(LoopStateError, "another controller"):
                self.fixture.controller(
                    run_id="leased-run",
                    state=LoopState(
                        self.fixture.loop_state_root / "leased-run",
                        repository_root=self.fixture.repository,
                    ),
                ).run()

    def test_phase_and_ledger_publication_interruptions_reconcile(self) -> None:
        class FailOneLedger(Ledger):
            def __init__(
                self,
                root: Path,
                *,
                repository_root: Path,
                selected_event: str,
            ) -> None:
                super().__init__(root, repository_root=repository_root)
                self.selected_event = selected_event
                self.failed = False

            def append(self, **values: object) -> dict[str, object]:
                if values["event_type"] == self.selected_event and not self.failed:
                    self.failed = True
                    raise LedgerError("injected ledger publication interruption")
                return super().append(**values)  # type: ignore[arg-type,return-value]

        for selected_event, resume_phase in (
            ("proposal_finished", "proposed"),
            ("trial_nominated", "terminal"),
        ):
            fixture = LoopFixture()
            run_id = f"ledger-{selected_event}"
            try:
                first = fixture.controller(
                    run_id=run_id,
                    ledger=FailOneLedger(
                        fixture.ledger_root,
                        repository_root=fixture.repository,
                        selected_event=selected_event,
                    ),
                ).run()
                self.assertEqual(first["status"], "interrupted")
                self.assertEqual(first["resume_phase"], resume_phase)
                second = fixture.controller(run_id=run_id).run()
                self.assertEqual(second["status"], "completed")
                entries = Ledger(
                    fixture.ledger_root,
                    repository_root=fixture.repository,
                ).replay()
                self.assertEqual(
                    sum(entry["event_type"] == selected_event for entry in entries),
                    1,
                )
            finally:
                fixture.close()

    def test_short_soak_is_resumable_and_cannot_change_champion(self) -> None:
        ledger_root = self.fixture.root / "soak-ledger"
        ledger_root.mkdir(mode=0o700)
        state_root = self.fixture.root / "soak-state"
        registry = CommandRegistry(
            (
                CommandSpec(
                    "refinement-loop-smoke",
                    (
                        sys.executable,
                        "-c",
                        "import time; time.sleep(0.2)",
                    ),
                    5,
                ),
            )
        )
        arguments = {
            "repository": self.fixture.repository,
            "state_root": state_root,
            "ledger_root": ledger_root,
            "run_id": "short-soak",
            "duration_seconds": 1,
            "interval_seconds": 0,
            "pause_file": self.fixture.root / "soak-pause",
            "no_promotion": True,
            "registry": registry,
        }
        first = run_soak(**arguments)  # type: ignore[arg-type]
        self.assertEqual(first["status"], "passed")
        self.assertFalse(first["qualified_24h"])
        self.assertGreaterEqual(first["cycles"], 1)
        first_event = load_file(state_root / "events" / "00000000000000000000.json")
        self.assertRegex(first_event["command_receipt_id"], r"^1220[0-9a-f]{64}$")
        second = run_soak(**arguments)  # type: ignore[arg-type]
        self.assertEqual(second, first)
        self.assertEqual(
            repository_identity(self.fixture.repository, require_clean=True),
            self.fixture.champion,
        )
        self.assertEqual(
            Ledger(
                ledger_root,
                repository_root=self.fixture.repository,
            ).replay(),
            [],
        )

    def test_soak_journal_exceeds_default_evidence_directory_limit(self) -> None:
        state_root = self.fixture.root / "large-soak-state"
        journal = SoakJournal(state_root, repository=self.fixture.repository)
        for cycle in range(2_050):
            (journal.root / "commands" / f"{cycle:020d}").mkdir(mode=0o700)

        reopened = SoakJournal(state_root, repository=self.fixture.repository)

        self.assertEqual(reopened.replay(), [])

    def test_custody_packet_is_content_free_and_awaits_independent_review(
        self,
    ) -> None:
        packet = prepare_custody_review(ROOT, require_clean=False)
        unsigned = dict(packet)
        claimed = unsigned.pop("packet_id")
        self.assertEqual(identity(unsigned), claimed)
        self.assertFalse(packet["contains_private_content"])
        self.assertEqual(packet["review_status"], "awaiting-independent-review")
        self.assertGreaterEqual(len(packet["required_reviewer_assertions"]), 5)
        serialized = canonical_bytes(packet)
        for forbidden in (
            b"CIGAR_CORPUS_SHADOW_",
            b"CIGAR_CORPUS_SEALED_",
            b"-----BEGIN PRIVATE KEY-----",
        ):
            self.assertNotIn(forbidden, serialized)

        class FailOnePhase(LoopState):
            def __init__(
                self,
                root: Path,
                *,
                repository_root: Path,
                selected_phase: str,
            ) -> None:
                super().__init__(root, repository_root=repository_root)
                self.selected_phase = selected_phase
                self.failed = False

            def append(self, **values: object) -> dict[str, object]:
                if values["phase"] == self.selected_phase and not self.failed:
                    self.failed = True
                    raise LoopStateError("injected phase publication interruption")
                return super().append(**values)  # type: ignore[arg-type,return-value]

        for selected_phase, resume_phase in (
            ("proposed", "materialized"),
            ("terminal", "evaluated"),
        ):
            fixture = LoopFixture()
            run_id = f"phase-{selected_phase}"
            try:
                first = fixture.controller(
                    run_id=run_id,
                    state=FailOnePhase(
                        fixture.loop_state_root / run_id,
                        repository_root=fixture.repository,
                        selected_phase=selected_phase,
                    ),
                ).run()
                self.assertEqual(first["status"], "interrupted")
                self.assertEqual(first["resume_phase"], resume_phase)
                second = fixture.controller(run_id=run_id).run()
                self.assertEqual(second["status"], "completed")
                self.assertEqual(second["last_decision"], "nominate")
                self.assertEqual(
                    repository_identity(fixture.repository, require_clean=True),
                    fixture.champion,
                )
            finally:
                fixture.close()

    def test_twenty_hosted_local_seeded_iterations_nominate_only_known_good(
        self,
    ) -> None:
        manifest = load_file(
            ROOT / "refinement" / "qualification" / "loop-seeds-v1.json"
        )
        SchemaRegistry(ROOT / "schemas" / "refinement").validate(
            "loop-seeds-v1.schema.json", manifest
        )
        unsigned_manifest = dict(manifest)
        unsigned_manifest.pop("qualification_id")
        self.assertEqual(manifest["qualification_id"], identity(unsigned_manifest))
        seeds = manifest["seeds"]
        self.assertEqual(len(seeds), 20)
        self.assertEqual(len({seed["seed_id"] for seed in seeds}), 20)
        signals = [
            make_signal(
                source_kind="test_failure",
                visibility="public",
                summary=seed["seed_id"],
                source_commitment="1220" + f"{index + 10:064x}",
                owner_hint="fixture-owner",
                metric=f"correctness-{index:02d}",
                magnitude=1.0,
                estimated_cost=1.0,
                strata=[],
                reproducible=True,
            )
            for index, seed in enumerate(seeds)
        ]
        patches = {
            "known-good": lambda index: replacement_patch(f"refined-good-{index}"),
            "known-bad": lambda index: replacement_patch(f"wrong-{index}"),
            "leaky": lambda _index: replacement_patch(
                "CIGAR_CORPUS_SHADOW_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            ),
            "faster-but-wrong": lambda index: replacement_patch(f"fast-wrong-{index}"),
            "metric-gaming": lambda index: outside_patch(
                "refinement/metrics.json", f"score={index}"
            ),
            "test-weakening": lambda index: outside_patch(
                "tests/qualification_test.py", f"disabled={index}"
            ),
            "evaluator-edit": lambda index: outside_patch(
                "tools/refinement/evaluator.py", f"bypass={index}"
            ),
        }
        lanes: list[str] = []

        class Transport:
            def __init__(self, patch: str) -> None:
                self.patch = patch
                self.calls = 0
                self.session_id: str | None = None

            def __call__(
                self,
                _endpoint: str,
                _headers: dict[str, str],
                body: bytes,
                _timeout: int,
            ) -> tuple[int, dict[str, str], bytes]:
                request = loads(body)
                if self.calls == 0:
                    envelope = loads(request["input"][0]["content"][0]["text"].encode())
                    self.session_id = envelope["session_id"]
                    selected = action(
                        "apply_patch",
                        "patch",
                        session_id=self.session_id,
                        patch=self.patch,
                    )
                else:
                    selected = action(
                        "finish",
                        "finish",
                        session_id=self.session_id,
                        summary="Seed proposal complete.",
                    )
                response = {
                    "id": f"response-{self.calls}",
                    "output": [
                        {
                            "type": "function_call",
                            "name": "model_action",
                            "call_id": f"call-{self.calls}",
                            "arguments": canonical_bytes(selected).decode(),
                        }
                    ],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }
                self.calls += 1
                return 200, {}, canonical_bytes(response)

        def seed_for(packet: dict[str, object]) -> tuple[int, dict[str, object]]:
            summary = str(packet["failure_cluster"])
            for index, seed in enumerate(seeds):
                if summary == seed["seed_id"]:
                    return index, seed
            raise AssertionError("unknown seeded packet")

        def factory(packet: dict[str, object]) -> object:
            index, seed = seed_for(packet)
            category = str(seed["category"])
            transport = Transport(patches[category](index))
            if seed["adapter_lane"] == "hosted":
                lanes.append("hosted")
                return OpenAIResponsesAdapter(
                    model="qualification-hosted-double",
                    instructions="Return one bounded model action.",
                    credential_handle=None,
                    transport=transport,
                    maximum_turns=4,
                    maximum_retries=0,
                )
            lanes.append("local")
            return OpenAICompatibleAdapter(
                endpoint="http://127.0.0.1:18080/v1/responses",
                model="qualification-local-double",
                instructions="Return one bounded model action.",
                transport=transport,
                maximum_turns=4,
                maximum_retries=0,
            )

        class SeedEvaluator(GateOnlyEvaluator):
            evaluator_id = "seeded-loop-qualification-v1"

            def evaluate(
                self,
                *,
                worktree: Path,
                packet: dict[str, object],
                diff: dict[str, object],
                gates: dict[str, object],
            ) -> dict[str, object]:
                base = super().evaluate(
                    worktree=worktree,
                    packet=packet,  # type: ignore[arg-type]
                    diff=diff,  # type: ignore[arg-type]
                    gates=gates,  # type: ignore[arg-type]
                )
                if base["decision"] != "nominate":
                    return base
                value = (worktree / "src/value.txt").read_text(encoding="utf-8").strip()
                if value.startswith("refined-good-"):
                    decision = "nominate"
                    failure = None
                    reason = "Known-good answer and evidence checks passed."
                    correctness = 1
                else:
                    decision = "reject_incorrect"
                    failure = (
                        "faster_but_wrong"
                        if value.startswith("fast-wrong-")
                        else "verified_task_failure"
                    )
                    reason = (
                        "Candidate answer failed the independent correctness oracle."
                    )
                    correctness = 0
                return _seal_evaluation(
                    evaluator_id=self.evaluator_id,
                    trial_id=str(packet["_trial_id"]),
                    decision=decision,
                    failure_category=failure,
                    reasons=[reason],
                    diff_snapshot_id=str(diff["snapshot"]["snapshot_id"]),  # type: ignore[index]
                    gate_id=str(gates["gate_id"]),
                    metrics=[
                        {
                            "name": "verified_task_success",
                            "numerator": correctness,
                            "denominator": 1,
                            "unit": "ratio",
                        }
                    ],
                    hard_invariants=[
                        {"name": "named_gates", "status": "passed"},
                        {"name": "sensitive_content", "status": "passed"},
                        {
                            "name": "correctness",
                            "status": "passed" if correctness else "failed",
                        },
                    ],
                )

        controller = LoopController(
            repository=self.fixture.repository,
            loaded_config=self.fixture.config,
            run_id="twenty-seeds",
            state=LoopState(
                self.fixture.loop_state_root / "twenty-seeds",
                repository_root=self.fixture.repository,
            ),
            trials=TrialStore(
                self.fixture.trial_state_root / "twenty-seeds",
                repository_root=self.fixture.repository,
            ),
            worktree_root=self.fixture.worktrees,
            command_state_root=self.fixture.commands,
            ledger=Ledger(
                self.fixture.ledger_root,
                repository_root=self.fixture.repository,
            ),
            quota=QuotaLedger(
                self.fixture.quota_root,
                repository_root=self.fixture.repository,
                policy_path=LIMITS,
            ),
            utc_day="2026-07-27",
            signals=signals,
            history=[],
            trial_class="product",
            adapter_profile="hosted-local-protocol-doubles",
            adapter_factory=factory,  # type: ignore[arg-type]
            evaluator=SeedEvaluator(),
            mode="patch",
            maximum_iterations=20,
            maximum_estimated_cost=10,
            pause_file=self.fixture.root / "pause",
            no_promotion=True,
            registry=self.fixture.registry,
        )
        result = controller.run()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["iterations"], 20)
        self.assertEqual(lanes.count("hosted"), 10)
        self.assertEqual(lanes.count("local"), 10)
        entries = Ledger(
            self.fixture.ledger_root,
            repository_root=self.fixture.repository,
        ).replay()
        terminals = [
            entry
            for entry in entries
            if entry["event_type"] in {"trial_nominated", "trial_rejected"}
        ]
        self.assertEqual(len(terminals), 20)
        self.assertEqual(
            sum(entry["event_type"] == "trial_nominated" for entry in terminals),
            5,
        )
        self.assertTrue(
            all(
                entry["decision"] == "nominate"
                for entry in terminals
                if entry["event_type"] == "trial_nominated"
            )
        )
        failure_decisions = {
            entry["decision"]
            for entry in terminals
            if entry["event_type"] == "trial_rejected"
        }
        self.assertEqual(
            failure_decisions,
            {"reject_incorrect", "reject_leakage", "reject_invalid"},
        )
        state = LoopState(
            self.fixture.loop_state_root / "twenty-seeds",
            repository_root=self.fixture.repository,
        )
        events = state.replay()
        trial_seeds: dict[str, dict[str, object]] = {}
        for event in events:
            if event["phase"] != "scheduled":
                continue
            scheduled = state.artifact(event["artifact_ids"][0])
            summary = scheduled["packet"]["failure_cluster"]
            trial_seeds[event["trial_id"]] = next(
                seed for seed in seeds if seed["seed_id"] == summary
            )
        terminal_events = [event for event in events if event["phase"] == "terminal"]
        self.assertEqual(len(terminal_events), 20)
        for event in terminal_events:
            seed = trial_seeds[event["trial_id"]]
            self.assertEqual(
                event["failure_category"],
                seed["expected_failure_category"],
            )
            self.assertEqual(event["status"], seed["expected_decision"])
            terminal = state.artifact(event["artifact_ids"][0])
            self.assertEqual(
                terminal["candidate"] is not None,
                seed["expected_candidate_commit"],
            )
        evaluations = {
            event["trial_id"]: state.artifact(event["artifact_ids"][0])
            for event in events
            if event["phase"] == "evaluated"
        }
        prepared = []
        for event in terminal_events:
            seed = trial_seeds[event["trial_id"]]
            terminal = state.artifact(event["artifact_ids"][0])
            evaluation = evaluations.get(event["trial_id"])
            if evaluation is None:
                evaluation = _seal_evaluation(
                    evaluator_id="malicious-promotion-attempt-v1",
                    trial_id=event["trial_id"],
                    decision="nominate",
                    failure_category=None,
                    reasons=["Synthetic hostile promotion attempt."],
                    diff_snapshot_id="1220" + "d" * 64,
                    gate_id="1220" + "e" * 64,
                    metrics=[],
                    hard_invariants=[{"name": "synthetic", "status": "passed"}],
                )
            candidate = terminal["candidate"]
            decision_body = {
                "schema_version": "cigar.refinement-decision.v1",
                "trial_id": event["trial_id"],
                "comparison_id": identity(
                    {"seed_id": seed["seed_id"], "kind": "comparison"}
                ),
                "champion_source": {
                    "revision": self.fixture.champion["revision"],
                    "tree": self.fixture.champion["tree"],
                },
                "candidate_source": (
                    {
                        "revision": candidate["revision"],
                        "tree": candidate["tree"],
                    }
                    if candidate is not None
                    else {
                        "revision": self.fixture.champion["revision"],
                        "tree": self.fixture.champion["tree"],
                    }
                ),
                "policy_digest": manifest["qualification_id"],
                "decision": "promote",
                "reasons": ["independent-seeded-qualification"],
                "passed_gates": ["seed-oracle"],
                "failed_gates": [],
                "human_review": {
                    "reviewer_id": "independent-seed-oracle",
                    "approval_digest": identity(
                        {"seed_id": seed["seed_id"], "approved": True}
                    ),
                },
            }
            decision = {
                **decision_body,
                "decision_id": identity(decision_body),
            }
            if seed["expected_candidate_commit"]:
                prepared.append(
                    prepare_development_update(
                        terminal=terminal,
                        evaluation=evaluation,
                        decision=decision,
                        schema_root=ROOT / "schemas" / "refinement",
                    )
                )
            else:
                with self.assertRaisesRegex(
                    DevelopmentPromotionError, "cannot promote"
                ):
                    prepare_development_update(
                        terminal=terminal,
                        evaluation=evaluation,
                        decision=decision,
                        schema_root=ROOT / "schemas" / "refinement",
                    )
        self.assertEqual(len(prepared), 5)
        self.assertTrue(
            all(
                intent["branch_update_authority"] is False
                and intent["target_branch"] == "refinement/development"
                for intent in prepared
            )
        )
        nominated_events = [
            event for event in terminal_events if event["status"] == "nominate"
        ]
        self.assertEqual(len(nominated_events), 5)
        for event in nominated_events:
            terminal = state.artifact(event["artifact_ids"][0])
            candidate = terminal["candidate"]
            self.assertEqual(
                git(
                    self.fixture.repository,
                    "rev-parse",
                    f"{candidate['branch']}^{{commit}}",
                ),
                candidate["revision"],
            )
            self.assertEqual(
                git(
                    self.fixture.repository,
                    "rev-parse",
                    f"{candidate['revision']}^{{tree}}",
                ),
                candidate["tree"],
            )
        self.assertEqual(
            repository_identity(self.fixture.repository, require_clean=True),
            self.fixture.champion,
        )


if __name__ == "__main__":
    unittest.main()
