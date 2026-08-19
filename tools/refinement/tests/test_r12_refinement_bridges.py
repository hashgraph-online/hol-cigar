from __future__ import annotations

# ruff: noqa: E402

import copy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import canonical_bytes, identity, loads
from tools.refinement.ledger import Ledger
from tools.refinement.opportunity_miner import (
    OpportunityMiningError,
    attest_review,
    mine,
    publish,
)
from tools.refinement.pr_bridge import (
    DraftPRBridgeError,
    execute,
    preview,
)

POLICY = ROOT / "refinement" / "opportunities" / "mining-policy-v1.json"


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class OpportunityMiningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.external = Path(self.temporary.name).resolve(strict=True)
        self.ledger_root = self.external / "ledger"
        self.facts_path = self.external / "facts.json"
        self.pareto_root = self.external / "pareto"
        self.pareto_root.mkdir(mode=0o700)
        self.revision = git(ROOT, "rev-parse", "HEAD")
        self.tree = git(ROOT, "rev-parse", "HEAD^{tree}")
        self._write_facts()
        self._write_pareto()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_facts(self) -> None:
        facts: list[dict[str, object]] = []
        previous: dict[str, object] | None = None
        for index, recall in enumerate((990_000, 900_000), start=1):
            comparison_id = "1220" + str(index) * 64
            entry = Ledger(self.ledger_root, repository_root=ROOT).append(
                event_type="trial_rejected",
                iteration_id=f"iteration-{index}",
                source_revision=self.revision,
                source_tree=self.tree,
                artifact_ids=[comparison_id],
                evidence_class="development",
                decision="reject",
            )
            fact_body: dict[str, object] = {
                "fact_id": "",
                "iteration_id": f"iteration-{index}",
                "ledger_entry_id": entry["entry_id"],
                "status": "rejected",
                "family_id": "feature-extraction",
                "adapter": "recorded-proposal-v1",
                "provider_id": "recorded-proposal-v1",
                "failure_class": "provider_outage",
                "comparison_id": comparison_id,
                "decision_id": None,
                "source_artifact_ids": [comparison_id],
                "resources": {
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "cost_microusd": 0,
                    "compute_milliseconds": 500,
                },
                "metrics": [
                    {
                        "name": "critical_context_recall",
                        "direction": "higher",
                        "value_ppm": recall,
                    },
                    {
                        "name": "evidence_token_precision",
                        "direction": "higher",
                        "value_ppm": 900_000,
                    },
                    {
                        "name": "first_useful_evidence_rank",
                        "direction": "lower",
                        "value_ppm": 1_000_000,
                    },
                    {
                        "name": "latency_ms",
                        "direction": "lower",
                        "value_ppm": 100_000_000,
                    },
                ],
            }
            fact_body["fact_id"] = identity(
                {key: value for key, value in fact_body.items() if key != "fact_id"}
            )
            facts.append(fact_body)
            previous = entry
        assert previous is not None
        body: dict[str, object] = {
            "schema_version": "cigar.refinement-dashboard-facts.v1",
            "facts_id": "",
            "ledger_head": previous["entry_id"],
            "facts": facts,
        }
        body["facts_id"] = identity(
            {key: value for key, value in body.items() if key != "facts_id"}
        )
        self.facts_path.write_bytes(canonical_bytes(body))

    def _write_pareto(self) -> None:
        body = {
            "schema_version": "cigar.pareto-record.v1",
            "sequence": 0,
            "previous_record_id": None,
            "comparison_id": "1220" + "a" * 64,
            "candidate_source": {
                "revision": self.revision,
                "tree": self.tree,
            },
            "decision": "reject_no_meaningful_improvement",
            "objectives": [
                {
                    "name": "critical_context_recall",
                    "direction": "higher",
                    "value": 0.8,
                },
                {
                    "name": "evidence_token_precision",
                    "direction": "higher",
                    "value": 0.7,
                },
                {
                    "name": "first_useful_evidence_rank",
                    "direction": "lower",
                    "value": 3,
                },
            ],
            "dominated_by": [],
            "frontier_after": ["1220" + "a" * 64],
        }
        record = {**body, "record_id": identity(body)}
        path = self.pareto_root / "00000000000000000000.json"
        path.write_bytes(canonical_bytes(record))
        path.chmod(0o400)

    def _mine(self) -> dict[str, object]:
        return mine(
            repository_root=ROOT,
            ledger_root=self.ledger_root,
            facts_path=self.facts_path,
            policy_path=POLICY,
            pareto_root=self.pareto_root,
        )

    def test_mining_replays_kpi_failure_and_pareto_evidence_deterministically(
        self,
    ) -> None:
        first = self._mine()
        second = self._mine()
        self.assertEqual(first, second)
        kinds = [row["derivation_kind"] for row in first["candidates"]]
        self.assertEqual(
            {kind: kinds.count(kind) for kind in set(kinds)},
            {"kpi_regression": 1, "failure_cluster": 1, "pareto_gap": 3},
        )
        self.assertEqual(
            [row["candidate_id"] for row in first["candidates"]],
            sorted(row["candidate_id"] for row in first["candidates"]),
        )
        for candidate in first["candidates"]:
            self.assertTrue(candidate["signal"]["reproducible"])
            self.assertEqual(
                candidate["derivation_kind"], candidate["evidence"]["kind"]
            )

    def test_independent_review_is_exact_attested_and_publication_filters(
        self,
    ) -> None:
        candidates = self._mine()
        chosen = candidates["candidates"][0]["candidate_id"]
        rejected = {
            row["candidate_id"]: "Not the next bounded experiment."
            for row in candidates["candidates"][1:]
        }
        key = b"r12-independent-opportunity-review-key"
        review = attest_review(
            repository_root=ROOT,
            candidate_set=candidates,
            reviewer_id="independent-reviewer-v1",
            accepted={chosen},
            rejected=rejected,
            key_id="r12-review-key",
            key=key,
        )
        registry = publish(
            repository_root=ROOT,
            candidate_set=candidates,
            review=review,
            key=key,
        )
        self.assertEqual(len(registry["signals"]), 1)
        selected = next(
            row["signal"]
            for row in candidates["candidates"]
            if row["candidate_id"] == chosen
        )
        self.assertEqual(registry["signals"], [selected])

        tampered = copy.deepcopy(review)
        tampered["attestation"]["mac"] = "0" * 64
        with self.assertRaisesRegex(OpportunityMiningError, "attestation"):
            publish(
                repository_root=ROOT,
                candidate_set=candidates,
                review=tampered,
                key=key,
            )
        with self.assertRaisesRegex(OpportunityMiningError, "independent"):
            attest_review(
                repository_root=ROOT,
                candidate_set=candidates,
                reviewer_id=candidates["producer_id"],
                accepted={chosen},
                rejected=rejected,
                key_id="r12-review-key",
                key=key,
            )


class DraftPRBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.external = Path(self.temporary.name).resolve(strict=True)
        self.repository = self.external / "repository"
        self.remote = self.external / "remote.git"
        self.repository.mkdir(mode=0o700)
        git(self.repository, "init", "-b", "main")
        git(self.repository, "config", "user.name", "CIGAR Test")
        git(self.repository, "config", "user.email", "cigar@example.invalid")
        shutil.copytree(ROOT / "schemas", self.repository / "schemas")
        (self.repository / "value.txt").write_text("honey\n", encoding="utf-8")
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-m", "base")
        self.base = git(self.repository, "rev-parse", "HEAD")
        git(self.repository, "switch", "-c", "refine/trial-trial-1")
        (self.repository / "value.txt").write_text("refined\n", encoding="utf-8")
        git(self.repository, "add", "value.txt")
        git(self.repository, "commit", "-m", "candidate")
        self.candidate = git(self.repository, "rev-parse", "HEAD")
        self.tree = git(self.repository, "rev-parse", "HEAD^{tree}")
        git(self.repository, "switch", "main")
        git(self.external, "init", "--bare", str(self.remote))
        git(self.repository, "remote", "add", "origin", str(self.remote))
        git(self.repository, "push", "origin", "main:main")
        body = {
            "schema_version": "cigar.refinement-pr-payload.v1",
            "operation": "create-review-request-only",
            "trial_id": "trial-1",
            "base_revision": self.base,
            "candidate_revision": self.candidate,
            "candidate_tree": self.tree,
            "branch": "refine/trial-trial-1",
            "evaluation_id": "1220" + "1" * 64,
            "merge_authority": False,
            "publication_authority": False,
        }
        self.payload = {**body, "payload_id": identity(body)}
        self.title = "refinement: trial-1"
        self.body = "Draft review only."

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _pr(self) -> dict[str, object]:
        return {
            "number": 7,
            "html_url": "https://github.com/example/cigar/pull/7",
            "draft": True,
            "state": "open",
            "title": self.title,
            "body": self.body,
            "maintainer_can_modify": False,
            "head": {
                "ref": self.payload["branch"],
                "sha": self.candidate,
                "repo": {"full_name": "example/cigar"},
            },
            "base": {
                "ref": "main",
                "sha": self.base,
                "repo": {"full_name": "example/cigar"},
            },
        }

    def test_preview_and_execute_push_only_exact_ref_and_create_draft(self) -> None:
        inspected = preview(
            repository=self.repository,
            payload=self.payload,
            remote="origin",
            base_branch="main",
            github_repository="example/cigar",
            title=self.title,
            body=self.body,
            allow_non_github_remote=True,
        )
        self.assertEqual(inspected["remote"]["candidate_state"], "absent")
        requests: list[tuple[str, str, bytes | None]] = []

        def transport(
            method: str,
            endpoint: str,
            _headers: dict[str, str],
            body: bytes | None,
            _timeout: int,
        ) -> tuple[int, dict[str, str], bytes]:
            requests.append((method, endpoint, body))
            if method == "GET":
                return 200, {}, b"[]"
            request = loads(body or b"")
            self.assertTrue(request["draft"])
            self.assertFalse(request["maintainer_can_modify"])
            self.assertEqual(request["head"], f"example:{self.payload['branch']}")
            return 201, {}, canonical_bytes(self._pr())

        receipt = execute(
            repository=self.repository,
            payload=self.payload,
            remote="origin",
            base_branch="main",
            github_repository="example/cigar",
            title=self.title,
            body=self.body,
            confirmation_payload_id=self.payload["payload_id"],
            token="x" * 40,
            transport=transport,
            allow_non_github_remote=True,
        )
        self.assertTrue(receipt["remote"]["pushed"])
        self.assertTrue(receipt["pull_request"]["draft"])
        self.assertTrue(receipt["pull_request"]["created"])
        remote_head = git(
            self.repository,
            "ls-remote",
            "origin",
            f"refs/heads/{self.payload['branch']}",
        ).split()[0]
        self.assertEqual(remote_head, self.candidate)
        self.assertEqual([row[0] for row in requests], ["GET", "POST"])
        self.assertFalse(receipt["merge_authority"])
        self.assertFalse(receipt["publication_authority"])

        def existing_transport(
            method: str,
            _endpoint: str,
            _headers: dict[str, str],
            body: bytes | None,
            _timeout: int,
        ) -> tuple[int, dict[str, str], bytes]:
            self.assertEqual(method, "GET")
            self.assertIsNone(body)
            return 200, {}, canonical_bytes([self._pr()])

        resumed = execute(
            repository=self.repository,
            payload=self.payload,
            remote="origin",
            base_branch="main",
            github_repository="example/cigar",
            title=self.title,
            body=self.body,
            confirmation_payload_id=self.payload["payload_id"],
            token="x" * 40,
            transport=existing_transport,
            allow_non_github_remote=True,
        )
        self.assertFalse(resumed["remote"]["pushed"])
        self.assertFalse(resumed["pull_request"]["created"])

    def test_execution_confirmation_and_identity_tampering_fail_before_push(
        self,
    ) -> None:
        with self.assertRaisesRegex(DraftPRBridgeError, "credential"):
            execute(
                repository=self.repository,
                payload=self.payload,
                remote="origin",
                base_branch="main",
                github_repository="example/cigar",
                title=self.title,
                body=self.body,
                confirmation_payload_id=self.payload["payload_id"],
                token="",
                transport=lambda *_args: self.fail("transport must not be called"),
                allow_non_github_remote=True,
            )
        with self.assertRaisesRegex(DraftPRBridgeError, "confirmation"):
            execute(
                repository=self.repository,
                payload=self.payload,
                remote="origin",
                base_branch="main",
                github_repository="example/cigar",
                title=self.title,
                body=self.body,
                confirmation_payload_id="1220" + "0" * 64,
                token="x" * 40,
                transport=lambda *_args: self.fail("transport must not be called"),
                allow_non_github_remote=True,
            )
        self.assertEqual(
            git(
                self.repository,
                "ls-remote",
                "origin",
                f"refs/heads/{self.payload['branch']}",
            ),
            "",
        )
        tampered = dict(self.payload)
        tampered["candidate_tree"] = "0" * 40
        with self.assertRaisesRegex(DraftPRBridgeError, "identity"):
            preview(
                repository=self.repository,
                payload=tampered,
                remote="origin",
                base_branch="main",
                github_repository="example/cigar",
                title=self.title,
                body=self.body,
                allow_non_github_remote=True,
            )


if __name__ == "__main__":
    unittest.main()
