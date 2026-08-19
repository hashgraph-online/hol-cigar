from __future__ import annotations

import copy
import hashlib
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement import canonical
from tools.refinement.consumer import (
    ConsumerError,
    load_assignment,
    run_pair,
    run_profile_three_way,
    run_three_way,
    validate_observation,
)
from tools.refinement.schema import SchemaError, SchemaRegistry

SCHEMAS = ROOT / "schemas" / "refinement"
MH = "1220" + "1" * 64
GIT_A = "a" * 40
GIT_B = "b" * 40
CANARY = "CIGAR_R03_CANARY_NEVER_EMIT"


FAKE_CONSUMER = r"""#!/usr/bin/env python3
import base64
import hashlib
import json
import pathlib
import sys

def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()

def multihash(payload):
    return "1220" + hashlib.sha256(payload).hexdigest()

assignment_bytes = sys.stdin.buffer.read()
assignment = json.loads(assignment_bytes)
executable_digest = multihash(pathlib.Path(__file__).read_bytes())
version = multihash(b"version")
contract = multihash(b"contract")
manifest_id = multihash(b"manifest-id")
bundle_id = multihash(b"bundle-id")
output_digest = multihash(b"output")
block_id = multihash(b"block")
plan = {
    "catalog_watermark": multihash(b"catalog"),
    "contract_digest": contract,
    "dispositions": [[version, {"lane": "evidence", "score": 1, "state": "selected"}]],
    "extensions": {},
    "lanes": [{"budget_tokens": 8, "candidate_versions": [version], "kind": "evidence"}],
    "plan_id": "plan-1",
    "schema_version": "cigar.context-plan.v1",
    "total_input_tokens": 8,
}
bundle = {
    "blocks": [{
        "block_id": block_id,
        "content_digest": multihash(b"allowed"),
        "lane": "evidence",
        "provenance": [version],
        "representation": "exact",
        "token_count": 1,
    }],
    "bundle_id": bundle_id,
    "contract_digest": contract,
    "extensions": {},
    "manifest_digest": manifest_id,
    "schema_version": "cigar.context-bundle.v1",
    "total_tokens": 1,
}
disposition = {"lane": "evidence", "score": 1, "state": "selected"}
manifest = {
    "contract_digest": contract,
    "entries": [{
        "disposition": disposition,
        "provenance_digest": multihash(b"provenance"),
        "reason_codes": [],
        "version_id": version,
    }],
    "extensions": {},
    "manifest_id": manifest_id,
    "schema_version": "cigar.selection-manifest.v1",
}
explanation = {"entries": [{"disposition": disposition, "version_id": version}]}
materialization = {
    "bundle_id": bundle_id,
    "byte_count": 1,
    "content_digest": output_digest,
    "materializer_fingerprint": multihash(b"materializer"),
    "media_type": "application/json",
    "physical_input_tokens": 1,
    "schema_version": "cigar.materialization-reference.v1",
    "tokenizer_fingerprint": multihash(b"tokenizer"),
}
values = {
    "plan": plan,
    "bundle": bundle,
    "manifest": manifest,
    "explanation": explanation,
    "materialization": materialization,
}
artifacts = []
for kind in ("plan", "bundle", "manifest", "explanation", "materialization"):
    retained = canonical(values[kind])
    artifacts.append({
        "bytes": len(retained),
        "digest": multihash(retained),
        "kind": kind,
        "retained_base64url": base64.urlsafe_b64encode(retained).decode().rstrip("="),
    })
body = {
    "archive_digest": assignment["archive_digest"],
    "artifacts": artifacts,
    "assignment_digest": multihash(assignment_bytes),
    "consumer_mode": assignment["consumer_mode"],
    "dispositions": [{"candidate_id": version, "reason": "selected:evidence"}],
    "effect_replay": {
        "effects": 0,
        "handoffs": 0,
        "replay_dispatches": 0,
        "unsafe_retries": 0,
    },
    "input_digest": multihash(assignment_bytes),
    "output_digest": output_digest,
    "pair_id": assignment["pair_id"],
    "phases": [
        {"duration_ms": 0, "phase": phase}
        for phase in (
            "fixture", "setup", "ingest", "index", "plan", "compile",
            "explain", "materialize", "optional_flows"
        )
    ],
    "pins": {
        "catalog": multihash(b"catalog"),
        "compiler": multihash(b"compiler"),
        "consumer": executable_digest,
        "graph": multihash(b"graph"),
        "index": multihash(b"index"),
        "materializer": materialization["materializer_fingerprint"],
        "model": assignment["model"],
        "planner": multihash(b"planner"),
        "policy": multihash(b"policy"),
        "prompt": assignment["prompt_digest"],
        "tokenizer": materialization["tokenizer_fingerprint"],
    },
    "resources": {
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "cost_usd": 0,
        "cpu_measured": False,
        "cpu_ms": 0,
        "latency_ms": 0,
        "output_tokens": 0,
        "peak_rss_bytes": 0,
        "peak_rss_measured": False,
        "physical_input_tokens": 1,
    },
    "run_id": assignment["run_id"],
    "schema_version": "cigar.benchmark-observation.v2",
    "selected_blocks": [{
        "block_id": block_id,
        "lane": "evidence",
        "provenance_ids": [version],
        "rank": 1,
        "representation": "exact",
        "tokens": 1,
    }],
    "source": assignment["source"],
    "status": "completed",
    "task_id": assignment["task_id"],
    "tool_observations": [
        {
            "exit_code": 0,
            "request_digest": multihash(("request:" + tool).encode()),
            "response_digest": multihash(("response:" + tool).encode()),
            "tool": tool,
        }
        for tool in (
            "discoverSources", "ingestCatalog", "createContextPlan",
            "compileContextBundle", "getContextBundleManifest",
            "explainContextBundle", "materializeContextBundle"
        )
    ],
    "treatment": assignment["treatment"],
}
observation = dict(body)
observation["observation_id"] = multihash(canonical(body))
sys.stdout.buffer.write(canonical(observation) + b"\n")
"""


class ConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name).resolve(strict=True)
        self.registry = SchemaRegistry(SCHEMAS)
        self.archive = self.temp / "fixture.json"
        archive = {
            "files": [
                {
                    "bytes_base64url": "YWxsb3dlZA",
                    "media_type": "text/markdown",
                    "path": "allowed.md",
                },
                {
                    "bytes_base64url": "Q0lHQVJfUjAzX0NBTkFSWV9ORVZFUl9FTUlU",
                    "media_type": "text/plain",
                    "path": "denied/secret.txt",
                },
            ],
            "schema_version": "cigar.fixture-archive.v1",
        }
        self.archive_bytes = canonical.canonical_bytes(archive)
        self.archive.write_bytes(self.archive_bytes)
        self.consumer = self.temp / "consumer.py"
        self.consumer.write_text(
            textwrap.dedent(FAKE_CONSUMER),
            encoding="utf-8",
        )
        self.consumer.chmod(0o555)
        self.state = self.temp / "state"

    def assignment(self, treatment: str, source: str) -> dict[str, object]:
        return {
            "archive_digest": canonical.multihash_bytes(self.archive_bytes),
            "archive_path": str(self.archive),
            "consumer_mode": "recorded",
            "excluded_prefixes": ["denied"],
            "flows": {"effect": False, "handoff": False, "replay": False},
            "job_goal": "Use authorized evidence only",
            "max_context_tokens": 1024,
            "model": "deterministic-recorded-v1",
            "output_reserve_tokens": 128,
            "pair_id": "pair-r03",
            "prompt_digest": MH,
            "query": "allowed",
            "run_id": "run-r03",
            "schema_version": "cigar.benchmark-assignment.v2",
            "semantic_type": "documentation",
            "source": {"revision": source, "tree": source},
            "task_id": "task-r03",
            "token_budget": 512,
            "treatment": treatment,
        }

    def write_assignment(
        self, name: str, treatment: str, source: str
    ) -> tuple[Path, bytes]:
        path = self.temp / name
        payload = canonical.canonical_bytes(self.assignment(treatment, source))
        path.write_bytes(payload)
        return path, payload

    def run_fixture_pair(self) -> dict[str, object]:
        champion, _champion_bytes = self.write_assignment(
            "champion.json", "champion", GIT_A
        )
        candidate, _candidate_bytes = self.write_assignment(
            "candidate.json", "candidate", GIT_B
        )
        return run_pair(
            champion_assignment_path=champion,
            candidate_assignment_path=candidate,
            champion_executable_path=self.consumer,
            candidate_executable_path=self.consumer,
            cwd=self.temp,
            state=self.state,
            schemas=SCHEMAS,
            timeout_seconds=10,
        )

    def test_assignment_and_fixture_archive_schemas_are_strict(self) -> None:
        assignment = self.assignment("candidate", GIT_B)
        self.registry.validate("assignment-v2.schema.json", assignment)
        self.registry.validate(
            "fixture-archive-v1.schema.json",
            canonical.loads(self.archive_bytes),
        )
        for field in tuple(assignment):
            incomplete = copy.deepcopy(assignment)
            incomplete.pop(field)
            with self.assertRaises(SchemaError):
                self.registry.validate("assignment-v2.schema.json", incomplete)
        unknown = copy.deepcopy(assignment)
        unknown["oracle"] = {"answer": CANARY}
        with self.assertRaises(SchemaError):
            self.registry.validate("assignment-v2.schema.json", unknown)
        duplicated = canonical.loads(self.archive_bytes)
        duplicated["files"].append(copy.deepcopy(duplicated["files"][0]))
        with self.assertRaises(SchemaError):
            self.registry.validate("fixture-archive-v1.schema.json", duplicated)

    def test_pair_is_balanced_bound_and_byte_reproducible(self) -> None:
        first = self.run_fixture_pair()
        second = self.run_fixture_pair()
        self.assertEqual(first, second)
        self.assertEqual(first["order"], second["order"])
        self.assertEqual(
            {value["treatment"] for value in first["observations"]},
            {"champion", "candidate"},
        )
        self.assertNotIn(CANARY, canonical.canonical_bytes(first).decode())
        unsigned = dict(first)
        result_id = unsigned.pop("pair_result_id")
        self.assertEqual(result_id, canonical.identity(unsigned))
        for observation in first["observations"]:
            body = dict(observation)
            observation_id = body.pop("observation_id")
            self.assertEqual(observation_id, canonical.identity(body))

    def test_three_way_is_source_bound_balanced_and_reproducible(self) -> None:
        honey, _ = self.write_assignment("honey.json", "honey", "c" * 40)
        champion, _ = self.write_assignment("champion.json", "champion", GIT_A)
        candidate, _ = self.write_assignment("candidate.json", "candidate", GIT_B)
        for assignment_path in (honey, champion, candidate):
            value = canonical.load_file(assignment_path)
            value["intelligence_profile"] = "balanced.v1"
            assignment_path.write_bytes(canonical.canonical_bytes(value))
        arguments = {
            "honey_assignment_path": honey,
            "champion_assignment_path": champion,
            "candidate_assignment_path": candidate,
            "honey_executable_path": self.consumer,
            "champion_executable_path": self.consumer,
            "candidate_executable_path": self.consumer,
            "cwd": self.temp,
            "state": self.state,
            "schemas": SCHEMAS,
            "timeout_seconds": 10,
        }
        first = run_three_way(**arguments)
        second = run_three_way(**arguments)
        self.assertEqual(first, second)
        self.assertEqual(set(first["order"]), {"honey", "champion", "candidate"})
        self.assertEqual(
            [row["treatment"] for row in first["observations"]],
            ["honey", "champion", "candidate"],
        )
        unsigned = dict(first)
        claimed = unsigned.pop("three_way_result_id")
        self.assertEqual(claimed, canonical.identity(unsigned))

    def test_three_way_records_a_bounded_treatment_process_failure(self) -> None:
        honey, _ = self.write_assignment("honey.json", "honey", "c" * 40)
        champion, _ = self.write_assignment("champion.json", "champion", GIT_A)
        candidate, _ = self.write_assignment("candidate.json", "candidate", GIT_B)
        for assignment_path in (honey, champion, candidate):
            value = canonical.load_file(assignment_path)
            value["intelligence_profile"] = "balanced.v1"
            assignment_path.write_bytes(canonical.canonical_bytes(value))
        failed = self.temp / "failed.py"
        failed.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            "sys.stderr.write('cigarbench consumer rejected the observation: "
            "ingestCatalog:api-1400\\n')\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        failed.chmod(0o555)
        result = run_three_way(
            honey_assignment_path=honey,
            champion_assignment_path=champion,
            candidate_assignment_path=candidate,
            honey_executable_path=failed,
            champion_executable_path=self.consumer,
            candidate_executable_path=self.consumer,
            cwd=self.temp,
            state=self.state,
            schemas=SCHEMAS,
            timeout_seconds=10,
        )
        self.assertEqual(result["status"], "completed-with-treatment-failures")
        self.assertEqual(
            result["outcomes"]["honey"]["failure"]["failure_code"],
            "ingestCatalog:api-1400",
        )
        self.assertIsNone(result["observation_ids"]["honey"])
        self.assertEqual(
            [row["treatment"] for row in result["observations"]],
            ["champion", "candidate"],
        )

    def test_profile_three_way_records_failures_and_closes_transitions(self) -> None:
        paths = {}
        profiles = {
            "honey": "balanced.v1",
            "champion": "balanced.v2-candidate.1",
            "candidate": "balanced.v2-candidate.1",
        }
        for treatment in ("honey", "champion", "candidate"):
            path, _ = self.write_assignment(
                f"profile-{treatment}.json", treatment, GIT_A
            )
            value = canonical.load_file(path)
            value["intelligence_profile"] = profiles[treatment]
            path.write_bytes(canonical.canonical_bytes(value))
            paths[treatment] = path
        failed = self.temp / "profile-failed.py"
        failed.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            "sys.stderr.write('cigarbench consumer rejected the observation: "
            "ingestCatalog:api-1400\\n')\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        failed.chmod(0o555)
        arguments = {
            "honey_assignment_path": paths["honey"],
            "champion_assignment_path": paths["champion"],
            "candidate_assignment_path": paths["candidate"],
            "honey_executable_path": failed,
            "champion_executable_path": self.consumer,
            "candidate_executable_path": self.consumer,
            "cwd": self.temp,
            "state": self.state,
            "schemas": SCHEMAS,
            "timeout_seconds": 10,
        }
        with self.assertRaisesRegex(ConsumerError, "frozen balanced.v1"):
            run_three_way(**arguments)
        result = run_profile_three_way(**arguments)
        self.assertEqual(result["status"], "completed-with-treatment-failures")
        self.assertEqual(
            result["outcomes"]["honey"]["failure"]["failure_code"],
            "ingestCatalog:api-1400",
        )
        self.assertEqual(
            [row["treatment"] for row in result["observations"]],
            ["champion", "candidate"],
        )
        candidate = canonical.load_file(paths["candidate"])
        candidate["intelligence_profile"] = "balanced.v1"
        paths["candidate"].write_bytes(canonical.canonical_bytes(candidate))
        with self.assertRaisesRegex(ConsumerError, "sequentially allowed"):
            run_profile_three_way(**arguments)

    def test_noncanonical_duplicate_and_oracle_assignments_fail_closed(self) -> None:
        path, payload = self.write_assignment("assignment.json", "candidate", GIT_B)
        path.write_bytes(payload + b"\n")
        with self.assertRaisesRegex(ConsumerError, "canonical"):
            load_assignment(path, self.registry)
        path.write_bytes(
            b'{"schema_version":"cigar.benchmark-assignment.v2",'
            b'"schema_version":"cigar.benchmark-assignment.v2"}'
        )
        with self.assertRaisesRegex(ConsumerError, "strict JSON"):
            load_assignment(path, self.registry)
        value = self.assignment("candidate", GIT_B)
        value["oracle"] = CANARY
        path.write_bytes(canonical.canonical_bytes(value))
        with self.assertRaisesRegex(ConsumerError, "contract"):
            load_assignment(path, self.registry)
        substituted = self.assignment("candidate", GIT_B)
        substituted["archive_digest"] = MH
        path.write_bytes(canonical.canonical_bytes(substituted))
        with self.assertRaisesRegex(ConsumerError, "digest binding"):
            load_assignment(path, self.registry)
        alias = self.temp / "assignment-alias.json"
        alias.symlink_to(path)
        with self.assertRaisesRegex(ConsumerError, "non-symlink"):
            load_assignment(alias, self.registry)

    def test_incomplete_tampered_and_duplicate_observations_fail_closed(self) -> None:
        result = self.run_fixture_pair()
        candidate_path = self.temp / "candidate.json"
        assignment, assignment_bytes = load_assignment(candidate_path, self.registry)
        executable_digest = (
            "1220" + hashlib.sha256(self.consumer.read_bytes()).hexdigest()
        )
        observation = next(
            value
            for value in result["observations"]
            if value["treatment"] == "candidate"
        )
        incomplete = dict(observation)
        incomplete.pop("artifacts")
        with self.assertRaisesRegex(ConsumerError, "schema"):
            validate_observation(
                canonical.canonical_bytes(incomplete) + b"\n",
                assignment=assignment,
                assignment_bytes=assignment_bytes,
                executable_digest=executable_digest,
                registry=self.registry,
            )
        tampered = copy.deepcopy(observation)
        tampered["artifacts"][0]["digest"] = MH
        body = dict(tampered)
        body.pop("observation_id")
        tampered["observation_id"] = canonical.identity(body)
        with self.assertRaisesRegex(ConsumerError, "artifact binding"):
            validate_observation(
                canonical.canonical_bytes(tampered) + b"\n",
                assignment=assignment,
                assignment_bytes=assignment_bytes,
                executable_digest=executable_digest,
                registry=self.registry,
            )
        encoded = canonical.canonical_bytes(observation)
        duplicate = encoded[:-1] + b',"status":"completed"}\n'
        with self.assertRaisesRegex(ConsumerError, "strict JSON"):
            validate_observation(
                duplicate,
                assignment=assignment,
                assignment_bytes=assignment_bytes,
                executable_digest=executable_digest,
                registry=self.registry,
            )

    def test_mismatched_pair_and_oversized_output_fail_closed(self) -> None:
        champion, _ = self.write_assignment("champion.json", "champion", GIT_A)
        changed = self.assignment("candidate", GIT_B)
        changed["task_id"] = "other-task"
        candidate = self.temp / "candidate.json"
        candidate.write_bytes(canonical.canonical_bytes(changed))
        with self.assertRaisesRegex(ConsumerError, "differ"):
            run_pair(
                champion_assignment_path=champion,
                candidate_assignment_path=candidate,
                champion_executable_path=self.consumer,
                candidate_executable_path=self.consumer,
                cwd=self.temp,
                state=self.state,
                schemas=SCHEMAS,
            )

        candidate.write_bytes(
            canonical.canonical_bytes(self.assignment("candidate", GIT_B))
        )
        flood = self.temp / "flood.py"
        flood.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(b'x' * 2048)\n",
            encoding="utf-8",
        )
        flood.chmod(0o555)
        with (
            mock.patch("tools.refinement.consumer.MAX_STDOUT_BYTES", 1024),
            self.assertRaisesRegex(ConsumerError, "output bound"),
        ):
            run_pair(
                champion_assignment_path=champion,
                candidate_assignment_path=candidate,
                champion_executable_path=flood,
                candidate_executable_path=self.consumer,
                cwd=self.temp,
                state=self.state,
                schemas=SCHEMAS,
                timeout_seconds=10,
            )

    def test_timeout_stderr_and_descendant_leaks_fail_closed(self) -> None:
        champion, _ = self.write_assignment("champion.json", "champion", GIT_A)
        candidate, _ = self.write_assignment("candidate.json", "candidate", GIT_B)
        common = {
            "champion_assignment_path": champion,
            "candidate_assignment_path": candidate,
            "candidate_executable_path": self.consumer,
            "cwd": self.temp,
            "state": self.state,
            "schemas": SCHEMAS,
        }

        timeout = self.temp / "timeout.py"
        timeout.write_text(
            "#!/usr/bin/env python3\n"
            "import sys,time\n"
            "sys.stdin.buffer.read()\n"
            "time.sleep(30)\n",
            encoding="utf-8",
        )
        timeout.chmod(0o555)
        with self.assertRaisesRegex(ConsumerError, "time bound"):
            run_pair(
                champion_executable_path=timeout,
                timeout_seconds=1,
                **common,
            )

        stderr = self.temp / "stderr.py"
        stderr.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            "sys.stderr.write('content must not pass through')\n",
            encoding="utf-8",
        )
        stderr.chmod(0o555)
        with self.assertRaisesRegex(ConsumerError, "emitted stderr"):
            run_pair(
                champion_executable_path=stderr,
                timeout_seconds=10,
                **common,
            )

        leak = self.temp / "leak.py"
        leak.write_text(
            "#!/usr/bin/env python3\n"
            "import subprocess,sys\n"
            "sys.stdin.buffer.read()\n"
            "subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'])\n",
            encoding="utf-8",
        )
        leak.chmod(0o555)
        with self.assertRaisesRegex(ConsumerError, "descendant"):
            run_pair(
                champion_executable_path=leak,
                timeout_seconds=10,
                **common,
            )

    def test_v1_benchmark_entrypoints_remain_present(self) -> None:
        self.assertTrue((ROOT / "benches/cigarbench/cigarbench.py").is_file())
        self.assertTrue(
            (ROOT / "benches/cigarbench/schemas/raw-event-v1.schema.json").is_file()
        )
        self.assertTrue(
            (ROOT / "benches/cigarbench/tests/test_cigarbench.py").is_file()
        )

    def test_real_rust_consumer_replays_without_canary_disclosure(self) -> None:
        configured = os.environ.get("CIGARBENCH_CONSUMER")
        if configured is None:
            self.skipTest("set CIGARBENCH_CONSUMER for production-path qualification")
        executable = Path(configured)
        if not executable.is_absolute():
            self.fail("CIGARBENCH_CONSUMER must be absolute")
        revision = os.environ.get("CIGARBENCH_SOURCE_REVISION", GIT_A)
        tree = os.environ.get("CIGARBENCH_SOURCE_TREE", revision)
        champion_value = self.assignment("champion", revision)
        candidate_value = self.assignment("candidate", revision)
        for value in (champion_value, candidate_value):
            value["source"]["tree"] = tree
            value["flows"] = {"effect": True, "handoff": True, "replay": True}
        champion = self.temp / "real-champion.json"
        candidate = self.temp / "real-candidate.json"
        champion.write_bytes(canonical.canonical_bytes(champion_value))
        candidate.write_bytes(canonical.canonical_bytes(candidate_value))
        arguments = {
            "champion_assignment_path": champion,
            "candidate_assignment_path": candidate,
            "champion_executable_path": executable,
            "candidate_executable_path": executable,
            "cwd": self.temp,
            "state": self.state,
            "schemas": SCHEMAS,
            "timeout_seconds": 60,
        }
        first = run_pair(**arguments)
        second = run_pair(**arguments)
        self.assertEqual(first, second)
        encoded = canonical.canonical_bytes(first)
        self.assertNotIn(CANARY.encode(), encoded)
        for observation in first["observations"]:
            self.assertEqual(
                {artifact["kind"] for artifact in observation["artifacts"]},
                {
                    "plan",
                    "bundle",
                    "manifest",
                    "explanation",
                    "materialization",
                    "handoff",
                    "effect",
                    "replay",
                },
            )
        for payload in (
            canonical.canonical_bytes(champion_value) + b"\n",
            canonical.canonical_bytes({**champion_value, "archive_digest": MH}),
            canonical.canonical_bytes({**champion_value, "oracle": CANARY}),
        ):
            rejected = subprocess.run(
                [str(executable)],
                cwd=self.temp,
                input=payload,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout, b"")
            self.assertNotIn(CANARY.encode(), rejected.stderr)

        malformed_archive = self.temp / "malformed-archive.json"
        archive_value = canonical.loads(self.archive_bytes)
        archive_value["files"].append(copy.deepcopy(archive_value["files"][0]))
        malformed_bytes = canonical.canonical_bytes(archive_value)
        malformed_archive.write_bytes(malformed_bytes)
        malformed_assignment = {
            **champion_value,
            "archive_path": str(malformed_archive),
            "archive_digest": canonical.multihash_bytes(malformed_bytes),
        }
        rejected = subprocess.run(
            [str(executable)],
            cwd=self.temp,
            input=canonical.canonical_bytes(malformed_assignment),
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, b"")
        self.assertNotIn(CANARY.encode(), rejected.stderr)


if __name__ == "__main__":
    unittest.main()
