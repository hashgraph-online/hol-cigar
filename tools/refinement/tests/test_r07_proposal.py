from __future__ import annotations

# ruff: noqa: E402

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.adapters import (
    AdapterError,
    CodexCliAdapter,
    OpenAICompatibleAdapter,
    OpenAIResponsesAdapter,
    PatchJsonAdapter,
    ProviderFailure,
    RecordedAdapter,
    SubprocessJsonlAdapter,
    validate_action,
)
from tools.refinement.canonical import canonical_bytes, identity, loads
from tools.refinement.commands import CommandRegistry, CommandSpec
from tools.refinement.proposal import (
    ProposalController,
    ProposalError,
    context_pack,
)
from tools.refinement.schema import SchemaRegistry


PATCH = """diff --git a/src/value.txt b/src/value.txt
index 257cc56..3bd1f0e 100644
--- a/src/value.txt
+++ b/src/value.txt
@@ -1 +1 @@
-honey
+refined
"""


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def action(
    kind: str,
    action_id: str,
    *,
    session_id: str = "replaced-at-start",
    **values: object,
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": "cigar.refinement-model-action.v1",
        "action_id": action_id,
        "session_id": session_id,
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
    record.update(values)
    return record


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.repository = self.root / "candidate"
        self.repository.mkdir()
        git(self.repository, "init", "-b", "main")
        git(self.repository, "config", "user.name", "CIGAR Test")
        git(self.repository, "config", "user.email", "cigar@example.invalid")
        (self.repository / "src").mkdir()
        (self.repository / "src/value.txt").write_text("honey\n", encoding="utf-8")
        (self.repository / "secret").mkdir()
        (self.repository / "secret/oracle.txt").write_text(
            "SEALED-CANARY\n", encoding="utf-8"
        )
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-m", "fixture")
        revision = git(self.repository, "rev-parse", "HEAD")
        tree = git(self.repository, "rev-parse", "HEAD^{tree}")
        unsigned = {
            "schema_version": "cigar.refinement-task-packet.v1",
            "packet_id": "1220" + "0" * 64,
            "champion": {"revision": revision, "tree": tree},
            "architecture_summary": "A harmless one-line development fixture.",
            "failure_cluster": "fixture-value",
            "hypothesis": "Replace the harmless fixture value.",
            "constraints": ["Do not read the sealed fixture."],
            "allowed_paths": ["src"],
            "forbidden_paths": ["secret"],
            "budgets": {
                "files": 1,
                "lines": 2,
                "turns": 8,
                "input_tokens": 10000,
                "output_tokens": 10000,
                "wall_seconds": 30,
                "cost_usd": 1,
            },
            "named_gates": [
                "fixture-pass",
                "fixture-fail",
                "fixture-fail-2",
                "fixture-fail-3",
            ],
            "public_examples": [],
            "prior_rejections": [],
            "required_final_schema": "schemas/refinement/model-action-v1.schema.json",
        }
        commitment = dict(unsigned)
        commitment.pop("packet_id")
        unsigned["packet_id"] = identity(commitment)
        self.packet = unsigned
        self.state_parent = self.root / "state"
        self.state_parent.mkdir()
        self.registry = CommandRegistry(
            (
                CommandSpec(
                    "fixture-pass",
                    (sys.executable, "-c", "raise SystemExit(0)"),
                    10,
                ),
                CommandSpec(
                    "fixture-fail",
                    (sys.executable, "-c", "raise SystemExit(1)"),
                    10,
                ),
                CommandSpec(
                    "fixture-fail-2",
                    (sys.executable, "-c", "raise SystemExit(1)"),
                    10,
                ),
                CommandSpec(
                    "fixture-fail-3",
                    (sys.executable, "-c", "raise SystemExit(1)"),
                    10,
                ),
            )
        )

    def controller(self, adapter: object) -> ProposalController:
        return ProposalController(
            worktree=self.repository,
            task_packet=self.packet,
            adapter=adapter,  # type: ignore[arg-type]
            registry=self.registry,
            command_state=self.state_parent / "command",
            context_resources={"architecture": b"public fixture context\n"},
        )

    def close(self) -> None:
        self.temporary.cleanup()


def patch_actions() -> list[dict[str, object]]:
    return [
        action("apply_patch", "patch-1", patch=PATCH),
        action("finish", "finish-1", summary="Harmless fixture refined."),
    ]


class ResponsesDouble:
    def __init__(self, sequence: list[dict[str, object]], secret: str | None = None):
        self.sequence = list(sequence)
        self.secret = secret
        self.calls = 0
        self.session_id: str | None = None
        self.request_bodies: list[bytes] = []

    def __call__(
        self, endpoint: str, headers: dict[str, str], body: bytes, timeout: int
    ) -> tuple[int, dict[str, str], bytes]:
        self.request_bodies.append(body)
        if self.secret is not None:
            assert headers["Authorization"] == "Bearer " + self.secret
            assert self.secret.encode() not in body
        request = loads(body)
        assert request["store"] is False
        assert "previous_response_id" not in request
        if self.calls:
            assert any(
                isinstance(item, dict) and item.get("type") == "function_call_output"
                for item in request["input"]
            )
        if self.calls == 0:
            envelope = loads(request["input"][0]["content"][0]["text"].encode())
            self.session_id = envelope["session_id"]
        selected = dict(self.sequence[self.calls])
        selected["session_id"] = self.session_id
        response = {
            "id": f"resp-{self.calls}",
            "output": [
                {
                    "type": "function_call",
                    "name": "model_action",
                    "call_id": f"call-{self.calls}",
                    "arguments": canonical_bytes(selected).decode(),
                }
            ],
            "usage": {"input_tokens": 3, "output_tokens": 2},
        }
        self.calls += 1
        return 200, {}, canonical_bytes(response)


class ProposalAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_schemas_profiles_prompts_and_context_pack_are_bound(self) -> None:
        registry = SchemaRegistry(ROOT / "schemas/refinement")
        profiles = json.loads(
            (ROOT / "refinement/profiles/proposal-adapters.v1.json").read_text()
        )
        self.assertEqual(len(profiles["profiles"]), 6)
        for profile in profiles["profiles"]:
            registry.validate("adapter-profile-v1.schema.json", profile)
        prompts = sorted((ROOT / "refinement/prompts").glob("*.md"))
        pack = context_pack(
            self.fixture.packet, [path.resolve(strict=True) for path in prompts], {}
        )
        registry.validate("context-pack-v1.schema.json", pack)
        self.assertEqual(
            sorted(pack["prompt_digests"]),
            sorted(profiles["profiles"][0]["prompt_digests"]),
        )

    def test_recorded_patch_only_local_and_hosted_have_identical_patch(self) -> None:
        digests: list[str] = []
        for adapter_factory in (
            lambda: RecordedAdapter(patch_actions()),
            lambda: PatchJsonAdapter(
                lambda packet: canonical_bytes(
                    {
                        "hypothesis": packet["hypothesis"],
                        "patch": PATCH,
                        "summary": "Harmless fixture refined.",
                    }
                )
            ),
            lambda: OpenAICompatibleAdapter(
                endpoint="http://127.0.0.1:9999/v1/responses",
                model="fixture-local",
                instructions="fixture",
                transport=ResponsesDouble(patch_actions()),
            ),
        ):
            fixture = Fixture()
            try:
                outcome = fixture.controller(adapter_factory()).run()
                digests.append(outcome["patch_digests"][0])
                self.assertEqual(
                    (fixture.repository / "src/value.txt").read_text(), "refined\n"
                )
            finally:
                fixture.close()
        secret = "credential-value-must-never-leak"
        double = ResponsesDouble(patch_actions(), secret)
        with mock.patch.dict(os.environ, {"CIGAR_R07_TEST_KEY": secret}):
            hosted = OpenAIResponsesAdapter(
                model="gpt-5.6-sol",
                instructions="fixture",
                credential_handle="CIGAR_R07_TEST_KEY",  # gitleaks:allow
                transport=double,
            )
            outcome = self.fixture.controller(hosted).run()
            digests.append(outcome["patch_digests"][0])
            self.assertNotIn(secret, json.dumps(hosted.describe()))
            self.assertNotIn(secret, json.dumps(outcome))
        self.assertEqual(len(set(digests)), 1)
        self.assertEqual(digests[0], hashlib.sha256(PATCH.encode()).hexdigest())

    def test_subprocess_jsonl_completes_same_fixture(self) -> None:
        script = self.fixture.root / "agent.py"
        script.write_text(
            "import json,sys\n"
            "start=json.loads(sys.stdin.readline()); sid=start['session_id']\n"
            f"patch={PATCH!r}\n"
            "base={'schema_version':'cigar.refinement-model-action.v1','session_id':sid,"
            "'query':None,'path':None,'start_line':None,'max_lines':None,'gate':None,"
            "'resource':None,'reason':None}\n"
            "print(json.dumps({**base,'action_id':'patch-1','kind':'apply_patch',"
            "'patch':patch,'summary':None}),flush=True)\n"
            "json.loads(sys.stdin.readline())\n"
            "print(json.dumps({**base,'action_id':'finish-1','kind':'finish',"
            "'patch':None,'summary':'done'}),flush=True)\n",
            encoding="utf-8",
        )
        adapter = SubprocessJsonlAdapter(
            Path(sys.executable).resolve(strict=True), (str(script),)
        )
        outcome = self.fixture.controller(adapter).run()
        self.assertEqual(
            outcome["patch_digests"], [hashlib.sha256(PATCH.encode()).hexdigest()]
        )

    def test_codex_cli_login_is_tool_isolated_and_usage_is_measured(self) -> None:
        script = self.fixture.root / "codex"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json,re,sys\n"
            "if sys.argv[1:] == ['login','status']:\n"
            " print('Logged in using fixture'); raise SystemExit(0)\n"
            'prompt=sys.stdin.read(); sid=re.search(r\'"session_id":"([^"]+)"\',prompt).group(1)\n'
            f"patch={PATCH!r}\n"
            "base={'schema_version':'cigar.refinement-model-action.v1','session_id':sid,"
            "'query':None,'path':None,'start_line':None,'max_lines':None,'gate':None,"
            "'resource':None,'reason':None}\n"
            "if 'tool_result' in prompt:\n"
            " action={**base,'action_id':'finish-1','kind':'finish','patch':None,"
            "'summary':'done'}\n"
            "else:\n"
            " action={**base,'action_id':'patch-1','kind':'apply_patch','patch':patch,"
            "'summary':None}\n"
            "events=[{'type':'thread.started','thread_id':'fixture-thread'},"
            "{'type':'turn.started'},"
            "{'type':'item.completed','item':{'type':'agent_message',"
            "'text':json.dumps(action,separators=(',',':'))}},"
            "{'type':'turn.completed','usage':{'input_tokens':7,'output_tokens':3,"
            "'cached_input_tokens':0}}]\n"
            "for event in events: print(json.dumps(event,separators=(',',':')))\n",
            encoding="utf-8",
        )
        script.chmod(0o555)
        adapter = CodexCliAdapter(
            executable=script.resolve(strict=True),
            model="gpt-5.6-sol",
            instructions="fixture",
        )
        outcome = self.fixture.controller(adapter).run()
        self.assertEqual(
            outcome["patch_digests"], [hashlib.sha256(PATCH.encode()).hexdigest()]
        )
        self.assertEqual(outcome["usage"]["adapter"], "codex-cli-tools-v1")
        self.assertEqual(outcome["usage"]["input_tokens"], 14)
        self.assertEqual(outcome["usage"]["output_tokens"], 6)

    def test_forbidden_read_and_arbitrary_gate_abort_without_disclosure(self) -> None:
        bad_read = RecordedAdapter(
            [
                action(
                    "read",
                    "read-1",
                    path="secret/oracle.txt",
                    start_line=1,
                    max_lines=10,
                ),
                action("finish", "finish", summary="should not finish"),
            ]
        )
        denied = self.fixture.controller(bad_read)
        with self.assertRaisesRegex(ProposalError, "outside allowed|forbidden"):
            denied.run()
        self.assertIsNotNone(denied.failed_usage)
        assert denied.failed_usage is not None
        self.assertEqual(denied.failed_usage["adapter"], "recorded-proposal-v1")
        self.assertEqual(denied.failed_usage["turns"], 1)
        self.assertNotIn(
            "SEALED-CANARY",
            json.dumps(
                self.fixture.controller(RecordedAdapter(patch_actions())).transcript
            ),
        )
        arbitrary = RecordedAdapter(
            [
                action("run_gate", "gate-1", gate="sh -c id"),
                action("finish", "finish", summary="should not finish"),
            ]
        )
        with self.assertRaisesRegex(ProposalError, "not present"):
            self.fixture.controller(arbitrary).run()

    def test_search_without_matches_returns_an_empty_passed_result(self) -> None:
        controller = self.fixture.controller(RecordedAdapter(patch_actions()))
        result = controller.execute(
            action(
                "search",
                "no-match",
                query="value-that-is-not-present",
                path="src",
            )
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["content_bytes"], 0)

    def test_two_distinct_repairs_allowed_but_repeat_or_third_aborts(self) -> None:
        allowed = RecordedAdapter(
            [
                action("run_gate", "g1", gate="fixture-fail"),
                action("run_gate", "g2", gate="fixture-fail-2"),
                action("finish", "finish", summary="bounded repairs completed"),
            ]
        )
        outcome = self.fixture.controller(allowed).run()
        self.assertEqual(outcome["repair_cycles"], 2)
        repeated = RecordedAdapter(
            [
                action("run_gate", "g1", gate="fixture-fail"),
                action("run_gate", "g2", gate="fixture-fail"),
                action("finish", "finish", summary="no"),
            ]
        )
        with self.assertRaisesRegex(ProposalError, "same focused-gate"):
            fixture = Fixture()
            try:
                fixture.controller(repeated).run()
            finally:
                fixture.close()
        third = RecordedAdapter(
            [
                action("run_gate", "g1", gate="fixture-fail"),
                action("run_gate", "g2", gate="fixture-fail-2"),
                action("run_gate", "g3", gate="fixture-fail-3"),
                action("finish", "finish", summary="no"),
            ]
        )
        with self.assertRaisesRegex(ProposalError, "repair-cycle limit"):
            fixture = Fixture()
            try:
                fixture.controller(third).run()
            finally:
                fixture.close()

    def test_malformed_actions_provider_failures_retry_and_redirect_status(
        self,
    ) -> None:
        malformed = action("finish", "finish", summary="done")
        malformed["unexpected"] = True
        with self.assertRaises(AdapterError):
            validate_action(malformed)
        session_packet = self.fixture.packet

        def duplicate_json(
            endpoint: str, headers: dict[str, str], body: bytes, timeout: int
        ) -> tuple[int, dict[str, str], bytes]:
            return 200, {}, b'{"id":"a","id":"b","output":[]}'

        duplicate = OpenAICompatibleAdapter(
            endpoint="http://127.0.0.1:9999/v1/responses",
            model="fixture",
            instructions="fixture",
            transport=duplicate_json,
        )
        session = duplicate.start(session_packet)
        with self.assertRaisesRegex(AdapterError, "strict JSON"):
            duplicate.next(session)
        duplicate.cancel(session)
        calls = 0

        def retry(
            endpoint: str, headers: dict[str, str], body: bytes, timeout: int
        ) -> tuple[int, dict[str, str], bytes]:
            nonlocal calls
            calls += 1
            if calls < 3:
                return 503, {}, b"{}"
            request = loads(body)
            envelope = loads(request["input"][0]["content"][0]["text"].encode())
            final = action(
                "finish", "finish", session_id=envelope["session_id"], summary="done"
            )
            return (
                200,
                {},
                canonical_bytes(
                    {
                        "id": "response",
                        "output": [
                            {
                                "type": "function_call",
                                "name": "model_action",
                                "call_id": "call",
                                "arguments": canonical_bytes(final).decode(),
                            }
                        ],
                    }
                ),
            )

        adapter = OpenAICompatibleAdapter(
            endpoint="http://127.0.0.1:9999/v1/responses",
            model="fixture",
            instructions="fixture",
            transport=retry,
            maximum_retries=2,
        )
        outcome = self.fixture.controller(adapter).run()
        self.assertEqual(outcome["terminal_kind"], "finish")
        self.assertEqual(calls, 3)

        def redirect(*args: object) -> tuple[int, dict[str, str], bytes]:
            return 307, {"Location": "https://evil.invalid"}, b""

        bad = OpenAICompatibleAdapter(
            endpoint="http://127.0.0.1:9999/v1/responses",
            model="fixture",
            instructions="fixture",
            transport=redirect,
        )
        with self.assertRaisesRegex(ProviderFailure, "HTTP 307"):
            self.fixture.controller(bad).run()

    def test_endpoint_and_turn_limits_are_closed(self) -> None:
        with self.assertRaises(AdapterError):
            OpenAICompatibleAdapter(
                endpoint="http://example.com/v1/responses",
                model="bad",
                instructions="bad",
            )
        limited = RecordedAdapter(
            [
                action("inspect_git", "a1", query="status"),
                action("finish", "a2", summary="done"),
            ],
            maximum_turns=1,
        )
        with self.assertRaisesRegex(AdapterError, "turn limit"):
            self.fixture.controller(limited).run()


if __name__ == "__main__":
    unittest.main()
