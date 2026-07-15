from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "run_matrix", ROOT / "tools" / "quality" / "run_matrix.py"
)
assert SPEC is not None and SPEC.loader is not None
run_matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_matrix
SPEC.loader.exec_module(run_matrix)


def matrix(case: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "cigar.test-matrix.v1",
        "suite": "runner-self-test",
        "description": "Runner self test.",
        "cases": [case],
    }


def valid_case() -> dict[str, object]:
    return {
        "id": "SELF-001",
        "title": "A passing child.",
        "command": ["python3", "-c", "raise SystemExit(0)"],
        "timeout_seconds": 10,
        "profiles": ["local", "release"],
        "platforms": ["linux", "macos", "windows"],
        "requirements": ["VER-EVIDENCE-001"],
        "isolate_home": True,
    }


class MatrixRunnerTests(unittest.TestCase):
    def write_matrix(self, directory: Path, document: dict[str, object]) -> Path:
        path = directory / "matrix.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def evidence_arguments(
        self,
        *,
        profile: str = "release",
        evidence_dir: Path | None = None,
        output: Path = run_matrix.DEFAULT_OUTPUT,
        log_dir: Path | None = None,
        require_evidence: bool = False,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            profile=profile,
            evidence_dir=evidence_dir,
            output=output,
            log_dir=log_dir,
            require_evidence=require_evidence,
        )

    def test_valid_matrix_executes_and_emits_content_free_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            source = self.write_matrix(directory, matrix(valid_case()))
            loaded = run_matrix.load_matrix(source)
            result = run_matrix.run_case(
                ROOT,
                loaded.document["suite"],
                "local",
                loaded.document["cases"][0],
                None,
            )
            self.assertEqual(result["status"], "passed")
            self.assertNotIn("command", result)
            self.assertEqual(result["stdout"]["bytes"], 0)
            self.assertEqual(result["canary_scan"], "passed")

    def test_source_identity_fails_closed_without_a_git_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            identity = run_matrix.source_identity(Path(raw))
            self.assertEqual(identity["kind"], "workspace")
            self.assertIsNone(identity["revision"])
            self.assertFalse(identity["committed"])
            self.assertFalse(identity["clean"])

    def test_canary_output_is_a_hard_failure_without_serializing_it(self) -> None:
        case = valid_case()
        case["command"] = [
            "python3",
            "-c",
            "import os; print(os.environ['CIGAR_TEST_SECRET_CANARY'])",
        ]
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            source = self.write_matrix(directory, matrix(case))
            loaded = run_matrix.load_matrix(source)
            result = run_matrix.run_case(
                ROOT,
                loaded.document["suite"],
                "local",
                loaded.document["cases"][0],
                None,
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_kind"], "canary-leak")
            self.assertNotIn(run_matrix.SYNTHETIC_CANARY, json.dumps(result))

    def test_missing_required_environment_fails_closed(self) -> None:
        case = valid_case()
        case["required_environment"] = ["CIGAR_RUNNER_TEST_MISSING"]
        os.environ.pop("CIGAR_RUNNER_TEST_MISSING", None)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            source = self.write_matrix(directory, matrix(case))
            loaded = run_matrix.load_matrix(source)
            result = run_matrix.run_case(
                ROOT,
                loaded.document["suite"],
                "release",
                loaded.document["cases"][0],
                None,
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_kind"], "missing-required-environment")

    def test_child_environment_always_forces_cargo_offline(self) -> None:
        with mock.patch.dict(os.environ, {"CARGO_NET_OFFLINE": "false"}):
            environment = run_matrix.sanitized_environment(
                "runner-self-test", "local", isolated_home=None
            )
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")

    def test_receipted_execution_withholds_the_evidence_root_from_children(
        self,
    ) -> None:
        case = valid_case()
        case["command"] = [
            "python3",
            "-c",
            "import os; raise SystemExit(1 if 'CIGAR_EVIDENCE_DIR' in os.environ else 0)",
        ]
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": "/private/external-evidence"}
        ):
            result = run_matrix.run_case(
                ROOT,
                "runner-self-test",
                "local",
                case,
                None,
                isolate_evidence_environment=True,
            )
        self.assertEqual(result["status"], "passed")

    def test_offline_cargo_preflight_fails_once_without_disclosing_output(self) -> None:
        protected = b"private registry diagnostic and path"
        capture = run_matrix.CommandCapture(
            exit_code=102,
            stdout=b"",
            stderr=protected,
            timed_out=False,
        )
        case = valid_case()
        case["command"] = ["cargo", "nextest", "run", "--locked", "-p", "cigar-canon"]
        with mock.patch.object(
            run_matrix, "run_captured_command", return_value=capture
        ) as command:
            with self.assertRaises(run_matrix.MatrixError) as raised:
                run_matrix.preflight_offline_cargo(ROOT, [case])
        message = str(raised.exception)
        self.assertNotIn(protected.decode("utf-8"), message)
        self.assertIn(run_matrix.sha256_bytes(protected), message)
        invoked = command.call_args.args[0]
        self.assertEqual(invoked[:2], ["cargo", "metadata"])
        self.assertIn("--offline", invoked)
        self.assertEqual(
            command.call_args.kwargs["environment"]["CARGO_NET_OFFLINE"], "true"
        )

    def test_non_cargo_selection_skips_cargo_preflight(self) -> None:
        with mock.patch.object(run_matrix, "run_captured_command") as command:
            run_matrix.preflight_offline_cargo(ROOT, [valid_case()])
        command.assert_not_called()

    def test_cargo_cache_preparation_is_separate_and_content_free(self) -> None:
        protected = b"private fetch output"
        capture = run_matrix.CommandCapture(
            exit_code=1,
            stdout=protected,
            stderr=b"private fetch error",
            timed_out=False,
        )
        with mock.patch.object(
            run_matrix, "run_captured_command", return_value=capture
        ) as command:
            with self.assertRaises(run_matrix.MatrixError) as raised:
                run_matrix.prepare_cargo_cache(ROOT)
        message = str(raised.exception)
        self.assertNotIn(protected.decode("utf-8"), message)
        self.assertIn(run_matrix.sha256_bytes(protected), message)
        self.assertEqual(command.call_args.args[0], ["cargo", "fetch", "--locked"])

    def test_unsorted_duplicate_unknown_and_skip_contracts_are_rejected(self) -> None:
        bad_cases: list[dict[str, object]] = []
        unknown = valid_case()
        unknown["unexpected"] = True
        bad_cases.append(matrix(unknown))
        skipped = valid_case()
        skipped["command"] = ["cargo", "test", "--ignored"]
        bad_cases.append(matrix(skipped))
        empty_selection_prone = valid_case()
        empty_selection_prone["command"] = ["cargo", "test", "some_filter"]
        bad_cases.append(matrix(empty_selection_prone))
        duplicate = matrix(valid_case())
        duplicate["cases"] = [valid_case(), valid_case()]
        bad_cases.append(duplicate)
        unsorted = matrix(valid_case())
        second = valid_case()
        second["id"] = "AAA-001"
        unsorted["cases"] = [valid_case(), second]
        bad_cases.append(unsorted)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for index, document in enumerate(bad_cases):
                with self.subTest(index=index):
                    source = self.write_matrix(directory, document)
                    with self.assertRaises(run_matrix.MatrixError):
                        run_matrix.load_matrix(source)

    def test_security_matrix_contains_the_complete_mcp_gate(self) -> None:
        loaded = run_matrix.load_matrix(ROOT / "tests/security/matrix-v1.json")
        cases = {case["id"]: case for case in loaded.document["cases"]}
        self.assertIn("SEC-MCP-001", cases)
        mcp = cases["SEC-MCP-001"]
        self.assertEqual(
            mcp["command"],
            [
                "cargo",
                "nextest",
                "run",
                "--locked",
                "--config-file",
                ".config/nextest.toml",
                "--user-config-file",
                "none",
                "-P",
                "macos-qualification",
                "--no-tests",
                "fail",
                "-p",
                "cigar-mcp",
                "--all-targets",
            ],
        )
        self.assertEqual(mcp["profiles"], ["local", "release"])
        self.assertEqual(mcp["platforms"], ["linux", "macos", "windows"])
        self.assertEqual(
            mcp["requirements"],
            ["SEC-INPUT-001", "SEC-RESOURCE-001", "VER-CANCEL-001"],
        )
        historical = cases["SEC-MCP-002"]
        self.assertEqual(
            historical["command"],
            ["python3", "tools/quality/historical_crashes.py", "run"],
        )
        self.assertEqual(historical["profiles"], ["local", "release"])
        self.assertEqual(historical["platforms"], ["macos"])
        self.assertEqual(
            historical["requirements"],
            ["SEC-INPUT-001", "VER-HERMETIC-001"],
        )

    def test_compatibility_matrix_contains_the_complete_local_interface_gate(
        self,
    ) -> None:
        loaded = run_matrix.load_matrix(ROOT / "tests/compatibility/matrix-v1.json")
        cases = {case["id"]: case for case in loaded.document["cases"]}
        self.assertEqual(
            {
                "COMPAT-API-001",
                "COMPAT-GO-001",
                "COMPAT-LOCAL-IPC-001",
                "COMPAT-PYTHON-001",
                "COMPAT-RUST-001",
                "COMPAT-TYPESCRIPT-001",
            }
            - cases.keys(),
            set(),
        )
        vector_cases = {
            case_id: cases[case_id]["command"]
            for case_id in (
                "COMPAT-VECTORS-GO-001",
                "COMPAT-VECTORS-PYTHON-001",
                "COMPAT-VECTORS-RUST-001",
                "COMPAT-VECTORS-TYPESCRIPT-001",
            )
        }
        self.assertEqual(
            {command[0] for command in vector_cases.values()},
            {"cargo", "corepack", "go", "uv"},
        )
        self.assertTrue(
            all(command[:2] != ["cargo", "xtask"] for command in vector_cases.values())
        )
        local_ipc = cases["COMPAT-LOCAL-IPC-001"]
        self.assertEqual(local_ipc["platforms"], ["macos"])
        self.assertEqual(
            local_ipc["command"],
            [
                "cargo",
                "nextest",
                "run",
                "--locked",
                "--config-file",
                ".config/nextest.toml",
                "--user-config-file",
                "none",
                "-P",
                "macos-qualification",
                "--no-tests",
                "fail",
                "-p",
                "cigar-daemon",
                "--lib",
                "-E",
                "test(=server::tests::macos_unix_socket_routes_all_45_operations_through_the_generated_contract)",
            ],
        )

    def test_xtask_quality_matrix_inventory_is_exact_real_and_strict_serial(
        self,
    ) -> None:
        matrices = {
            "chaos": (ROOT / "tests/chaos/matrix-v1.json", 7, 6),
            "compatibility": (
                ROOT / "tests/compatibility/matrix-v1.json",
                13,
                13,
            ),
            "e2e": (ROOT / "tests/e2e/matrix-v1.json", 3, 3),
            "integration": (ROOT / "tests/integration/matrix-v1.json", 7, 7),
            "migration": (ROOT / "tests/migration/matrix-v1.json", 13, 12),
            "models": (ROOT / "tests/models/matrix-v1.json", 1, 1),
            "offline": (ROOT / "tests/offline/matrix-v1.json", 4, 4),
            "security": (ROOT / "tests/security/matrix-v1.json", 12, 12),
        }
        forbidden_arguments = {
            "--ignored",
            "--include-ignored",
            "--no-run",
            "--skip",
        }
        forbidden_tokens = {
            "cigar-soak",
            "cargo-fuzz",
            "mutation",
            "mutations",
            "coverage",
        }
        strict_suffix = [
            "--user-config-file",
            "none",
            "-P",
            "macos-qualification",
            "--no-tests",
            "fail",
        ]
        seen_suites: set[str] = set()
        for expected_suite, (path, expected_total, expected_local) in matrices.items():
            with self.subTest(suite=expected_suite):
                loaded = run_matrix.load_matrix(path)
                self.assertEqual(loaded.document["suite"], expected_suite)
                self.assertEqual(len(loaded.document["cases"]), expected_total)
                self.assertNotIn(loaded.document["suite"], seen_suites)
                seen_suites.add(loaded.document["suite"])
                local_cases = [
                    case
                    for case in loaded.document["cases"]
                    if "local" in case["profiles"] and "macos" in case["platforms"]
                ]
                self.assertEqual(len(local_cases), expected_local)
                self.assertGreater(len(local_cases), 0)
                for case in local_cases:
                    command = case["command"]
                    self.assertTrue(forbidden_arguments.isdisjoint(command))
                    rendered_tokens = [token.lower() for token in command]
                    self.assertFalse(
                        any(
                            token in forbidden_tokens or token.startswith("fuzz/")
                            for token in rendered_tokens
                        ),
                        f"{case['id']} invokes an excluded tranche",
                    )
                    if command[:3] == ["cargo", "nextest", "run"]:
                        self.assertIn("--locked", command)
                        config = (
                            "tests/properties/.config/nextest.toml"
                            if expected_suite == "models"
                            else ".config/nextest.toml"
                        )
                        strict = ["--config-file", config, *strict_suffix]
                        for offset in range(len(command) - len(strict) + 1):
                            if command[offset : offset + len(strict)] == strict:
                                break
                        else:
                            self.fail(
                                f"{case['id']} lacks exact strict serial Nextest arguments"
                            )

        policy = (ROOT / ".config/nextest.toml").read_text(encoding="utf-8")
        profile = policy.split("[profile.macos-qualification]", maxsplit=1)[1]
        profile = profile.split("\n[", maxsplit=1)[0]
        self.assertIn('inherits = "ci"', profile)
        self.assertIn("test-threads = 1", profile)
        ci_profile = policy.split("[profile.ci]", maxsplit=1)[1]
        ci_profile = ci_profile.split("\n[", maxsplit=1)[0]
        self.assertIn("retries = 0", ci_profile)
        self.assertIn('leak-timeout = { period = "2s", result = "fail" }', ci_profile)
        properties_policy = (ROOT / "tests/properties/.config/nextest.toml").read_text(
            encoding="utf-8"
        )
        properties_profile = properties_policy.split(
            "[profile.macos-qualification]", maxsplit=1
        )[1]
        properties_profile = properties_profile.split("\n[", maxsplit=1)[0]
        self.assertIn('inherits = "ci"', properties_profile)
        self.assertIn("test-threads = 1", properties_profile)

    def test_local_matrix_selection_excludes_external_shared_service_scripts(
        self,
    ) -> None:
        for relative in [
            "tests/chaos/matrix-v1.json",
            "tests/migration/matrix-v1.json",
        ]:
            loaded = run_matrix.load_matrix(ROOT / relative)
            local = [
                case
                for case in loaded.document["cases"]
                if "local" in case["profiles"] and "macos" in case["platforms"]
            ]
            self.assertTrue(local)
            self.assertTrue(all(case["command"][0] != "bash" for case in local))
            self.assertTrue(all("SHARED" not in case["id"] for case in local))

    def test_release_requires_one_explicit_external_evidence_directory(self) -> None:
        arguments = self.evidence_arguments()
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                run_matrix.MatrixError, "release profile requires"
            ):
                run_matrix.selected_evidence_directory(arguments)

            arguments.evidence_dir = Path("relative/evidence")
            with self.assertRaisesRegex(run_matrix.MatrixError, "absolute path"):
                run_matrix.selected_evidence_directory(arguments)

    def test_argument_and_environment_evidence_locations_must_not_conflict(
        self,
    ) -> None:
        arguments = self.evidence_arguments(evidence_dir=Path("/private/one"))
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": "/private/two"}, clear=True
        ):
            with self.assertRaisesRegex(run_matrix.MatrixError, "conflicts"):
                run_matrix.selected_evidence_directory(arguments)

        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": "/private/one"}, clear=True
        ):
            self.assertEqual(
                run_matrix.selected_evidence_directory(arguments),
                Path("/private/one"),
            )

    def test_local_profile_retains_legacy_output_when_no_workspace_is_set(self) -> None:
        arguments = self.evidence_arguments(profile="local")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(run_matrix.selected_evidence_directory(arguments))

    def test_xtask_local_profile_can_require_external_evidence(self) -> None:
        arguments = self.evidence_arguments(profile="local", require_evidence=True)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(run_matrix.MatrixError, "execution requires"):
                run_matrix.selected_evidence_directory(arguments)

    @unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
    def test_external_workspace_publishes_canonical_owner_only_create_new_json(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            evidence = Path(raw).resolve() / "evidence"
            arguments = self.evidence_arguments(evidence_dir=evidence)
            with mock.patch.dict(os.environ, {}, clear=True):
                workspace = run_matrix.open_evidence_workspace(arguments, ROOT)
            self.assertIsNotNone(workspace)
            assert workspace is not None
            try:
                run_matrix.write_matrix_result(
                    arguments, {"status": "passed"}, workspace
                )
            finally:
                workspace.close()

            output = evidence / run_matrix.DEFAULT_OUTPUT
            self.assertEqual(json.loads(output.read_bytes()), {"status": "passed"})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)

            with mock.patch.dict(os.environ, {}, clear=True):
                second = run_matrix.open_evidence_workspace(arguments, ROOT)
            self.assertIsNotNone(second)
            assert second is not None
            try:
                with self.assertRaisesRegex(run_matrix.MatrixError, "overwrite"):
                    run_matrix.write_matrix_result(
                        arguments, {"status": "failed"}, second
                    )
            finally:
                second.close()
            self.assertEqual(json.loads(output.read_bytes()), {"status": "passed"})

    @unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
    def test_workspace_rejects_repository_paths_symlinks_and_public_modes(self) -> None:
        internal = self.evidence_arguments(evidence_dir=ROOT / "reports" / "evidence")
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(run_matrix.MatrixError, "outside"):
                run_matrix.open_evidence_workspace(internal, ROOT)

        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            target = base / "target"
            target.mkdir(mode=0o700)
            alias = base / "alias"
            alias.symlink_to(target, target_is_directory=True)
            symlinked = self.evidence_arguments(evidence_dir=alias)
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(run_matrix.MatrixError, "unsafe"):
                    run_matrix.open_evidence_workspace(symlinked, ROOT)

            public = base / "public"
            public.mkdir(mode=0o755)
            os.chmod(public, 0o755)
            public_arguments = self.evidence_arguments(evidence_dir=public)
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(run_matrix.MatrixError, "0700"):
                    run_matrix.open_evidence_workspace(public_arguments, ROOT)

    @unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
    def test_workspace_rejects_output_escape_collision_and_private_logs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            evidence = base / "evidence"
            escaping = self.evidence_arguments(
                evidence_dir=evidence, output=Path("../escaped.json")
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(run_matrix.MatrixError, "evidence path"):
                    run_matrix.open_evidence_workspace(escaping, ROOT)

            logging = self.evidence_arguments(
                evidence_dir=evidence, log_dir=base / "logs"
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(run_matrix.MatrixError, "content-free"):
                    run_matrix.open_evidence_workspace(logging, ROOT)

            first_arguments = self.evidence_arguments(
                evidence_dir=evidence, output=Path("Result.json")
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                first = run_matrix.open_evidence_workspace(first_arguments, ROOT)
            self.assertIsNotNone(first)
            assert first is not None
            try:
                run_matrix.write_matrix_result(first_arguments, {"ok": True}, first)
            finally:
                first.close()

            collision_arguments = self.evidence_arguments(
                evidence_dir=evidence, output=Path("result.json")
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                collision = run_matrix.open_evidence_workspace(
                    collision_arguments, ROOT
                )
            self.assertIsNotNone(collision)
            assert collision is not None
            try:
                with self.assertRaisesRegex(run_matrix.MatrixError, "collision"):
                    run_matrix.write_matrix_result(
                        collision_arguments, {"ok": False}, collision
                    )
            finally:
                collision.close()

    @unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
    def test_clean_release_is_eligible_but_local_receipts_remain_ineligible(
        self,
    ) -> None:
        case = valid_case()
        loaded = run_matrix.LoadedMatrix(
            path=ROOT / "packaging" / "test-matrix.v1.json",
            digest="a" * 64,
            document=matrix(case),
        )
        clean_source = {
            "kind": "git",
            "revision": "b" * 40,
            "committed": True,
            "clean": True,
        }
        with tempfile.TemporaryDirectory() as raw:
            for profile, eligible in [("local", False), ("release", True)]:
                evidence = Path(raw).resolve() / f"{profile}-evidence"
                arguments = SimpleNamespace(
                    root=ROOT,
                    matrix=loaded.path,
                    output=run_matrix.DEFAULT_OUTPUT,
                    evidence_dir=evidence,
                    profile=profile,
                    case=None,
                    validate_only=False,
                    prepare_cargo_cache=False,
                    log_dir=None,
                    require_evidence=True,
                    isolate_evidence_environment=True,
                )
                with (
                    mock.patch.dict(os.environ, {}, clear=True),
                    mock.patch.object(run_matrix, "load_matrix", return_value=loaded),
                    mock.patch.object(
                        run_matrix, "source_identity", return_value=clean_source
                    ),
                    mock.patch.object(
                        run_matrix, "host_platform", return_value="macos"
                    ),
                    mock.patch.object(run_matrix, "preflight_offline_cargo"),
                    mock.patch.object(
                        run_matrix,
                        "run_case",
                        return_value={"id": "SELF-001", "status": "passed"},
                    ),
                ):
                    self.assertEqual(run_matrix.execute(arguments), 0)
                document = json.loads(
                    (evidence / run_matrix.DEFAULT_OUTPUT).read_bytes()
                )
                self.assertEqual(document["profile"], profile)
                self.assertEqual(document["status"], "passed")
                self.assertEqual(document["release_eligible"], eligible)


if __name__ == "__main__":
    unittest.main()
