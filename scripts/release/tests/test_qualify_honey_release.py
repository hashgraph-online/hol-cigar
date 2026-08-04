from __future__ import annotations

import ast
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPTS = REPOSITORY_ROOT / "scripts" / "release"
if str(RELEASE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(RELEASE_SCRIPTS))

import qualify_honey_release as honey  # noqa: E402
from release_lib import ReleaseError, load_json  # noqa: E402


EXPECTED_ARTIFACTS = [
    ("source", "cigar-0.9.2-source.tar.gz"),
    ("docs", "cigar-0.9.2-docs.tar.gz"),
    (
        "schemas-conformance",
        "cigar-0.9.2-schemas-conformance.tar.gz",
    ),
    (
        "macos-runtime-aarch64",
        "cigar-0.9.2-aarch64-apple-darwin.tar.gz",
    ),
    ("typescript-sdk", "cigar-sdk-0.9.2.tgz"),
    ("python-sdk-wheel", "hol_cigar-0.9.2-py3-none-any.whl"),
    ("python-sdk-sdist", "hol_cigar-0.9.2.tar.gz"),
    (
        "rust-sdk-local-registry",
        "cigar-rust-sdk-0.9.2-local-registry.tar.gz",
    ),
    ("claude-code-plugin", "cigar-claude-code-0.9.2.tar.gz"),
    ("honey-demos", "cigar-honey-demos-0.9.2.tar.gz"),
    ("release-notes", "RELEASE_NOTES_HONEY_v0.9.2.md"),
    ("release-manifest", "honey-release-manifest.json"),
    ("checksums", "SHA256SUMS"),
]

EXPECTED_EVIDENCE_LOCATIONS = {
    "bounded-safety-report": ("gate-reports", "bounded-safety-report.json"),
    "claude-lifecycle-report": (
        "claude-qualification",
        "claude-code-plugin-installed-development-qualification.json",
    ),
    "documentation-report": ("docs-report", "documentation-report.json"),
    "efficiency-reliability-report": (
        "efficiency-qualification",
        "honey-efficiency-reliability-report.json",
    ),
    "installed-runtime-report": ("installed", "installed-runtime-report.json"),
    "license-inventory": (
        "static-reports",
        "third-party-license-inventory.v1.json",
    ),
    "offline-dependency-check": (
        "gate-reports",
        "offline-dependency-check.json",
    ),
    "other-demo-reports": ("demo-other", "other-demo-report.json"),
    "python-clean-install": ("python", "python-sdk-build-receipt.json"),
    "qualification-tools": ("static-reports", "conformance-result.v1.json"),
    "rust-clean-consumer": (
        "rust",
        "rust-sdk-local-registry-build-receipt.json",
    ),
    "secret-scan": ("gate-reports", "secret-scan.json"),
    "two-agent-demo-report": ("demo-two-agent", "two-agent-demo-report.json"),
    "typescript-clean-install": (
        "typescript",
        "typescript-sdk-build-receipt.json",
    ),
}


class HoneyParserAndDispatchTests(unittest.TestCase):
    def test_parser_exposes_only_the_four_bounded_subcommands(self) -> None:
        parser = honey._parser()
        for command in ("build", "qualify", "verify", "all"):
            with self.subTest(command=command):
                arguments = parser.parse_args(
                    [
                        "--root",
                        os.fspath(REPOSITORY_ROOT),
                        "--evidence-root",
                        "/private/tmp/cigar-honey-test",
                        "--source-date-epoch",
                        "1234",
                        command,
                    ]
                )
                self.assertEqual(arguments.command, command)
                self.assertEqual(
                    arguments.evidence_root, Path("/private/tmp/cigar-honey-test")
                )
                self.assertEqual(arguments.source_date_epoch, 1234)
                self.assertIsNone(arguments.efficiency_raw_observations)

        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    ["--evidence-root", "/private/tmp/cigar-honey-test", "publish"]
                )

    def test_main_dispatches_build_qualify_verify_and_all_without_other_actions(
        self,
    ) -> None:
        expected_calls = {
            "build": ["build"],
            "qualify": ["qualify"],
            "verify": ["verify"],
            "all": ["build", "qualify"],
        }
        for command, expected in expected_calls.items():
            with self.subTest(command=command):
                calls: list[str] = []

                def record(name: str):
                    def invoke(*_args: object, **_kwargs: object) -> dict[str, str]:
                        calls.append(name)
                        return {"status": name}

                    return invoke

                arguments = mock.Mock(
                    root=REPOSITORY_ROOT,
                    evidence_root=Path("/private/tmp/cigar-honey-test"),
                    source_date_epoch=None,
                    command=command,
                )
                external_root = mock.Mock(return_value=arguments.evidence_root)
                with (
                    mock.patch.object(honey, "parse_arguments", return_value=arguments),
                    mock.patch.object(honey, "_epoch", return_value=1234),
                    mock.patch.object(honey, "_external_root", external_root),
                    mock.patch.object(honey, "_build", side_effect=record("build")),
                    mock.patch.object(honey, "_qualify", side_effect=record("qualify")),
                    mock.patch.object(honey, "_verify", side_effect=record("verify")),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(honey.main(), 0)
                self.assertEqual(calls, expected)
                external_root.assert_called_once_with(
                    arguments.evidence_root,
                    REPOSITORY_ROOT,
                    create=command in {"build", "all"},
                )


class HoneyArtifactLayoutTests(unittest.TestCase):
    def test_matrix_and_control_projection_are_the_exact_thirteen_artifacts(
        self,
    ) -> None:
        matrix = load_json(REPOSITORY_ROOT / "packaging/honey/artifact-matrix.v1.json")
        observed = [(row["id"], row["filename"]) for row in matrix["artifacts"]]
        self.assertEqual(observed, EXPECTED_ARTIFACTS)
        self.assertEqual(len(observed), 13)

        layout = honey.Layout(Path("/private/tmp/cigar-honey-test"))
        self.assertEqual(
            honey._artifact_rows(layout, matrix),
            [
                {"id": identifier, "workspace": "candidate", "path": filename}
                for identifier, filename in EXPECTED_ARTIFACTS
            ],
        )

    def test_layout_uses_closed_nonoverlapping_workspace_names(self) -> None:
        root = Path("/private/tmp/cigar-honey-test")
        layout = honey.Layout(root)
        workspaces = {
            layout.portable_container,
            layout.portable,
            layout.native,
            layout.tools,
            layout.typescript,
            layout.python,
            layout.rust,
            layout.claude,
            layout.demos,
            layout.candidate,
            layout.source,
        }
        self.assertEqual(len(workspaces), 11)
        self.assertEqual(layout.portable, root / "portable" / "payload")
        self.assertEqual(layout.tools, root / "qualification-tools")
        self.assertEqual(layout.candidate, root / "candidate")
        self.assertTrue(all(path.is_relative_to(root) for path in workspaces))


class HoneyInstalledDemoTests(unittest.TestCase):
    def test_demo_commands_execute_the_runner_and_manifest_from_candidate_archive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(strict=True)
            layout = honey.Layout(root)
            layout.candidate.mkdir()
            for filename in (
                honey.RUNTIME_NAME,
                honey.PYTHON_WHEEL_NAME,
                honey.CLAUDE_NAME,
            ):
                (layout.candidate / filename).write_bytes(filename.encode("ascii"))
            commands: list[list[str]] = []

            def capture(
                _root: Path,
                command: list[str],
                **_kwargs: object,
            ) -> bytes:
                commands.append(command)
                return b""

            with mock.patch.object(honey, "_run", side_effect=capture):
                honey._run_demos(root, layout, {}, "/usr/bin/python3")

        self.assertEqual(len(commands), 2)
        expected_runner = os.fspath(
            layout.path("installed-demos") / "demos/run_honey.py"
        )
        expected_manifest = os.fspath(
            layout.path("installed-demos") / "demos/honey-manifest.v1.json"
        )
        for command in commands:
            self.assertEqual(command[:2], ["/usr/bin/python3", expected_runner])
            manifest_index = command.index("--manifest")
            self.assertEqual(command[manifest_index + 1], expected_manifest)
            self.assertNotIn(os.fspath(REPOSITORY_ROOT / "demos/run_honey.py"), command)

    def test_candidate_archive_extraction_is_bounded_regular_and_preserves_mode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            archive_path = base / "demos.tar.gz"
            payload = b"#!/usr/bin/env python3\n"
            with tarfile.open(archive_path, mode="w:gz") as archive:
                directory = tarfile.TarInfo("demos/")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                archive.addfile(directory)
                runner = tarfile.TarInfo("demos/run_honey.py")
                runner.size = len(payload)
                runner.mode = 0o755
                archive.addfile(runner, io.BytesIO(payload))
            target = base / "installed"
            honey._extract_candidate_archive(archive_path, target)
            installed = target / "demos/run_honey.py"
            self.assertEqual(installed.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o755)

    def test_candidate_archive_extraction_rejects_traversal_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            traversal = base / "traversal.tar.gz"
            with tarfile.open(traversal, mode="w:gz") as archive:
                member = tarfile.TarInfo("../escape")
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
            with self.assertRaisesRegex(ReleaseError, "unsafe path"):
                honey._extract_candidate_archive(traversal, base / "traversal-out")
            self.assertFalse((base / "escape").exists())

            linked = base / "linked.tar.gz"
            with tarfile.open(linked, mode="w:gz") as archive:
                member = tarfile.TarInfo("demos/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "run_honey.py"
                archive.addfile(member)
            with self.assertRaisesRegex(
                honey.HoneyQualificationError, "link or special"
            ):
                honey._extract_candidate_archive(linked, base / "linked-out")


class HoneyExternalRootTests(unittest.TestCase):
    def test_create_and_reopen_require_owner_private_external_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            evidence = base / "evidence"
            with mock.patch.object(honey.sys, "platform", "linux"):
                self.assertEqual(
                    honey._external_root(evidence, repository, create=True), evidence
                )
                self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
                self.assertEqual(
                    honey._external_root(evidence, repository, create=False), evidence
                )
                evidence.chmod(0o755)
                with self.assertRaisesRegex(
                    honey.HoneyQualificationError, "owner-private"
                ):
                    honey._external_root(evidence, repository, create=False)

    def test_relative_internal_existing_and_noncanonical_roots_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            existing = base / "existing"
            existing.mkdir(mode=0o700)
            with mock.patch.object(honey.sys, "platform", "linux"):
                with self.assertRaisesRegex(honey.HoneyQualificationError, "absolute"):
                    honey._external_root(Path("relative"), repository, create=True)
                with self.assertRaisesRegex(honey.HoneyQualificationError, "outside"):
                    honey._external_root(
                        repository / "evidence", repository, create=True
                    )
                with self.assertRaisesRegex(
                    honey.HoneyQualificationError, "create-new"
                ):
                    honey._external_root(existing, repository, create=True)
                with self.assertRaisesRegex(honey.HoneyQualificationError, "canonical"):
                    honey._external_root(
                        base / "missing-parent" / "evidence",
                        repository,
                        create=True,
                    )

    def test_symlinked_parent_cannot_redirect_creation_into_repository(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            redirect = base / "redirect"
            redirect.symlink_to(repository, target_is_directory=True)
            escaped = redirect / "evidence"
            with (
                mock.patch.object(honey.sys, "platform", "linux"),
                self.assertRaisesRegex(honey.HoneyQualificationError, "canonical"),
            ):
                honey._external_root(escaped, repository, create=True)
            self.assertFalse((repository / "evidence").exists())


class HoneySourceIdentityTests(unittest.TestCase):
    def test_child_environment_is_offline_deterministic_and_has_no_ambient_output(
        self,
    ) -> None:
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": "/tmp/ambient", "TZ": "ambient"},
            clear=True,
        ):
            environment = honey._environment(1_720_000_000)
        self.assertNotIn("CIGAR_EVIDENCE_DIR", environment)
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "1720000000")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["NPM_CONFIG_OFFLINE"], "true")
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertEqual(environment["UV_OFFLINE"], "1")
        self.assertEqual(environment["TZ"], "UTC")

    def test_source_identity_requires_clean_tree_and_reads_exact_commit_and_tree(
        self,
    ) -> None:
        responses = {
            ("status", "--porcelain=v1", "-z", "--untracked-files=all"): b"",
            ("rev-parse", "--verify", "HEAD^{commit}"): b"a" * 40 + b"\n",
            ("rev-parse", "--verify", "HEAD^{tree}"): b"b" * 40 + b"\n",
        }
        with mock.patch.object(
            honey, "_git", side_effect=lambda _root, *args: responses[args]
        ):
            self.assertEqual(
                honey._source_identity(REPOSITORY_ROOT), ("a" * 40, "b" * 40)
            )
        with mock.patch.object(honey, "_git", return_value=b"?? untracked\0"):
            with self.assertRaisesRegex(
                honey.HoneyQualificationError, "clean Git tree"
            ):
                honey._source_identity(REPOSITORY_ROOT)

    def test_epoch_is_commit_timestamp_and_rejects_supplied_mismatch(self) -> None:
        with mock.patch.object(honey, "_git", return_value=b"1720000000\n"):
            self.assertEqual(honey._epoch(REPOSITORY_ROOT, None), 1_720_000_000)
            self.assertEqual(
                honey._epoch(REPOSITORY_ROOT, 1_720_000_000), 1_720_000_000
            )
            with self.assertRaisesRegex(
                honey.HoneyQualificationError, "exact candidate commit timestamp"
            ):
                honey._epoch(REPOSITORY_ROOT, 1_720_000_001)


class HoneyEvidencePolicyTests(unittest.TestCase):
    def test_evidence_rows_have_closed_locations_schemas_and_authority_bindings(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            gate_root = Path(raw)
            tools = {
                "bounded-safety-report": {
                    "name": "bounded-runner",
                    "version": "1",
                    "database_updated_at": None,
                    "database_freshness": "not-applicable",
                    "offline": True,
                },
                "offline-dependency-check": {
                    "name": "offline-runner",
                    "version": "1",
                    "database_updated_at": None,
                    "database_freshness": "not-applicable",
                    "offline": True,
                },
                "secret-scan": {
                    "name": "secret-runner",
                    "version": "1",
                    "database_updated_at": "2026-07-14T00:00:00Z",
                    "database_freshness": "current",
                    "offline": True,
                },
            }
            filenames = {
                "bounded-safety-report": "bounded-safety-report.json",
                "offline-dependency-check": "offline-dependency-check.json",
                "secret-scan": "secret-scan.json",
            }
            for identifier, filename in filenames.items():
                (gate_root / filename).write_text(
                    json.dumps({"tool": tools[identifier]}), encoding="utf-8"
                )

            layout = honey.Layout(Path("/private/tmp/cigar-honey-test"))
            rows = honey._evidence_rows(
                REPOSITORY_ROOT,
                layout,
                gate_root,
                layout.path("static-reports"),
            )

        self.assertEqual(
            [row["id"] for row in rows], sorted(honey.honey_evidence.REQUIRED_EVIDENCE)
        )
        self.assertEqual(len(rows), 14)
        all_capabilities: set[str] = set()
        all_gates: set[str] = set()
        all_artifacts: set[str] = set()
        for row in rows:
            identifier = row["id"]
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    (row["workspace"], row["path"]),
                    EXPECTED_EVIDENCE_LOCATIONS[identifier],
                )
                self.assertEqual(
                    row["category"],
                    honey.honey_evidence.REQUIRED_EVIDENCE[identifier],
                )
                self.assertEqual(
                    row["schema_version"],
                    honey.honey_evidence.ACCEPTED_REPORT_SCHEMAS[identifier],
                )
                self.assertEqual(
                    row["artifact_ids"],
                    sorted(honey.honey_evidence.EVIDENCE_ARTIFACT_POLICY[identifier]),
                )
                self.assertEqual(
                    row["mandatory_gate_ids"],
                    sorted(honey.honey_evidence.EVIDENCE_GATE_POLICY[identifier]),
                )
                self.assertTrue(row["capability_ids"])
                if identifier in tools:
                    self.assertEqual(row["tool"], tools[identifier])
                elif row["category"] != "security":
                    self.assertIsNone(row["tool"])
                all_capabilities.update(row["capability_ids"])
                all_gates.update(row["mandatory_gate_ids"])
                all_artifacts.update(row["artifact_ids"])

        profile = load_json(
            REPOSITORY_ROOT / "packaging/honey/capability-profile.v1.json"
        )
        requirements = load_json(
            REPOSITORY_ROOT / "packaging/honey/release-requirements.v1.json"
        )
        self.assertEqual(
            all_capabilities, {row["id"] for row in profile["capabilities"]}
        )
        self.assertEqual(
            all_gates, {row["id"] for row in requirements["mandatory_gates"]}
        )
        self.assertEqual(
            all_artifacts, {identifier for identifier, _ in EXPECTED_ARTIFACTS}
        )


class HoneyNoPublicationTests(unittest.TestCase):
    def test_orchestrator_contains_no_publish_tag_or_upload_command(self) -> None:
        source_path = RELEASE_SCRIPTS / "qualify_honey_release.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        function_by_name = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        operational = {
            "_build",
            "_qualify",
            "_verify",
            "_check_evidence",
            "_run_demos",
            "main",
        }
        constants = [
            value.value
            for name in operational
            for value in ast.walk(function_by_name[name])
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        ]
        forbidden_tokens = {
            "gh",
            "twine",
            "curl",
            "wget",
            "publish",
            "upload",
            "tag",
            "release create",
        }
        self.assertTrue(forbidden_tokens.isdisjoint(constants))

        git_calls: list[tuple[str, ...]] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_git"
            ):
                git_calls.append(
                    tuple(
                        argument.value
                        for argument in node.args[1:]
                        if isinstance(argument, ast.Constant)
                        and isinstance(argument.value, str)
                    )
                )
        self.assertEqual(
            git_calls,
            [
                ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
                ("rev-parse", "--verify", "HEAD^{commit}"),
                ("rev-parse", "--verify", "HEAD^{tree}"),
                ("show", "-s", "--format=%ct", "HEAD"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
