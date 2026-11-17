from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "ci_tool_authority_test_module", ROOT / "tools/quality/ci_tool_authority.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CiToolAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cigar-ci-authority-", dir="/private/tmp"
        )
        self.base = Path(self.temporary.name).resolve(strict=True)
        self.base.chmod(0o700)
        self.root = self.base / "authority"
        self.lane = "source-quality"
        actions = []
        for name in ("github-env", "github-path"):
            path = self.base / name
            path.touch(mode=0o600)
            actions.append(path)
        self.env_file, self.path_file = actions
        MODULE.prepare(
            argparse.Namespace(
                root=self.root,
                lane=self.lane,
                github_env=self.env_file,
                github_path=self.path_file,
            )
        )
        self.source = {
            "kind": "git",
            "revision": "1" * 40,
            "tree": "2" * 40,
            "committed": True,
            "clean": True,
            "status_entry_count": 0,
            "status_sha256": hashlib.sha256(b"").hexdigest(),
        }
        self.image = {
            "system": "Darwin",
            "architecture": "arm64",
            "image_os": "macos15",
            "image_version": "test-1",
        }
        self.tools = {}
        for name in sorted(
            set().union(
                *(
                    MODULE.authority.ROUTE_TOOLS[route]
                    for route in MODULE.LANES[self.lane]
                )
            )
        ):
            path = self.base / f"tool-{name}"
            payload = f"#!/bin/sh\n# fixture {name}\nexit 0\n".encode()
            path.write_bytes(payload)
            path.chmod(0o700)
            self.tools[name] = {
                "path": str(path),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        self.patches = [
            mock.patch.object(
                MODULE.authority, "source_binding", return_value=self.source
            ),
            mock.patch.object(MODULE, "runner", return_value=self.image),
            mock.patch.object(
                MODULE, "observed_tool", side_effect=lambda name: self.tools[name]
            ),
        ]
        for patch in self.patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in reversed(self.patches)])
        self.addCleanup(self.temporary.cleanup)

    def args(
        self, action: str = "collect", command_id: str = "format-check"
    ) -> argparse.Namespace:
        return argparse.Namespace(
            action=action,
            lane=self.lane,
            root=self.root,
            command_id=command_id,
            evidence_dir=self.base / "evidence",
        )

    def proposal(self) -> dict:
        MODULE.collect(self.args())
        return json.loads((self.root / "review/proposal.json").read_bytes())

    def approved(self, document: dict | None = None):
        if document is None:
            document = self.proposal()["approval_candidate"]
        return mock.patch.dict(
            os.environ, {"CIGAR_CI_TOOL_APPROVAL": json.dumps(document)}
        )

    def test_prepare_creates_private_external_roots_without_overriding_shell_home(
        self,
    ) -> None:
        values = MODULE.environment(self.root, self.lane)
        self.assertEqual(set(values), MODULE.authority.ENVIRONMENT)
        for path in values.values():
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o700)
        exported_names = {
            line.split("=", 1)[0] for line in self.env_file.read_text().splitlines()
        }
        self.assertNotIn("HOME", exported_names)
        self.assertIn("CARGO_HOME", exported_names)
        with self.assertRaises(FileExistsError):
            MODULE.prepare(
                argparse.Namespace(
                    root=self.root,
                    lane=self.lane,
                    github_env=self.env_file,
                    github_path=self.path_file,
                )
            )

    def test_multicall_staging_preserves_names_single_links_and_actual_dispatch(
        self,
    ) -> None:
        source = self.base / "rustup-source"
        payload = b'#!/bin/sh\nprintf "%s\\n" "$0"\n'
        source.write_bytes(payload)
        source.chmod(0o500)
        os.link(source, self.base / "rustup-source-hardlink")
        self.assertEqual(source.stat().st_nlink, 2)
        with mock.patch.object(MODULE.shutil, "which", return_value=str(source)):
            result = MODULE.stage_launchers(
                argparse.Namespace(
                    root=self.root, lane=self.lane, github_path=self.path_file
                )
            )
        self.assertEqual(result["approval_status"], "unapproved-observation")
        for name in MODULE.RUST_LAUNCHERS:
            target = self.root / "launchers" / name
            self.assertEqual(target.resolve(strict=True), target)
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual(target.stat().st_mode & 0o777, 0o500)
            self.assertEqual(target.read_bytes(), payload)
            observed = MODULE.subprocess.run(
                [str(target)], check=True, capture_output=True, text=True, timeout=5
            )
            self.assertEqual(Path(observed.stdout.strip()).name, name)
        self.assertNotIn("CIGAR_XTASK_TOOL_INPUTS", self.env_file.read_text())

    def test_observation_rejects_fifo_symlink_and_changed_file_without_execution(
        self,
    ) -> None:
        fifo = self.base / "tool-fifo"
        os.mkfifo(fifo, 0o700)
        with self.assertRaises(MODULE.authority.ToolAuthorityError):
            MODULE.observed_payload(fifo)
        source = Path(self.tools["cargo"]["path"])
        alias = self.base / "tool-symlink"
        alias.symlink_to(source)
        with self.assertRaises(OSError):
            MODULE.observed_payload(alias)
        real_read = os.read
        changed = False

        def replace_after_read(descriptor: int, size: int) -> bytes:
            nonlocal changed
            payload = real_read(descriptor, size)
            if not changed:
                changed = True
                source.write_bytes(b"#!/bin/sh\nexit 99\n")
            return payload

        with mock.patch.object(MODULE.os, "read", side_effect=replace_after_read):
            with self.assertRaises(MODULE.authority.ToolAuthorityError):
                MODULE.observed_payload(source)

    def test_shared_bootstrap_source_is_copy_only_and_private_targets_still_require_review(
        self,
    ) -> None:
        shared = self.base / "package-manager"
        shared.mkdir(mode=0o775)
        shared.chmod(0o775)
        source = shared / "rustup"
        payload = b'#!/bin/sh\nprintf "%s\\n" "$0"\n'
        source.write_bytes(payload)
        source.chmod(0o775)
        with self.assertRaises(MODULE.authority.ToolAuthorityError):
            MODULE.observed_payload(source)
        with mock.patch.object(MODULE.shutil, "which", return_value=str(source)):
            result = MODULE.stage_launchers(
                argparse.Namespace(
                    root=self.root, lane=self.lane, github_path=self.path_file
                )
            )
        self.assertEqual(result["approval_status"], "unapproved-observation")
        target = self.root / "launchers/cargo"
        MODULE.authority._reviewed_tool(
            {"path": str(target), "sha256": hashlib.sha256(payload).hexdigest()},
            "cargo",
        )
        self.assertEqual(target.stat().st_mode & 0o777, 0o500)
        self.proposal()
        with (
            mock.patch.dict(os.environ, {"CIGAR_CI_TOOL_APPROVAL": ""}),
            mock.patch.object(MODULE.subprocess, "run") as execute,
        ):
            with self.assertRaises(MODULE.authority.ToolAuthorityError):
                MODULE.run(self.args("run"))
            execute.assert_not_called()

    def test_collection_is_unapproved_and_does_not_export_selectors_or_execute(
        self,
    ) -> None:
        with mock.patch.object(MODULE.subprocess, "run") as execute:
            proposal = self.proposal()
        execute.assert_not_called()
        self.assertEqual(proposal["approval_status"], "unapproved-observation")
        self.assertIs(proposal["release_eligible"], False)
        self.assertIs(proposal["independent_review_required"], True)
        for selector in MODULE.SELECTORS:
            self.assertNotIn(selector, self.env_file.read_text())
        for command_id, entry in proposal["approval_candidate"]["routes"].items():
            path = self.root / "review" / f"{command_id}.observed-authority.json"
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(), entry["authority_sha256"]
            )

    def test_observations_alone_and_missing_approval_never_launch(self) -> None:
        proposal = self.proposal()
        for payload in ("", json.dumps(proposal)):
            with (
                mock.patch.dict(os.environ, {"CIGAR_CI_TOOL_APPROVAL": payload}),
                mock.patch.object(MODULE.subprocess, "run") as execute,
            ):
                with self.assertRaises(MODULE.authority.ToolAuthorityError):
                    MODULE.run(self.args("run"))
                execute.assert_not_called()

    def test_external_approval_scopes_both_selectors_to_one_child_and_reopens_receipt(
        self,
    ) -> None:
        document = self.proposal()["approval_candidate"]
        with (
            self.approved(document),
            mock.patch.object(MODULE.subprocess, "run") as execute,
        ):
            result = MODULE.run(self.args("run"))
            self.assertNotIn(MODULE.SELECTORS[0], os.environ)
            self.assertNotIn(MODULE.SELECTORS[1], os.environ)
        self.assertTrue(result["receipt_verified"])
        self.assertFalse(result["release_eligible"])
        self.assertEqual(execute.call_count, 2)
        first, second = execute.call_args_list
        self.assertEqual(first.args[0][-2:], ["fmt", "--check"])
        self.assertEqual(
            first.kwargs["env"][MODULE.SELECTORS[1]],
            document["routes"]["format-check"]["authority_sha256"],
        )
        self.assertNotIn("CIGAR_CI_TOOL_APPROVAL", first.kwargs["env"])
        self.assertEqual(second.args[0][:3], ["/usr/bin/python3", "-B", "-I"])
        self.assertIn("verify", second.args[0])

    def test_stale_source_image_lane_or_route_inventory_blocks_before_launch(
        self,
    ) -> None:
        original = self.proposal()["approval_candidate"]
        for field, value in (
            ("source", {**self.source, "revision": "3" * 40}),
            ("runner", {**self.image, "image_version": "other"}),
            ("lane", "coverage"),
            ("routes", {}),
        ):
            document = {**original, field: value}
            with (
                self.subTest(field=field),
                self.approved(document),
                mock.patch.object(MODULE.subprocess, "run") as execute,
            ):
                with self.assertRaises(MODULE.authority.ToolAuthorityError):
                    MODULE.run(self.args("run"))
                execute.assert_not_called()

    def test_changed_executable_and_wrong_authority_digest_block(self) -> None:
        document = self.proposal()["approval_candidate"]
        wrong_digest = copy.deepcopy(document)
        wrong_digest["routes"]["format-check"]["authority_sha256"] = "0" * 64
        with (
            self.approved(wrong_digest),
            mock.patch.object(MODULE.subprocess, "run") as execute,
        ):
            with self.assertRaises(MODULE.authority.ToolAuthorityError):
                MODULE.run(self.args("run"))
            execute.assert_not_called()
        cargo = Path(self.tools["cargo"]["path"])
        cargo.write_bytes(b"#!/bin/sh\nexit 99\n")
        with (
            self.approved(document),
            mock.patch.object(MODULE.subprocess, "run") as execute,
        ):
            with self.assertRaises(MODULE.authority.ToolAuthorityError):
                MODULE.approval(self.lane)
            execute.assert_not_called()

    def test_duplicate_json_keys_and_wrong_route_are_rejected(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CIGAR_CI_TOOL_APPROVAL": '{"lane":"source-quality","lane":"coverage"}'},
        ):
            with self.assertRaises(MODULE.authority.ToolAuthorityError):
                MODULE.approval(self.lane)
        with self.assertRaises(MODULE.authority.ToolAuthorityError):
            MODULE.approved_authority(self.args("run", "test-coverage-verify"))

    def test_modified_environment_and_tool_symlink_are_rejected(self) -> None:
        path = self.root / "home"
        path.chmod(0o755)
        with self.assertRaises(MODULE.authority.ToolAuthorityError):
            MODULE.environment(self.root, self.lane)
        alias = self.base / "alias"
        alias.symlink_to(self.tools["cargo"]["path"])
        with self.assertRaises(MODULE.authority.ToolAuthorityError):
            MODULE.authority._reviewed_tool(
                {"path": str(alias), "sha256": self.tools["cargo"]["sha256"]}, "cargo"
            )

    def test_diagnostic_or_substituted_receipt_does_not_reach_receipt_verifier(
        self,
    ) -> None:
        document = self.proposal()["approval_candidate"]
        with self.approved(document):
            MODULE.approved_authority(self.args("run"))
            path = self.base / "evidence/command-plane"
            path.mkdir(parents=True, mode=0o700)
            receipt = path / "format-check.receipt.json"
            MODULE.write_new(
                receipt,
                {"tool_authority": {"review_status": "diagnostic-self-observed"}},
            )
            with mock.patch.object(MODULE, "verify_record") as verify_record:
                with self.assertRaises(MODULE.authority.ToolAuthorityError):
                    MODULE.verify(self.args("verify"))
                verify_record.assert_not_called()


if __name__ == "__main__":
    unittest.main()
