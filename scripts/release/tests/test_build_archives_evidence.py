#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_archives  # noqa: E402
from evidence_workspace import Attachment, EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class BuildArchivesEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-archives-output-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.root = build_archives.repo_root().resolve(strict=True)

    @staticmethod
    def arguments(
        *,
        output: Path,
        evidence: Path | None,
        replace: bool = False,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            out=output,
            evidence_dir=evidence,
            replace=replace,
        )

    def build_arguments(
        self,
        *,
        root: Path,
        output: Path,
        evidence: Path | None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            root=root,
            manifest="manifest.json",
            out=output,
            evidence_dir=evidence,
            source_date_epoch="1",
            require_committed_clean=False,
            replace=False,
        )

    def minimal_source(self, name: str) -> Path:
        root = self.base / name
        root.mkdir()
        (root / "input.txt").write_text("deterministic input\n", encoding="utf-8")
        (root / "contract.json").write_text("{}\n", encoding="utf-8")
        manifest = {
            "schema_version": "cigar.local-archives.v1",
            "product_version": "1.0.0-test.1",
            "context_abi": "cigar.context.v1",
            "archives": [
                {
                    "id": "source",
                    "filename": "source.tar.gz",
                    "contract": "contract.json",
                    "include": ["input.txt"],
                }
            ],
            "always_exclude": [],
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return root

    def minimal_honey_source(self, name: str) -> Path:
        root = self.minimal_source(name)
        manifest = json.loads((root / "manifest.json").read_bytes())
        manifest["product_version"] = "0.9.1-honey.1"
        honey_manifest = root / build_archives.HONEY_MANIFEST_PATH
        honey_manifest.parent.mkdir(parents=True, exist_ok=True)
        honey_manifest.write_text(json.dumps(manifest), encoding="utf-8")
        for relative in build_archives.HONEY_AUTHORITY_PATHS:
            path = root / relative
            if path == honey_manifest:
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        return root

    def run_build_main(
        self,
        arguments: argparse.Namespace,
        *,
        verification_error: ReleaseError | None = None,
    ) -> tuple[int, Path]:
        real_open = build_archives.ArchiveOutput.open
        staging: list[Path] = []

        def capture_open(
            selected: argparse.Namespace, *, repository_root: Path
        ) -> build_archives.ArchiveOutput:
            opened = real_open(selected, repository_root=repository_root)
            staging.append(opened.output_root)
            return opened

        verification = (
            mock.Mock(side_effect=verification_error)
            if verification_error is not None
            else mock.Mock(return_value={"status": "passed"})
        )
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                build_archives, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(build_archives.ArchiveOutput, "open", capture_open),
            mock.patch.object(
                build_archives,
                "git_state",
                return_value={
                    "revision": "a" * 40,
                    "committed": True,
                    "clean": True,
                    "source_tree_sha256": "b" * 64,
                },
            ),
            mock.patch.object(build_archives, "verify_package", verification),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = build_archives.main()
        self.assertEqual(len(staging), 1)
        return result, staging[0]

    def test_protected_archive_set_is_create_new_and_read_only(self) -> None:
        evidence = self.base / "evidence"
        arguments = self.arguments(output=Path("archives"), evidence=evidence)
        with mock.patch.dict(os.environ, {}, clear=True):
            output = build_archives.ArchiveOutput.open(
                arguments, repository_root=self.root
            )
        staging = output.output_root
        try:
            first = staging / "first.tar.gz"
            second = staging / "build-manifest.json"
            first.write_bytes(b"archive payload")
            second.write_bytes(b'{"status":"development"}\n')
            os.chmod(first, 0o600)
            os.chmod(second, 0o600)
            output.publish([first.name, second.name])
        finally:
            output.close()

        self.assertFalse(staging.exists())
        for name, expected in (
            ("first.tar.gz", b"archive payload"),
            ("build-manifest.json", b'{"status":"development"}\n'),
        ):
            published = evidence / "archives" / name
            self.assertEqual(published.read_bytes(), expected)
            metadata = published.stat(follow_symlinks=False)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
            self.assertEqual(metadata.st_nlink, 1)

        with mock.patch.dict(os.environ, {}, clear=True):
            repeated = build_archives.ArchiveOutput.open(
                arguments, repository_root=self.root
            )
        try:
            candidate = repeated.output_root / "first.tar.gz"
            candidate.write_bytes(b"replacement")
            os.chmod(candidate, 0o600)
            with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
                repeated.publish([candidate.name])
        finally:
            repeated.close()
        self.assertEqual(
            (evidence / "archives" / "first.tar.gz").read_bytes(),
            b"archive payload",
        )

    def test_main_builds_direct_archive_set(self) -> None:
        root = self.minimal_source("direct-source")
        destination = self.base / "direct-build"
        arguments = self.build_arguments(root=root, output=destination, evidence=None)

        result, output_root = self.run_build_main(arguments)

        self.assertEqual(result, 0)
        self.assertEqual(output_root, destination)
        self.assertTrue((destination / "source.tar.gz").is_file())
        self.assertTrue((destination / "SHA256SUMS").is_file())
        manifest = json.loads((destination / "build-manifest.json").read_bytes())
        self.assertEqual(manifest["artifacts"][0]["path"], "source.tar.gz")
        self.assertNotIn("authority", manifest)

    def test_honey_portable_build_requires_clean_flag_and_binds_authority(self) -> None:
        root = self.minimal_honey_source("honey-source")
        missing_flag = self.build_arguments(
            root=root,
            output=self.base / "honey-missing-flag",
            evidence=None,
        )
        missing_flag.manifest = build_archives.HONEY_MANIFEST_PATH
        with self.assertRaisesRegex(ReleaseError, "require-committed-clean"):
            self.run_build_main(missing_flag)

        destination = self.base / "honey-build"
        arguments = self.build_arguments(
            root=root,
            output=destination,
            evidence=None,
        )
        arguments.manifest = build_archives.HONEY_MANIFEST_PATH
        arguments.require_committed_clean = True
        result, _ = self.run_build_main(arguments)
        self.assertEqual(result, 0)
        receipt = json.loads((destination / "build-manifest.json").read_bytes())
        expected_paths = {
            *build_archives.HONEY_AUTHORITY_PATHS,
            "contract.json",
        }
        self.assertEqual(set(receipt["authority"]), expected_paths)
        for relative, binding in receipt["authority"].items():
            payload = (root / relative).read_bytes()
            self.assertEqual(binding["bytes"], len(payload))
            self.assertEqual(
                binding["sha256"], __import__("hashlib").sha256(payload).hexdigest()
            )

    def test_checked_in_honey_authority_inventory_is_exact(self) -> None:
        manifest = build_archives.load_json(
            self.root / build_archives.HONEY_MANIFEST_PATH
        )
        authority = build_archives._honey_authority(self.root, manifest)
        expected_paths = {
            *build_archives.HONEY_AUTHORITY_PATHS,
            *(entry["contract"] for entry in manifest["archives"]),
        }

        self.assertEqual(set(authority), expected_paths)

    def test_main_builds_protected_archive_set_and_removes_staging(self) -> None:
        root = self.minimal_source("protected-source")
        evidence = self.base / "protected-evidence"
        arguments = self.build_arguments(
            root=root, output=Path("archives"), evidence=evidence
        )

        result, staging = self.run_build_main(arguments)

        self.assertEqual(result, 0)
        self.assertFalse(staging.exists())
        published = evidence / "archives"
        self.assertEqual(
            {path.name for path in published.iterdir()},
            {"source.tar.gz", "SHA256SUMS", "build-manifest.json"},
        )
        for path in published.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)

    def test_protected_verification_failure_removes_staging_and_publishes_nothing(
        self,
    ) -> None:
        root = self.minimal_source("failing-source")
        evidence = self.base / "failing-evidence"
        arguments = self.build_arguments(
            root=root, output=Path("archives"), evidence=evidence
        )
        captured: list[Path] = []
        real_open = build_archives.ArchiveOutput.open

        def capture_open(
            selected: argparse.Namespace, *, repository_root: Path
        ) -> build_archives.ArchiveOutput:
            opened = real_open(selected, repository_root=repository_root)
            captured.append(opened.output_root)
            return opened

        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                build_archives, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(build_archives.ArchiveOutput, "open", capture_open),
            mock.patch.object(
                build_archives,
                "git_state",
                return_value={
                    "revision": "a" * 40,
                    "committed": True,
                    "clean": True,
                    "source_tree_sha256": "b" * 64,
                },
            ),
            mock.patch.object(
                build_archives,
                "verify_package",
                side_effect=ReleaseError("verification failed"),
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(ReleaseError, "verification failed"):
                build_archives.main()

        self.assertEqual(len(captured), 1)
        self.assertFalse(captured[0].exists())
        self.assertEqual(list(evidence.iterdir()), [])

    def test_selector_requires_canonical_relative_output_and_no_replace(self) -> None:
        evidence = self.base / "evidence"
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "unsafe evidence workspace"):
                build_archives.ArchiveOutput.open(
                    self.arguments(output=self.base / "absolute", evidence=evidence),
                    repository_root=self.root,
                )
            with self.assertRaisesRegex(ReleaseError, "--replace is forbidden"):
                build_archives.ArchiveOutput.open(
                    self.arguments(
                        output=Path("archives"), evidence=evidence, replace=True
                    ),
                    repository_root=self.root,
                )
            with self.assertRaisesRegex(ReleaseError, "absolute path"):
                build_archives.ArchiveOutput.open(
                    self.arguments(
                        output=Path("archives"), evidence=Path("relative-evidence")
                    ),
                    repository_root=self.root,
                )

    def test_selector_conflict_and_internal_workspace_fail_closed(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "environment")},
            clear=True,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                build_archives.ArchiveOutput.open(
                    self.arguments(
                        output=Path("archives"), evidence=self.base / "argument"
                    ),
                    repository_root=self.root,
                )

        internal = self.root / "reports" / "archive-output-test"
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "outside"):
                build_archives.ArchiveOutput.open(
                    self.arguments(output=Path("archives"), evidence=internal),
                    repository_root=self.root,
                )
        self.assertFalse(internal.exists())

    def test_staged_links_and_duplicate_inventory_are_rejected(self) -> None:
        evidence = self.base / "evidence"
        with mock.patch.dict(os.environ, {}, clear=True):
            output = build_archives.ArchiveOutput.open(
                self.arguments(output=Path("archives"), evidence=evidence),
                repository_root=self.root,
            )
        try:
            source = output.output_root / "source.tar.gz"
            source.write_bytes(b"payload")
            os.chmod(source, 0o600)
            hardlink = output.output_root / "hardlink.tar.gz"
            os.link(source, hardlink)
            with self.assertRaisesRegex(EvidenceWorkspaceError, "hardlinked"):
                output.publish([source.name])
            with self.assertRaisesRegex(ReleaseError, "duplicated"):
                output.publish([source.name, source.name])
            with self.assertRaisesRegex(ReleaseError, "portable collision"):
                output.publish(["Archive.tar.gz", "archive.tar.gz"])
        finally:
            output.close()

    def test_staged_file_changed_after_validation_is_not_published(self) -> None:
        evidence = self.base / "changed-evidence"
        with mock.patch.dict(os.environ, {}, clear=True):
            output = build_archives.ArchiveOutput.open(
                self.arguments(output=Path("archives"), evidence=evidence),
                repository_root=self.root,
            )
        try:
            source = output.output_root / "source.tar.gz"
            source.write_bytes(b"payload")
            os.chmod(source, 0o600)
            assert output.workspace is not None
            attach_file = output.workspace.attach_file

            def mutate_then_attach(
                attachment: Path,
                relative: str,
                *,
                read_only: bool = True,
                expected_sha256: str | None = None,
                expected_bytes: int | None = None,
            ) -> Attachment:
                attachment.write_bytes(b"PAYLOAD")
                os.chmod(attachment, 0o600)
                return attach_file(
                    attachment,
                    relative,
                    read_only=read_only,
                    expected_sha256=expected_sha256,
                    expected_bytes=expected_bytes,
                )

            with mock.patch.object(
                output.workspace, "attach_file", side_effect=mutate_then_attach
            ):
                with self.assertRaisesRegex(
                    EvidenceWorkspaceError, "SHA-256 differs from validated content"
                ):
                    output.publish([source.name])
        finally:
            output.close()

        self.assertEqual(list(evidence.iterdir()), [])

    def test_source_mutation_after_snapshot_publishes_nothing(self) -> None:
        root = self.minimal_source("mutated-source")
        evidence = self.base / "mutated-source-evidence"
        arguments = self.build_arguments(
            root=root, output=Path("archives"), evidence=evidence
        )
        real_write_archive = build_archives._write_archive
        source = root / "input.txt"

        def write_then_mutate(*args: object, **kwargs: object) -> None:
            real_write_archive(*args, **kwargs)
            original = source.read_bytes()
            source.write_bytes(b"X" * (len(original) - 1) + b"\n")

        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                build_archives, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(
                build_archives,
                "git_state",
                return_value={
                    "revision": "a" * 40,
                    "committed": True,
                    "clean": True,
                    "tree_sha256": "b" * 64,
                },
            ),
            mock.patch.object(
                build_archives, "verify_package", return_value={"status": "passed"}
            ),
            mock.patch.object(
                build_archives, "_write_archive", side_effect=write_then_mutate
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(
                ReleaseError, "source member changed after snapshot"
            ):
                build_archives.main()

        self.assertEqual(list(evidence.iterdir()), [])

    def test_manifest_rejects_unsafe_and_portable_colliding_filenames(self) -> None:
        base = {
            "schema_version": "cigar.local-archives.v1",
            "archives": [
                {
                    "id": "source",
                    "filename": "source.tar.gz",
                    "include": ["README.md"],
                }
            ],
        }
        build_archives._validate_manifest(base)

        unsafe = {**base, "archives": [{**base["archives"][0], "filename": ".."}]}
        with self.assertRaisesRegex(ReleaseError, "invalid archive filename"):
            build_archives._validate_manifest(unsafe)

        colliding = {
            **base,
            "archives": [
                base["archives"][0],
                {
                    "id": "docs",
                    "filename": "SOURCE.tar.gz",
                    "include": ["docs/**"],
                },
            ],
        }
        with self.assertRaisesRegex(ReleaseError, "duplicate archive filename"):
            build_archives._validate_manifest(colliding)

    def test_direct_output_remains_development_only_behavior(self) -> None:
        destination = self.base / "direct"
        arguments = self.arguments(output=destination, evidence=None, replace=True)
        with mock.patch.dict(os.environ, {}, clear=True):
            output = build_archives.ArchiveOutput.open(
                arguments, repository_root=self.root
            )
        try:
            self.assertIsNone(output.workspace)
            self.assertIsNone(output.temporary)
            self.assertEqual(output.output_root, destination)
            output.publish(["not-created-by-output-wrapper"])
        finally:
            output.close()


if __name__ == "__main__":
    unittest.main()
