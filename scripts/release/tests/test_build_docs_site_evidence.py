#!/usr/bin/env python3
from __future__ import annotations

import argparse
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

import build_docs_site  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError, write_bytes, write_json  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class DocumentationSiteEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-docs-site-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self.input = self.base / "site-input.md"
        self.input.write_text("# Input\n", encoding="utf-8")
        os.chmod(self.input, 0o600)

    def arguments(
        self,
        *,
        out: Path | None,
        evidence_dir: Path | None = None,
        check: bool = False,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.repository,
            out=out,
            evidence_dir=evidence_dir,
            check=check,
        )

    def open_output(
        self,
        *,
        out: Path | None,
        evidence_dir: Path | None = None,
        environment: str = "",
        inputs: list[Path] | None = None,
    ) -> build_docs_site.DocsSiteOutput:
        arguments = self.arguments(out=out, evidence_dir=evidence_dir)
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": environment},
            clear=False,
        ):
            return build_docs_site.DocsSiteOutput.open(
                arguments,
                self.repository,
                inputs if inputs is not None else [self.input],
            )

    def staged_site(self, name: str = "stage") -> tuple[Path, dict[str, object]]:
        stage = self.base / name
        page = b"<!doctype html>\n<html><body>Home</body></html>\n"
        write_bytes(stage / "docs/site/index.html", page)
        write_bytes(stage / "index.html", page)
        write_bytes(stage / "assets/style.css", b"body{}\n")
        site: dict[str, object] = {
            "schema_version": "cigar.generated-docs-site.v1",
            "product_version": "1.0.0-dev.1",
            "context_abi": "cigar.context.v1",
            "version_selectors": ["1.0.0-dev.1"],
            "pages": [
                {
                    "source": "docs/site/index.md",
                    "output": "docs/site/index.html",
                    "title": "Home",
                }
            ],
            "asset_count": 1,
        }
        write_json(stage / "site-manifest.json", site)
        return stage, site

    def test_external_site_is_staged_canonical_owner_only_and_create_new(self) -> None:
        stage, site = self.staged_site()
        evidence = self.base / "evidence"
        output = self.open_output(out=Path("docs-site"), evidence_dir=evidence)
        self.addCleanup(output.close)

        output.publish(stage, site)

        destination = evidence / "docs-site/site-manifest.json"
        self.assertEqual(json.loads(destination.read_bytes()), site)
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
        for path in (evidence / "docs-site").rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                self.assertEqual(path.stat().st_nlink, 1)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
            output.publish(stage, site)

    def test_invalid_stage_fails_before_any_file_is_published(self) -> None:
        stage, site = self.staged_site()
        (stage / "unsafe-link").symlink_to(stage / "index.html")
        evidence = self.base / "invalid-stage-evidence"
        output = self.open_output(out=Path("docs-site"), evidence_dir=evidence)
        self.addCleanup(output.close)

        with self.assertRaisesRegex(ReleaseError, "not a regular file"):
            output.publish(stage, site)

        self.assertEqual(list(evidence.iterdir()), [])

    def test_stage_substitution_after_validation_is_rejected_before_publish(
        self,
    ) -> None:
        stage, site = self.staged_site()
        evidence = self.base / "substitution-evidence"
        output = self.open_output(out=Path("docs-site"), evidence_dir=evidence)
        self.addCleanup(output.close)
        validate = build_docs_site._validated_stage_files

        def validate_then_substitute(
            selected_stage: Path, selected_site: dict[str, object]
        ) -> list[build_docs_site._StagedFile]:
            validated = validate(selected_stage, selected_site)
            write_bytes(selected_stage / "assets/style.css", b"evil{}\n")
            return validated

        with mock.patch.object(
            build_docs_site,
            "_validated_stage_files",
            side_effect=validate_then_substitute,
        ):
            with self.assertRaisesRegex(ReleaseError, "changed after validation"):
                output.publish(stage, site)

        self.assertEqual(list(evidence.iterdir()), [])

    def test_environment_selection_conflict_and_relative_root_fail(self) -> None:
        stage, site = self.staged_site()
        evidence = self.base / "environment-evidence"
        output = self.open_output(
            out=Path("docs-site"),
            environment=str(evidence),
        )
        self.addCleanup(output.close)
        output.publish(stage, site)
        self.assertTrue((evidence / "docs-site/index.html").is_file())

        arguments = self.arguments(
            out=Path("docs-site"), evidence_dir=self.base / "argument"
        )
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "different")},
            clear=False,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                build_docs_site.selected_evidence_directory(arguments)

        arguments.evidence_dir = Path("relative")
        with mock.patch.dict(os.environ, {"CIGAR_EVIDENCE_DIR": ""}, clear=False):
            with self.assertRaisesRegex(ReleaseError, "absolute"):
                build_docs_site.selected_evidence_directory(arguments)

    def test_direct_development_output_and_input_alias_rejection(self) -> None:
        stage, site = self.staged_site()
        direct = self.base / "development-site"
        output = self.open_output(out=direct)
        output.publish(stage, site)
        output.close()
        self.assertEqual(
            stat.S_IMODE((direct / "site-manifest.json").stat().st_mode), 0o644
        )
        with self.assertRaisesRegex(ReleaseError, "must be empty"):
            output = self.open_output(out=direct)
            self.addCleanup(output.close)
            output.publish(stage, site)

        with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
            self.open_output(out=self.input, inputs=[self.input])

        evidence = self.base / "alias-evidence"
        alias_parent = evidence / "docs-site"
        alias_parent.mkdir(parents=True, mode=0o700)
        os.chmod(evidence, 0o700)
        aliased_input = alias_parent / "index.html"
        aliased_input.write_text("input\n", encoding="utf-8")
        os.chmod(aliased_input, 0o600)
        output = self.open_output(
            out=Path("docs-site"),
            evidence_dir=evidence,
            inputs=[aliased_input],
        )
        self.addCleanup(output.close)
        with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
            output.publish(stage, site)
        self.assertEqual(
            sorted(
                path.relative_to(evidence).as_posix() for path in evidence.rglob("*")
            ),
            ["docs-site", "docs-site/index.html"],
        )

    def test_selected_output_rejects_escape_absolute_and_internal_root(self) -> None:
        evidence = self.base / "unsafe-path-evidence"
        with self.assertRaisesRegex(ReleaseError, "--out is required"):
            self.open_output(out=None, evidence_dir=evidence)
        for output in (
            Path("../escape"),
            Path("nested/../../escape"),
            self.base / "absolute",
            Path("nested\\site"),
        ):
            with self.subTest(output=output):
                with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
                    self.open_output(out=output, evidence_dir=evidence)
        self.assertFalse(evidence.exists())

        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self.open_output(
                out=Path("docs-site"),
                evidence_dir=self.repository / "evidence",
            )

        with self.assertRaisesRegex(ReleaseError, "--out must be relative"):
            self.open_output(
                out=self.base / "absolute-site",
                evidence_dir=self.base / "absolute-evidence",
            )

    def test_workspace_rejects_links_modes_collisions_and_rebinding(self) -> None:
        stage, site = self.staged_site()
        target = self.base / "target"
        target.mkdir(mode=0o700)
        linked = self.base / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self.open_output(out=Path("docs-site"), evidence_dir=linked)

        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        os.chmod(insecure, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            self.open_output(out=Path("docs-site"), evidence_dir=insecure)

        hardlinks = self.base / "hardlinks"
        hardlinks.mkdir(mode=0o700)
        first = hardlinks / "first.html"
        second = hardlinks / "second.html"
        first.write_text("first\n", encoding="utf-8")
        os.chmod(first, 0o400)
        os.link(first, second)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "hardlinked"):
            self.open_output(out=Path("docs-site"), evidence_dir=hardlinks)

        collision = self.base / "collision"
        colliding_prefix = collision / "Docs-Site"
        colliding_prefix.mkdir(parents=True, mode=0o700)
        os.chmod(collision, 0o700)
        output = self.open_output(out=Path("docs-site"), evidence_dir=collision)
        self.addCleanup(output.close)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
            output.publish(stage, site)
        self.assertEqual(list(colliding_prefix.iterdir()), [])

        rebound = self.base / "rebound"
        output = self.open_output(out=Path("docs-site"), evidence_dir=rebound)
        self.addCleanup(output.close)
        displaced = self.base / "displaced"
        rebound.rename(displaced)
        rebound.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            output.publish(stage, site)
        self.assertFalse((displaced / "docs-site").exists())
        self.assertFalse((rebound / "docs-site").exists())


if __name__ == "__main__":
    unittest.main()
