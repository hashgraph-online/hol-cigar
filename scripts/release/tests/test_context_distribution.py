from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import context_distribution as distribution  # noqa: E402
import context_platforms  # noqa: E402
import context_sdk_inputs  # noqa: E402
from context_sdk_cases import build_cases  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


class DistributionBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cigar-distribution-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()

    def test_complete_platform_inventory_requires_ten_archives(self):
        platforms = context_platforms.platforms()
        self.assertEqual(len(platforms), 7)
        files = distribution.artifact_names(set(platforms))
        self.assertEqual(len(files), 10)
        self.assertEqual(sum(name.endswith(".whl") for name in files), 7)
        self.assertIn("hol_cigar-0.11.0-py3-none-win_amd64.whl", files)
        self.assertIn("hol_cigar-0.11.0-py3-none-musllinux_1_2_aarch64.whl", files)
        with self.assertRaises(ReleaseError):
            distribution.artifact_names({"freebsd-x64"})

    def test_missing_platform_cannot_pass_even_with_updated_archive_hashes(self):
        with self.assertRaisesRegex(ReleaseError, "inventory"):
            distribution.verify_packages(
                self.directory, {key: {} for key in context_platforms.platforms()}
            )

    def test_diagnostic_and_incomplete_candidates_cannot_qualify_a_release(self):
        candidate = {
            "schema": "cigar.context-distribution-candidate.v1",
            "release": "0.11.0",
            "source_binding": {"clean": True},
            "diagnostic": True,
            "platforms": ["darwin-arm64"],
        }
        path = self.directory / "candidate.json"
        path.write_text(json.dumps(candidate))
        with self.assertRaisesRegex(ReleaseError, "diagnostic"):
            distribution.verify_candidate(self.directory)
        candidate["diagnostic"] = False
        path.write_text(json.dumps(candidate))
        with self.assertRaisesRegex(ReleaseError, "matrix"):
            distribution.verify_candidate(self.directory)

    def test_archive_traversal_links_and_duplicate_members_are_rejected(self):
        for kind in ("traversal", "link", "duplicate"):
            with self.subTest(kind=kind):
                path = self.directory / f"{kind}.tgz"
                with tarfile.open(path, "w:gz") as archive:
                    member = tarfile.TarInfo(
                        "../escape" if kind == "traversal" else "package/file"
                    )
                    member.size = 1
                    if kind == "link":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/outside"
                    archive.addfile(member, io.BytesIO(b"x"))
                    if kind == "duplicate":
                        archive.addfile(member, io.BytesIO(b"y"))
                with self.assertRaises(ReleaseError):
                    distribution.archive_files(path)
        self.assertFalse((self.directory.parent / "escape").exists())

    def test_oversized_archive_is_rejected_before_member_is_read(self):
        path = self.directory / "large.whl"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload", b"0" * 2048)
        with (
            mock.patch.object(distribution, "MAX_FILE", 1024),
            self.assertRaisesRegex(ReleaseError, "limits"),
        ):
            distribution.archive_files(path)

    def test_windows_source_binding_rejects_links_and_matches_regular_bytes(self):
        path = self.directory / "source.py"
        path.write_bytes(b"source\n")
        self.assertEqual(
            context_sdk_inputs.windows_source_digest(self.directory, path),
            hashlib.sha256(b"source\n").hexdigest(),
        )
        link = self.directory / "alias.py"
        link.symlink_to(path)
        with self.assertRaisesRegex(ReleaseError, "link"):
            context_sdk_inputs.windows_source_digest(self.directory, link)
        with self.assertRaisesRegex(ReleaseError, "outside"):
            context_sdk_inputs.windows_source_digest(self.directory / "child", path)

    def test_native_format_rejects_wrong_architecture_and_deployment_floor(self):
        # Minimal Mach-O executable header with a macOS LC_BUILD_VERSION command.
        data = bytearray(64)
        struct.pack_into(
            "<IIIIIIII", data, 0, 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0
        )
        struct.pack_into("<IIIIII", data, 32, 0x32, 24, 1, 11 << 16, 11 << 16, 0)
        path = self.directory / "worker"
        path.write_bytes(data)
        self.assertEqual(
            context_platforms.inspect_binary(path, "darwin-arm64")["minimum_os"],
            [11, 0, 0],
        )
        with self.assertRaisesRegex(ReleaseError, "architecture"):
            context_platforms.inspect_binary(path, "darwin-x64")
        struct.pack_into("<I", data, 44, 12 << 16)
        path.write_bytes(data)
        with self.assertRaisesRegex(ReleaseError, "floor"):
            context_platforms.inspect_binary(path, "darwin-arm64")
        path.write_bytes(b"not executable" * 5)
        for platform_id in context_platforms.platforms():
            with self.subTest(platform=platform_id), self.assertRaises(ReleaseError):
                context_platforms.inspect_binary(path, platform_id)

    def test_windows_ctime_uses_consistent_apis_and_still_detects_mutation(self):
        path = self.directory / "stable.py"
        path.write_bytes(b"unchanged")
        metadata = path.stat()
        values = {
            key: getattr(metadata, key)
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        }
        opened = SimpleNamespace(
            **(values | {"st_ctime_ns": values["st_ctime_ns"] + 100})
        )
        with mock.patch.object(context_sdk_inputs.os, "fstat", return_value=opened):
            self.assertEqual(
                context_sdk_inputs.windows_source_digest(self.directory, path),
                hashlib.sha256(b"unchanged").hexdigest(),
            )
        changed = SimpleNamespace(
            **(values | {"st_ctime_ns": values["st_ctime_ns"] + 101})
        )
        with mock.patch.object(
            context_sdk_inputs.os, "fstat", side_effect=[opened, changed]
        ):
            with self.assertRaisesRegex(ReleaseError, "changed while reading"):
                context_sdk_inputs.windows_source_digest(self.directory, path)

    def test_old_and_new_qualifiers_share_the_full_seeded_case_set(self):
        cases = build_cases(distribution.ROOT)
        self.assertEqual(len(cases), 172)
        self.assertEqual(cases, build_cases(distribution.ROOT))
        self.assertEqual(sum(case["domain"].startswith("seed-") for case in cases), 100)
        self.assertTrue(any(case["request"].get("allowed") for case in cases))
        self.assertTrue(
            any(
                "索引" in document["text"]
                for case in cases
                for document in case["documents"]
            )
        )


if __name__ == "__main__":
    unittest.main()
