#!/usr/bin/env python3
from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import verify_npm_sdk as verifier  # noqa: E402


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class NpmSdkVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-npm-verifier-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.profile = copy.deepcopy(
            json.loads(verifier.DEFAULT_PROFILE.read_text(encoding="utf-8"))
        )
        self.profile["release_decision"] = {
            "publishable": True,
            "status": "approved",
            "blockers": [],
        }

    def test_committed_profile_is_terminal_after_publication(self) -> None:
        profile = verifier._load_profile(verifier.DEFAULT_PROFILE)
        self.assertFalse(profile["release_decision"]["publishable"])
        self.assertEqual(
            profile["release_decision"]["status"],
            "published-with-tag-policy-exception",
        )
        self.assertEqual(
            {item["id"] for item in profile["release_decision"]["blockers"]},
            {"npm-latest-tag-removal-required"},
        )
        self.assertEqual(
            profile["source"]["revision"], "6e518ad95a018a80a04db295c0f91ec928a0ba0c"
        )
        self.assertEqual(
            profile["source"]["tree"], "eb0926ccb63b9a5a0ad1777334a04b3539b03d8b"
        )
        self.assertEqual(
            profile["source"]["published_from_revision"],
            "7866bab567c29fecc19d34d9071dccd90d30bd7c",
        )
        self.assertEqual(
            profile["source"]["published_from_tree"],
            "71cc42969ec0636efa918cd57709352e627a5482",
        )
        self.assertEqual(profile["registry"]["dist_tags"]["alpha"], "0.9.4")
        self.assertEqual(profile["registry"]["dist_tags"]["latest"], "0.9.4")
        self.assertEqual(
            profile["registry"]["sha1"],
            profile["canonical_release_asset"]["sha1"],
        )
        self.assertEqual(
            profile["registry"]["integrity"],
            "sha512-+XfQU9iD1RtUw5V1uGeABuMkbC2I2u6rbSJqp83nc4n9DOB/"
            "p0AacFyUqyOSFKbWVVKpSPK7WaetcgzHpUs6VA==",
        )
        self.assertEqual(profile["registry"]["file_count"], 78)
        self.assertEqual(
            profile["registry"]["latest_policy"]["removal_result"],
            "E400 Bad Request",
        )

    def entries(self, *, repository: str | None = None) -> dict[str, bytes]:
        source = self.profile["source"]
        package = {
            "name": "@hol-org/cigar",
            "version": "0.9.4",
            "description": "CIGAR v1 TypeScript SDK",
            "license": "Apache-2.0",
            "repository": {
                "type": "git",
                "url": repository or source["repository_manifest_url"],
                "directory": "sdk/typescript",
            },
            "homepage": f"{source['repository']}#readme",
            "bugs": {"url": f"{source['repository']}/issues"},
            "publishConfig": {
                "access": "public",
                "registry": "https://registry.npmjs.org/",
                "tag": "alpha",
            },
            "type": "module",
            "packageManager": "pnpm@10.34.5",
            "engines": {"node": ">=24.10.0 <25"},
            "exports": {
                ".": {"types": "./dist/index.d.ts", "import": "./dist/index.js"}
            },
            "types": "./dist/index.d.ts",
            "files": ["dist/", "fixtures/", "README.md", "LICENSE", "NOTICE"],
            "sideEffects": False,
            "dependencies": {"@bufbuild/protobuf": "2.12.1"},
            "scripts": {"test": "node --test"},
        }
        release = {
            "schema_version": "cigar.sdk-release.v1",
            "name": "@hol-org/cigar",
            "version": "0.9.4",
            "context_abi": "cigar.context.v1",
        }
        operations = (
            "export const OPERATIONS={\n"
            + "\n".join(
                f'  operation{index}: {{"operationId":"operation{index}"}},'
                for index in range(45)
            )
            + "\n};\n"
        )
        return {
            "package/package.json": canonical(package),
            "package/README.md": b"# CIGAR SDK\n",
            "package/LICENSE": b"Apache License\n",
            "package/NOTICE": b"CIGAR\n",
            "package/dist/index.js": b'export const CONTEXT_ABI="cigar.context.v1";\n',
            "package/dist/index.d.ts": b"export declare const CONTEXT_ABI: string;\n",
            "package/dist/release.json": canonical(release),
            "package/dist/generated/operations.js": operations.encode(),
            "package/fixtures/semantic-bundle-v1.json": b"{}\n",
        }

    def archive(self, entries: dict[str, bytes], *, symlink: bool = False) -> Path:
        target = self.root / "cigar-sdk-0.9.4.tgz"
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=1) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, payload in sorted(entries.items()):
                    member = tarfile.TarInfo(name)
                    member.uid = 0
                    member.gid = 0
                    member.mode = 0o644
                    member.mtime = 1
                    if symlink and name == "package/README.md":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/etc/passwd"
                        member.size = 0
                        archive.addfile(member)
                    else:
                        member.size = len(payload)
                        archive.addfile(member, io.BytesIO(payload))
        target.write_bytes(buffer.getvalue())
        return target

    def profile_path(self, archive: Path) -> Path:
        payload = archive.read_bytes()
        _archive_payload, entries = verifier._read_archive(archive)
        self.profile["canonical_release_asset"] = {
            "filename": archive.name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "sha1": hashlib.sha1(payload).hexdigest(),
            "bytes": len(payload),
            "file_count": len(self.entries()),
            "semantic_tree_sha256": verifier._semantic_tree(entries),
        }
        path = self.root / "profile.json"
        path.write_bytes(canonical(self.profile))
        return path

    def test_valid_publishable_archive_has_complete_identity(self) -> None:
        archive = self.archive(self.entries())
        profile = self.profile_path(archive)
        report = verifier.assess(archive, profile, require_canonical_bytes=True)
        self.assertEqual(report["status"], "publishable")
        self.assertTrue(all(report["checks"].values()))
        self.assertTrue(all(report["canonical_asset_checks"].values()))
        self.assertEqual(report["package"]["operation_count"], 45)
        self.assertEqual(len(report["inventory"]), 9)

    def test_repository_mismatch_blocks_without_hiding_other_results(self) -> None:
        archive = self.archive(
            self.entries(repository="git+https://github.com/CIGAR/cigar.git")
        )
        report = verifier.assess(archive, self.profile_path(archive))
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["checks"]["repository"])
        self.assertTrue(report["checks"]["operation_count"])

    def test_non_regular_members_and_private_paths_fail_closed(self) -> None:
        archive = self.archive(self.entries(), symlink=True)
        with self.assertRaisesRegex(verifier.VerificationError, "regular file"):
            verifier.assess(archive, self.profile_path(archive))

        entries = self.entries()
        entries["package/README.md"] = b"built in /Users/alice/private/repo\n"
        archive = self.archive(entries)
        with self.assertRaisesRegex(
            verifier.VerificationError, "private absolute path"
        ):
            verifier.assess(archive, self.profile_path(archive))

    def test_report_is_create_new_and_owner_read_only(self) -> None:
        archive = self.archive(self.entries())
        report = verifier.assess(archive, self.profile_path(archive))
        destination = self.root / "assessment.json"
        verifier._write_report(destination, report)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o400)
        with self.assertRaises(FileExistsError):
            verifier._write_report(destination, report)

    def test_stage_dry_run_must_exactly_bind_the_assessed_archive(self) -> None:
        archive = self.archive(self.entries())
        report = verifier.assess(archive, self.profile_path(archive))
        package = report["package"]
        assessed_archive = report["archive"]
        files = [
            {
                "path": item["path"].removeprefix("package/"),
                "size": item["bytes"],
                "mode": int(item["mode"], 8),
            }
            for item in report["inventory"]
        ]
        entry = {
            "id": f"{package['name']}@{package['version']}",
            "name": package["name"],
            "version": package["version"],
            "size": assessed_archive["bytes"],
            "unpackedSize": sum(item["size"] for item in files),
            "shasum": assessed_archive["sha1"],
            "integrity": assessed_archive["npm_integrity"],
            "filename": assessed_archive["path"],
            "files": files,
            "entryCount": assessed_archive["file_count"],
            "bundled": [],
        }
        stage_report = self.root / "stage-dry-run.json"
        stage_report.write_bytes(canonical({package["name"]: entry}))
        verifier._verify_stage_dry_run(stage_report, report)

        entry["integrity"] = "sha512-tampered"
        stage_report.write_bytes(canonical({package["name"]: entry}))
        with self.assertRaisesRegex(verifier.VerificationError, "assessed archive"):
            verifier._verify_stage_dry_run(stage_report, report)


if __name__ == "__main__":
    unittest.main()
