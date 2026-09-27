from __future__ import annotations

import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import context_native_sources as sources  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


class NativeSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cigar-native-sources-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.versions = {sources.CONTEXT: "0.14.0", sources.ADAPTER: "0.9.4"}
        self.contents = {}
        for name, version in self.versions.items():
            self.contents[name] = {
                "Cargo.toml": f'[package]\nname = "{name}"\nversion = "{version}"\n'.encode(),
                "src/lib.rs": b"// native source\n",
            }
        self.contents[sources.CONTEXT]["Cargo.toml"] += (
            '[target."cfg(windows)".dependencies.cigar-windows-ipc]\n'
            'version = "=0.9.4"\ndefault-features = false\noptional = true\n'
        ).encode()
        adapter = self.archive(sources.ADAPTER)
        self.lock = (
            '# Cargo lock fixture\nversion = 4\n\n[[package]]\nname = "cigar-context"\n'
            'version = "0.14.0"\ndependencies = ["cigar-windows-ipc", "serde"]\n\n'
            '[[package]]\nname = "cigar-windows-ipc"\nversion = "0.9.4"\n'
            f'source = "{sources.REGISTRY}"\n'
            f'checksum = "{hashlib.sha256(adapter.read_bytes()).hexdigest()}"\n'
            'dependencies = ["windows-sys"]\n\n'
            '[[package]]\nname = "serde"\nversion = "1.0.228"\n'
            f'source = "{sources.REGISTRY}"\nchecksum = "' + "1" * 64 + '"\n'
        ).encode()
        self.contents[sources.CONTEXT]["Cargo.lock"] = self.lock
        self.archive(sources.CONTEXT)

    def archive(self, name):
        prefix = f"{name}-{self.versions[name]}"
        path = self.root / f"{prefix}.crate"
        with tarfile.open(path, "w:gz") as archive:
            for relative, payload in self.contents[name].items():
                member = tarfile.TarInfo(f"{prefix}/{relative}")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return path

    def test_preparation_preserves_archives_and_unrelated_lock_records(self):
        before = {p.name: p.read_bytes() for p in self.root.glob("*.crate")}
        crates, receipt = sources.prepare(
            self.root, self.root / "unpacked", self.versions
        )
        expected = tomllib.loads(self.lock.decode())
        adapter = expected["package"][1]
        del adapter["source"]
        del adapter["checksum"]
        effective = (crates[sources.CONTEXT] / "Cargo.lock").read_bytes()
        self.assertEqual(tomllib.loads(effective.decode()), expected)
        self.assertEqual(receipt["effective_lock_sha256"], sources.sha256(effective))
        self.assertEqual(
            {p.name: p.read_bytes() for p in self.root.glob("*.crate")}, before
        )
        self.assertEqual(sources.inspect(self.root, self.versions)[0], receipt)
        config = tomllib.loads(
            (crates[sources.CONTEXT] / ".cargo/config.toml").read_text()
        )
        self.assertEqual(
            config["patch"]["crates-io"][sources.ADAPTER]["path"],
            "../cigar-windows-ipc-0.9.4",
        )
        self.assertEqual(config["profile"]["release"], sources.RELEASE_PROFILE)
        self.assertEqual(receipt["release_profile"], sources.RELEASE_PROFILE)
        with self.assertRaises(FileExistsError):
            sources.prepare(self.root, self.root / "unpacked", self.versions)

    def test_missing_companion_fails_before_extraction(self):
        (self.root / "cigar-windows-ipc-0.9.4.crate").unlink()
        with self.assertRaisesRegex(ReleaseError, "source archive"):
            sources.prepare(self.root, self.root / "unpacked", self.versions)
        self.assertFalse((self.root / "unpacked").exists())

    def test_workspace_profile_drift_requires_explicit_review(self):
        (self.root / "Cargo.toml").write_text(
            "[profile.release]\ncodegen-units = 16\nlto = false\n"
            'panic = "unwind"\nstrip = "none"\n'
        )
        with self.assertRaisesRegex(ReleaseError, "profile differs"):
            sources.versions(self.root)

    def test_substituted_adapter_cannot_match_the_context_lock(self):
        self.contents[sources.ADAPTER]["src/lib.rs"] = b"// substituted adapter\n"
        self.archive(sources.ADAPTER)
        with self.assertRaisesRegex(ReleaseError, "does not match the context lock"):
            sources.inspect(self.root, self.versions)

    def test_unpinned_or_default_feature_adapter_is_rejected(self):
        original = self.contents[sources.CONTEXT]["Cargo.toml"]
        for replacement in (
            original.replace(b'"=0.9.4"', b'"^0.9.4"'),
            original.replace(b"default-features = false", b"default-features = true"),
        ):
            with self.subTest(manifest=replacement):
                self.contents[sources.CONTEXT]["Cargo.toml"] = replacement
                self.archive(sources.CONTEXT)
                with self.assertRaisesRegex(ReleaseError, "pin the expected"):
                    sources.inspect(self.root, self.versions)

    def test_missing_duplicate_or_wrong_version_lock_entries_are_rejected(self):
        parsed = tomllib.loads(self.lock.decode())
        checksum = parsed["package"][1]["checksum"]
        for payload in (
            self.lock.replace(b'"cigar-windows-ipc"', b'"another-package"'),
            self.lock.replace(b'"0.9.4"', b'"0.9.5"'),
            self.lock
            + b'\n[[package]]\nname = "cigar-windows-ipc"\nversion = "0.9.4"\n',
        ):
            with self.subTest(payload=payload), self.assertRaises(ReleaseError):
                sources.local_adapter_lock(payload, "0.9.4", checksum)

    def test_archive_paths_and_special_files_are_rejected(self):
        path = self.root / "invalid.crate"
        prefix = "cigar-windows-ipc-0.9.4"
        for name, kind in (
            ("../escape", tarfile.REGTYPE),
            (prefix + "/../escape", tarfile.REGTYPE),
            (prefix + "/src\\escape", tarfile.REGTYPE),
            (prefix + "/src/link", tarfile.SYMTYPE),
        ):
            with self.subTest(name=name):
                with tarfile.open(path, "w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "outside" if kind == tarfile.SYMTYPE else ""
                    archive.addfile(member)
                with self.assertRaises(ReleaseError):
                    sources.read_archive(path, prefix)


if __name__ == "__main__":
    unittest.main()
