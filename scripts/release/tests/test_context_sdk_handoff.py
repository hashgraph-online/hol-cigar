"""Composition tests using disposable keys and deliberately synthetic archives.

The retained RC logs are checked-in test inputs, not a qualification of these
synthetic payloads. No production identity or private key is accessed.
"""

from copy import deepcopy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

RELEASE = Path(__file__).resolve().parents[1]
ROOT = RELEASE.parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import context_sdk_handoff as handoff  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError, canonical_json_bytes  # noqa: E402
import signatures  # noqa: E402

SIGNED_AT = 1_788_739_200
VERIFY_AT = SIGNED_AT + 60
VERSION = "0.10.0-rc.1"


def write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)


def write_json(path, value):
    write(path, canonical_json_bytes(value))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(os.name == "posix", "evidence workspaces require POSIX")
class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="cigar-context-handoff-fixture-"
        )
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name).resolve()
        cls.openssl = Path(shutil.which("openssl")).resolve(strict=True)
        cls.openssl_sha256 = sha(cls.openssl)
        cls.private = cls.fixture / "test-only-private.pem"
        cls.public = cls.fixture / "test-only-public.pem"
        subprocess.run(
            [
                str(cls.openssl),
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(cls.private),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        cls.private.chmod(0o600)
        subprocess.run(
            [
                str(cls.openssl),
                "pkey",
                "-in",
                str(cls.private),
                "-pubout",
                "-out",
                str(cls.public),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        cls.public.chmod(0o400)
        cls.crypto = {"openssl_path": cls.openssl, "openssl_sha256": cls.openssl_sha256}
        cls.policy = {
            "schema_version": "cigar.release-trust-policy.v1",
            "keys": [
                {
                    "key_id": signatures.public_key_id(cls.public, **cls.crypto),
                    "public_key": cls.public.name,
                    "public_key_sha256": sha(cls.public),
                    "signer_principal": "test-only-context-sdk",
                    "purposes": [
                        handoff.PURPOSE + value
                        for value in ("artifact", "evidence", "checksums", "manifest")
                    ],
                    "status": "active",
                    "active_from": SIGNED_AT - 60,
                }
            ],
        }
        cls.candidate = cls.fixture / "candidate"
        cls.evidence = cls.fixture / "retained"
        original = ROOT / "reports/evidence/context-sdk-010-rc1"
        report = json.loads((original / "release.json").read_bytes())
        for row in report["artifacts"]:
            payload = b"synthetic signing composition fixture: " + row["file"].encode()
            write(cls.candidate / row["file"], payload)
            row["sha256"] = hashlib.sha256(payload).hexdigest()
            row["bytes"] = len(payload)
        report["worker"]["source_archive_sha256"] = next(
            row["sha256"]
            for row in report["artifacts"]
            if row["file"].endswith(".crate")
        )
        build = json.loads(
            gzip.decompress((original / "build-release.json.gz").read_bytes())
        )
        build["artifacts"] = report["artifacts"]
        build["worker"] = report["worker"]
        for row in report["evidence"]:
            payload = (
                gzip.compress(canonical_json_bytes(build), mtime=0)
                if row["file"] == "build-release.json.gz"
                else (original / row["file"]).read_bytes()
            )
            write(cls.evidence / row["file"], payload)
            row["sha256"] = hashlib.sha256(payload).hexdigest()
            row["bytes"] = len(payload)
        write_json(cls.candidate / "release.json", report)
        write_json(cls.evidence / "release.json", report)
        cls.plan = handoff.stage(
            cls.candidate, cls.evidence, cls.fixture / "handoff", VERSION
        )
        for request in cls.plan["signatures_required"]:
            cls.sign(cls.fixture / "handoff", request["file"], request["purpose"])

    @classmethod
    def sign(cls, directory, name, purpose, **overrides):
        output = directory / "signatures" / (name + ".sig.json")
        output.parent.mkdir(exist_ok=True, mode=0o700)
        if output.exists():
            output.unlink()
        signatures.sign(
            directory / name,
            cls.private,
            cls.public,
            output,
            signer_principal="test-only-context-sdk",
            purpose=purpose,
            signed_at=SIGNED_AT,
            expires_at=overrides.get("expires_at", SIGNED_AT + 3600),
            **cls.crypto,
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cigar-context-handoff-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.dist = self.root / "handoff"
        shutil.copytree(self.fixture / "handoff", self.dist)
        self.policy_path = self.root / "policy.json"
        write_json(self.policy_path, self.policy)
        write(self.root / self.public.name, self.public.read_bytes())

    def verify(self, **overrides):
        arguments = {
            "expected_release": VERSION,
            "manifest_sha256": self.plan["manifest_sha256"],
            "policy_sha256": sha(self.policy_path),
            "openssl": self.openssl,
            "openssl_sha256": self.openssl_sha256,
            "verification_time": VERIFY_AT,
        }
        return handoff.verify(self.dist, self.policy_path, **(arguments | overrides))

    def test_seven_real_signatures_verify_without_claiming_release_readiness(self):
        result = self.verify()
        self.assertEqual(result["signatures_verified"], 7)
        self.assertFalse(result["release_ready"])
        self.assertIn(
            "two-independent-clean-native-builds-and-provenance",
            result["release_blockers"],
        )

    def test_repeat_staging_is_deterministic_and_never_overwrites(self):
        result = handoff.stage(
            self.candidate, self.evidence, self.root / "second", VERSION
        )
        self.assertEqual(result, self.plan)
        with self.assertRaisesRegex(ReleaseError, "must be new"):
            handoff.stage(self.candidate, self.evidence, self.root / "second", VERSION)

    def test_artifact_substitution_rejected(self):
        write(self.dist / "cigar-context-0.10.0.crate", b"substituted")
        with self.assertRaises(EvidenceWorkspaceError):
            self.verify()

    def test_retained_evidence_substitution_rejected(self):
        write(self.dist / "evidence/rust-oracle.json.gz", b"substituted")
        with self.assertRaises(EvidenceWorkspaceError):
            self.verify()

    def test_manifest_pin_rejects_edited_manifest_before_signature_verification(self):
        write(self.dist / handoff.MANIFEST, b"{}")
        with self.assertRaises(EvidenceWorkspaceError):
            self.verify()

    def test_trust_policy_pin_rejects_policy_substitution(self):
        with self.assertRaises(EvidenceWorkspaceError):
            self.verify(policy_sha256="0" * 64)

    def test_candidate_cannot_supply_its_own_trust_policy(self):
        shutil.copy2(self.policy_path, self.dist / "policy.json")
        with self.assertRaisesRegex(ReleaseError, "independent"):
            handoff.verify(
                self.dist,
                self.dist / "policy.json",
                expected_release=VERSION,
                manifest_sha256=self.plan["manifest_sha256"],
                policy_sha256=sha(self.policy_path),
                openssl=self.openssl,
                openssl_sha256=self.openssl_sha256,
                verification_time=VERIFY_AT,
            )

    def test_valid_signature_cannot_relabel_rc_as_beta(self):
        with self.assertRaisesRegex(ReleaseError, "identity mismatch"):
            self.verify(expected_release="0.10.0-beta.1")

    def test_wrong_openssl_digest_rejected(self):
        with self.assertRaises(ReleaseError):
            self.verify(openssl_sha256="0" * 64)

    def test_missing_individual_artifact_signature_rejected(self):
        (self.dist / "signatures/cigar-context-0.10.0.crate.sig.json").unlink()
        with self.assertRaises(EvidenceWorkspaceError):
            self.verify()

    def test_wrong_signature_purpose_rejected(self):
        self.sign(self.dist, "cigar-context-0.10.0.crate", handoff.PURPOSE + "manifest")
        with self.assertRaisesRegex(ReleaseError, "purpose"):
            self.verify()

    def test_manifest_signature_must_authenticate_manifest_not_another_payload(self):
        output = self.dist / "signatures" / (handoff.MANIFEST + ".sig.json")
        output.unlink()
        signatures.sign(
            self.policy_path,
            self.private,
            self.public,
            output,
            signer_principal="test-only-context-sdk",
            purpose=handoff.PURPOSE + "manifest",
            signed_at=SIGNED_AT,
            **self.crypto,
        )
        with self.assertRaisesRegex(
            ReleaseError, "manifest signature payload substitution"
        ):
            self.verify()

    def test_revoked_wrong_scope_wrong_principal_and_inactive_keys_rejected(self):
        for change in (
            {"status": "revoked"},
            {"purposes": ["unrelated-purpose"]},
            {"signer_principal": "different-principal"},
            {"active_from": SIGNED_AT + 1},
            {"status": "retired", "retired_at": SIGNED_AT - 1},
        ):
            with self.subTest(change=change):
                policy = deepcopy(self.policy)
                policy["keys"][0].update(change)
                write_json(self.policy_path, policy)
                with self.assertRaises(ReleaseError):
                    self.verify()

    def test_expired_and_future_signatures_rejected(self):
        for verification_time in (SIGNED_AT + 4000, SIGNED_AT - 1):
            with self.subTest(time=verification_time), self.assertRaises(ReleaseError):
                self.verify(verification_time=verification_time)

    def test_extra_files_are_not_silently_authenticated(self):
        write(self.dist / "unreviewed.tgz", b"extra")
        with self.assertRaisesRegex(ReleaseError, "unexpected or missing"):
            self.verify()

    def test_symlink_and_hardlink_artifacts_rejected(self):
        artifact = self.dist / "cigar-context-0.10.0.crate"
        original = self.root / "original.crate"
        artifact.rename(original)
        artifact.symlink_to(original)
        with self.assertRaises(EvidenceWorkspaceError):
            self.verify()
        artifact.unlink()
        os.link(original, artifact)
        with self.assertRaises(EvidenceWorkspaceError):
            self.verify()

    def test_recomputed_manifest_cannot_waive_release_gates(self):
        manifest = json.loads((self.dist / handoff.MANIFEST).read_bytes())
        manifest["release_blockers"] = []
        write_json(self.dist / handoff.MANIFEST, manifest)
        self.sign(self.dist, handoff.MANIFEST, handoff.PURPOSE + "manifest")
        with self.assertRaisesRegex(ReleaseError, "cannot be waived"):
            self.verify(manifest_sha256=sha(self.dist / handoff.MANIFEST))

    def test_inventories_reject_duplicates_traversal_booleans_and_oversize(self):
        good = {"file": "valid.json", "sha256": "0" * 64, "bytes": 1}
        for inventory in (
            [good, good],
            [good | {"file": "../escape"}],
            [good | {"bytes": True}],
            [good | {"bytes": handoff.MAX_FILE_BYTES + 1}],
            [good | {"sha256": "invalid"}],
        ):
            with (
                self.subTest(inventory=inventory),
                self.assertRaises((ReleaseError, EvidenceWorkspaceError)),
            ):
                handoff.rows(inventory)

    def test_missing_failed_duplicate_or_boolean_checks_are_rejected(self):
        for checks in (
            [],
            [{"name": "required", "exit_code": 1}],
            [{"name": "required", "exit_code": False}],
            [{"name": "required", "exit_code": 0}] * 2,
        ):
            with self.subTest(checks=checks), self.assertRaises(ReleaseError):
                handoff.passed_checks(checks, {"required"})

    def test_optimized_python_still_rejects_invalid_release_identity(self):
        result = subprocess.run(
            [
                sys.executable,
                "-O",
                str(RELEASE / "context_sdk_handoff.py"),
                "verify",
                "--handoff",
                str(self.dist),
                "--trust-policy",
                str(self.policy_path),
                "--expected-release",
                "0.10.0",
                "--manifest-sha256",
                self.plan["manifest_sha256"],
                "--trust-policy-sha256",
                sha(self.policy_path),
                "--openssl",
                str(self.openssl),
                "--openssl-sha256",
                self.openssl_sha256,
                "--verification-time",
                str(VERIFY_AT),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit 0.10.0 rc/beta prerelease", result.stderr)
