#!/usr/bin/env python3
from __future__ import annotations

import copy
import gzip
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
ROOT = RELEASE.parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import beta_artifacts  # noqa: E402
import beta_profile  # noqa: E402
import beta_release  # noqa: E402
import signatures  # noqa: E402
from release_lib import (  # noqa: E402
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    sha256_file,
)


SIGNED_AT = int(time.time()) - 120
VERIFY_AT = SIGNED_AT + 60
SOURCE_REVISION = "1" * 40
SOURCE_TREE = "2" * 40


def write_file(path: Path, payload: bytes, mode: int = 0o400) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    os.chmod(path, mode)


def write_json(path: Path, value: object, mode: int = 0o400) -> None:
    write_file(path, canonical_json_bytes(value), mode)


def replace_json(path: Path, value: object) -> None:
    os.chmod(path, 0o600)
    path.write_bytes(canonical_json_bytes(value))
    os.chmod(path, 0o400)


@unittest.skipUnless(os.name == "posix", "beta release evidence requires POSIX")
class BetaReleaseTests(unittest.TestCase):
    fixture_temporary: tempfile.TemporaryDirectory[str]
    fixture: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_temporary = tempfile.TemporaryDirectory(
            prefix="cigar-beta-release-fixture-"
        )
        cls.fixture = Path(cls.fixture_temporary.name).resolve()
        os.chmod(cls.fixture, 0o700)
        cls._generate_keys(cls.fixture / "keys", "release")
        cls._generate_keys(cls.fixture / "keys", "untrusted")
        cls._build_candidate(cls.fixture / "candidate")
        cls._build_qualification(
            cls.fixture / "qualification", cls.fixture / "candidate"
        )
        cls._build_trust_policy(cls.fixture)
        cls._sign_supporting_payloads(cls.fixture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_temporary.cleanup()

    @classmethod
    def _generate_keys(cls, directory: Path, name: str) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private = directory / f"{name}.private.pem"
        public = directory / f"{name}.public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private),
                "-pubout",
                "-out",
                str(public),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.chmod(private, 0o600)
        os.chmod(public, 0o400)

    @classmethod
    def _build_candidate(cls, candidate: Path) -> None:
        candidate.mkdir(mode=0o700)
        matrix = beta_profile.expected_artifact_matrix()
        artifacts: list[dict[str, object]] = []
        for index, entry in enumerate(matrix["artifacts"]):
            relative = f"artifacts/{entry['filename']}"
            path = candidate / relative
            write_file(path, f"reviewed artifact {index}\n".encode())
            artifacts.append(
                {
                    "id": entry["id"],
                    "path": relative,
                    "sha256": sha256_file(path),
                    "bytes": path.stat().st_size,
                    "contract": entry["contract"],
                    "status": "passed",
                }
            )
        descriptor = {
            "schema_version": "cigar.source-descriptor.v1",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(SIGNED_AT)),
            "git": {
                "revision": SOURCE_REVISION,
                "tree": SOURCE_TREE,
                "committed": True,
                "clean": True,
                "status_entry_count": 0,
                "status_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "source_archive": {
                "name": Path(str(artifacts[0]["path"])).name,
                "sha256": artifacts[0]["sha256"],
                "bytes": artifacts[0]["bytes"],
            },
            "policy_inputs": [],
            "tool_inputs": [],
        }
        write_json(candidate / beta_artifacts.SOURCE_DESCRIPTOR_PATH, descriptor)
        for relative, value in (
            (beta_artifacts.CHECKSUM_PATH, b"fixture checksums\n"),
            (beta_artifacts.SBOM_PATH, canonical_json_bytes({"fixture": "cyclonedx"})),
            (beta_artifacts.SPDX_PATH, canonical_json_bytes({"fixture": "spdx"})),
            (
                beta_artifacts.PROVENANCE_PATH,
                canonical_json_bytes({"fixture": "provenance"}),
            ),
            (
                beta_artifacts.VERIFICATION_PATH,
                canonical_json_bytes({"fixture": "verification"}),
            ),
        ):
            write_file(candidate / relative, value)
        reference = lambda relative: {  # noqa: E731
            "path": relative,
            "sha256": sha256_file(candidate / relative),
            "bytes": (candidate / relative).stat().st_size,
        }
        manifest = beta_artifacts._build_manifest_document(
            snapshot=beta_artifacts.GitSnapshot(
                revision=SOURCE_REVISION,
                tree=SOURCE_TREE,
                source_date_epoch=SIGNED_AT,
                generated_at=str(descriptor["generated_at"]),
            ),
            artifacts=artifacts,
            source_descriptor_reference=reference(
                beta_artifacts.SOURCE_DESCRIPTOR_PATH
            ),
            checksums_reference=reference(beta_artifacts.CHECKSUM_PATH),
            sbom_reference=reference(beta_artifacts.SBOM_PATH),
            spdx_reference=reference(beta_artifacts.SPDX_PATH),
            provenance_reference=reference(beta_artifacts.PROVENANCE_PATH),
            binary_build={"fixture": True},
        )
        write_json(candidate / beta_artifacts.BUILD_MANIFEST_PATH, manifest)
        self_inventory = {
            path.relative_to(candidate).as_posix()
            for path in candidate.rglob("*")
            if path.is_file()
        }
        if self_inventory != set(beta_release._candidate_paths()):
            raise AssertionError(
                f"fixture candidate mismatch: {self_inventory ^ set(beta_release._candidate_paths())}"
            )

    @classmethod
    def _build_qualification(cls, directory: Path, candidate: Path) -> None:
        directory.mkdir(mode=0o700)
        manifest, _ = beta_release._candidate_manifest(candidate)
        artifacts = beta_release._artifact_records(manifest)
        policy_by_category = {
            category["id"]: category
            for category in beta_profile.expected_qualification_policy()["categories"]
        }
        source = {
            "revision": SOURCE_REVISION,
            "tree": SOURCE_TREE,
            "archive": {
                "id": "source",
                "sha256": artifacts["source"]["sha256"],
                "bytes": artifacts["source"]["bytes"],
            },
        }
        for category in sorted(policy_by_category):
            policy = policy_by_category[category]
            attachment_relative = f"attachments/{category}.txt"
            attachment = directory / attachment_relative
            write_file(attachment, f"reviewed {category} evidence\n".encode())
            receipt = {
                "schema_version": beta_release.QUALIFICATION_SCHEMA,
                "release_profile": beta_profile.PROFILE_ID,
                "product_version": beta_profile.VERSION,
                "evidence_purpose": beta_release.QUALIFICATION_PURPOSE,
                "id": f"beta-{category}",
                "category": category,
                "source": copy.deepcopy(source),
                "status": "passed",
                "artifact_bindings": [
                    {
                        "id": identifier,
                        "sha256": artifacts[identifier]["sha256"],
                        "bytes": artifacts[identifier]["bytes"],
                    }
                    for identifier in policy["artifact_ids"]
                ],
                "producer": {
                    "name": "cigar-beta-qualification-test",
                    "version": "1",
                    "invocation_id": f"fixture-{category}",
                },
                "checks": [
                    {"id": identifier, "status": "passed"}
                    for identifier in policy["required_checks"]
                ],
                "metrics": {
                    gate["id"]: gate["value"] for gate in policy["metric_gates"]
                },
                "attachments": [
                    {
                        "path": attachment_relative,
                        "sha256": sha256_file(attachment),
                        "bytes": attachment.stat().st_size,
                    }
                ],
            }
            write_json(directory / f"receipts/{category}.json", receipt)

    @classmethod
    def _build_trust_policy(cls, base: Path) -> None:
        trust = base / "trust"
        roots = trust / "roots"
        roots.mkdir(mode=0o700, parents=True)
        public = base / "keys/release.public.pem"
        destination = roots / "release.public.pem"
        write_file(destination, public.read_bytes())
        policy = {
            "schema_version": beta_release.TRUST_POLICY_SCHEMA,
            "policy_id": "initial-beta-release",
            "release_profile": beta_profile.PROFILE_ID,
            "product_version": beta_profile.VERSION,
            "approved_at": SIGNED_AT - 100,
            "valid_from": SIGNED_AT - 200,
            "valid_until": SIGNED_AT + 10_000,
            "signature_verifier": {
                "implementation": "openssl",
                "sha256": signatures.openssl_sha256(),
            },
            "keys": [
                {
                    "key_id": signatures.public_key_id(destination),
                    "public_key": "roots/release.public.pem",
                    "public_key_sha256": sha256_file(destination),
                    "signer_principal": "beta-release-test@example.invalid",
                    "purposes": sorted(beta_profile.BETA_SIGNATURE_PURPOSES),
                    "status": "active",
                    "active_from": SIGNED_AT - 200,
                    "active_until": SIGNED_AT + 10_000,
                    "status_changed_at": None,
                }
            ],
        }
        write_json(trust / "policy.json", policy)

    @classmethod
    def _sign_supporting_payloads(cls, base: Path) -> None:
        signature_directory = base / "signatures"
        signature_directory.mkdir(mode=0o700)
        candidate = base / "candidate"
        manifest, _ = beta_release._candidate_manifest(candidate)
        qualification = beta_release._validate_qualification(
            base / "qualification", manifest
        )
        payloads = (
            *beta_release._candidate_signed_payloads(candidate),
            *beta_release._qualification_signed_payloads(qualification),
        )
        private = base / "keys/release.private.pem"
        public = base / "keys/release.public.pem"
        for index, payload in enumerate(payloads):
            signatures.sign(
                payload.path,
                private,
                public,
                signature_directory / f"support-{index:03d}.sig.json",
                signer_principal="beta-release-test@example.invalid",
                purpose=payload.purpose,
                signed_at=SIGNED_AT,
                expires_at=SIGNED_AT + 5_000,
            )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-beta-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()
        os.chmod(self.work, 0o700)
        for name in ("candidate", "qualification", "signatures", "trust", "keys"):
            shutil.copytree(self.fixture / name, self.work / name)

    def candidate(self) -> Path:
        return self.work / "candidate"

    def qualification(self) -> Path:
        return self.work / "qualification"

    def signature_directory(self) -> Path:
        return self.work / "signatures"

    def trust_policy(self) -> Path:
        return self.work / "trust/policy.json"

    def private_key(self, name: str = "release") -> Path:
        return self.work / f"keys/{name}.private.pem"

    def public_key(self, name: str = "release") -> Path:
        return self.work / f"keys/{name}.public.pem"

    def fake_offline_verification(self, candidate: Path) -> dict[str, object]:
        manifest, _ = beta_release._candidate_manifest(candidate)
        return {
            "status": "passed",
            "source_revision": manifest["source"]["revision"],
            "checks": {"binary_executed": False},
        }

    def plan(self) -> Path:
        output_directory = self.work / "plan"
        output_directory.mkdir(mode=0o700, exist_ok=True)
        output = output_directory / beta_release.RELEASE_EVIDENCE_NAME
        beta_release.plan_release(
            root=ROOT,
            candidate=self.candidate(),
            qualification_directory=self.qualification(),
            signature_directory=self.signature_directory(),
            trust_policy=self.trust_policy(),
            verification_time=VERIFY_AT,
            output=output,
        )
        return output

    def sign_release_evidence(
        self, evidence: Path, *, purpose: str = beta_release.RELEASE_EVIDENCE_PURPOSE
    ) -> Path:
        output = self.work / beta_release.RELEASE_SIGNATURE_NAME
        signatures.sign(
            evidence,
            self.private_key(),
            self.public_key(),
            output,
            signer_principal="beta-release-test@example.invalid",
            purpose=purpose,
            signed_at=SIGNED_AT,
            expires_at=SIGNED_AT + 5_000,
        )
        return output

    def replace_payload_signature(
        self,
        payload: Path,
        *,
        purpose: str,
        key_name: str = "release",
        expires_at: int = SIGNED_AT + 5_000,
    ) -> None:
        selected: Path | None = None
        for envelope_path in self.signature_directory().glob("*.sig.json"):
            envelope = load_json(envelope_path)
            if envelope["payload"]["name"] == payload.name:
                selected = envelope_path
                break
        if selected is None:
            raise AssertionError(f"no signature found for {payload}")
        selected.unlink()
        signatures.sign(
            payload,
            self.private_key(key_name),
            self.public_key(key_name),
            selected,
            signer_principal="beta-release-test@example.invalid",
            purpose=purpose,
            signed_at=SIGNED_AT,
            expires_at=expires_at,
        )

    def mutate_receipt(self, category: str, mutation: callable) -> Path:  # type: ignore[type-arg]
        receipt_path = self.qualification() / f"receipts/{category}.json"
        receipt = load_json(receipt_path)
        mutation(receipt)
        replace_json(receipt_path, receipt)
        self.replace_payload_signature(
            receipt_path, purpose=beta_release.QUALIFICATION_PURPOSE
        )
        return receipt_path

    def test_complete_plan_assembly_and_independent_offline_verification(self) -> None:
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            evidence = self.plan()
            evidence_document = load_json(evidence)
            self.assertEqual(
                evidence_document["claims"],
                {
                    "supporting_payloads_signed": True,
                    "release_evidence_signature_required": True,
                    "published": False,
                    "production_ready": False,
                },
            )
            self.assertNotIn("signed", evidence_document["claims"])
            signature = self.sign_release_evidence(evidence)
            report = beta_release.assemble_release(
                root=ROOT,
                candidate=self.candidate(),
                qualification_directory=self.qualification(),
                signature_directory=self.signature_directory(),
                trust_policy=self.trust_policy(),
                verification_time=VERIFY_AT,
                release_evidence=evidence,
                release_signature=signature,
                output=self.work / "release",
            )
            independent = beta_release.verify_final_release(
                release_directory=self.work / "release",
                trust_policy=self.trust_policy(),
                verification_time=VERIFY_AT,
            )
        self.assertEqual(
            {key: value for key, value in report.items() if key != "verification_time"},
            {
                key: value
                for key, value in independent.items()
                if key != "verification_time"
            },
        )
        self.assertLessEqual(
            abs(report["verification_time"] - independent["verification_time"]), 5
        )
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["binary_executed"])
        self.assertFalse(report["published"])
        self.assertFalse(report["production_ready"])
        self.assertEqual(report["qualification_count"], 11)
        self.assertEqual(
            report["qualification_policy_sha256"],
            beta_release._qualification_policy_reference()["sha256"],
        )

    def test_qualification_policy_is_exact_and_thresholds_are_enforced(self) -> None:
        manifest, _ = beta_release._candidate_manifest(self.candidate())
        mutations = (
            ("missing check", lambda receipt: receipt["checks"].pop()),
            (
                "renamed check",
                lambda receipt: receipt["checks"][0].__setitem__(
                    "id", "renamed-review-check"
                ),
            ),
            (
                "arbitrary check",
                lambda receipt: receipt["checks"].append(
                    {"id": "unreviewed-extra-check", "status": "passed"}
                ),
            ),
            (
                "missing metric",
                lambda receipt: receipt["metrics"].pop(next(iter(receipt["metrics"]))),
            ),
            (
                "extra metric",
                lambda receipt: receipt["metrics"].__setitem__(
                    "unreviewed_extra_metric", 0
                ),
            ),
            (
                "threshold failure",
                lambda receipt: receipt["metrics"].__setitem__(
                    "artifact_count", receipt["metrics"]["artifact_count"] + 1
                ),
            ),
            (
                "noninteger metric",
                lambda receipt: receipt["metrics"].__setitem__("artifact_count", 6.0),
            ),
        )
        for index, (label, mutation) in enumerate(mutations):
            with self.subTest(label=label):
                if index:
                    self.tearDown()
                    self.setUp()
                    manifest, _ = beta_release._candidate_manifest(self.candidate())
                receipt_path = self.qualification() / "receipts/archive-contract.json"
                receipt = load_json(receipt_path)
                mutation(receipt)
                replace_json(receipt_path, receipt)
                with self.assertRaisesRegex(
                    beta_release.BetaReleaseError, "check|metric"
                ):
                    beta_release._validate_qualification(self.qualification(), manifest)

    def test_security_and_all_artifact_qualification_are_mandatory(self) -> None:
        policy = beta_release._qualification_policy()
        all_artifacts = [
            entry["id"]
            for entry in beta_profile.expected_artifact_matrix()["artifacts"]
        ]
        for category in ("security", "provenance", "reproducibility"):
            self.assertEqual(policy[category]["artifact_ids"], all_artifacts)

        (self.qualification() / "receipts/security.json").unlink()
        manifest, _ = beta_release._candidate_manifest(self.candidate())
        with self.assertRaisesRegex(beta_release.BetaReleaseError, "incomplete"):
            beta_release._validate_qualification(self.qualification(), manifest)

    def test_missing_and_duplicate_signatures_are_rejected(self) -> None:
        missing = next(self.signature_directory().glob("*.sig.json"))
        missing.unlink()
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "missing"):
                self.plan()

        self.tearDown()
        self.setUp()
        original = next(self.signature_directory().glob("*.sig.json"))
        duplicate = self.signature_directory() / "duplicate.sig.json"
        shutil.copyfile(original, duplicate)
        os.chmod(duplicate, 0o400)
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "duplicate"):
                self.plan()

    def test_artifact_substitution_is_rejected(self) -> None:
        source_entry = beta_profile.expected_artifact_matrix()["artifacts"][0]
        source = self.candidate() / f"artifacts/{source_entry['filename']}"
        os.chmod(source, 0o600)
        source.write_bytes(b"substituted source archive\n")
        os.chmod(source, 0o400)
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaises(beta_release.BetaReleaseError):
                self.plan()

    def test_candidate_manifest_requires_exact_four_field_source_identity(
        self,
    ) -> None:
        manifest, _descriptor = beta_release._candidate_manifest(self.candidate())
        self.assertEqual(
            manifest["source"],
            {
                "revision": SOURCE_REVISION,
                "tree": SOURCE_TREE,
                "committed": True,
                "clean": True,
            },
        )
        manifest_path = self.candidate() / beta_artifacts.BUILD_MANIFEST_PATH
        for source in (
            {"revision": SOURCE_REVISION, "tree": SOURCE_TREE},
            {
                "revision": SOURCE_REVISION,
                "tree": SOURCE_TREE,
                "committed": False,
                "clean": True,
            },
            {
                "revision": SOURCE_REVISION,
                "tree": SOURCE_TREE,
                "committed": True,
                "clean": True,
                "unexpected": True,
            },
        ):
            with self.subTest(source=source):
                substituted = copy.deepcopy(manifest)
                substituted["source"] = source
                replace_json(manifest_path, substituted)
                with self.assertRaisesRegex(
                    beta_release.BetaReleaseError, "source identity"
                ):
                    beta_release._candidate_manifest(self.candidate())
                replace_json(manifest_path, manifest)

    def test_openssl_path_shadow_and_configuration_environment_are_ignored(
        self,
    ) -> None:
        shadow = self.work / "shadow-bin"
        shadow.mkdir(mode=0o700)
        marker = self.work / "shadow-executed"
        shadow_openssl = shadow / "openssl"
        write_file(
            shadow_openssl,
            f"#!/bin/sh\ntouch '{marker}'\nexit 99\n".encode(),
            0o500,
        )
        captured_environments: list[dict[str, str]] = []
        original_run_bounded = signatures.run_bounded

        def capture_run(*arguments: object, **keywords: object) -> object:
            environment = keywords.get("env")
            self.assertIsInstance(environment, dict)
            captured_environments.append(dict(environment))  # type: ignore[arg-type]
            return original_run_bounded(*arguments, **keywords)  # type: ignore[arg-type]

        polluted = {
            "PATH": str(shadow),
            "OPENSSL_CONF": str(self.work / "attacker.cnf"),
            "OPENSSL_MODULES": str(self.work / "modules"),
            "HOME": str(self.work / "attacker-home"),
            "LANG": "attacker",
            "LC_ALL": "attacker",
        }
        with (
            mock.patch.dict(os.environ, polluted, clear=False),
            mock.patch.object(signatures, "run_bounded", side_effect=capture_run),
        ):
            selected = signatures._secure_openssl(None)
            self.assertNotEqual(selected, shadow_openssl.resolve())
            signatures.public_key_id(self.public_key())
        self.assertFalse(marker.exists())
        self.assertTrue(captured_environments)
        self.assertTrue(
            all(
                environment == signatures._fixed_environment()
                for environment in captured_environments
            )
        )
        self.assertEqual(captured_environments[0]["OPENSSL_MODULES"], "/nonexistent")
        self.assertEqual(captured_environments[0]["OPENSSL_ENGINES"], "/nonexistent")

    def test_pinned_openssl_digest_rejects_tool_substitution(self) -> None:
        substituted = self.work / "substituted-openssl"
        marker = self.work / "substituted-openssl-executed"
        write_file(
            substituted,
            f"#!/bin/sh\ntouch '{marker}'\nexit 0\n".encode(),
            0o500,
        )
        with self.assertRaisesRegex(ReleaseError, "pinned SHA-256|matches the pinned"):
            beta_release._load_trust_policy(
                self.trust_policy(),
                VERIFY_AT,
                openssl_path=substituted,
            )
        self.assertFalse(marker.exists())

    def test_sign_and_verify_use_immutable_input_snapshots(self) -> None:
        payload = self.work / "race-payload.txt"
        write_file(payload, b"reviewed payload\n")
        output = self.work / "race-payload.sig.json"
        original_run = signatures._run
        mutated = False

        def mutate_during_sign(*arguments: object, **keywords: object) -> object:
            nonlocal mutated
            if not mutated:
                mutated = True
                os.chmod(payload, 0o600)
                payload.write_bytes(b"substituted payload\n")
                os.chmod(payload, 0o400)
            return original_run(*arguments, **keywords)  # type: ignore[arg-type]

        with (
            mock.patch.object(signatures, "_run", side_effect=mutate_during_sign),
            self.assertRaisesRegex(ReleaseError, "payload changed"),
        ):
            signatures.sign(
                payload,
                self.private_key(),
                self.public_key(),
                output,
                signer_principal="beta-release-test@example.invalid",
                purpose=beta_release.QUALIFICATION_PURPOSE,
                signed_at=SIGNED_AT,
                expires_at=SIGNED_AT + 5_000,
            )
        self.assertFalse(output.exists())

        os.chmod(payload, 0o600)
        payload.write_bytes(b"reviewed payload\n")
        os.chmod(payload, 0o400)
        signatures.sign(
            payload,
            self.private_key(),
            self.public_key(),
            output,
            signer_principal="beta-release-test@example.invalid",
            purpose=beta_release.QUALIFICATION_PURPOSE,
            signed_at=SIGNED_AT,
            expires_at=SIGNED_AT + 5_000,
        )
        mutated = False

        def mutate_during_verify(*arguments: object, **keywords: object) -> object:
            nonlocal mutated
            if not mutated:
                mutated = True
                os.chmod(payload, 0o600)
                payload.write_bytes(b"transiently changed payload\n")
                os.chmod(payload, 0o400)
            return original_run(*arguments, **keywords)  # type: ignore[arg-type]

        with (
            mock.patch.object(signatures, "_run", side_effect=mutate_during_verify),
            self.assertRaisesRegex(ReleaseError, "payload changed"),
        ):
            signatures.verify(
                output,
                payload,
                self.public_key(),
                expected_purpose=beta_release.QUALIFICATION_PURPOSE,
                expected_signer="beta-release-test@example.invalid",
                verification_time=VERIFY_AT,
            )

        symlink = self.work / "race-payload-link.txt"
        symlink.symlink_to(payload)
        with self.assertRaisesRegex(ReleaseError, "securely open|stable"):
            signatures.verify(
                output,
                symlink,
                self.public_key(),
                expected_purpose=beta_release.QUALIFICATION_PURPOSE,
                verification_time=VERIFY_AT,
            )

    def test_signature_payload_snapshot_is_streamed_and_publish_is_no_clobber(
        self,
    ) -> None:
        payload = self.work / "streamed-payload.bin"
        write_file(payload, b"reviewed-streaming-block\n" * 100_000)
        output = self.work / "streamed-payload.sig.json"
        original_stable_bytes = signatures._stable_regular_bytes

        def reject_payload_buffering(
            path: Path,
            maximum: int,
            label: str,
            **keywords: object,
        ) -> bytes:
            if "signature payload" in label:
                raise AssertionError("large payload was buffered in memory")
            return original_stable_bytes(path, maximum, label, **keywords)

        with mock.patch.object(
            signatures, "_stable_regular_bytes", side_effect=reject_payload_buffering
        ):
            signatures.sign(
                payload,
                self.private_key(),
                self.public_key(),
                output,
                signer_principal="beta-release-test@example.invalid",
                purpose=beta_release.QUALIFICATION_PURPOSE,
                signed_at=SIGNED_AT,
                expires_at=SIGNED_AT + 5_000,
            )
            signatures.verify(
                output,
                payload,
                self.public_key(),
                expected_purpose=beta_release.QUALIFICATION_PURPOSE,
                expected_signer="beta-release-test@example.invalid",
                verification_time=VERIFY_AT,
            )
        before = output.read_bytes()
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
        self.assertEqual(output.stat().st_nlink, 1)
        with self.assertRaisesRegex(ReleaseError, "overwrite"):
            signatures.sign(
                payload,
                self.private_key(),
                self.public_key(),
                output,
                signer_principal="beta-release-test@example.invalid",
                purpose=beta_release.QUALIFICATION_PURPOSE,
                signed_at=SIGNED_AT,
            )
        self.assertEqual(output.read_bytes(), before)

        actual_parent = self.work / "signature-output-parent"
        actual_parent.mkdir(mode=0o700)
        parent_alias = self.work / "signature-output-parent-alias"
        parent_alias.symlink_to(actual_parent, target_is_directory=True)
        aliased_output = parent_alias / "aliased.sig.json"
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            signatures.sign(
                payload,
                self.private_key(),
                self.public_key(),
                aliased_output,
                signer_principal="beta-release-test@example.invalid",
                purpose=beta_release.QUALIFICATION_PURPOSE,
                signed_at=SIGNED_AT,
            )
        self.assertFalse((actual_parent / aliased_output.name).exists())

    def test_long_verification_uses_one_start_time_and_a_fresh_completion_check(
        self,
    ) -> None:
        output_directory = self.work / "long-plan"
        output_directory.mkdir(mode=0o700)
        output = output_directory / beta_release.RELEASE_EVIDENCE_NAME
        with (
            mock.patch.object(
                beta_release, "time", wraps=beta_release.time
            ) as mocked_time,
            mock.patch.object(
                beta_release,
                "_verify_candidate_offline",
                side_effect=self.fake_offline_verification,
            ),
        ):
            mocked_time.time.side_effect = [VERIFY_AT, VERIFY_AT + 301]
            beta_release.plan_release(
                root=ROOT,
                candidate=self.candidate(),
                qualification_directory=self.qualification(),
                signature_directory=self.signature_directory(),
                trust_policy=self.trust_policy(),
                verification_time=VERIFY_AT,
                output=output,
            )
        self.assertTrue(output.is_file())

    def test_strict_json_rejects_depth_and_integer_resource_abuse(self) -> None:
        nested = b"[" * 66 + b"0" + b"]" * 66
        with self.assertRaisesRegex(ReleaseError, "levels|bounded strict JSON"):
            load_json_bytes(nested, "nested beta evidence")
        with self.assertRaisesRegex(ReleaseError, "signed 64-bit"):
            load_json_bytes(b"9223372036854775808", "oversized beta integer")

    def test_trust_and_qualification_collection_bounds_are_enforced(self) -> None:
        policy = load_json(self.trust_policy())
        policy["keys"] = [copy.deepcopy(policy["keys"][0]) for _ in range(257)]
        replace_json(self.trust_policy(), policy)
        with self.assertRaisesRegex(
            beta_release.BetaReleaseError, "public-root inventory"
        ):
            beta_release._snapshot_trust_policy(
                self.trust_policy(), self.work / "bounded-trust"
            )

        self.tearDown()
        self.setUp()
        receipt_path = self.qualification() / "receipts/archive-contract.json"
        receipt = load_json(receipt_path)
        receipt["checks"] = [
            {"id": f"check-{index}", "status": "passed"} for index in range(4097)
        ]
        replace_json(receipt_path, receipt)
        manifest, _ = beta_release._candidate_manifest(self.candidate())
        with self.assertRaisesRegex(beta_release.BetaReleaseError, "checks"):
            beta_release._validate_qualification(self.qualification(), manifest)

        self.tearDown()
        self.setUp()
        receipt_path = self.qualification() / "receipts/archive-contract.json"
        receipt = load_json(receipt_path)
        receipt["attachments"] = [
            copy.deepcopy(receipt["attachments"][0]) for _ in range(4097)
        ]
        replace_json(receipt_path, receipt)
        manifest, _ = beta_release._candidate_manifest(self.candidate())
        with self.assertRaisesRegex(beta_release.BetaReleaseError, "attachments"):
            beta_release._validate_qualification(self.qualification(), manifest)

        self.tearDown()
        self.setUp()
        oversized = self.qualification() / "attachments/oversized.bin"
        with oversized.open("xb") as handle:
            handle.seek(beta_release.MAX_WORKSPACE_FILE_BYTES)
            handle.write(b"\0")
        os.chmod(oversized, 0o400)
        receipt_path = self.qualification() / "receipts/archive-contract.json"
        receipt = load_json(receipt_path)
        receipt["attachments"][0] = {
            "path": "attachments/oversized.bin",
            "sha256": "0" * 64,
            "bytes": beta_release.MAX_WORKSPACE_FILE_BYTES + 1,
        }
        replace_json(receipt_path, receipt)
        manifest, _ = beta_release._candidate_manifest(self.candidate())
        with self.assertRaisesRegex(beta_release.BetaReleaseError, "changed"):
            beta_release._validate_qualification(self.qualification(), manifest)

        with self.assertRaisesRegex(beta_release.BetaReleaseError, "metric"):
            beta_release._validate_metrics({"overflow": 1 << 63})

    def test_source_extraction_streams_and_bounds_entries_before_materialization(
        self,
    ) -> None:
        archive_path = self.work / "bounded-source.tar.gz"
        with archive_path.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=SIGNED_AT
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for name in ("a.txt", "b.txt", "c.txt"):
                        payload = name.encode()
                        information = tarfile.TarInfo(name)
                        information.size = len(payload)
                        information.mode = 0o644
                        information.mtime = SIGNED_AT
                        information.uid = 0
                        information.gid = 0
                        information.uname = ""
                        information.gname = ""
                        archive.addfile(information, io.BytesIO(payload))
        os.chmod(archive_path, 0o400)
        with (
            mock.patch.object(beta_release, "MAX_TAR_ENTRIES", 2),
            mock.patch.object(
                tarfile.TarFile,
                "getmembers",
                side_effect=AssertionError("unbounded getmembers call"),
            ),
            self.assertRaisesRegex(beta_release.BetaReleaseError, "entry count"),
        ):
            beta_release._extract_source_archive(
                archive_path,
                self.work / "extracted-source",
                SIGNED_AT,
            )

    def test_source_extraction_bounds_raw_gzip_expansion_before_tar_parsing(
        self,
    ) -> None:
        archive_path = self.work / "expansion-source.tar.gz"
        with archive_path.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=SIGNED_AT
            ) as compressed:
                compressed.write(b"\0" * 64 * 1024)
        os.chmod(archive_path, 0o400)
        with (
            mock.patch.object(beta_release, "MAX_TAR_ENTRIES", 1),
            mock.patch.object(beta_release, "MAX_TAR_TOTAL_BYTES", 1024),
            mock.patch.object(
                tarfile,
                "open",
                side_effect=AssertionError("tar parser reached before expansion check"),
            ),
            self.assertRaisesRegex(beta_release.BetaReleaseError, "expansion"),
        ):
            beta_release._extract_source_archive(
                archive_path,
                self.work / "expanded-source",
                SIGNED_AT,
            )

    def test_wrong_signature_purpose_is_rejected(self) -> None:
        payload = self.candidate() / beta_artifacts.CHECKSUM_PATH
        self.replace_payload_signature(
            payload, purpose="cigar-beta-release-artifact-v1"
        )
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "purpose"):
                self.plan()

    def test_wrong_version_source_and_artifact_bindings_are_rejected(self) -> None:
        mutations = (
            (
                "archive-contract",
                lambda receipt: receipt.__setitem__("product_version", "9.9.9"),
            ),
            (
                "archive-contract",
                lambda receipt: receipt["source"].__setitem__("revision", "3" * 40),
            ),
            (
                "archive-contract",
                lambda receipt: receipt["artifact_bindings"][0].__setitem__(
                    "sha256", "4" * 64
                ),
            ),
        )
        for index, (category, mutation) in enumerate(mutations):
            if index:
                self.tearDown()
                self.setUp()
            self.mutate_receipt(category, mutation)
            with mock.patch.object(
                beta_release,
                "_verify_candidate_offline",
                side_effect=self.fake_offline_verification,
            ):
                with self.assertRaises(beta_release.BetaReleaseError):
                    self.plan()

    def test_untrusted_revoked_and_expired_signatures_are_rejected(self) -> None:
        payload = self.candidate() / beta_artifacts.CHECKSUM_PATH
        self.replace_payload_signature(
            payload,
            purpose="cigar-beta-release-checksums-v1",
            key_name="untrusted",
        )
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "untrusted"):
                self.plan()

        self.tearDown()
        self.setUp()
        policy = load_json(self.trust_policy())
        policy["keys"][0]["status"] = "revoked"
        policy["keys"][0]["status_changed_at"] = SIGNED_AT + 1
        replace_json(self.trust_policy(), policy)
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "revoked"):
                self.plan()

        self.tearDown()
        self.setUp()
        policy = load_json(self.trust_policy())
        policy["keys"][0]["status"] = "retired"
        policy["keys"][0]["status_changed_at"] = SIGNED_AT + 1
        replace_json(self.trust_policy(), policy)
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "retired"):
                self.plan()

        self.tearDown()
        self.setUp()
        policy = load_json(self.trust_policy())
        policy["keys"][0]["active_until"] = VERIFY_AT
        replace_json(self.trust_policy(), policy)
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "not active"):
                self.plan()

        self.tearDown()
        self.setUp()
        self.replace_payload_signature(
            self.candidate() / beta_artifacts.CHECKSUM_PATH,
            purpose="cigar-beta-release-checksums-v1",
            expires_at=VERIFY_AT,
        )
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "expired"):
                self.plan()

    def test_expired_trust_policy_is_rejected(self) -> None:
        policy = load_json(self.trust_policy())
        policy["valid_until"] = VERIFY_AT
        replace_json(self.trust_policy(), policy)
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(
                beta_release.BetaReleaseError, "validity window|not valid"
            ):
                self.plan()

        self.tearDown()
        self.setUp()
        policy = load_json(self.trust_policy())
        policy["approved_at"] = int(time.time()) + 1_000
        replace_json(self.trust_policy(), policy)
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "unapproved"):
                self.plan()

        with self.assertRaisesRegex(
            beta_release.BetaReleaseError, "trusted host clock"
        ):
            beta_release._current_verification_time(SIGNED_AT - 10_000)

    def test_release_signature_wrong_purpose_and_document_substitution_are_rejected(
        self,
    ) -> None:
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            evidence = self.plan()
            signature = self.sign_release_evidence(
                evidence, purpose="cigar-beta-release-artifact-v1"
            )
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "purpose"):
                beta_release.assemble_release(
                    root=ROOT,
                    candidate=self.candidate(),
                    qualification_directory=self.qualification(),
                    signature_directory=self.signature_directory(),
                    trust_policy=self.trust_policy(),
                    verification_time=VERIFY_AT,
                    release_evidence=evidence,
                    release_signature=signature,
                    output=self.work / "release-wrong-purpose",
                )

        self.tearDown()
        self.setUp()
        with mock.patch.object(
            beta_release,
            "_verify_candidate_offline",
            side_effect=self.fake_offline_verification,
        ):
            evidence = self.plan()
            signature = self.sign_release_evidence(evidence)
            document = load_json(evidence)
            document["product_version"] = "9.9.9"
            replace_json(evidence, document)
            with self.assertRaisesRegex(
                beta_release.BetaReleaseError, "canonical plan"
            ):
                beta_release.assemble_release(
                    root=ROOT,
                    candidate=self.candidate(),
                    qualification_directory=self.qualification(),
                    signature_directory=self.signature_directory(),
                    trust_policy=self.trust_policy(),
                    verification_time=VERIFY_AT,
                    release_evidence=evidence,
                    release_signature=signature,
                    output=self.work / "release-substituted",
                )


if __name__ == "__main__":
    unittest.main()
