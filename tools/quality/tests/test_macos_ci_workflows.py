from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
LONG_RUNNING = WORKFLOWS / "macos-long-running-qualification.yml"
RELEASE_CANDIDATE = WORKFLOWS / "macos-release-candidate-diagnostics.yml"
SECURITY = WORKFLOWS / "security.yml"
SHA_PIN = re.compile(r"^[0-9a-f]{40}$")


def workflow(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def job_section(document: str, start: str, end: str | None = None) -> str:
    marker = f"  {start}:\n"
    if marker not in document:
        raise AssertionError(f"workflow job {start!r} is absent")
    section = document.split(marker, 1)[1]
    if end is not None:
        end_marker = f"  {end}:\n"
        if end_marker not in section:
            raise AssertionError(f"workflow job {end!r} is absent")
        section = section.split(end_marker, 1)[0]
    return section


def uses_references(document: str) -> list[str]:
    references: list[str] = []
    for line in document.splitlines():
        match = re.match(r"^\s*(?:-\s*)?uses:\s+(\S+)", line)
        if match is not None:
            references.append(match.group(1))
    return references


def assert_immutable_actions(document: str) -> None:
    references = uses_references(document)
    if not references:
        raise AssertionError("workflow has no actions to validate")
    for reference in references:
        separator = reference.rfind("@")
        if separator <= 0 or SHA_PIN.fullmatch(reference[separator + 1 :]) is None:
            raise AssertionError(f"action is not pinned to a full commit: {reference}")


def assert_native_read_only_workflow(document: str) -> None:
    if "permissions:\n  contents: read\n" not in document:
        raise AssertionError("workflow does not use read-only repository permissions")
    if "concurrency:\n" not in document or "cancel-in-progress: false" not in document:
        raise AssertionError("workflow lacks its non-cancelling concurrency lock")
    if document.count("runs-on: macos-15") != document.count("timeout-minutes:"):
        raise AssertionError("every native job must have a timeout")
    if re.search(r"(?m)^\s+runs-on:\s+(?!macos-15$)\S+", document):
        raise AssertionError("workflow contains a non-native runner")
    if "${{ secrets." in document or re.search(
        r"(?m)^\s+(?:contents|id-token|packages|pull-requests):\s+write\s*$", document
    ):
        raise AssertionError("workflow requests secrets or elevated token permissions")
    assert_immutable_actions(document)
    checkouts = document.count("uses: actions/checkout@")
    if checkouts != document.count("persist-credentials: false"):
        raise AssertionError("every checkout must disable persisted credentials")


def run_script_text(document: str) -> str:
    lines = document.splitlines()
    scripts: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)run:\s*\|\s*$", line)
        if match is None:
            index += 1
            continue
        indentation = len(match.group(1))
        index += 1
        while index < len(lines):
            candidate = lines[index]
            if (
                candidate.strip()
                and len(candidate) - len(candidate.lstrip()) <= indentation
            ):
                break
            scripts.append(candidate.strip())
            index += 1
    return "\n".join(scripts)


def assert_bounded_commands(document: str) -> None:
    scripts = run_script_text(document)
    forbidden = (
        r"\bcargo\s+(?:\+\S+\s+)?fuzz\b",
        r"\bcargo\s+xtask\b[^\n]*\btest\s+(?:fuzz|soak|scale)\b",
        r"\blocal_scale\.py\s+run\b",
        r"\bcargo\s+publish\b",
        r"\bnpm\s+publish\b",
        r"\btwine\s+upload\b",
        r"\bgh\s+release\b",
        r"\bcargo\s+xtask\b[^\n]*\brelease\s+sign\b",
    )
    for pattern in forbidden:
        if re.search(pattern, scripts):
            raise AssertionError(f"workflow executes a deferred command: {pattern}")


def assert_upload_digests(document: str) -> None:
    uploads = document.count("uses: actions/upload-artifact@")
    if uploads == 0 or document.count("outputs.artifact-digest") != uploads:
        raise AssertionError("every upload must fail closed on its service digest")
    if document.count('re.fullmatch(r"[0-9a-f]{64}"') != uploads:
        raise AssertionError("every upload digest must be structurally validated")


class MacosCiWorkflowPolicyTests(unittest.TestCase):
    def test_typescript_production_audit_uses_isolated_pnpm11_on_native_macos(
        self,
    ) -> None:
        section = job_section(workflow(SECURITY), "sdk-dependency-policy", "coverage")
        self.assertIn("runs-on: macos-15", section)
        self.assertIn("timeout-minutes: 20", section)
        self.assertIn("corepack prepare pnpm@11.13.0 --activate", section)
        self.assertIn("tools/quality/pnpm_audit.py verify-tool", section)
        self.assertIn("tools/quality/pnpm_audit.py scan", section)
        self.assertIn("tools/quality/pnpm_audit.py verify-receipt", section)
        self.assertIn("CIGAR_AUDIT_NODE", section)
        self.assertIn("CIGAR_PNPM_AUDITOR_ROOT", section)
        self.assertIn("TYPESCRIPT_PRODUCTION_AUDIT_OUTCOME", section)
        self.assertNotIn("corepack pnpm audit", section)
        self.assertNotIn("pnpm install", section)
        self.assertNotIn("cache: pnpm", section)
        self.assertNotIn('--node "$(command -v node)"', section)
        self.assertNotIn("--ignore-registry-errors", section)
        assert_immutable_actions(section)

    def test_weekly_and_manual_long_running_lanes_are_bounded(self) -> None:
        document = workflow(LONG_RUNNING)
        assert_native_read_only_workflow(document)
        assert_bounded_commands(document)
        assert_upload_digests(document)
        self.assertIn('cron: "41 5 * * 0"', document)
        for lane in (
            "mutation",
            "effect-rc",
            "scale-diagnostic",
            "performance-diagnostic",
        ):
            self.assertIn(f"--lane {lane}", document)
        self.assertIn('--evidence-dir "${CIGAR_MUTATION_EVIDENCE}/mutation"', document)
        self.assertIn("test mutations --verify", document)
        self.assertIn("env CIGAR_EFFECT_RC_REPETITIONS=1000", document)
        self.assertIn('process_kill_cases": 24_000', document)
        self.assertIn('possible_remote_commit_logical_operations": 100_000', document)
        self.assertIn(
            "scaled_physical_run_recovers_checkpoint_and_verifies_backup_restore",
            document,
        )
        self.assertIn("local_scale.py preflight", document)
        self.assertIn("local_scale.py verify", document)
        self.assertIn("cigarbench.py", document)
        self.assertIn("replay.receipt.json", document)

    def test_nightly_sanitizer_invokes_and_independently_verifies_manifest(
        self,
    ) -> None:
        document = workflow(SECURITY)
        sanitizer = job_section(
            document, "nightly-production-sanitizers", "nightly-native-qualification"
        )
        self.assertIn("runs-on: macos-15", sanitizer)
        self.assertIn("timeout-minutes: 240", sanitizer)
        self.assertIn("nightly-2026-07-13-aarch64-apple-darwin", sanitizer)
        self.assertIn('test "$(brew list --versions llvm)" = "llvm 22.1.8"', sanitizer)
        self.assertIn("| grep -Fx 'rust-src'", sanitizer)
        for command in ("verify-manifest", "run --receipt", "verify-receipt --receipt"):
            self.assertIn(f"production_sanitizers.py {command}", sanitizer)
        self.assertIn("--lane production-sanitizers", sanitizer)
        self.assertIn('receipt["source_before"]["revision"]', sanitizer)
        self.assertIn('receipt["source_after"]["revision"]', sanitizer)
        assert_immutable_actions(sanitizer)
        assert_bounded_commands(sanitizer)
        assert_upload_digests(sanitizer)

    def test_manual_rc_diagnostics_cover_only_local_authority(self) -> None:
        document = workflow(RELEASE_CANDIDATE)
        assert_native_read_only_workflow(document)
        assert_bounded_commands(document)
        assert_upload_digests(document)
        event_header = document.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", event_header)
        self.assertNotIn("schedule:", event_header)
        self.assertNotIn("push:", event_header)
        self.assertNotIn("pull_request:", event_header)
        self.assertIn("test security", document)
        self.assertIn("release reproduce", document)
        self.assertIn("build_macos_aarch64_archive.py", document)
        self.assertIn("build_macos_homebrew_artifacts.py", document)
        self.assertIn("verify_macos_homebrew_artifacts.py", document)
        self.assertIn("--lane rc-source-security-reproducibility", document)
        self.assertIn("--lane rc-macos-package-chain", document)
        self.assertNotIn("environment:", document)

    def test_workflow_receipt_is_published_then_reopened_in_every_lane(self) -> None:
        long_running = workflow(LONG_RUNNING)
        release_candidate = workflow(RELEASE_CANDIDATE)
        sanitizer = job_section(
            workflow(SECURITY),
            "nightly-production-sanitizers",
            "nightly-native-qualification",
        )
        for document, lane_count in (
            (long_running, 4),
            (release_candidate, 2),
            (sanitizer, 1),
        ):
            with self.subTest(lane_count=lane_count):
                self.assertEqual(
                    document.count("ci_workflow_receipt.py publish"), lane_count
                )
                self.assertEqual(
                    document.count("ci_workflow_receipt.py verify"), lane_count
                )
                self.assertGreaterEqual(
                    document.count('--event-sha "${GITHUB_SHA}"'), lane_count
                )
                self.assertGreaterEqual(
                    document.count('--run-attempt "${GITHUB_RUN_ATTEMPT}"'), lane_count
                )

    def test_policy_helpers_reject_hostile_workflow_mutations(self) -> None:
        document = workflow(LONG_RUNNING)
        mutations = {
            "floating action": document.replace(
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "actions/checkout@v4",
                1,
            ),
            "write permission": document.replace(
                "contents: read", "contents: write", 1
            ),
            "unbounded job": document.replace("timeout-minutes: 355\n", "", 1),
            "non-native runner": document.replace(
                "runs-on: macos-15", "runs-on: ubuntu-latest", 1
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                assert_native_read_only_workflow(mutation)
        with self.assertRaises(AssertionError):
            assert_bounded_commands(
                document.replace(
                    "command_binding='cargo xtask --evidence-dir <external>/mutation test mutations --verify'",
                    "cargo xtask test fuzz",
                    1,
                )
            )
        with self.assertRaises(AssertionError):
            assert_upload_digests(
                document.replace("outputs.artifact-digest", "outputs.ignored", 1)
            )


if __name__ == "__main__":
    unittest.main()
