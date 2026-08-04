from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/quality/semgrep_policy.py"
SPEC = importlib.util.spec_from_file_location("semgrep_policy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
semgrep_policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(semgrep_policy)


class SemgrepPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = semgrep_policy.load_policy()

    def test_policy_pins_scanner_upstream_and_effective_ruleset(self) -> None:
        self.assertEqual(
            self.policy["scanner"], {"name": "semgrep", "version": "1.168.0"}
        )
        self.assertEqual(
            self.policy["upstream_ruleset"],
            {
                "canonical": {
                    "bytes": 2423491,
                    "sha256": "0cfcba111781ed0d7f8d4da5bf93e954ac7913066adb1ac554f6e9de38cc7de5",
                },
                "canonicalization": "cigar.semgrep-rule-block-order.v1",
                "retrieved_utc": "2026-07-28T03:01:23Z",
                "rule_count": 1074,
                "url": "https://semgrep.dev/c/p/default",
            },
        )
        self.assertEqual(
            self.policy["effective_ruleset"],
            {
                "bytes": 2423567,
                "sha256": "4414ba8e83cf38b74eab4484cdb44f83d12f0c3ddd0b0cd9e92082859ec283cc",
            },
        )
        self.assertFalse(self.policy["scan"]["use_git_ignore"])
        self.assertNotIn("*", self.policy["scan"]["exclude"])
        self.assertNotIn("**", self.policy["scan"]["exclude"])

    def test_canonicalization_pins_complete_rule_blocks_not_registry_order(
        self,
    ) -> None:
        rule_a = (
            b"- patterns:\n"
            b"  - pattern: safe(...)\n"
            b"  id: example.a\n"
            b"  message: first rule\n"
        )
        rule_z = b"- id: example.z\n  pattern: danger(...)\n  message: last rule\n"
        descriptor = {
            "canonicalization": semgrep_policy.RULESET_CANONICALIZATION,
            "rule_count": 2,
        }
        expected = b"rules:\n" + rule_a + rule_z
        first_order = b"rules:\n" + rule_z + rule_a
        second_order = b"rules:\n" + rule_a + rule_z
        self.assertEqual(
            semgrep_policy.canonicalize_upstream_ruleset(first_order, descriptor),
            expected,
        )
        self.assertEqual(
            semgrep_policy.canonicalize_upstream_ruleset(second_order, descriptor),
            expected,
        )

        pinned = {
            "bytes": len(expected),
            "sha256": hashlib.sha256(expected).hexdigest(),
        }
        semgrep_policy.verify_descriptor(expected, pinned, "fixture")
        changed = first_order.replace(b"danger(...)", b"dangerous(...)")
        changed_canonical = semgrep_policy.canonicalize_upstream_ruleset(
            changed, descriptor
        )
        with self.assertRaisesRegex(
            semgrep_policy.PolicyError, "(size|digest) mismatch"
        ):
            semgrep_policy.verify_descriptor(changed_canonical, pinned, "fixture")

    def test_canonicalization_rejects_ambiguous_or_changed_rule_identity(self) -> None:
        descriptor = {
            "canonicalization": semgrep_policy.RULESET_CANONICALIZATION,
            "rule_count": 2,
        }
        invalid_payloads = {
            "duplicate": (
                b"rules:\n- id: example.same\n  pattern: one(...)\n"
                b"- id: example.same\n  pattern: two(...)\n"
            ),
            "missing": (
                b"rules:\n- pattern: one(...)\n  message: no identity\n"
                b"- id: example.two\n  pattern: two(...)\n"
            ),
            "multiple": (
                b"rules:\n- id: example.one\n  id: example.alias\n"
                b"- id: example.two\n  pattern: two(...)\n"
            ),
            "crlf": (
                b"rules:\r\n- id: example.one\r\n  pattern: one(...)\r\n"
                b"- id: example.two\r\n  pattern: two(...)\r\n"
            ),
        }
        for label, payload in invalid_payloads.items():
            with (
                self.subTest(label=label),
                self.assertRaises(semgrep_policy.PolicyError),
            ):
                semgrep_policy.canonicalize_upstream_ruleset(payload, descriptor)

    def test_policy_rejects_unversioned_or_malformed_canonical_authority(
        self,
    ) -> None:
        mutations = {
            "algorithm": ("canonicalization", "unreviewed.v2"),
            "count": ("rule_count", 0),
        }
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            for label, (field, value) in mutations.items():
                with self.subTest(label=label):
                    policy = copy.deepcopy(self.policy)
                    policy["upstream_ruleset"][field] = value
                    path = temporary / f"{label}.json"
                    path.write_text(json.dumps(policy), encoding="utf-8")
                    with self.assertRaises(semgrep_policy.PolicyError):
                        semgrep_policy.load_policy(path)

            policy = copy.deepcopy(self.policy)
            policy["upstream_ruleset"]["canonical"]["sha256"] = "NOT-A-DIGEST"
            path = temporary / "digest.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(semgrep_policy.PolicyError, "descriptor"):
                semgrep_policy.load_policy(path)

    def test_only_rule_exception_is_bound_to_the_exact_upstream_notice(self) -> None:
        [exception] = self.policy["rule_exceptions"]
        self.assertEqual(
            exception["rule_id"],
            "html.security.plaintext-http-link.plaintext-http-link",
        )
        self.assertEqual(
            exception["path"], "packaging/licenses/rust/COPYRIGHT-library.html"
        )
        semgrep_policy.verify_exception_subject(exception)
        notice = (ROOT / exception["path"]).read_bytes()
        self.assertEqual(len(notice), exception["subject_bytes"])
        self.assertEqual(
            hashlib.sha256(notice).hexdigest(), exception["subject_sha256"]
        )
        self.assertIn(b'href="http://www.apache.org/licenses/LICENSE-2.0"', notice)
        self.assertIn(b'href="http://opensource.org/licenses/MIT"', notice)

    def test_exact_exception_transform_is_deterministic_and_fails_on_subject_change(
        self,
    ) -> None:
        upstream = (
            b"rules:\n"
            b"- id: example.other\n"
            b"  pattern: danger(...)\n"
            b"- id: example.target\n"
            b"  patterns:\n"
            b'  - pattern: <a href="$URL">...</a>\n'
            b"  message: test\n"
            b"  languages: [html]\n"
        )
        expected = upstream.replace(
            b"  patterns:\n",
            b"  paths:\n    exclude:\n    - /notice.html\n  patterns:\n",
            1,
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subject = root / "notice.html"
            subject.write_bytes(b"upstream legal notice\n")
            policy = copy.deepcopy(self.policy)
            policy["rule_exceptions"] = [
                {
                    "path": "notice.html",
                    "rationale": "This fixture is an exact immutable upstream legal notice used to test fail-closed transformation behavior.",
                    "rule_id": "example.target",
                    "subject_bytes": subject.stat().st_size,
                    "subject_sha256": hashlib.sha256(subject.read_bytes()).hexdigest(),
                }
            ]
            policy["effective_ruleset"] = {
                "bytes": len(expected),
                "sha256": hashlib.sha256(expected).hexdigest(),
            }
            self.assertEqual(
                semgrep_policy.apply_exact_exceptions(upstream, policy, root=root),
                expected,
            )
            subject.write_bytes(b"changed legal notice\n")
            with self.assertRaisesRegex(
                semgrep_policy.PolicyError, "exception subject (size|digest) changed"
            ):
                semgrep_policy.apply_exact_exceptions(upstream, policy, root=root)

    def test_scanner_outputs_are_external_owner_only_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cigar-semgrep-output-") as raw:
            parent = Path(raw).resolve(strict=True)
            output = parent / "report.json"
            prepared = semgrep_policy.prepare_external_output(
                output, ROOT, "test report"
            )
            self.assertEqual(prepared, output)
            semgrep_policy.atomic_write(prepared, b"{}\n")
            metadata = prepared.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            with self.assertRaisesRegex(semgrep_policy.PolicyError, "create-new"):
                semgrep_policy.prepare_external_output(output, ROOT, "test report")
            with self.assertRaisesRegex(semgrep_policy.PolicyError, "protected output"):
                semgrep_policy.atomic_write(prepared, b"replacement\n")

            loose = parent / "loose"
            loose.mkdir(mode=0o700)
            os.chmod(loose, 0o755)
            with self.assertRaisesRegex(semgrep_policy.PolicyError, "owner-only"):
                semgrep_policy.prepare_external_output(
                    loose / "report.json", ROOT, "test report"
                )

        with self.assertRaises(semgrep_policy.PolicyError):
            semgrep_policy.prepare_external_output(
                ROOT / "semgrep-report.json", ROOT, "test report"
            )

    def test_security_suppressions_are_exact_rule_same_line_and_safety_preserving(
        self,
    ) -> None:
        ignored_parts = {".git", ".venv", "dist", "node_modules", "target", "vendor"}
        security_suppressions: list[tuple[Path, int, str, str]] = []
        for extension in ("*.py", "*.go"):
            for path in ROOT.rglob(extension):
                if ignored_parts.intersection(path.relative_to(ROOT).parts):
                    continue
                for line_number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), start=1
                ):
                    marker = "nosemgrep: "
                    if marker not in line:
                        continue
                    rule = line.split(marker, 1)[1].strip()
                    if ".security." in rule:
                        security_suppressions.append(
                            (path.relative_to(ROOT), line_number, line, rule)
                        )

        self.assertGreaterEqual(len(security_suppressions), 30)
        allowed_rules = {
            "go.grpc.security.grpc-server-insecure-connection.grpc-server-insecure-connection",
            "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected",
            "python.lang.security.audit.insecure-file-permissions.insecure-file-permissions",
            "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1",
        }
        for relative, line_number, line, rule in security_suppressions:
            with self.subTest(path=str(relative), line=line_number, rule=rule):
                self.assertIn(rule, allowed_rules)
                self.assertRegex(rule, r"^[a-z0-9][a-z0-9.-]+$")
                source_lines = (
                    (ROOT / relative).read_text(encoding="utf-8").splitlines()
                )
                rationale_candidates = source_lines[
                    max(0, line_number - 4) : line_number - 1
                ]
                rationale = [
                    candidate.strip().lstrip("#/ ")
                    for candidate in rationale_candidates
                    if candidate.strip().startswith(("#", "//"))
                    and "fmt:" not in candidate
                ]
                self.assertTrue(any(len(candidate) >= 30 for candidate in rationale))

                if rule.endswith("insecure-file-permissions"):
                    self.assertIn("os.chmod(", line)
                    # The qualifier must be on Semgrep's match-start line. Include the
                    # complete nearby multiline call while validating its exact mode.
                    permission_context = "\n".join(
                        source_lines[
                            max(0, line_number - 5) : min(
                                len(source_lines), line_number + 5
                            )
                        ]
                    )
                    permission_call = re.sub(
                        r"#(?:\s*fmt:\s*skip\s*#)?\s*nosemgrep:[^\n]+",
                        "",
                        permission_context,
                    )
                    match = re.search(
                        r"os\.chmod\(\s*([^,\s]+)\s*,\s*(0o700|0o755)\s*,?\s*\)",
                        permission_call,
                    )
                    self.assertIsNotNone(match)
                    assert match is not None
                    if match.group(2) == "0o755":
                        self.assertEqual(
                            relative, Path("scripts/release/qualify_install.py")
                        )
                        self.assertEqual(match.group(1).strip(), "readonly")
                    else:
                        self.assertEqual(match.group(2), "0o700")
                elif rule.endswith("insecure-hash-algorithm-sha1"):
                    self.assertIn("hashlib.sha1(", line)
                    context = "\n".join(source_lines[line_number - 3 : line_number + 2])
                    self.assertTrue(
                        "usedforsecurity=False" in context
                        or (
                            "historical libFuzzer filename" in context
                            and "sha256_bytes" in context
                        )
                    )
                elif rule.endswith("dynamic-urllib-use-detected"):
                    self.assertEqual(relative, Path("tools/quality/semgrep_policy.py"))
                    self.assertIn("urllib.request.urlopen(request, timeout=60)", line)
                    self.assertEqual(
                        self.policy["upstream_ruleset"]["url"],
                        "https://semgrep.dev/c/p/default",
                    )
                else:
                    context = "\n".join(source_lines[line_number - 4 : line_number + 1])
                    self.assertIn("bufconn.Listen", context)
                    full_source = "\n".join(source_lines)
                    self.assertIn("grpc.WithContextDialer", full_source)

    def test_ci_uses_the_pinned_offline_wrapper_not_registry_auto_config(self) -> None:
        workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertNotIn("semgrep scan --config auto", workflow)
        self.assertIn("tools/quality/semgrep_policy.py hydrate", workflow)
        self.assertIn("tools/quality/semgrep_policy.py scan", workflow)
        self.assertIn("--no-rewrite-rule-ids", semgrep_policy.scan.__code__.co_consts)
        self.assertIn('mkdir -m 0700 "$evidence_directory"', workflow)
        self.assertIn("/cigar-semgrep-security", workflow)
        self.assertNotIn("$RUNNER_TEMP/cigar-semgrep-report.json", workflow)

    def test_failover_script_no_longer_hits_the_semgrep_bash_parser_blind_spot(
        self,
    ) -> None:
        source = (ROOT / "tools/wp18-failover/qualify.sh").read_text(encoding="utf-8")
        self.assertNotIn("${schema_shape##*|}", source)
        self.assertIn("IFS='|' read -r _ PHYSICAL_RESTORE_MIGRATION_SEQUENCE", source)


if __name__ == "__main__":
    unittest.main()
