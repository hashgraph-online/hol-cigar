#!/usr/bin/env python3
"""Run bounded WP19 memory/fuzz gates and emit content-free evidence.

This runner deliberately records only commands, digests, counters, timings, and outcomes. Fuzzer
inputs and subprocess output never enter qualification artifacts. A smoke result can never satisfy
the separately declared seven-day-equivalent accumulation requirement.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN = ROOT / "fuzz" / "campaign-v1.json"
SMOKE_EVIDENCE = ROOT / "artifacts" / "qualification" / "wp19-quality-smoke.json"
MUTATION_EVIDENCE = ROOT / "artifacts" / "qualification" / "wp19-quality-mutation.json"
MUTATION_FILTER = (
    "(encode_head|from_deterministic_cbor|semantic_envelope_v1|"
    "semantic_multihash_v1|digest_v1)"
)
MUTATION_THRESHOLD_PERCENT = 90.0
SOURCE_SUFFIXES = {
    ".rs",
    ".toml",
    ".lock",
    ".proto",
    ".json",
    ".yaml",
    ".yml",
}


class GateFailure(RuntimeError):
    """A qualification command or threshold failed."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_files(files: Iterable[Path]) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for path in sorted({path.resolve() for path in files}):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT.resolve()).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256_file(path)))
        count += 1
    return digest.hexdigest(), count


def source_digest() -> dict[str, Any]:
    files: list[Path] = [
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        Path(__file__).resolve(),
    ]
    for base in (
        ROOT / "crates",
        ROOT / "vendor",
        ROOT / "fuzz",
        ROOT / "tests" / "properties",
        ROOT / "tests" / "miri",
    ):
        for path in base.rglob("*"):
            if not path.is_file() or "target" in path.parts or "corpus" in path.parts:
                continue
            if path.suffix in SOURCE_SUFFIXES or path.name in {
                "Cargo.toml",
                "Cargo.lock",
            }:
                files.append(path)
    digest, count = digest_files(files)
    return {
        "algorithm": "sha256-path-and-content-v1",
        "digest": digest,
        "file_count": count,
    }


def corpus_state(path: Path) -> dict[str, Any]:
    files = [candidate for candidate in path.rglob("*") if candidate.is_file()]
    digest = hashlib.sha256()
    total_bytes = 0
    for candidate in sorted(files):
        relative = candidate.relative_to(path).as_posix().encode()
        body_digest = bytes.fromhex(sha256_file(candidate))
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(body_digest)
        total_bytes += candidate.stat().st_size
    return {
        "algorithm": "sha256-path-and-content-v1",
        "digest": digest.hexdigest(),
        "file_count": len(files),
        "total_bytes": total_bytes,
    }


def artifact_state(target: str) -> dict[str, Any]:
    path = ROOT / "fuzz" / "artifacts" / target
    files = (
        [candidate for candidate in path.rglob("*") if candidate.is_file()]
        if path.exists()
        else []
    )
    return {
        "file_count": len(files),
        "digests": sorted(sha256_file(path) for path in files),
    }


def run(
    command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None
) -> dict[str, Any]:
    rendered = " ".join(command)
    print(f"running: {rendered}", flush=True)
    started = utc_now()
    monotonic = time.monotonic()
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    process = subprocess.run(
        command,
        cwd=cwd,
        env=merged_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    duration = round(time.monotonic() - monotonic, 3)
    return {
        "command": rendered,
        "started_at": started,
        "finished_at": utc_now(),
        "duration_seconds": duration,
        "exit_code": process.returncode,
        "_output": process.stdout,
    }


def public_result(result: dict[str, Any], **extra: Any) -> dict[str, Any]:
    redacted = {key: value for key, value in result.items() if key != "_output"}
    redacted.update(extra)
    return redacted


def tool_version(command: list[str]) -> str:
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    return (result.stdout or result.stderr).strip().splitlines()[0]


def platform_record() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def write_evidence(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(body)
    os.replace(temporary, path)


def require_clean(
    result: dict[str, Any], label: str, *, include_output: bool = True
) -> None:
    if result["exit_code"] != 0:
        if not include_output:
            raise GateFailure(
                f"{label} failed with exit {result['exit_code']}; subprocess output withheld"
            )
        tail = "\n".join(result["_output"].splitlines()[-30:])
        raise GateFailure(f"{label} failed with exit {result['exit_code']}:\n{tail}")


def count_passed_tests(output: str) -> int:
    return sum(
        int(match) for match in re.findall(r"test result: ok\. (\d+) passed", output)
    )


def parse_fuzzer_runs(output: str) -> int | None:
    matches = re.findall(r"stat::number_of_executed_units:\s*(\d+)", output)
    if matches:
        return int(matches[-1])
    matches = re.findall(r"Done\s+(\d+)\s+runs", output)
    return int(matches[-1]) if matches else None


def parse_fuzzer_elapsed_seconds(output: str) -> int | None:
    matches = re.findall(r"Done\s+\d+\s+runs in\s+(\d+)\s+second", output)
    return int(matches[-1]) if matches else None


def validate_campaign(campaign: dict[str, Any]) -> list[str]:
    targets = campaign.get("targets")
    if not isinstance(targets, list) or len(targets) != 14 or len(set(targets)) != 14:
        raise GateFailure("campaign must contain exactly fourteen unique targets")
    if campaign.get("sanitizers") != ["address"]:
        raise GateFailure("native smoke sanitizer must be exactly AddressSanitizer")
    declared = {
        match.group(1)
        for match in re.finditer(
            r'^name\s*=\s*"([^"]+)"',
            (ROOT / "fuzz" / "Cargo.toml").read_text(),
            flags=re.MULTILINE,
        )
    }
    missing = sorted(set(targets) - declared)
    if missing:
        raise GateFailure(f"campaign targets missing Cargo bins: {missing}")
    for target in targets:
        if not (ROOT / "fuzz" / "fuzz_targets" / f"{target}.rs").is_file():
            raise GateFailure(f"missing target wrapper: {target}")
        if not (ROOT / "fuzz" / "corpus" / target).is_dir():
            raise GateFailure(f"missing seed corpus: {target}")
    return targets


def smoke(args: argparse.Namespace) -> None:
    campaign = json.loads(CAMPAIGN.read_text())
    targets = validate_campaign(campaign)
    started_at = utc_now()
    source = source_digest()

    check = run(
        [
            "cargo",
            "check",
            "--locked",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--all-targets",
        ]
    )
    require_clean(check, "fuzz harness check")

    properties = run(
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "tests/properties/Cargo.toml",
            "--all-targets",
        ]
    )
    require_clean(properties, "property and Loom suite")

    miri = run(
        [
            "cargo",
            "+nightly",
            "miri",
            "test",
            "--locked",
            "--manifest-path",
            "tests/miri/Cargo.toml",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--test",
            "memory_model",
        ],
        env={"MIRIFLAGS": "-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check"},
    )
    require_clean(miri, "strict Miri slice")

    campaign_smoke_seconds = int(campaign["smoke_seconds_per_target"])
    qualifying_smoke = args.runs is None
    requested_seconds = args.seconds if qualifying_smoke else None
    if qualifying_smoke and requested_seconds < campaign_smoke_seconds:
        raise GateFailure(
            f"--seconds must be at least the campaign smoke threshold ({campaign_smoke_seconds})"
        )

    def fuzz_one(index: int, target: str) -> dict[str, Any]:
        corpus = ROOT / "fuzz" / "corpus" / target
        before_corpus = corpus_state(corpus)
        before_artifacts = artifact_state(target)
        if before_artifacts["file_count"] != 0:
            raise GateFailure(
                f"ASan fuzz target {target} has a pre-existing crash artifact"
            )
        seed = args.seed + index
        limiter = (
            f"-max_total_time={requested_seconds}"
            if qualifying_smoke
            else f"-runs={args.runs}"
        )
        command = [
            "cargo",
            "+nightly",
            "fuzz",
            "run",
            "--sanitizer",
            "address",
            target,
            f"corpus/{target}",
            "--",
            f"-dict={ROOT / 'fuzz' / 'dictionaries' / 'cigar.dict'}",
            limiter,
            f"-seed={seed}",
            f"-timeout={campaign['timeout_seconds']}",
            f"-rss_limit_mb={campaign['rss_limit_mib']}",
            f"-max_len={campaign['maximum_input_bytes']}",
            "-print_final_stats=1",
        ]
        result = run(
            command,
            cwd=ROOT / "fuzz",
        )
        after_artifacts = artifact_state(target)
        after_corpus = corpus_state(corpus)
        require_clean(result, f"ASan fuzz target {target}", include_output=False)
        if after_artifacts["file_count"] != 0:
            raise GateFailure(f"ASan fuzz target {target} created a crash artifact")
        observed_runs = parse_fuzzer_runs(result["_output"])
        observed_seconds = parse_fuzzer_elapsed_seconds(result["_output"])
        if observed_runs is None or observed_runs < 1:
            raise GateFailure(f"ASan fuzz target {target} reported no executed units")
        if not qualifying_smoke and observed_runs < args.runs:
            raise GateFailure(
                f"ASan fuzz target {target} did not report at least {args.runs} executed units"
            )
        if qualifying_smoke and (
            observed_seconds is None or observed_seconds < requested_seconds
        ):
            raise GateFailure(
                f"ASan fuzz target {target} did not report {requested_seconds} elapsed seconds"
            )
        return public_result(
            result,
            target=target,
            sanitizer="address",
            deterministic_seed=seed,
            qualification_mode="time-threshold"
            if qualifying_smoke
            else "run-count-viability",
            requested_minimum_seconds=requested_seconds,
            requested_minimum_runs=None if qualifying_smoke else args.runs,
            observed_fuzzer_seconds=observed_seconds,
            observed_executed_units=observed_runs,
            corpus_before=before_corpus,
            corpus_after=after_corpus,
            crash_artifacts_before=before_artifacts["file_count"],
            crash_artifacts_after=after_artifacts["file_count"],
            clean=True,
        )

    indexed_results: dict[int, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(fuzz_one, index, target): index
            for index, target in enumerate(targets)
        }
        for future in concurrent.futures.as_completed(futures):
            indexed_results[futures[future]] = future.result()
    fuzz_results = [indexed_results[index] for index in range(len(targets))]

    minimum_cpu_seconds = int(campaign["minimum_clean_cpu_seconds_per_target"])
    finished_source = source_digest()
    if finished_source != source:
        raise GateFailure(
            "qualification source changed while the smoke gates were running"
        )
    document = {
        "schema_version": "cigar.wp19-quality-smoke.v1",
        "content_policy": "metadata-only-no-corpus-no-subprocess-output",
        "started_at": started_at,
        "finished_at": utc_now(),
        "source": finished_source,
        "campaign": {
            "path": "fuzz/campaign-v1.json",
            "sha256": sha256_file(CAMPAIGN),
            "target_count": len(targets),
            "smoke_seconds_per_target": campaign_smoke_seconds,
            "minimum_clean_cpu_seconds_per_target": minimum_cpu_seconds,
        },
        "toolchains": {
            "rustc": tool_version(["rustc", "--version"]),
            "cargo_nightly": tool_version(["cargo", "+nightly", "--version"]),
            "cargo_fuzz": tool_version(["cargo", "fuzz", "--version"]),
            "miri": tool_version(["cargo", "+nightly", "miri", "--version"]),
        },
        "platform": platform_record(),
        "gates": {
            "harness_check": public_result(check, clean=True),
            "properties_and_loom": public_result(
                properties,
                passed_test_count=count_passed_tests(properties["_output"]),
                clean=True,
            ),
            "strict_miri": public_result(
                miri,
                passed_test_count=count_passed_tests(miri["_output"]),
                clean=True,
            ),
            "asan_libfuzzer": fuzz_results,
        },
        "outcome": {
            "viability_passed": True,
            "campaign_smoke_passed": qualifying_smoke,
            "all_fourteen_targets_executed": len(fuzz_results) == 14,
            "crash_count": 0,
            "sanitizer_failure_count": 0,
            "seven_day_equivalent_satisfied": False,
            "release_threshold_status": "not-satisfied-by-smoke",
            "required_clean_cpu_seconds_per_target": minimum_cpu_seconds,
            "note": (
                "The campaign smoke threshold is distinct from the release accumulation. This "
                "evidence intentionally does not claim the cumulative 604800 clean CPU-seconds "
                "required for each target."
            ),
        },
    }
    write_evidence(SMOKE_EVIDENCE, document)
    print(f"wrote {SMOKE_EVIDENCE.relative_to(ROOT)}", flush=True)


def mutation(_: argparse.Namespace) -> None:
    started_at = utc_now()
    source = source_digest()
    with tempfile.TemporaryDirectory(prefix="cigar-wp19-mutants-") as temporary:
        output_parent = Path(temporary)
        command = [
            "cargo",
            "mutants",
            "--manifest-path",
            "crates/cigar-canon/Cargo.toml",
            "--file",
            "crates/cigar-canon/src/lib.rs",
            "--re",
            MUTATION_FILTER,
            "--baseline",
            "run",
            "--jobs",
            "4",
            "--timeout",
            "120",
            "--minimum-test-timeout",
            "20",
            "--colors",
            "never",
            "--annotations",
            "none",
            "--output",
            str(output_parent),
        ]
        result = run(command)
        if result["exit_code"] not in {0, 2, 3}:
            require_clean(result, "representative mutation campaign")
        outcomes_path = output_parent / "mutants.out" / "outcomes.json"
        if not outcomes_path.is_file():
            raise GateFailure("cargo-mutants did not emit outcomes.json")
        outcome_document = json.loads(outcomes_path.read_text())

    if not isinstance(outcome_document, dict) or not isinstance(
        outcome_document.get("outcomes"), list
    ):
        raise GateFailure("unexpected cargo-mutants outcome schema")
    outcomes = outcome_document["outcomes"]
    counts = {
        name: int(outcome_document.get(name, 0))
        for name in ("caught", "missed", "timeout", "unviable")
    }
    survivors: list[str] = []
    for item in outcomes:
        summary = str(item.get("summary", "")).lower()
        if summary in {"missed", "timeout"}:
            survivors.append(str(item.get("scenario", "unknown mutant")))

    caught = counts.get("caught", 0)
    missed = counts.get("missed", 0)
    timeout = counts.get("timeout", 0)
    denominator = caught + missed + timeout
    if denominator == 0:
        raise GateFailure(f"no viable mutation outcomes found: {counts}")
    score = round(100.0 * caught / denominator, 3)
    passed = score >= MUTATION_THRESHOLD_PERCENT and missed == 0 and timeout == 0
    finished_source = source_digest()
    if finished_source != source:
        raise GateFailure(
            "qualification source changed while the mutation gate was running"
        )
    document = {
        "schema_version": "cigar.wp19-quality-mutation.v1",
        "content_policy": "metadata-only-no-build-logs-no-mutated-source",
        "started_at": started_at,
        "finished_at": utc_now(),
        "source": finished_source,
        "toolchain": {
            "cargo_mutants": tool_version(["cargo", "mutants", "--version"]),
            "rustc": tool_version(["rustc", "--version"]),
        },
        "platform": platform_record(),
        "scope": {
            "package": "cigar-canon",
            "file": "crates/cigar-canon/src/lib.rs",
            "filter": MUTATION_FILTER,
            "representative_not_full_workspace": True,
        },
        "command": public_result(result),
        "outcomes": {
            "counts": counts,
            "viable_denominator": denominator,
            "caught": caught,
            "missed": missed,
            "timeout": timeout,
            "score_percent": score,
            "required_score_percent": MUTATION_THRESHOLD_PERCENT,
            "survivors": survivors,
        },
        "outcome": {
            "representative_campaign_passed": passed,
            "full_release_candidate_campaign_satisfied": False,
            "note": (
                "This deterministic trust-boundary slice is a real threshold gate, but it does "
                "not claim the PRD's four-hour full release-candidate mutation campaign."
            ),
        },
    }
    write_evidence(MUTATION_EVIDENCE, document)
    print(f"wrote {MUTATION_EVIDENCE.relative_to(ROOT)}", flush=True)
    if not passed:
        raise GateFailure(
            f"mutation threshold failed: {score}% caught, {missed} missed, {timeout} timeout"
        )


def verify_evidence(_: argparse.Namespace) -> None:
    """Fail closed on stale, incomplete, threshold-failing, or overclaiming evidence."""

    problems: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            problems.append(message)

    try:
        smoke_document = json.loads(SMOKE_EVIDENCE.read_text())
        mutation_document = json.loads(MUTATION_EVIDENCE.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise GateFailure(f"cannot read quality evidence: {error}") from error

    current_source = source_digest()
    expect(
        smoke_document.get("schema_version") == "cigar.wp19-quality-smoke.v1",
        "unexpected smoke evidence schema",
    )
    expect(
        mutation_document.get("schema_version") == "cigar.wp19-quality-mutation.v1",
        "unexpected mutation evidence schema",
    )
    expect(smoke_document.get("source") == current_source, "smoke evidence is stale")
    expect(
        mutation_document.get("source") == current_source, "mutation evidence is stale"
    )
    expect(
        smoke_document.get("source") == mutation_document.get("source"),
        "smoke and mutation evidence bind different source trees",
    )

    campaign = json.loads(CAMPAIGN.read_text())
    targets = validate_campaign(campaign)
    evidence_campaign = smoke_document.get("campaign", {})
    expect(
        evidence_campaign.get("sha256") == sha256_file(CAMPAIGN),
        "smoke evidence binds a different campaign",
    )
    fuzz_results = smoke_document.get("gates", {}).get("asan_libfuzzer", [])
    expect(isinstance(fuzz_results, list), "ASan result set is not a list")
    if isinstance(fuzz_results, list):
        expect(
            [item.get("target") for item in fuzz_results] == targets,
            "ASan result set does not exactly match the fourteen campaign targets",
        )
        for item in fuzz_results:
            target = item.get("target", "unknown")
            expect(item.get("exit_code") == 0, f"{target}: nonzero fuzz exit")
            expect(item.get("clean") is True, f"{target}: not marked clean")
            expect(item.get("sanitizer") == "address", f"{target}: wrong sanitizer")
            expect(
                item.get("qualification_mode") == "time-threshold",
                f"{target}: only a run-count viability check was recorded",
            )
            expect(
                int(item.get("observed_fuzzer_seconds") or -1)
                >= int(campaign["smoke_seconds_per_target"]),
                f"{target}: campaign smoke duration was not met",
            )
            expect(
                int(item.get("observed_executed_units") or 0) > 0,
                f"{target}: no executed units",
            )
            expect(
                item.get("crash_artifacts_before") == 0
                and item.get("crash_artifacts_after") == 0,
                f"{target}: crash artifact present",
            )

    gates = smoke_document.get("gates", {})
    properties = gates.get("properties_and_loom", {})
    miri = gates.get("strict_miri", {})
    expect(
        properties.get("exit_code") == 0
        and int(properties.get("passed_test_count") or 0) >= 15,
        "property/Loom gate is incomplete",
    )
    expect(
        miri.get("exit_code") == 0 and int(miri.get("passed_test_count") or 0) >= 1,
        "strict Miri gate is incomplete",
    )
    smoke_outcome = smoke_document.get("outcome", {})
    expect(smoke_outcome.get("campaign_smoke_passed") is True, "campaign smoke failed")
    expect(
        smoke_outcome.get("seven_day_equivalent_satisfied") is False,
        "bounded smoke must not claim seven-day-equivalent accumulation",
    )

    mutation_outcomes = mutation_document.get("outcomes", {})
    mutation_outcome = mutation_document.get("outcome", {})
    expect(
        mutation_document.get("command", {}).get("exit_code") == 0,
        "cargo-mutants command did not exit cleanly",
    )
    expect(
        mutation_outcomes.get("missed") == 0 and mutation_outcomes.get("timeout") == 0,
        "mutation survivors or timeouts remain",
    )
    expect(
        float(mutation_outcomes.get("score_percent") or 0)
        >= MUTATION_THRESHOLD_PERCENT,
        "representative mutation score is below threshold",
    )
    expect(
        mutation_outcome.get("representative_campaign_passed") is True,
        "representative mutation campaign failed",
    )
    expect(
        mutation_outcome.get("full_release_candidate_campaign_satisfied") is False,
        "representative mutation evidence must not claim the full RC campaign",
    )
    if problems:
        raise GateFailure("evidence verification failed:\n- " + "\n- ".join(problems))
    print(
        "verified source-bound WP19 ASan smoke, property/Loom, strict Miri, and "
        "representative mutation evidence",
        flush=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_smoke_options(command_parser: argparse.ArgumentParser) -> None:
        limit = command_parser.add_mutually_exclusive_group()
        limit.add_argument("--seconds", type=int, default=60)
        limit.add_argument("--runs", type=int)
        command_parser.add_argument("--jobs", type=int, default=4)
        command_parser.add_argument("--seed", type=int, default=190000)

    smoke_parser = subparsers.add_parser("smoke")
    add_smoke_options(smoke_parser)
    smoke_parser.set_defaults(function=smoke)
    mutation_parser = subparsers.add_parser("mutation")
    mutation_parser.set_defaults(function=mutation)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.set_defaults(function=verify_evidence)
    all_parser = subparsers.add_parser("all")
    add_smoke_options(all_parser)

    def run_all(args: argparse.Namespace) -> None:
        smoke(args)
        mutation(args)

    all_parser.set_defaults(function=run_all)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if getattr(args, "runs", None) is not None and args.runs < 1:
        raise GateFailure("--runs must be positive")
    if getattr(args, "seconds", 1) < 1:
        raise GateFailure("--seconds must be positive")
    if getattr(args, "jobs", 1) < 1:
        raise GateFailure("--jobs must be positive")
    args.function(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as error:
        print(f"quality gate failed: {error}", file=sys.stderr)
        raise SystemExit(1)
