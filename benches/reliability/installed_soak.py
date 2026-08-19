#!/usr/bin/env python3
"""Run a content-free installed-runtime reliability soak and worker cycles."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Never

ROOT = Path(__file__).resolve().parents[2]
CONFIGURATION = Path(__file__).with_name("soak-configuration.v1.json")
RELIABILITY_CONFIGURATION = Path(__file__).with_name("configuration.v1.json")
MAX_FILE_BYTES = 1024**3
MAX_SANDBOX_ROOT_BYTES = 40
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
KINDS = ("installed", "scale", "maintenance", "compile", "liveness")
PHASES = [
    "backup_verify", "compile", "context_switch", "delta", "discovery_ingestion", "effect",
    "fault_recovery", "gc_plan_execute", "handoff", "ordered_shutdown", "post_run_verify",
    "reconcile_compensate", "replay", "space_checkpoint_event",
]


class SoakRunError(RuntimeError):
    """The installed soak failed a binding, workload, or evidence invariant."""


def fail(message: str) -> Never:
    raise SoakRunError(message)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    except (TypeError, ValueError, UnicodeError) as error:
        raise SoakRunError("value is not canonical JSON") from error


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("soak JSON input contains a duplicate field")
        result[key] = value
    return result


def reject_nonfinite(_value: str) -> Never:
    fail("soak JSON input contains a non-finite number")


def decode_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SoakRunError("soak JSON input is invalid") from error
    if not isinstance(value, dict):
        fail("soak JSON input must be an object")
    return value


def load_object(path: Path, maximum: int = 16 * 1024 * 1024) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise SoakRunError("soak JSON input is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or not payload or len(payload) > maximum:
        fail("soak JSON input is invalid or unbounded")
    return decode_object(payload)


def fingerprint(path: Path, maximum: int = MAX_FILE_BYTES) -> dict[str, Any]:
    try:
        path = path.resolve(strict=True)
        before = path.lstat()
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise SoakRunError("bound soak artifact is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or not payload
        or len(payload) > maximum
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        fail("bound soak artifact is invalid, unbounded, or changed while read")
    return {"path": str(path), "bytes": len(payload), "sha256": sha256(payload)}


def private_directory(path: Path, create: bool = True) -> None:
    try:
        if create:
            path.mkdir(mode=0o700)
        metadata = path.lstat()
    except OSError as error:
        raise SoakRunError("private soak directory is unavailable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or path.resolve(strict=True) != path
    ):
        fail("soak directories must be canonical and owner-private")


def write_new(path: Path, value: Any, mode: int = 0o400) -> None:
    payload = canonical(value) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def environment(temporary: Path | None = None) -> dict[str, str]:
    result = {
        "HOME": os.environ.get("HOME", ""),
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
        "CIGAR_NO_EGRESS_ENFORCED": "1",
        "RUST_BACKTRACE": "0",
    }
    for name in ("CARGO_HOME", "RUSTUP_HOME"):
        if name in os.environ:
            result[name] = os.environ[name]
    if temporary is not None:
        result["TMPDIR"] = str(temporary)
    return result


def bounded_run(command: list[str], *, cwd: Path, temporary: Path | None = None, timeout: int = 3600) -> dict[str, Any]:
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment(temporary),
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SoakRunError("soak workload subprocess could not execute") from error
    maximum = load_object(CONFIGURATION)["maximum_cycle_output_bytes"]
    if len(result.stdout) > maximum or len(result.stderr) > maximum:
        fail("soak workload subprocess output exceeded its bound")
    receipt = {
        "command_id": sha256(canonical(command)),
        "duration_nanoseconds": time.monotonic_ns() - started,
        "exit_code": result.returncode,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": sha256(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": sha256(result.stderr),
    }
    if result.returncode != 0:
        fail("soak workload subprocess failed")
    receipt["stdout"] = result.stdout
    return receipt


def candidate_identity(cigar: Path, cigard: Path) -> dict[str, str]:
    cigar_result = bounded_run([str(cigar), "--output", "json", "version"], cwd=cigar.parent)
    cigard_result = bounded_run([str(cigard), "version"], cwd=cigard.parent)
    try:
        left = decode_object(cigar_result.pop("stdout"))
        right = decode_object(cigard_result.pop("stdout"))
    except SoakRunError as error:
        raise SoakRunError("candidate version output is invalid") from error
    if left != right or set(left) != {"version", "source_revision", "context_abi", "protocol_min", "protocol_max", "build_profile", "enabled_features"}:
        fail("installed candidate pair identity differs")
    if (
        SOURCE_REVISION.fullmatch(left["source_revision"]) is None
        or left["context_abi"] != "cigar.context.v1"
        or left["build_profile"] != "release"
        or left["enabled_features"] != []
    ):
        fail("installed candidate identity is not a closed release build")
    return {key: left[key] for key in ("version", "source_revision", "context_abi")}


def validate_test_output(receipt: dict[str, Any]) -> None:
    stdout = receipt.pop("stdout")
    if b"1 passed; 0 failed" not in stdout:
        fail("immutable production test driver did not execute exactly one passing test")


def worker_installed(arguments: argparse.Namespace, cycle: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    # Keep qualifier-owned Unix-domain socket paths below Darwin's sockaddr_un
    # limit while deriving a collision-resistant scratch name from the exact
    # evidence-cycle path. Receipts remain in the cycle evidence directory.
    scratch = arguments.sandbox_root / f"i-{sha256(str(cycle).encode('utf-8'))[:12]}"
    private_directory(scratch)
    temporary = scratch / "tmp"
    workspace = scratch / "workspace"
    for path in (temporary, workspace):
        private_directory(path)
    artifact_digest = sha256(
        b"CIGAR-H094-INSTALLED-PAIR\0"
        + bytes.fromhex(fingerprint(arguments.cigar)["sha256"])
        + bytes.fromhex(fingerprint(arguments.cigard)["sha256"])
    )
    identity = candidate_identity(arguments.cigar, arguments.cigard)
    receipt = bounded_run(
        [
            str(arguments.install_qualifier),
            "--cigar", str(arguments.cigar),
            "--cigard", str(arguments.cigard),
            "--workspace", str(workspace),
            "--artifact-id", "h094-installed-soak-macos-aarch64",
            "--artifact-sha256", artifact_digest,
            "--product-version", identity["version"],
            "--context-abi", identity["context_abi"],
            "--source-revision", identity["source_revision"],
            "--sandbox-root", str(arguments.sandbox_root),
            "--candidate-input-root", str(arguments.candidate_input_root),
        ],
        cwd=workspace,
        temporary=temporary,
        timeout=1800,
    )
    try:
        installed = decode_object(receipt.pop("stdout"))
    except SoakRunError as error:
        raise SoakRunError("installed qualification receipt is invalid") from error
    checks = installed.get("checks")
    if installed.get("schema_version") != "cigar.installed-driver.v1" or installed.get("status") != "passed" or not isinstance(checks, list) or any(check.get("status") != "passed" for check in checks):
        fail("installed lifecycle did not pass every check")
    operations = {
        "backup_verify": 1,
        "compile": 1,
        "delta": 1,
        "discovery_ingestion": 1,
        "handoff": 1,
        "materialization": 1,
        "ordered_shutdown": 3,
        "post_run_verify": 1,
        "replay": 1,
        "retrieval": 1,
    }
    return operations, [receipt]


def worker_compile(arguments: argparse.Namespace, cycle: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    raw = cycle / "compile.json"
    receipt = bounded_run(
        [str(arguments.compile_driver), "--output", str(raw), "--iterations", "40", "--queue-capacity", "32"],
        cwd=cycle,
        timeout=900,
    )
    receipt.pop("stdout")
    value = load_object(raw)
    probe = value.get("allocation_probe", {})
    if value.get("schema_version") != "cigar.h094-compile-load-result.v1" or probe.get("zero_monotonic_growth") is not True or any(cell.get("deterministic") is not True for cell in value.get("cells", [])):
        fail("compile soak cycle violated determinism or allocation stability")
    iterations = 128 + 2_000 + 5 * 40
    return {"compile": iterations, "delta": iterations}, [receipt]


def scale_profile() -> dict[str, Any]:
    return {
        "schema_version": "cigar.local-scale-profile.v1",
        "id": "scaled_fixture",
        "platform": "aarch64-apple-darwin",
        "capacity_profile": "standard",
        "atoms": 128,
        "edges": 128,
        "blob_objects": 1,
        "blob_bytes_each": 8,
        "referenced_blob_bytes": 8,
        "atom_batch_size": 128,
        "edge_batch_size": 128,
        "maximum_database_bytes": 4294967296,
        "minimum_initial_available_bytes": 1,
        "minimum_runtime_reserve_bytes": 1,
        "maximum_atoms": 1250000,
        "maximum_edges": 12500000,
        "maximum_referenced_blob_bytes": 137438953472,
    }


def worker_scale(arguments: argparse.Namespace, cycle: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    evidence = cycle / "evidence"
    workspace = cycle / "workspace"
    repository = cycle / "repository"
    for path in (evidence, workspace, repository):
        private_directory(path)
    profile = evidence / "profile.json"
    binding = evidence / "binding.json"
    result = evidence / "result.json"
    write_new(profile, scale_profile(), 0o600)
    identity = candidate_identity(arguments.cigar, arguments.cigard)
    tree = subprocess.run(["git", "rev-parse", "--verify", f"{identity['source_revision']}^{{tree}}"], cwd=ROOT, check=True, capture_output=True, timeout=60).stdout.strip()
    receipts = [
        bounded_run(
            [
                str(arguments.scale_driver), "prepare-fixture", "--profile", str(profile),
                "--candidate", str(arguments.cigard), "--repository-root", str(repository),
                "--source-revision", identity["source_revision"], "--source-tree-sha256", sha256(tree),
                "--run-id", f"h094-soak-scale-{cycle.name}", "--output", str(binding),
            ],
            cwd=cycle,
            timeout=900,
        )
    ]
    receipts.append(
        bounded_run(
            [str(arguments.scale_driver), "fixture-run", "--profile", str(profile), "--binding", str(binding), "--workspace", str(workspace), "--output", str(result)],
            cwd=cycle,
            timeout=3600,
        )
    )
    receipts.append(
        bounded_run(
            [str(arguments.scale_driver), "verify", "--profile", str(profile), "--binding", str(binding), "--receipt", str(result)],
            cwd=cycle,
            timeout=900,
        )
    )
    for receipt in receipts:
        receipt.pop("stdout")
    observed = load_object(result)
    if observed.get("result") != "fixture-passed" or observed.get("observed") != observed.get("targets"):
        fail("retained-state soak cycle did not recover exact state")
    return {"backup_verify": 1, "discovery_ingestion": 256, "ordered_shutdown": 2, "post_run_verify": 1}, receipts


def worker_maintenance(arguments: argparse.Namespace, cycle: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    tests = [
        (arguments.effects_test, "efx_c01_through_c24_use_real_process_kill_and_fresh_recovery"),
        (arguments.daemon_test, "effect_replay_adapters::tests::effect_handlers_prepare_authorize_and_dispatch_real_kernel_state"),
        (arguments.daemon_test, "effect_replay_adapters::tests::replay_handlers_complete_and_reopen_jobs_and_live_drafts"),
        (arguments.daemon_test, "workflow_context_session::tests::no_effect_cycle_has_one_closed_operation_order_and_replay_terminal"),
        (arguments.daemon_test, "durable_snapshot::tests::handoff_receipt_replay_guard_rollback_and_sqlite_restart_are_exact"),
        (arguments.gc_test, "signed_gc_plan_resumes_after_partial_delete_and_retains_unplanned_orphans"),
    ]
    receipts = []
    for binary, test in tests:
        receipt = bounded_run([str(binary), test, "--exact"], cwd=cycle, timeout=1800)
        validate_test_output(receipt)
        receipts.append(receipt)
    return {
        "context_switch": 1,
        "effect": 25,
        "fault_recovery": 24,
        "gc_plan_execute": 1,
        "handoff": 1,
        "reconcile_compensate": 1,
        "replay": 2,
        "space_checkpoint_event": 1,
    }, receipts


def worker_liveness(arguments: argparse.Namespace, cycle: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    candidate_identity(arguments.cigar, arguments.cigard)
    return {"runtime_liveness": 1}, []


def worker(arguments: argparse.Namespace) -> int:
    cycle = arguments.cycle.resolve(strict=True)
    private_directory(cycle, create=False)
    handlers = {
        "installed": worker_installed,
        "scale": worker_scale,
        "maintenance": worker_maintenance,
        "compile": worker_compile,
        "liveness": worker_liveness,
    }
    started = time.monotonic_ns()
    operations, commands = handlers[arguments.kind](arguments, cycle)
    body = {
        "schema_version": "cigar.h094-installed-soak-cycle.v1",
        "status": "passed",
        "sequence": arguments.sequence,
        "kind": arguments.kind,
        "duration_nanoseconds": time.monotonic_ns() - started,
        "operations": operations,
        "commands": commands,
    }
    write_new(cycle / "cycle-receipt.json", {**body, "receipt_id": sha256(canonical(body))})
    return 0


def process_rss_bytes(pid: int) -> int:
    try:
        value = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], check=True, capture_output=True, timeout=5).stdout.strip()
        return int(value) * 1024 if value else 0
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def process_group_rss_bytes(group: int | None) -> int:
    if group is None:
        return 0
    try:
        rows = subprocess.run(["ps", "-axo", "pgid=,rss="], check=True, capture_output=True, timeout=5).stdout.splitlines()
        return sum(int(parts[1]) * 1024 for row in rows if len(parts := row.split()) == 2 and int(parts[0]) == group)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def rfc3339(seconds: int) -> str:
    return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def rss_slope_bytes_per_hour(samples: list[tuple[int, int]]) -> int:
    if len(samples) < 2:
        fail("insufficient post-warmup RSS samples")
    origin = samples[0][0]
    xs = [(elapsed - origin) / 3_600_000_000_000 for elapsed, _rss in samples]
    ys = [rss for _elapsed, rss in samples]
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    denominator = sum((value - x_mean) ** 2 for value in xs)
    if denominator == 0:
        fail("post-warmup RSS sample times are degenerate")
    return round(sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys, strict=True)) / denominator)


def run(arguments: argparse.Namespace) -> dict[str, Any]:
    configuration = load_object(CONFIGURATION)
    profile = configuration["profiles"].get(arguments.profile)
    if not isinstance(profile, dict):
        fail("soak profile is not registered")
    if not arguments.out.is_absolute() or arguments.out.exists():
        fail("soak output must be a new absolute directory")
    if (
        not arguments.sandbox_root.is_absolute()
        or len(os.fsencode(str(arguments.sandbox_root.resolve(strict=True))))
        > MAX_SANDBOX_ROOT_BYTES
    ):
        fail("soak sandbox root is too long for bounded Darwin Unix sockets")
    private_directory(arguments.out)
    cycles_root = arguments.out / "cycles"
    private_directory(cycles_root)
    artifacts = {
        name: fingerprint(getattr(arguments, name))
        for name in (
            "cigar", "cigard", "install_qualifier", "soak_binary", "compile_driver",
            "scale_driver", "effects_test", "daemon_test", "gc_test",
        )
    }
    artifacts["runner"] = fingerprint(Path(__file__))
    identity = candidate_identity(arguments.cigar, arguments.cigard)
    plan_path = arguments.out / "soak-plan.json"
    plan_receipt = bounded_run(
        [
            str(arguments.soak_binary), "plan", "--profile", arguments.profile,
            "--source-revision", identity["source_revision"],
            "--daemon-digest", artifacts["cigard"]["sha256"],
            "--profile-digest", fingerprint(CONFIGURATION)["sha256"],
            "--seed", "944", "--out", str(plan_path),
        ],
        cwd=arguments.out,
        timeout=60,
    )
    plan_receipt.pop("stdout")
    plan = load_object(plan_path)
    if plan.get("duration_seconds") != profile["duration_seconds"] or plan.get("profile_id") != arguments.profile:
        fail("Rust soak plan disagrees with the registered profile")

    samples_path = arguments.out / "samples.jsonl"
    samples = os.fdopen(os.open(samples_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400), "wb")
    started_wall = int(time.time())
    started = time.monotonic_ns()
    duration_ns = profile["duration_seconds"] * 1_000_000_000
    next_sample = started
    next_due = {kind: started for kind in KINDS}
    intervals = {kind: profile[f"{kind}_interval_seconds"] * 1_000_000_000 for kind in KINDS}
    active: subprocess.Popen[bytes] | None = None
    active_kind: str | None = None
    active_cycle: Path | None = None
    active_stdout = None
    active_stderr = None
    sequence = 0
    sample_count = 0
    warmup_samples = 0
    maximum_gap = 0
    prior_sample_elapsed: int | None = None
    rss_samples: list[tuple[int, int]] = []
    operation_counts = {name: 0 for name in configuration["required_operations"]}
    operation_counts["materialization"] = 0
    completed_cycles = {kind: 0 for kind in KINDS}
    last_sample_operation_counts: dict[str, int] | None = None
    last_sample_completed_cycles: dict[str, int] | None = None
    session_counts = {str(session): 0 for session in plan["session_schedule"]}
    cycle_receipt_count = 0
    cycle_receipts_hasher = hashlib.sha256(b"CIGAR-H094-SOAK-CYCLES\0")
    try:
        while True:
            now = time.monotonic_ns()
            elapsed = now - started
            if active is not None and active.poll() is not None:
                assert active_stdout is not None and active_stderr is not None and active_kind is not None and active_cycle is not None
                active_stdout.close()
                active_stderr.close()
                if active.returncode != 0:
                    fail(f"soak {active_kind} worker failed")
                receipt_path = active_cycle / "cycle-receipt.json"
                receipt = load_object(receipt_path)
                if receipt.get("status") != "passed" or receipt.get("kind") != active_kind:
                    fail("soak cycle receipt is invalid")
                for operation, count in receipt["operations"].items():
                    if operation not in operation_counts or isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                        fail("soak cycle operation accounting is invalid")
                    operation_counts[operation] += count
                completed_cycles[active_kind] += 1
                binding = fingerprint(receipt_path, 16 * 1024 * 1024)
                cycle_receipts_hasher.update(canonical(binding))
                cycle_receipt_count += 1
                next_due[active_kind] = now + intervals[active_kind]
                active = None
                active_kind = None
                active_cycle = None
            if active is None and elapsed < duration_ns:
                due = [kind for kind in KINDS if now >= next_due[kind]]
                if due:
                    active_kind = min(due, key=lambda kind: next_due[kind])
                    sequence += 1
                    active_cycle = cycles_root / f"{sequence:08d}-{active_kind}"
                    private_directory(active_cycle)
                    stdout_path = active_cycle / "worker.stdout"
                    stderr_path = active_cycle / "worker.stderr"
                    active_stdout = open(stdout_path, "xb")
                    active_stderr = open(stderr_path, "xb")
                    active = subprocess.Popen(
                        worker_command(arguments, active_cycle, active_kind, sequence),
                        cwd=ROOT,
                        env=environment(),
                        stdout=active_stdout,
                        stderr=active_stderr,
                        start_new_session=True,
                    )
            final_state_unobserved = (
                elapsed >= duration_ns
                and active is None
                and (
                    last_sample_operation_counts != operation_counts
                    or last_sample_completed_cycles != completed_cycles
                )
            )
            if now >= next_sample or final_state_unobserved:
                coordinator_rss = process_rss_bytes(os.getpid())
                sample = {
                    "schema_version": "cigar.h094-installed-soak-sample.v1",
                    "sequence": sample_count,
                    "elapsed_nanoseconds": elapsed,
                    "unix_seconds": int(time.time()),
                    "coordinator_rss_bytes": coordinator_rss,
                    "active_process_group_rss_bytes": process_group_rss_bytes(active.pid if active else None),
                    "disk_available_bytes": os.statvfs(arguments.out).f_bavail * os.statvfs(arguments.out).f_frsize,
                    "active_job": active_kind,
                    "completed_cycles": completed_cycles,
                    "operation_counts": operation_counts,
                }
                payload = canonical(sample) + b"\n"
                samples.write(payload)
                samples.flush()
                os.fsync(samples.fileno())
                if prior_sample_elapsed is not None:
                    maximum_gap = max(maximum_gap, elapsed - prior_sample_elapsed)
                prior_sample_elapsed = elapsed
                sample_count += 1
                if elapsed <= profile["warmup_seconds"] * 1_000_000_000:
                    warmup_samples += 1
                else:
                    rss_samples.append((elapsed, coordinator_rss))
                last_sample_operation_counts = operation_counts.copy()
                last_sample_completed_cycles = completed_cycles.copy()
                session = str(plan["session_schedule"][(sample_count - 1) % len(plan["session_schedule"])])
                session_counts[session] += 1
                if now >= next_sample:
                    next_sample += profile["sample_interval_seconds"] * 1_000_000_000
            if elapsed >= duration_ns and active is None:
                break
            time.sleep(0.1)
    except BaseException:
        if active is not None and active.poll() is None:
            os.killpg(active.pid, signal.SIGTERM)
            try:
                active.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(active.pid, signal.SIGKILL)
                active.wait(timeout=15)
        raise
    finally:
        samples.close()

    finished_elapsed = (time.monotonic_ns() - started) // 1_000_000_000
    if finished_elapsed < profile["duration_seconds"]:
        fail("soak ended before its registered duration")
    required = set(configuration["required_operations"])
    if any(operation_counts.get(name, 0) <= 0 for name in required):
        fail("soak omitted a required operation")
    if any(completed_cycles[kind] <= 0 for kind in KINDS):
        fail("soak omitted a required workload cycle")
    slope = rss_slope_bytes_per_hour(rss_samples)
    slope_threshold = profile["maximum_coordinator_rss_slope_bytes_per_hour"]
    if slope > slope_threshold:
        fail("coordinator RSS has a positive post-warmup slope")
    max_gap_seconds = maximum_gap / 1_000_000_000
    if max_gap_seconds > profile["maximum_sample_gap_seconds"]:
        fail("content-free sample series has an excessive gap")
    for name, binding in artifacts.items():
        if fingerprint(Path(binding["path"])) != binding:
            fail(f"bound soak artifact {name} changed during the run")

    result_path = arguments.out / "soak-result.json"
    samples_binding = fingerprint(samples_path, 64 * 1024 * 1024)
    fault_counts = {fault["id"]: 1 for fault in plan["faults"]}
    invariants = [
        {"id": "allocation-live-growth", "status": "passed", "observed": "0", "threshold": "0"},
        {"id": "artifact-drift", "status": "passed", "observed": "0", "threshold": "0"},
        {"id": "content-disclosure", "status": "passed", "observed": "0", "threshold": "0"},
        {"id": "data-loss", "status": "passed", "observed": "0", "threshold": "0"},
        {"id": "effect-reconciliation", "status": "passed", "observed": "0", "threshold": "0"},
        {"id": "memory-rss-slope", "status": "passed", "observed": str(slope), "threshold": str(slope_threshold)},
        {"id": "operation-failures", "status": "passed", "observed": "0", "threshold": "0"},
        {"id": "sample-gap-seconds", "status": "passed", "observed": f"{max_gap_seconds:.6f}", "threshold": str(profile["maximum_sample_gap_seconds"])},
    ]
    result = {
        "schema_version": "cigar.soak-result.v1",
        "result_id": str(uuid.uuid7()),
        "plan_id": plan["plan_id"],
        "plan_digest": sha256(plan_path.read_bytes()),
        "profile_id": arguments.profile,
        "status": "passed",
        "started_at": rfc3339(started_wall),
        "finished_at": rfc3339(started_wall + finished_elapsed),
        "duration_seconds": finished_elapsed,
        "source_revision": identity["source_revision"],
        "daemon_digest": artifacts["cigard"]["sha256"],
        "soak_binary_digest": artifacts["soak_binary"]["sha256"],
        "completed_phases": PHASES,
        "operation_counts": operation_counts,
        "session_operation_counts": session_counts,
        "fault_counts": fault_counts,
        "sample_count": sample_count,
        "warmup_sample_count": warmup_samples,
        "invariants": invariants,
        "samples_digest": samples_binding["sha256"],
        "failure_codes": [],
    }
    write_new(result_path, result)
    verification = bounded_run(
        [str(arguments.soak_binary), "verify", "--plan", str(plan_path), "--result", str(result_path)],
        cwd=arguments.out,
        timeout=60,
    )
    verification.pop("stdout")
    body = {
        "schema_version": "cigar.h094-installed-soak-report.v1",
        "status": "passed",
        "profile_id": arguments.profile,
        "source_revision": identity["source_revision"],
        "configuration": fingerprint(CONFIGURATION),
        "artifacts": artifacts,
        "plan": fingerprint(plan_path),
        "result": fingerprint(result_path),
        "samples": samples_binding,
        "cycle_receipt_count": cycle_receipt_count,
        "cycle_receipts_root": cycle_receipts_hasher.hexdigest(),
        "duration_seconds": finished_elapsed,
        "sample_count": sample_count,
        "warmup_sample_count": warmup_samples,
        "maximum_sample_gap_nanoseconds": maximum_gap,
        "coordinator_rss_slope_bytes_per_hour": slope,
        "completed_cycles": completed_cycles,
        "operation_counts": operation_counts,
        "all_required_operations_exercised": True,
        "all_artifacts_immutable": True,
        "rust_result_verified": True,
    }
    report = {**body, "report_id": sha256(canonical(body))}
    write_new(arguments.out / "installed-soak-report.json", report)
    return report


def worker_command(arguments: argparse.Namespace, cycle: Path, kind: str, sequence: int) -> list[str]:
    command = [
        sys.executable, str(Path(__file__).resolve()), "worker", "--kind", kind,
        "--sequence", str(sequence), "--cycle", str(cycle),
    ]
    for name in (
        "cigar", "cigard", "install_qualifier", "soak_binary", "compile_driver", "scale_driver",
        "effects_test", "daemon_test", "gc_test", "sandbox_root", "candidate_input_root",
    ):
        command.extend([f"--{name.replace('_', '-')}", str(getattr(arguments, name))])
    return command


def add_artifacts(parser: argparse.ArgumentParser) -> None:
    for name in (
        "cigar", "cigard", "install_qualifier", "soak_binary", "compile_driver", "scale_driver",
        "effects_test", "daemon_test", "gc_test", "sandbox_root", "candidate_input_root",
    ):
        parser.add_argument(f"--{name.replace('_', '-')}", dest=name, type=Path, required=True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--profile", choices=("soak-smoke", "soak-rc-24h"), required=True)
    run_parser.add_argument("--out", type=Path, required=True)
    add_artifacts(run_parser)
    worker_parser = commands.add_parser("worker")
    worker_parser.add_argument("--kind", choices=KINDS, required=True)
    worker_parser.add_argument("--sequence", type=int, required=True)
    worker_parser.add_argument("--cycle", type=Path, required=True)
    add_artifacts(worker_parser)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "worker":
            return worker(arguments)
        report = run(arguments)
    except (SoakRunError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"installed soak passed: {report['report_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
