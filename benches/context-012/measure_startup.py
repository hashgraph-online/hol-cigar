"""Offline exploratory probes of an installed SDK and two isolated prototypes.

This does not modify the installation, qualify a release, or call a model. The
temporary facade and hashing changes are experiments, not shipping SDK code.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import shutil
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


STREAM_HASH = '''\
def _sha256_file(path):
    digest = hashlib.sha256()
    buffer = bytearray(1024 * 1024)
    view = memoryview(buffer)
    with path.open("rb") as handle:
        while size := handle.readinto(buffer):
            digest.update(view[:size])
    return digest.hexdigest()
'''

PROBE = '''\
import sys, time, json, resource
case, memory, worker = sys.argv[1:]
memory = memory == "1"
if case == "exports":
    import inspect, cigar_sdk
    values = {}
    for name in cigar_sdk.__all__:
        value = getattr(cigar_sdk, name)
        try:
            signature = str(inspect.signature(value))
        except (ValueError, TypeError):
            signature = None
        values[name] = {
            "module": getattr(value, "__module__", None),
            "qualname": getattr(value, "__qualname__", None),
            "type": type(value).__qualname__, "signature": signature,
        }
    print(json.dumps({"exports": values, "abi": cigar_sdk.CONTEXT_ABI}))
    raise SystemExit
if case == "graph_open":
    from cigar_sdk import LocalContextGraph
if case.startswith("hash_"):
    import hashlib
    from pathlib import Path
    path = Path(worker)
    __STREAM_HASH__
if memory:
    import tracemalloc
    tracemalloc.start()
start = time.perf_counter_ns()
if case == "import":
    import cigar_sdk
elif case == "local_api":
    from cigar_sdk import LocalContextGraph
elif case == "remote_api":
    from cigar_sdk import CigarClient
elif case in ("graph_open", "first_graph"):
    if case == "first_graph":
        from cigar_sdk import LocalContextGraph
    graph = LocalContextGraph("cigar.startup-probe")
elif case == "hash_whole":
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
elif case == "hash_stream":
    digest = _sha256_file(path)
else:
    raise ValueError(case)
elapsed_ms = (time.perf_counter_ns() - start) / 1e6
peak = tracemalloc.get_traced_memory()[1] if memory else None
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
if sys.platform != "darwin":
    rss *= 1024
if case in ("graph_open", "first_graph"):
    assert graph.stats()["documents"] == 0
    graph.close()
print(json.dumps({
    "operation_ms": elapsed_ms, "python_peak_bytes": peak,
    "parent_peak_rss_bytes": rss,
    "protobuf_loaded": "google.protobuf" in sys.modules,
    "loaded_sdk_modules": [name for name in (
        "cigar_sdk.client", "cigar_sdk.context", "cigar_sdk.generated.models",
        "cigar_sdk.workflow_session") if name in sys.modules],
    "module_count": len(sys.modules),
    "digest": digest if case.startswith("hash_") else None,
}))
'''.replace("    __STREAM_HASH__", "\n".join("    " + line for line in STREAM_HASH.splitlines()))


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def run_json(python: Path, source: str, args: list[str], *, cwd: Path, env: dict[str, str]) -> dict:
    start = time.perf_counter_ns()
    result = subprocess.run(
        [str(python), "-c", source, *args], cwd=cwd, env=env,
        capture_output=True, text=True, check=True, timeout=60,
    )
    value = json.loads(result.stdout)
    value["process_wall_ms"] = (time.perf_counter_ns() - start) / 1e6
    return value


def prototype_facade(source: str) -> str:
    tree = ast.parse(source)
    exports = next(
        ast.literal_eval(node.value) for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
    )
    imports = {
        alias.asname or alias.name: (node.module, alias.name)
        for node in tree.body if isinstance(node, ast.ImportFrom)
        and node.module and node.module.startswith("cigar_sdk.")
        for alias in node.names
    }
    assert set(exports) == {*imports, "CONTEXT_ABI"}
    typing_imports = "\n".join(
        "    " + ast.unparse(node) for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("cigar_sdk.")
    )
    return f'''\
"""Exploratory lazy facade; not a release implementation."""
from importlib import import_module
from typing import TYPE_CHECKING, Final
if TYPE_CHECKING:
{typing_imports}
CONTEXT_ABI: Final = "cigar.context.v1"
_EXPORTS = {imports!r}
__all__ = {exports!r}
def __getattr__(name):
    try:
        module, attribute = _EXPORTS[name]
    except KeyError:
        raise AttributeError(name) from None
    value = getattr(import_module(module), attribute)
    globals()[name] = value
    return value
def __dir__():
    return sorted(set(globals()) | set(__all__))
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-python", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rounds", type=int, default=25)
    parser.add_argument("--memory-rounds", type=int, default=5)
    args = parser.parse_args()
    if args.rounds < 5 or args.memory_rounds < 1:
        parser.error("use at least five timing rounds and one allocation round")
    python = args.installed_python.absolute()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    env = {**os.environ, "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    # Prevent a checkout or inherited PYTHONPATH from masquerading as the installed baseline.
    env.pop("PYTHONPATH", None)
    info = run_json(python, '''
import json, platform, sys, cigar_sdk
from importlib.metadata import version
from pathlib import Path
from cigar_sdk.local_runtime import bundled_worker
print(json.dumps({"package":str(Path(cigar_sdk.__file__).parent),
 "version":version("hol-cigar"),"python":sys.version,"platform":platform.platform(),
 "worker":str(bundled_worker())}))
''', [], cwd=output, env=env)
    package = Path(info["package"])
    worker = Path(info["worker"])
    baseline_init = (package / "__init__.py").read_text(encoding="utf-8")
    variants = ["baseline", "lazy_stream_prototype"]
    for variant in variants:
        target = output / variant / "cigar_sdk"
        shutil.copytree(package, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        if variant != "baseline":
            (target / "__init__.py").write_text(prototype_facade(baseline_init), encoding="utf-8")
            runtime = target / "local_runtime.py"
            source = runtime.read_text(encoding="utf-8")
            before = "hashlib.sha256(binary.read_bytes()).hexdigest()"
            assert source.count(before) == 1
            source = source.replace(before, "_sha256_file(binary)")
            runtime.write_text(source + "\n\n" + STREAM_HASH, encoding="utf-8")
        subprocess.run(
            [str(python), "-m", "compileall", "-q", str(target)],
            check=True, timeout=60, env=env, cwd=output,
        )
    exports = []
    for variant in variants:
        result = run_json(python, PROBE, ["exports", "0", str(worker)], cwd=output,
                          env={**env, "PYTHONPATH": str(output / variant)})
        result.pop("process_wall_ms")
        exports.append(result)
    assert exports[0] == exports[1], "prototype changed exported signatures or identities"
    cases = [(case, variants) for case in ("import", "local_api", "remote_api", "graph_open", "first_graph")]
    cases.extend((case, ["baseline"]) for case in ("hash_whole", "hash_stream"))
    rows = []
    for case, labels in cases:
        for memory, rounds in ((False, args.rounds), (True, args.memory_rounds)):
            for round_id in range(-2, rounds):
                order = labels if round_id % 2 == 0 else list(reversed(labels))
                for variant in order:
                    value = run_json(
                        python, PROBE, [case, str(int(memory)), str(worker)], cwd=output,
                        env={**env, "PYTHONPATH": str(output / variant)},
                    )
                    if value["digest"] is not None:
                        assert value["digest"] == sha256(worker)
                    if round_id >= 0:
                        rows.append({"case": case, "variant": variant, "memory": memory,
                                     "round": round_id, **value})
    summary = []
    for case, labels in cases:
        for variant in labels:
            timing = [r for r in rows if r["case"] == case and r["variant"] == variant and not r["memory"]]
            memory = [r for r in rows if r["case"] == case and r["variant"] == variant and r["memory"]]
            values = sorted(r["operation_ms"] for r in timing)
            summary.append({
                "case": case, "variant": variant, "n": len(timing),
                "p50_ms": statistics.median(values), "p95_ms": values[math.ceil(.95 * len(values)) - 1],
                "process_wall_p50_ms": statistics.median(r["process_wall_ms"] for r in timing),
                "parent_rss_p50_bytes": statistics.median(r["parent_peak_rss_bytes"] for r in timing),
                "allocation_peak_max_bytes": max(r["python_peak_bytes"] for r in memory),
                "protobuf_loaded": sorted({r["protobuf_loaded"] for r in timing}),
                "loaded_sdk_modules": timing[0]["loaded_sdk_modules"],
            })
    manifest = {
        "schema": "cigar.context-012.startup-exploration.v1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "version": info["version"], "python": info["python"], "platform": info["platform"],
        "harness_sha256": sha256(Path(__file__)),
        "baseline_init_sha256": sha256(package / "__init__.py"),
        "baseline_runtime_sha256": sha256(package / "local_runtime.py"),
        "prototype_init_sha256": sha256(output / variants[1] / "cigar_sdk" / "__init__.py"),
        "prototype_runtime_sha256": sha256(output / variants[1] / "cigar_sdk" / "local_runtime.py"),
        "worker_sha256": sha256(worker), "worker_bytes": worker.stat().st_size,
        "resolved_exports": len(exports[0]["exports"]),
        "rounds": args.rounds, "memory_rounds": args.memory_rounds, "warmup_rounds": 2,
        "limits": [
            "Exploratory prototypes, not an implemented or qualified v0.12.0 release.",
            "Fresh Python processes; warm filesystem/bytecode caches, not cold disk measurements.",
            "Common stdlib probe modules load before the operation timer; process wall includes them.",
            "Allocation instrumentation runs separately and its timings are not used.",
            "Parent RSS excludes the Rust worker; no whole-application RSS claim.",
            "One host/session; descriptive timings, not statistically independent deployment samples.",
            "Hash cases run against identical installed native bytes; no digest caching.",
        ],
        "summary": summary, "samples": rows,
    }
    with (output / "results.json").open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"output": str(output / "results.json"), "summary": summary}, indent=2))


if __name__ == "__main__":
    main()
