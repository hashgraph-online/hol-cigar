# 0.12 startup exploration

`compare_installed.py` is the candidate comparison harness. It runs two actual
installed distributions, without copying or patching SDK code. Under an OS
network-deny policy, pass `--baseline /path/to/011/bin/python`,
`--candidate /path/to/012/bin/python`, and `--output /new/result/directory`.
It retains 172 complete compile results and 160 answer-review scenarios per
version, two canonicalization regression controls, 25 paired fresh-process
startup samples, separate allocation samples, and eight paired persistent-worker
sessions (768 documents, 64 queries). It fails on changed valid context output or
fixture decisions. Runtime dependency versions and installed module paths are
retained. Timings are descriptive results on the tested host.

The older prototype study below remains historical evidence only.

This is an offline feasibility study for the
[0.12 engineering plan](../../docs/proposals/cigar-0.12.0-plan.md), not a release
qualification or a 0.11-versus-0.12 product comparison.

`measure_startup.py` copies a genuinely installed Python SDK into a new scratch
directory and creates a second copy with two small prototypes: lazy top-level
exports and a streaming SHA-256 implementation using a reusable 1 MiB buffer.
It does not change the installed package or the SDK source in the checkout.
The native worker bytes, core identity and hash checks remain identical.

Run the helper with Python 3.11 or newer, supplying an interpreter from a clean
installed `hol-cigar==0.11.0` environment:

```sh
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  python3 benches/context-012/measure_startup.py \
  --installed-python /absolute/path/to/installed-venv/bin/python \
  --output /absolute/path/to/new-probe-directory \
  --rounds 25 --memory-rounds 5
```

The output directory must not exist. macOS is the recorded platform; on Linux use
an equivalent network-deny environment. This helper uses Unix `resource` accounting
and is not a Windows qualification harness. There are no downloads, provider
calls or remote fixtures.

Each observation runs in a fresh Python process. Bytecode is compiled before
measurement and filesystem caches are warm. Two warmups are excluded; 25 timing
rounds alternate baseline/prototype order. Five separate allocation rounds use
`tracemalloc`; their timings are excluded from latency summaries. p95 uses the
nearest-rank observation. Standard probe modules load before the operation timer;
process wall time is also reported. Parent RSS excludes the Rust worker. Timing
repetitions on one host/session are descriptive, not independent deployment trials.

`import` measures the facade; `local_api` resolves `LocalContextGraph`; `remote_api`
resolves `CigarClient`. `graph_open` excludes imports and measures the constructor,
including actual worker startup/handshake. `first_graph` includes the import and
constructor. Graph stats/close occur after that operation timer. `hash_whole` and
`hash_stream` check the same executable and assert identical SHA-256 digests.
All 69 public export names, object descriptors and inspectable signatures must
agree between the copies before measurement; this is not a full compatibility suite.

## Recorded evidence

Recorded on 2026-09-25 with Python 3.14.7 on macOS 26.6.1, Apple M3 Ultra,
32 physical cores and 512 GiB RAM. The installed ARM64 worker is 7,282,320 bytes.
The result JSON records source, prototype, harness and worker hashes, raw samples,
timing/allocation summaries and methodological limits.

See [startup-2026-09-25.json](startup-2026-09-25.json) for the final recorded run,
including 300 timing and 60 allocation observations. The large prototype
directories and their copies of native executables remain scratch artifacts.

| Operation | Installed 0.11.0 copy, p50 / p95 ms | Prototype, p50 / p95 ms | p50 reduction |
| --- | --- | --- | --- |
| Import facade | 76.33 / 89.46 | 1.47 / 1.56 | 98.1% |
| Import local graph API | 67.27 / 85.20 | 11.95 / 12.50 | 82.2% |
| Import remote client API | 66.95 / 87.52 | 60.73 / 61.39 | 9.3% |
| Import plus first graph | 123.87 / 161.65 | 67.69 / 69.95 | 45.4% |
| Graph open after imports | 56.41 / 57.76 | 55.65 / 57.10 | 1.4% |

In separate hash-only probes, maximum traced Python allocation was 7,284,019 bytes
for whole-file hashing and 1,182,314 bytes for streaming: an 83.8% reduction.
Hash p50 was 3.32 versus 3.05 ms. Median parent RSS for facade import was 36.75 MB
versus 18.71 MB; first-graph parent RSS was 44.14 MB versus 25.90 MB. MB here means
1,000,000 bytes. These are parent-process measurements, not total graph memory.

The recorded local API probe loads `cigar_sdk.context` without the remote client,
generated models or workflow-session modules. Both copies resolve all 69 exports
to matching descriptors/signatures when explicitly accessed. The prototype remains
unqualified for typing, concurrent lazy access, all failure paths and other platforms.

The useful conclusions are that lazy exports avoid substantial unrelated SDK
work for local callers and a bounded buffer eliminates the full-worker Python
allocation. A remote client still incurs its own import cost. Streaming hashing
alone does not promise a large constructor-latency gain. The existing baseline
already avoids importing `google.protobuf`; that assertion alone would not catch
the eager SDK imports this experiment removes.
